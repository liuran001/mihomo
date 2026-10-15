//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	ECommon "github.com/metacubex/mihomo/common/ebpf"
	"github.com/metacubex/mihomo/component/iface"
	"github.com/metacubex/mihomo/component/netchange"
	"github.com/metacubex/mihomo/component/power"
	"github.com/metacubex/mihomo/listener/sing_tun"
	"github.com/metacubex/mihomo/log"
	"github.com/sagernet/netlink"

	tun "github.com/metacubex/sing-tun"
	"github.com/metacubex/sing/common/control"
	E "github.com/metacubex/sing/common/exceptions"
	"github.com/metacubex/sing/common/x/list"
)

type tcInterfaceMonitor struct {
	access                   sync.Mutex
	network                  tun.NetworkUpdateMonitor
	networkOwned             bool
	networkCallback          *list.Element[tun.NetworkUpdateCallback]
	defaultInterface         tun.DefaultInterfaceMonitor
	defaultInterfaceOwned    bool
	defaultInterfaceCallback *list.Element[tun.DefaultInterfaceUpdateCallback]
	defaultInterfaceName     string
	backgroundNetwork        *power.NetworkSource
	cancel                   context.CancelFunc
	updates                  chan struct{}
	done                     chan struct{}
}

func (i *Inbound) startTCInterfaceMonitor() error {
	networkMonitor, err := tun.NewNetworkUpdateMonitor(log.SingLogger)
	if err != nil {
		return E.Cause(err, "create TC eBPF network monitor")
	}
	networkOwned := true
	defaultInterfaceMonitor, err := tun.NewDefaultInterfaceMonitor(
		networkMonitor,
		log.SingLogger,
		tun.DefaultInterfaceMonitorOptions{
			InterfaceFinder: sing_tun.DefaultInterfaceFinder,
		},
	)
	if err != nil {
		if networkOwned {
			_ = networkMonitor.Close()
		}
		return E.Cause(err, "create TC eBPF default interface monitor")
	}
	return i.startTCInterfaceMonitors(networkMonitor, defaultInterfaceMonitor)
}

func (i *Inbound) startTCInterfaceMonitors(networkMonitor tun.NetworkUpdateMonitor, defaultInterfaceMonitor tun.DefaultInterfaceMonitor) error {
	networkOwned, defaultInterfaceOwned := true, true
	monitorContext, cancel := context.WithCancel(context.Background())
	updates := make(chan struct{}, 1)
	done := make(chan struct{})
	state := &i.interfaceMonitor
	state.access.Lock()
	if state.network != nil {
		state.access.Unlock()
		cancel()
		if defaultInterfaceOwned {
			_ = defaultInterfaceMonitor.Close()
		}
		if networkOwned {
			_ = networkMonitor.Close()
		}
		return nil
	}
	state.network = networkMonitor
	state.networkOwned = networkOwned
	state.defaultInterface = defaultInterfaceMonitor
	state.defaultInterfaceOwned = defaultInterfaceOwned
	state.cancel = cancel
	state.updates = updates
	state.done = done
	state.backgroundNetwork = power.NewNetworkSource()
	state.networkCallback = networkMonitor.RegisterCallback(i.notifyTCInterfaceUpdate)
	state.defaultInterfaceCallback = defaultInterfaceMonitor.RegisterCallback(i.defaultInterfaceUpdated)
	state.defaultInterfaceName = interfaceName(defaultInterfaceMonitor.DefaultInterface())
	state.access.Unlock()
	go func() {
		defer close(done)
		i.runTCInterfaceUpdates(monitorContext, updates)
	}()
	if networkOwned {
		if err := networkMonitor.Start(); err != nil {
			return E.Errors(E.Cause(err, "start TC eBPF network monitor"), i.stopTCInterfaceMonitor())
		}
	}
	if defaultInterfaceOwned {
		if err := defaultInterfaceMonitor.Start(); err != nil {
			return E.Errors(E.Cause(err, "start TC eBPF default interface monitor"), i.stopTCInterfaceMonitor())
		}
	}
	i.setDefaultInterfaceName(i.currentDefaultInterfaceName())
	return nil
}

func (i *Inbound) stopTCInterfaceMonitor() error {
	state := &i.interfaceMonitor
	state.access.Lock()
	networkMonitor := state.network
	networkOwned := state.networkOwned
	networkCallback := state.networkCallback
	defaultInterfaceMonitor := state.defaultInterface
	defaultInterfaceOwned := state.defaultInterfaceOwned
	defaultInterfaceCallback := state.defaultInterfaceCallback
	cancel := state.cancel
	done := state.done
	_ = state.backgroundNetwork.Close()
	state.backgroundNetwork = nil
	state.network = nil
	state.networkOwned = false
	state.networkCallback = nil
	state.defaultInterface = nil
	state.defaultInterfaceOwned = false
	state.defaultInterfaceCallback = nil
	state.defaultInterfaceName = ""
	state.cancel = nil
	state.updates = nil
	state.done = nil
	state.access.Unlock()
	if networkMonitor == nil {
		return nil
	}
	if networkCallback != nil {
		networkMonitor.UnregisterCallback(networkCallback)
	}
	if defaultInterfaceMonitor != nil && defaultInterfaceCallback != nil {
		defaultInterfaceMonitor.UnregisterCallback(defaultInterfaceCallback)
	}
	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
	var closeErr error
	if defaultInterfaceOwned {
		closeErr = defaultInterfaceMonitor.Close()
	}
	if networkOwned {
		closeErr = E.Errors(closeErr, networkMonitor.Close())
	}
	return closeErr
}

func (i *Inbound) defaultInterfaceUpdated(defaultInterface *control.Interface, _ int) {
	i.setDefaultInterfaceName(interfaceName(defaultInterface))
}

func interfaceName(networkInterface *control.Interface) string {
	if networkInterface == nil {
		return ""
	}
	return networkInterface.Name
}

func (i *Inbound) currentDefaultInterfaceName() string {
	state := &i.interfaceMonitor
	state.access.Lock()
	defaultInterfaceMonitor := state.defaultInterface
	state.access.Unlock()
	if defaultInterfaceMonitor == nil {
		return ""
	}
	return interfaceName(defaultInterfaceMonitor.DefaultInterface())
}

func (i *Inbound) setDefaultInterfaceName(interfaceName string) {
	state := &i.interfaceMonitor
	state.access.Lock()
	changed := state.defaultInterfaceName != interfaceName
	state.defaultInterfaceName = interfaceName
	state.backgroundNetwork.SetAvailable(interfaceName != "")
	updates := state.updates
	active := state.network != nil && updates != nil
	state.access.Unlock()
	if active {
		if changed {
			netchange.Notify()
		}
		notifyTCInterfaceUpdate(updates)
	}
}

func (i *Inbound) notifyTCInterfaceUpdate() {
	state := &i.interfaceMonitor
	state.access.Lock()
	updates := state.updates
	active := state.network != nil && updates != nil
	state.access.Unlock()
	if !active {
		return
	}
	notifyTCInterfaceUpdate(updates)
}

func notifyTCInterfaceUpdate(updates chan<- struct{}) {
	select {
	case updates <- struct{}{}:
	default:
	}
}

const (
	tcRetryInitialDelay = 2 * time.Second
	tcRetryMaximumDelay = time.Minute
)

// tcDriftCheckInterval is the low-frequency, unconditional recheck this loop
// also performs, independent of any outstanding recovery: a reconcile pass
// that finds nothing has drifted is cheap, and this is what catches drift no
// event ever fires for. Android's netd flushing the clsact filters out from
// under us is exactly that case -- the flush produces no netlink event this
// package subscribes to, so without this tick interception stays dead until
// some unrelated interface change happens to fire. It is a plain, real ticker
// rather than something folded into the retry timer's arm/disarm bookkeeping
// below, so it neither participates in nor disturbs the backoff any component
// is or is not currently in. A var, not a const, so a test can substitute a
// short interval instead of waiting on the real one.
var tcDriftCheckInterval = 10 * time.Minute

// tcSharedRewriteOutcome is what one named component of an interface update
// reported.
//
// A single update can name more than one outcome (see tcUpdateOutcome):
// tcSharedRewriteOutcome itself is not scoped to shared packet-rewrite
// specifically despite the name, which is kept because the shared
// packet-rewrite step is where the classification originated and where
// sharedRewriteDataPlane.retryOutcome still names it.
type tcSharedRewriteOutcome int

const (
	// tcSharedRewriteUnknown means this component's step did not run, because
	// the update returned before reaching it. It says nothing about whether a
	// recovery is outstanding, so a pending retry is left alone rather than
	// cancelled -- which is what makes it different from Settled.
	tcSharedRewriteUnknown tcSharedRewriteOutcome = iota
	// tcSharedRewriteSettled means there is nothing to recover: the step
	// succeeded, or there is nothing for it to act on.
	tcSharedRewriteSettled
	tcSharedRewriteRecoverable
	// tcSharedRewriteUnrecoverable means the backend is closed or has to be
	// rebuilt, so repeating the step cannot succeed.
	tcSharedRewriteUnrecoverable
)

// tcRetryComponent names one of tcUpdateOutcome's independently-backed-off
// fields, for logging and for indexing runTCInterfaceUpdateLoop's internal
// per-component state.
type tcRetryComponent int

const (
	tcRetryComponentSharedRewrite tcRetryComponent = iota
	tcRetryComponentGeneral
	tcRetryComponentBypassRuleSet
	tcRetryComponentFakeIPRanges
	tcRetryComponentCount
)

func (c tcRetryComponent) String() string {
	switch c {
	case tcRetryComponentSharedRewrite:
		return "shared packet-rewrite"
	case tcRetryComponentGeneral:
		return "TC attachment/infrastructure/host policy"
	case tcRetryComponentBypassRuleSet:
		return "bypass_rule_set"
	case tcRetryComponentFakeIPRanges:
		return "fake-ip ranges"
	default:
		return "unknown"
	}
}

// tcUpdateOutcome is what one full interface-update pass reported, broken out
// per component so runTCInterfaceUpdateLoop can back each one off
// independently: one component settling must not cancel another's pending
// recovery.
//
//   - sharedRewrite: the shared packet-rewrite attach step specifically
//     (sharedRewriteDataPlane.retryOutcome is this field's classifier).
//   - general: every other TC step in updateTCInterfaces -- inventory,
//     topology, infrastructure, the attachment reconcile itself, and host
//     address policy. These are combined into one bucket rather than tracked
//     individually: they already run as one sequential pass sharing the same
//     lock and largely the same recovery path (a fresh reconcile), so
//     splitting them further would track more state without changing what
//     actually gets retried or when.
//   - bypassRuleSet: refreshing the compiled bypass_rule_set policy, driven
//     normally by rule-provider update callbacks rather than network events,
//     which is exactly the case this scheduler exists to also cover: a
//     transient failure with no later rule-set change to retry it.
//   - fakeIPRanges: pushing the fake-ip ranges into the live backends. Same
//     shape as bypassRuleSet -- the driver is a DNS config change, which will
//     not happen again just because one backend refused the write.
type tcUpdateOutcome struct {
	sharedRewrite tcSharedRewriteOutcome
	general       tcSharedRewriteOutcome
	bypassRuleSet tcSharedRewriteOutcome
	fakeIPRanges  tcSharedRewriteOutcome
}

// tcRetryTimer is the slice of *time.Timer this loop needs, reduced to the two
// operations a round performs. A round makes at most one of them: an
// event-driven round that finds a component's step did not run makes none,
// because it must leave the deadline it did not observe exactly as it was.
// Arming hides the stop-and-drain a bare Reset would require, which keeps a
// signal from a previous delay out of the next one. Tests substitute it to
// drive the backoff without waiting on real time.
type tcRetryTimer interface {
	Arm(delay time.Duration)
	Disarm()
	Expired() <-chan time.Time
}

type tcRealRetryTimer struct {
	timer *time.Timer
}

// newTCRetryTimer returns a timer that is not running, so the loop can hold one
// for its whole life and arm it only when a recovery is outstanding.
func newTCRetryTimer() tcRetryTimer {
	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}
	return &tcRealRetryTimer{timer: timer}
}

func (t *tcRealRetryTimer) Arm(delay time.Duration) {
	t.drain()
	t.timer.Reset(delay)
}

func (t *tcRealRetryTimer) Disarm() {
	t.drain()
}

func (t *tcRealRetryTimer) drain() {
	if !t.timer.Stop() {
		select {
		case <-t.timer.C:
		default:
		}
	}
}

func (t *tcRealRetryTimer) Expired() <-chan time.Time { return t.timer.C }

var tcRetryTimerFactory = newTCRetryTimer

func (i *Inbound) runTCInterfaceUpdates(ctx context.Context, updates <-chan struct{}) {
	runTCInterfaceUpdateLoop(ctx, updates, i.updateTCInterfaces, logTCRetrySchedule)
}

// logTCRetrySchedule is runTCInterfaceUpdateLoop's onScheduleChange hook. There
// is no diagnostics endpoint here to publish the next retry deadline through,
// so the debug log is the only place the schedule is visible. Only an armed
// deadline is worth a line: a disarm happens on essentially every healthy
// round and says nothing.
func logTCRetrySchedule(deadline time.Time) {
	if deadline.IsZero() {
		return
	}
	log.Debugln("[EBPF] TC interface update retry scheduled in %s", time.Until(deadline).Round(time.Millisecond))
}

// tcRetryState is one component's independently-tracked backoff: delay is the
// duration it last waited (0 means nothing pending), and deadline is the
// absolute time that delay was measured from -- computed once, from the same
// "now" snapshot used across a whole round, specifically so a component that
// becomes the single earliest one this round arms the real timer for exactly
// delay, with no wall-clock rounding from re-deriving it through time.Now() a
// second time.
type tcRetryState struct {
	delay    time.Duration
	deadline time.Time
}

// runTCInterfaceUpdateLoop drives interface updates from netlink
// notifications, from a low-frequency unconditional drift check
// (tcDriftCheckInterval), and, while any of update's three components has a
// recoverable failure outstanding, from that component's own backoff timer.
//
// Only one physical timer exists; it is armed for whichever component's
// deadline is soonest. A netlink notification or the drift check still runs an
// update immediately, but neither resets any component's backoff: this data
// plane generates netlink events of its own while attaching and detaching, and
// an unrelated event on another interface arrives just as often, so treating
// any event as progress would keep restarting the delay and turn the backoff
// into a busy loop. A component's delay resets only after a round in which
// that component reported nothing left to recover. onScheduleChange, when
// non-nil, is called every time the loop's single physical timer is armed or
// disarmed, with the absolute time it is now armed for (or the zero time when
// disarmed), so a reporter sees the schedule the timer is actually running on
// rather than recomputing it from state this function does not otherwise
// expose.
func runTCInterfaceUpdateLoop(
	ctx context.Context,
	updates <-chan struct{},
	update func(context.Context) tcUpdateOutcome,
	onScheduleChange func(deadline time.Time),
) {
	retryTimer := tcRetryTimerFactory()
	defer retryTimer.Disarm()
	driftCheck := time.NewTicker(tcDriftCheckInterval)
	defer driftCheck.Stop()
	var (
		retryChannel <-chan time.Time
		states       [tcRetryComponentCount]tcRetryState
	)
	for {
		// The timer's channel is only selected on while some component has a
		// recovery outstanding, so a disarmed timer cannot deliver a signal
		// from an earlier delay.
		triggeredByTimer := false
		select {
		case <-ctx.Done():
			return
		case <-updates:
		case <-driftCheck.C:
		case <-retryChannel:
			triggeredByTimer = true
		}
		// A notification, the drift check, and the retry timer can all be ready
		// together and select picks one at random. The three signals are
		// handled differently and neither of the other two is lost: re-arming
		// or disarming below drains a timer fire that was already queued, since
		// it belongs to a deadline this round has just superseded, while a
		// queued notification stays in its channel and drives the next round,
		// and the drift ticker keeps its own schedule independently of anything
		// below.
		if ctx.Err() != nil {
			return
		}
		now := time.Now()
		outcome := update(ctx)
		outcomes := [tcRetryComponentCount]tcSharedRewriteOutcome{
			tcRetryComponentSharedRewrite: outcome.sharedRewrite,
			tcRetryComponentGeneral:       outcome.general,
			tcRetryComponentBypassRuleSet: outcome.bypassRuleSet,
			tcRetryComponentFakeIPRanges:  outcome.fakeIPRanges,
		}
		changed := false
		for component, componentOutcome := range outcomes {
			switch componentOutcome {
			case tcSharedRewriteRecoverable:
				// Advance on every failed round, including one an event or the
				// drift check triggered, so a stream of those cannot hold this
				// component's delay down.
				states[component].delay = nextTCRetryDelay(states[component].delay)
				states[component].deadline = now.Add(states[component].delay)
				changed = true
				// The failure itself was already reported, through whichever
				// rate-limited channel the step that failed owns. This names
				// the component that is now in backoff and for how long, which
				// none of those warnings can say -- there is no diagnostics
				// endpoint here to read the schedule out of instead.
				log.Debugln("[EBPF] %s reconcile failed; retrying in %s",
					tcRetryComponent(component), states[component].delay)
			case tcSharedRewriteUnknown:
				// This component's step did not run, so it says nothing about an
				// outstanding recovery for that component specifically. Only
				// re-arm when the timer is what woke this round: some component's
				// deadline has passed, and if it was this one its retry would
				// otherwise be dropped. An event- or drift-check-driven round
				// leaves this component's existing deadline alone, or a stream of
				// those returning early would postpone its retry indefinitely.
				if triggeredByTimer && states[component].delay > 0 {
					states[component].deadline = now.Add(states[component].delay)
					changed = true
				}
			default: // settled or unrecoverable
				// sharedRewrite touches the timer unconditionally; general and
				// bypassRuleSet only on a real transition. A component with
				// nothing to recover is by far the common case for those two, and
				// an unconditional touch would make every single round pay for a
				// real timer access on their behalf.
				if tcRetryComponent(component) == tcRetryComponentSharedRewrite || !states[component].deadline.IsZero() {
					changed = true
				}
				states[component].delay = 0
				states[component].deadline = time.Time{}
			}
		}
		if !changed {
			continue
		}
		earliest := -1
		for component := range states {
			if states[component].deadline.IsZero() {
				continue
			}
			if earliest == -1 || states[component].deadline.Before(states[earliest].deadline) {
				earliest = component
			}
		}
		if earliest == -1 {
			retryTimer.Disarm()
			retryChannel = nil
			if onScheduleChange != nil {
				onScheduleChange(time.Time{})
			}
			continue
		}
		delay := states[earliest].deadline.Sub(now)
		if delay < 0 {
			delay = 0
		}
		retryTimer.Arm(delay)
		retryChannel = retryTimer.Expired()
		if onScheduleChange != nil {
			onScheduleChange(states[earliest].deadline)
		}
	}
}

func nextTCRetryDelay(current time.Duration) time.Duration {
	if current <= 0 {
		return tcRetryInitialDelay
	}
	next := current * 2
	if next > tcRetryMaximumDelay {
		return tcRetryMaximumDelay
	}
	return next
}

// The general bucket reports a flat Recoverable rather than consulting backend
// health, because the steps in it are heterogeneous: a netlink inventory dump
// and an ip-rule repair fail for reasons that have nothing to do with whether
// some backend needs rebuilding, and judging them by that would drop the
// seconds-scale backoff to the ten-minute drift tick for a transient ENOBUFS.
// The shared packet-rewrite bucket below is different -- it has exactly one
// step, whose backend is the thing that fails.

// retryOutcome classifies a failed shared packet-rewrite reconcile. Repeating
// an attach can only help while the backend is still usable: once it is closed
// or has to be rebuilt, every later attempt fails the same way and recovery has
// to come from a restart instead.
func (d *sharedRewriteDataPlane) retryOutcome() tcSharedRewriteOutcome {
	if d == nil {
		return tcSharedRewriteUnrecoverable
	}
	d.access.Lock()
	defer d.access.Unlock()
	// A backend that has not been built yet is neither closed nor invalid: the
	// next attempt may manage to build it.
	if d.backend == nil {
		return tcSharedRewriteRecoverable
	}
	if d.backend.IsClosed() || d.backend.RequiresRebuild() {
		return tcSharedRewriteUnrecoverable
	}
	return tcSharedRewriteRecoverable
}

// updateTCInterfaces runs one reconciliation pass and reports what each of
// tcUpdateOutcome's three components made of it. general is left at its zero
// value (tcSharedRewriteUnknown) only while genuinely nothing in this pass has
// run it yet; every path that returns after touching it leaves it Recoverable,
// Unrecoverable or Settled, since it runs unconditionally every round.
func (i *Inbound) updateTCInterfaces(ctx context.Context) (outcome tcUpdateOutcome) {
	if ctx.Err() != nil {
		return
	}
	// Refreshing the interface inventory is a full netlink dump and touches no
	// inbound state, so it stays outside lifecycleAccess. The packet path takes
	// that lock for read on every datagram and Go's RWMutex parks new readers as
	// soon as a writer queues, so anything slow held under it stops the single
	// UDP read loop from draining the socket and the kernel starts dropping
	// datagrams. Updates are already serialised without the lock:
	// runTCInterfaceUpdates is the only caller and runs on one goroutine.
	if err := sing_tun.DefaultInterfaceFinder.Update(); err != nil {
		i.interfaceWarnings.inventory.warn(i.logWarn, "update interfaces for TC eBPF: ", err)
		outcome.general = tcSharedRewriteRecoverable
	}

	i.lifecycleAccess.Lock()
	defer i.lifecycleAccess.Unlock()
	if ctx.Err() != nil {
		// Shutting down. Report nothing at all, including the inventory failure
		// above: the loop is about to exit, and arming a retry for a pass that
		// will never run again only delays the exit's own disarm.
		return tcUpdateOutcome{}
	}
	outcome.bypassRuleSet = i.retryBypassRuleSetIfNeeded()
	outcome.fakeIPRanges = i.retryFakeIPRangesIfNeeded()
	defaultInterface := i.monitoredDefaultInterfaceName()
	localTCEnabled := i.localTCEnabled()
	localInterface, err := availableLocalTCInterface(localTCEnabled, defaultInterface)
	if err != nil {
		i.interfaceWarnings.topology.warn(i.logWarn, "inspect TC eBPF local interface: ", err)
		outcome.general = tcSharedRewriteRecoverable
		return
	}
	if localTCEnabled && localInterface == "" {
		i.interfaceWarnings.defaultInterface.warn(i.logWarn, "default interface unavailable; retaining previous local TC attachment")
	}
	sharedInterfaces := activeSharedInterfaces(i.sharedOptions.Interface, defaultInterface, i.sharedAllowsDefaultUpstream())
	tcSharedInterfaces := sharedInterfaces
	if i.sharedRewriteEnabled() {
		tcSharedInterfaces = nil
	}
	hostAddresses := i.hostAddresses()
	sharedDataPlane := (*sharedRewriteDataPlane)(nil)
	if i.sharedRewrite != nil {
		sharedDataPlane = i.sharedRewrite.dataPlane
	}
	if sharedDataPlane != nil {
		previous := sharedDataPlane.attachmentDescriptions()
		if err = sharedDataPlane.reconcile(sharedInterfaces, hostAddresses); err != nil {
			i.interfaceWarnings.reconcile.warn(i.logWarn, "refresh shared packet-rewrite interfaces: ", err)
			outcome.sharedRewrite = sharedDataPlane.retryOutcome()
		} else {
			outcome.sharedRewrite = tcSharedRewriteSettled
			if attachments := sharedDataPlane.attachmentDescriptions(); !slices.Equal(previous, attachments) {
				log.Debugln("[EBPF] shared packet-rewrite attachments updated: attachments=[%s]", strings.Join(attachments, ", "))
			}
		}
	} else {
		// No shared packet-rewrite data plane to run: nothing to recover.
		outcome.sharedRewrite = tcSharedRewriteSettled
	}
	infrastructureChanged, err := i.repairTCInfrastructure()
	infrastructureHealthy := err == nil
	if err != nil {
		i.interfaceWarnings.infrastructure.warn(i.logWarn, "repair TC eBPF network state: ", err)
		outcome.general = tcSharedRewriteRecoverable
	}
	changed, err := i.tcAttachmentStateChanged(localInterface, tcSharedInterfaces)
	if err != nil {
		i.interfaceWarnings.topology.warn(i.logWarn, "inspect TC eBPF interfaces: ", err)
		outcome.general = tcSharedRewriteRecoverable
		return
	}
	if !changed {
		if err = i.updateTCHostAddresses(hostAddresses); err != nil {
			i.interfaceWarnings.hostPolicy.warn(i.logWarn, "refresh TC eBPF host addresses: ", err)
			outcome.general = tcSharedRewriteRecoverable
		}
		if err = i.updateCgroupHostAddresses(hostAddresses); err != nil {
			i.interfaceWarnings.hostPolicy.warn(i.logWarn, "refresh cgroup eBPF host addresses: ", err)
			outcome.general = tcSharedRewriteRecoverable
		}
		if infrastructureChanged && infrastructureHealthy {
			log.Debugln("[EBPF] TC network state restored")
		}
		if outcome.general == tcSharedRewriteUnknown {
			outcome.general = tcSharedRewriteSettled
		}
		return
	}
	previousAttachments := i.tcAttachmentDescriptions()
	if err = i.reconcileTCDataPlane(localInterface, tcSharedInterfaces, hostAddresses); err != nil {
		i.interfaceWarnings.reconcile.warn(i.logWarn, "refresh TC eBPF interfaces: ", err)
		outcome.general = tcSharedRewriteRecoverable
		return
	}
	log.Debugln("[EBPF] TC attachments updated: %s -> [%s]",
		strings.Join(previousAttachments, ", "),
		strings.Join(i.tcAttachmentDescriptions(), ", "))
	if outcome.general == tcSharedRewriteUnknown {
		outcome.general = tcSharedRewriteSettled
	}
	return
}

func (i *Inbound) updateCgroupHostAddresses(hostAddresses []netip.Addr) error {
	cgroupBackend := i.cgroupBackendInstance()
	if cgroupBackend == nil {
		return nil
	}
	return cgroupBackend.UpdateHostAddresses(hostAddresses)
}

func (i *Inbound) repairTCInfrastructure() (bool, error) {
	i.tcDataPlaneAccess.RLock()
	defer i.tcDataPlaneAccess.RUnlock()
	if i.tcDataPlane == nil {
		return false, nil
	}
	return i.tcDataPlane.repairInfrastructure()
}

func (i *Inbound) monitoredDefaultInterfaceName() string {
	state := &i.interfaceMonitor
	state.access.Lock()
	defer state.access.Unlock()
	return state.defaultInterfaceName
}

func availableLocalTCInterface(enabled bool, interfaceName string) (string, error) {
	if !enabled || interfaceName == "" {
		return "", nil
	}
	_, err := netlink.LinkByName(interfaceName)
	if err != nil && tcLinkNotFound(err) {
		return "", nil
	}
	if err != nil {
		return "", E.Cause(err, "find local TC eBPF interface ", interfaceName)
	}
	return interfaceName, nil
}

// sharedAllowsDefaultUpstream reports whether the operator asked to keep
// shared interfaces attached even when one of them is the default upstream
// (single-armed gateway: the same NIC is downstream and upstream).
func (i *Inbound) sharedAllowsDefaultUpstream() bool {
	return i.sharedOptions.AllowDefaultUpstream != nil && *i.sharedOptions.AllowDefaultUpstream
}

func activeSharedInterfaces(configured []string, defaultInterface string, allowDefaultUpstream bool) []string {
	if allowDefaultUpstream {
		return slices.Clone(configured)
	}
	return slices.DeleteFunc(slices.Clone(configured), func(interfaceName string) bool {
		return interfaceName == defaultInterface
	})
}

func (i *Inbound) tcAttachmentStateChanged(localInterface string, sharedInterfaces []string) (bool, error) {
	i.tcDataPlaneAccess.RLock()
	defer i.tcDataPlaneAccess.RUnlock()
	if i.tcDataPlane == nil {
		return false, nil
	}
	return i.tcDataPlane.attachmentStateChanged(localInterface, sharedInterfaces)
}

func (i *Inbound) tcAttachmentDescriptions() []string {
	i.tcDataPlaneAccess.RLock()
	defer i.tcDataPlaneAccess.RUnlock()
	if i.tcDataPlane == nil {
		return nil
	}
	return i.tcDataPlane.attachmentDescriptions()
}

func (i *Inbound) updateTCHostAddresses(hostAddresses []netip.Addr) error {
	i.tcDataPlaneAccess.RLock()
	defer i.tcDataPlaneAccess.RUnlock()
	if i.tcDataPlane == nil {
		return nil
	}
	return i.tcDataPlane.updateHostAddresses(hostAddresses)
}

func (i *Inbound) hostAddresses() []netip.Addr {
	interfaces, err := iface.Interfaces()
	if err != nil {
		return nil
	}
	return collectHostAddresses(interfaces)
}

func collectHostAddresses(interfaces map[string]*iface.Interface) []netip.Addr {
	var addresses []netip.Addr
	for _, networkInterface := range interfaces {
		for _, prefix := range networkInterface.Addresses {
			if !prefix.IsValid() {
				continue
			}
			address := prefix.Addr().Unmap()
			if address.IsUnspecified() || address.IsLoopback() {
				continue
			}
			addresses = append(addresses, address)
		}
	}
	slices.SortFunc(addresses, func(left, right netip.Addr) int {
		return left.Compare(right)
	})
	addresses = slices.Compact(addresses)
	return addresses
}

func (d *tcDataPlane) attachmentStateChanged(localInterface string, sharedInterfaces []string) (bool, error) {
	d.access.Lock()
	defer d.access.Unlock()
	desired, err := d.desiredAttachmentState(localInterface, sharedInterfaces)
	if err != nil {
		return false, err
	}
	if tcAttachmentTopologyChanged(d.attachments, desired) {
		return true, nil
	}
	for _, attachment := range d.attachments {
		if localInterface == "" && attachment.role.local {
			if _, err = netlink.LinkByName(attachment.interfaceName); tcLinkNotFound(err) {
				continue
			}
			if err != nil {
				return false, err
			}
		}
		attached, err := attachment.filtersAttached(d.priority, d.backend.FakeIPICMPEnabled())
		if err != nil {
			return false, err
		}
		if !attached {
			return true, nil
		}
	}
	return false, nil
}

type tcAttachmentState struct {
	index   int
	framing ECommon.TCLinkFraming
	role    tcInterfaceRole
}

func desiredTCAttachmentState(
	localInterface string,
	sharedInterfaces []string,
	linkByName func(string) (netlink.Link, error),
) (map[string]tcAttachmentState, error) {
	roles := make(map[string]tcInterfaceRole, len(sharedInterfaces)+1)
	if localInterface != "" {
		roles[localInterface] = tcInterfaceRole{local: true}
	}
	for _, interfaceName := range sharedInterfaces {
		role := roles[interfaceName]
		role.shared = true
		roles[interfaceName] = role
	}
	interfaces := make(map[string]tcAttachmentState, len(roles))
	for interfaceName, role := range roles {
		link, err := linkByName(interfaceName)
		if err != nil && tcLinkNotFound(err) {
			continue
		}
		if err != nil {
			return nil, E.Cause(err, "find TC eBPF interface ", interfaceName)
		}
		if link == nil || link.Attrs() == nil {
			return nil, E.New("invalid TC eBPF interface ", interfaceName)
		}
		framing, err := tcLinkFraming(link)
		if err != nil {
			return nil, err
		}
		interfaces[interfaceName] = tcAttachmentState{
			index:   link.Attrs().Index,
			framing: framing,
			role:    role,
		}
	}
	return interfaces, nil
}

func tcAttachmentTopologyChanged(attachments []*tcInterfaceAttachment, desired map[string]tcAttachmentState) bool {
	if len(attachments) != len(desired) {
		return true
	}
	for _, attachment := range attachments {
		state, loaded := desired[attachment.interfaceName]
		if !loaded || state.index != attachment.interfaceIndex ||
			state.framing != attachment.framing || state.role != attachment.role {
			return true
		}
	}
	return false
}
