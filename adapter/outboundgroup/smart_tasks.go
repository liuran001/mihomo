package outboundgroup

import (
	"context"
	"math/rand"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/power"
	"github.com/metacubex/mihomo/component/smart"
	"github.com/metacubex/mihomo/component/smart/lightgbm"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

const smartTaskReadyPollInterval = time.Second

// smartResumeSettleDelay bounds how long a task that came due while the device
// was paused waits once it resumes. A var so tests can shorten it.
//
// It is not zero. The pause is armed by the eBPF and TUN listeners reporting
// that the default interface is gone, so a resume is the instant the network
// came back -- rarely the instant it works. Probing then is worse than not
// probing: a failed host-recovery probe re-blocks the node and extends its
// backoff, spending budget to learn nothing. The scheduler's jitter adds up to
// another 30s on top, which also keeps several groups from resuming in lockstep.
var smartResumeSettleDelay = 30 * time.Second

// resumeDelayFor is how long an overdue task waits after a resume.
//
// It used to wait a whole period. A phone that loses its default interface more
// often than a task's own interval -- 30 minutes, for the host-status recovery
// sweep -- therefore postponed that task on every resume and could go
// indefinitely without ever probing a blocked node, which is the one thing that
// returns a blocked node to service before its 24-hour TTL.
func resumeDelayFor(period time.Duration) time.Duration {
	delay := min(smartResumeSettleDelay, period)
	if delay < time.Millisecond {
		return time.Millisecond
	}
	return delay
}

type smartScheduledTask struct {
	initialDelay time.Duration
	interval     time.Duration
	name         string
	run          func()
	runOnce      bool
}

type smartScheduledTaskState struct {
	smartScheduledTask
	next     time.Time
	period   time.Duration
	running  bool
	finished bool
}

// runSmartTaskSchedule uses one timer for all maintenance jobs. Jobs run in
// short-lived goroutines so a slow network probe cannot delay unrelated cache
// maintenance; the running bit prevents a slow job from accumulating copies.
func runSmartTaskSchedule(
	ctx context.Context,
	tasks []smartScheduledTask,
	isRunning func() bool,
	readyPoll time.Duration,
	jitter func() time.Duration,
) {
	if len(tasks) == 0 {
		return
	}
	if readyPoll <= 0 {
		readyPoll = smartTaskReadyPollInterval
	}

	readyTimer := time.NewTimer(readyPoll)
	defer readyTimer.Stop()
	for !isRunning() {
		paused, changed := power.BackgroundState()
		if paused {
			readyTimer.Stop()
			select {
			case <-ctx.Done():
				return
			case <-changed:
				readyTimer.Reset(readyPoll)
			}
			continue
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return
		case <-readyTimer.C:
			readyTimer.Reset(readyPoll)
		}
	}
	readyTimer.Stop()

	now := time.Now()
	states := make([]smartScheduledTaskState, len(tasks))
	spread := jitter()
	for i, task := range tasks {
		period := task.interval
		if period <= 0 {
			period = time.Nanosecond
		}
		states[i] = smartScheduledTaskState{
			smartScheduledTask: task,
			next:               now.Add(task.initialDelay + spread),
			period:             period,
		}
	}

	done := make(chan int, len(states))
	var taskWG sync.WaitGroup
	timer := time.NewTimer(time.Hour)
	defer func() {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		taskWG.Wait()
	}()

	wasPaused := false
	complete := func(idx int) {
		state := &states[idx]
		state.running = false
		// Running jobs do not need timer wakeups. Skip the deadlines they
		// missed once, on completion, preserving the original cadence.
		now := time.Now()
		if !state.next.After(now) {
			missed := now.Sub(state.next)/state.period + 1
			state.next = state.next.Add(missed * state.period)
		}
	}
	for {
		paused, changed := power.BackgroundState()
		if paused {
			wasPaused = true
			timer.Stop()
			select {
			case <-ctx.Done():
				return
			case idx := <-done:
				states[idx].running = false
			case <-changed:
			}
			continue
		}
		if wasPaused {
			now = time.Now()
			for idx := range states {
				state := &states[idx]
				if !state.finished && !state.next.After(now) {
					state.next = now.Add(resumeDelayFor(state.period) + spread)
				}
			}
			wasPaused = false
		}
		var earliest time.Time
		unfinished := 0
		for i := range states {
			if states[i].finished {
				continue
			}
			unfinished++
			if states[i].running {
				continue
			}
			if earliest.IsZero() || states[i].next.Before(earliest) {
				earliest = states[i].next
			}
		}
		if unfinished == 0 {
			return
		}

		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		var timerC <-chan time.Time
		if !earliest.IsZero() {
			timer.Reset(max(time.Until(earliest), 0))
			timerC = timer.C
		}

		select {
		case <-ctx.Done():
			return
		case <-changed:
			continue
		case idx := <-done:
			complete(idx)
		case now = <-timerC:
			if ctx.Err() != nil {
				return
			}
			if paused, _ := power.BackgroundState(); paused {
				continue
			}
			for i := range states {
				state := &states[i]
				if state.finished || state.next.After(now) {
					continue
				}
				missed := now.Sub(state.next)/state.period + 1
				state.next = state.next.Add(missed * state.period)
				if state.running || !isRunning() {
					continue
				}

				state.running = true
				if state.runOnce {
					state.finished = true
				}
				taskWG.Add(1)
				go func(idx int, task smartScheduledTask) {
					defer taskWG.Done()
					task.run()
					if task.runOnce {
						log.Debugln("[Smart] Task [%s] completed", task.name)
					}
					done <- idx
				}(i, state.smartScheduledTask)
			}
		}
	}
}

func smartTaskJitter() time.Duration {
	return time.Duration(rand.Float64() * 30 * float64(time.Second))
}

type smartGlobalTaskRun struct {
	ctx    context.Context
	cancel context.CancelFunc
	store  *smart.Store

	groupsMu sync.Mutex
	groups   map[*Smart]struct{}
	wg       sync.WaitGroup
}

func newSmartGlobalTaskRun(store *smart.Store) *smartGlobalTaskRun {
	ctx, cancel := context.WithCancel(context.Background())
	return &smartGlobalTaskRun{
		ctx:    ctx,
		cancel: cancel,
		store:  store,
		groups: make(map[*Smart]struct{}),
	}
}

func (r *smartGlobalTaskRun) add(s *Smart) {
	r.groupsMu.Lock()
	r.groups[s] = struct{}{}
	r.groupsMu.Unlock()
}

func (r *smartGlobalTaskRun) remove(s *Smart) bool {
	r.groupsMu.Lock()
	delete(r.groups, s)
	empty := len(r.groups) == 0
	r.groupsMu.Unlock()
	return empty
}

func (r *smartGlobalTaskRun) snapshotGroupsByConfig() []*Smart {
	r.groupsMu.Lock()
	defer r.groupsMu.Unlock()

	byConfig := make(map[string]*Smart, len(r.groups))
	for group := range r.groups {
		if _, exists := byConfig[group.configName]; !exists {
			byConfig[group.configName] = group
		}
	}
	result := make([]*Smart, 0, len(byConfig))
	for _, group := range byConfig {
		result = append(result, group)
	}
	return result
}

func (r *smartGlobalTaskRun) cleanupOrphanedGroups() {
	for _, group := range r.snapshotGroupsByConfig() {
		if !group.beginBackgroundWork() {
			continue
		}
		group.cleanupOrphanedGroups()
		group.finishBackgroundWork()
	}
}

// closeStalledConnections closes the connections left stuck on members that
// new dials already avoid.
//
// The degrade path sweeps once, when the degrade lands, and from then on the
// member is excluded: nothing dials it, so nothing degrades it again. A
// connection that was idle at that moment and sends into the dead relay later
// was never looked at, and hung until the client or a keep-alive gave up --
// over ten minutes behind a 600s keep-alive idle. This catches those, and only
// those: a connection is closed when it has been waiting on a reply for
// stalledReplyAfter and the group carrying it currently avoids the member it is
// on. Idle connections and ones still getting answers are left alone, as is
// everything on a member the group still dials.
//
// It reports whether any connection is still waiting on a reply. Without one
// the next pass cannot find anything until some connection uploads again.
func (r *smartGlobalTaskRun) closeStalledConnections() (pending bool) {
	now := time.Now()
	type groupView struct {
		proxyByName  map[string]C.Proxy
		blockedNodes map[string]bool
	}
	var byName map[string][]*Smart
	views := make(map[*Smart]*groupView)
	defer func() {
		for _, groups := range byName {
			for _, s := range groups {
				s.finishBackgroundWork()
			}
		}
	}()

	statistic.DefaultManager.Range(func(tracker statistic.Tracker) bool {
		// Two atomic loads, and they reject nearly every connection, so they go
		// before anything that walks the chain or reads the store.
		info := tracker.Info()
		if !info.ReplyPending() {
			return true
		}
		pending = true
		if !info.AwaitingReply(now, stalledReplyAfter) {
			return true
		}
		if byName == nil {
			byName = r.admitGroupsByName()
		}
		chains := tracker.Chains()
		for hop := 1; hop < len(chains); hop++ {
			for _, s := range byName[chains[hop]] {
				view := views[s]
				if view == nil {
					_, proxyByName := s.GetProxiesByName(false)
					view = &groupView{proxyByName, s.store.GetBlockedNodes(s.Name(), s.configName)}
					views[s] = view
				}
				if s.avoidsMember(chains[hop-1], info.Metadata, view.proxyByName, view.blockedNodes) {
					closeStalled(tracker)
					return true
				}
			}
		}
		return true
	})
	return pending
}

// runStalledSweep paces closeStalledConnections apart from the shared schedule
// so that it can sleep. On a 15s ticker it woke an idle phone 240 times an
// hour to scan nothing; now a pass that finds no connection waiting on a reply
// blocks until the next upload, which is the only way one can appear.
//
// sweep reports whether a connection is still waiting on a reply; upload arms
// the wake for the next upload; background is power.BackgroundState.
func runStalledSweep(ctx context.Context, interval, jitter time.Duration, background func() (bool, <-chan struct{}), upload func() <-chan struct{}, sweep func() bool) {
	timer := time.NewTimer(interval + jitter)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		// Armed before the scan: an upload either shows up in it or fires this.
		// Suspended or paused, it waits too: a resume or the first upload
		// after it brings the sweep back.
		uploaded := upload()
		pending := false
		if paused, _ := background(); !paused {
			pending = sweep()
		}
		for !pending {
			paused, changed := background()
			if paused {
				uploaded = nil
			}
			select {
			case <-ctx.Done():
				return
			case <-uploaded:
				pending = true
			case <-changed:
				if paused {
					// Resumed: re-arm and look once more after the interval.
					pending = true
				}
			}
		}
		timer.Reset(interval)
	}
}

// admitGroupsByName indexes the registered groups that are not closing by
// name, each admitted as background work; the caller finishes every one.
func (r *smartGlobalTaskRun) admitGroupsByName() map[string][]*Smart {
	r.groupsMu.Lock()
	defer r.groupsMu.Unlock()
	byName := make(map[string][]*Smart, len(r.groups))
	for group := range r.groups {
		if group.beginBackgroundWork() {
			byName[group.Name()] = append(byName[group.Name()], group)
		}
	}
	return byName
}

func (r *smartGlobalTaskRun) start() {
	tasks := []smartScheduledTask{
		{5 * time.Minute, cleanupInterval, "Global orphaned groups clean up", r.cleanupOrphanedGroups, false},
		{5 * time.Second, cacheParamAdjustInterval, "Global cache parameters adjustment", r.store.AdjustCacheParameters, false},
		{5 * time.Minute, flushQueueInterval, "Global queues flush", func() { r.store.FlushQueue(true) }, false},
	}
	r.wg.Add(2)
	go func() {
		defer r.wg.Done()
		runSmartTaskSchedule(r.ctx, tasks, func() bool { return tunnel.Status() == tunnel.Running }, smartTaskReadyPollInterval, smartTaskJitter)
	}()
	go func() {
		defer r.wg.Done()
		runStalledSweep(r.ctx, stalledSweepInterval, smartTaskJitter(), power.BackgroundState, statistic.DefaultManager.UploadSignal, func() bool {
			// A suspended tunnel waits like an idle one: its first upload
			// after resuming brings the sweep back.
			return tunnel.Status() == tunnel.Running && r.closeStalledConnections()
		})
	}()
}

func (r *smartGlobalTaskRun) stop() {
	r.cancel()
	r.wg.Wait()
	r.store.FlushQueue(true)
	lightgbm.CloseAllCollectors()
}

type smartGlobalTaskRegistry struct {
	mu  sync.Mutex
	run *smartGlobalTaskRun
}

func (r *smartGlobalTaskRegistry) acquire(s *Smart) *smartGlobalTaskRun {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.run == nil {
		r.run = newSmartGlobalTaskRun(s.store)
		r.run.add(s)
		r.run.start()
		return r.run
	}
	r.run.add(s)
	return r.run
}

func (r *smartGlobalTaskRegistry) release(s *Smart, run *smartGlobalTaskRun) {
	if run == nil {
		return
	}

	r.mu.Lock()
	last := run.remove(s)
	if last && r.run == run {
		r.run = nil
	}
	if last {
		run.stop()
	}
	r.mu.Unlock()
}

var globalSmartTasks smartGlobalTaskRegistry

func (s *Smart) startGroupTasks() {
	tasks := []smartScheduledTask{
		{10 * time.Minute, cleanupInterval, "Group orphaned nodes clean up", s.cleanupOrphanedNodeCache, true},
		{5 * time.Minute, prefetchInterval, "Group targets prefetch", s.runPrefetch, false},
		{5 * time.Minute, checkInterval, "Group nodes stable check", s.checkNodesStable, false},
		{5 * time.Minute, rankingInterval, "Group nodes ranking", s.updateNodeRanking, false},
		{5 * time.Minute, recoveryCheckInterval, "Group nodes recovery check", s.checkBlockedNodes, false},
		{15 * time.Minute, hostStatusCheckInterval, "Group host status check", s.checkHostStatus, false},
		{time.Minute, prefetchInterval, "Group hostFailLimit refresh", s.applyHostFailLimit, false},
		{10 * time.Minute, cleanupInterval, "Group old records clean up", func() { s.store.CleanupOldRecords(s.Name(), s.configName) }, false},
	}
	// prefer-asn is fixed for the group's life; without it the refresh returns
	// at once, so scheduling it would only wake the device every two minutes.
	if s.preferASN {
		tasks = append(tasks, smartScheduledTask{time.Minute, claimInterval, "Group network claims refresh", s.claimASNEvidence, false})
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		runSmartTaskSchedule(s.ctx, tasks, func() bool { return tunnel.Status() == tunnel.Running }, smartTaskReadyPollInterval, smartTaskJitter)
	}()
}
