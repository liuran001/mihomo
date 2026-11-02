package outboundgroup

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/metacubex/mihomo/component/power"
	"github.com/metacubex/mihomo/component/smart"
)

func TestSmartTaskReadinessStopsPollingWhilePaused(t *testing.T) {
	power.SetDevicePaused(true)
	defer power.SetDevicePaused(false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var checks atomic.Int32
	var ready atomic.Bool
	done := make(chan struct{})
	ran := make(chan struct{}, 1)
	go func() {
		defer close(done)
		runSmartTaskSchedule(ctx, []smartScheduledTask{{runOnce: true, run: func() { ran <- struct{}{} }}}, func() bool { checks.Add(1); return ready.Load() }, time.Millisecond, func() time.Duration { return 0 })
	}()
	time.Sleep(30 * time.Millisecond)
	if n := checks.Load(); n > 1 {
		t.Fatalf("readiness polled %d times while paused", n)
	}
	ready.Store(true)
	power.SetDevicePaused(false)
	select {
	case <-ran:
	case <-time.After(time.Second):
		t.Fatal("readiness did not resume")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("scheduler did not exit")
	}
}

func TestSmartTaskSchedulePausesBackgroundWork(t *testing.T) {
	power.SetDevicePaused(true)
	defer power.SetDevicePaused(false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runs := make(chan struct{}, 10)
	done := make(chan struct{})
	go func() {
		defer close(done)
		runSmartTaskSchedule(ctx, []smartScheduledTask{{
			initialDelay: time.Millisecond, interval: 5 * time.Millisecond,
			run: func() { runs <- struct{}{} },
		}}, func() bool { return true }, time.Millisecond, func() time.Duration { return 0 })
	}()
	select {
	case <-runs:
		t.Fatal("maintenance ran while device paused")
	case <-time.After(20 * time.Millisecond):
	}
	power.SetDevicePaused(false)
	select {
	case <-runs:
	case <-time.After(time.Second):
		t.Fatal("maintenance did not resume")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("scheduler did not stop")
	}
}

func TestSmartTaskSchedulePreventsOverlap(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	started := make(chan struct{}, 4)
	release := make(chan struct{})
	var calls atomic.Int32
	var active atomic.Int32
	var maxActive atomic.Int32

	task := smartScheduledTask{
		initialDelay: 0,
		interval:     5 * time.Millisecond,
		name:         "slow",
		run: func() {
			calls.Add(1)
			current := active.Add(1)
			for {
				old := maxActive.Load()
				if current <= old || maxActive.CompareAndSwap(old, current) {
					break
				}
			}
			started <- struct{}{}
			<-release
			active.Add(-1)
		},
	}

	done := make(chan struct{})
	go func() {
		runSmartTaskSchedule(ctx, []smartScheduledTask{task}, func() bool { return true }, time.Millisecond, func() time.Duration { return 0 })
		close(done)
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("scheduled task did not start")
	}
	time.Sleep(30 * time.Millisecond)
	if got := calls.Load(); got != 1 {
		t.Fatalf("slow task overlapped: calls=%d", got)
	}
	if got := maxActive.Load(); got != 1 {
		t.Fatalf("maximum concurrent executions=%d, want 1", got)
	}

	close(release)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("scheduler did not stop after cancellation")
	}
}

func TestSmartTaskScheduleRunsIndependentTaskWhileAnotherIsBlocked(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	release := make(chan struct{})
	independent := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		runSmartTaskSchedule(ctx, []smartScheduledTask{
			{interval: 5 * time.Millisecond, run: func() {
				select {
				case <-started:
				default:
					close(started)
				}
				<-release
			}},
			{initialDelay: 30 * time.Millisecond, interval: time.Hour, runOnce: true, run: func() { close(independent) }},
		}, func() bool { return true }, time.Millisecond, func() time.Duration { return 0 })
	}()
	t.Cleanup(func() {
		cancel()
		close(release)
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("scheduler did not stop after blocked task finished")
		}
	})
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("blocking task did not start")
	}
	select {
	case <-independent:
	case <-time.After(time.Second):
		t.Fatal("running task prevented an independent deadline from firing")
	}
}

func TestSmartTaskScheduleSlowCompletionPreservesPhase(t *testing.T) {
	// The scheduler also selects on the process-wide power notification
	// channel, so it cannot become durably blocked inside a synctest bubble.
	// Use a long period to leave ample headroom for Windows timer precision.
	const period = time.Second
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan time.Time, 16)
	release := make(chan struct{})
	var releaseOnce sync.Once
	var calls atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		runSmartTaskSchedule(ctx, []smartScheduledTask{{
			interval: period,
			run: func() {
				first := calls.Add(1) == 1
				select {
				case started <- time.Now():
				default:
				}
				if first {
					<-release
				}
			},
		}}, func() bool { return true }, time.Millisecond, func() time.Duration { return 0 })
	}()
	t.Cleanup(func() {
		cancel()
		releaseOnce.Do(func() { close(release) })
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("scheduler did not stop")
		}
	})
	var first time.Time
	select {
	case first = <-started:
	case <-time.After(time.Second):
		t.Fatal("slow task did not start")
	}
	// Miss the deadlines at 1s and 2s, then finish at 2.6s. The next run
	// belongs at 3s, not immediately at completion or at completion + 1s.
	time.Sleep(time.Until(first.Add(26 * period / 10)))
	releaseOnce.Do(func() { close(release) })
	select {
	case next := <-started:
		elapsed := next.Sub(first)
		if elapsed < 28*period/10 || elapsed > 34*period/10 {
			t.Fatalf("next run after %s, want original 3s phase (2.8s–3.4s tolerance)", elapsed)
		}
	case <-time.After(2 * period):
		t.Fatal("slow task was not scheduled again after completion")
	}
}

func TestSmartTaskScheduleCancelsWhileWaitingForTunnel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runSmartTaskSchedule(ctx, []smartScheduledTask{{
			initialDelay: time.Hour,
			interval:     time.Hour,
			name:         "never",
			run:          func() { t.Error("task ran while tunnel was stopped") },
		}}, func() bool { return false }, 5*time.Millisecond, func() time.Duration { return 0 })
		close(done)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("scheduler ignored cancellation while waiting for tunnel")
	}
}

func TestSmartTaskScheduleBatchesSharedDeadlines(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ran := make(chan string, 2)
	tasks := []smartScheduledTask{
		{initialDelay: 0, interval: time.Hour, name: "first", run: func() { ran <- "first" }, runOnce: true},
		{initialDelay: 0, interval: time.Hour, name: "second", run: func() { ran <- "second" }, runOnce: true},
	}
	done := make(chan struct{})
	go func() {
		runSmartTaskSchedule(ctx, tasks, func() bool { return true }, time.Millisecond, func() time.Duration { return 5 * time.Millisecond })
		close(done)
	}()

	for i := 0; i < len(tasks); i++ {
		select {
		case <-ran:
		case <-time.After(time.Second):
			t.Fatal("tasks with a shared deadline were not dispatched together")
		}
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("run-once schedule did not finish")
	}
}

func TestSmartGlobalRegistrySurvivesGroupReplacement(t *testing.T) {
	registry := &smartGlobalTaskRegistry{}
	store := smart.NewStore(nil)
	oldGroup := &Smart{store: store, configName: "old"}
	newGroup := &Smart{store: store, configName: "new"}

	run := registry.acquire(oldGroup)
	if got := registry.acquire(newGroup); got != run {
		t.Fatal("replacement group started a second global task run")
	}
	registry.release(oldGroup, run)

	select {
	case <-run.ctx.Done():
		t.Fatal("closing the old group canceled global tasks owned by the replacement")
	default:
	}
	groups := run.snapshotGroupsByConfig()
	if len(groups) != 1 || groups[0] != newGroup {
		t.Fatalf("global task retained a closed first group: %#v", groups)
	}

	registry.release(newGroup, run)
	select {
	case <-run.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("last group did not stop global tasks")
	}
}

func TestSmartBackgroundGateRejectsWorkAfterClose(t *testing.T) {
	var s Smart
	if !s.beginBackgroundWork() {
		t.Fatal("open group rejected statistics")
	}

	waiting := make(chan struct{})
	go func() {
		s.waitBackgroundWork()
		close(waiting)
	}()
	select {
	case <-waiting:
		t.Fatal("wait returned before accepted statistics completed")
	case <-time.After(10 * time.Millisecond):
	}

	s.disableBackgroundWork()
	if s.beginBackgroundWork() {
		t.Fatal("closing group accepted new statistics")
	}
	s.finishBackgroundWork()
	select {
	case <-waiting:
	case <-time.After(time.Second):
		t.Fatal("wait did not observe accepted statistics completion")
	}
}

func TestSmartCloseIsConcurrentAndIdempotent(t *testing.T) {
	store := smart.NewStore(nil)
	ctx, cancel := context.WithCancel(context.Background())
	s := &Smart{store: store, ctx: ctx, cancel: cancel}
	s.global = globalSmartTasks.acquire(s)

	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < cap(errs); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- s.Close()
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-ctx.Done():
	default:
		t.Fatal("close did not cancel group context")
	}
	if s.global != nil {
		t.Fatal("close retained global task ownership")
	}
}

func TestResumeDelayNeverExceedsTheSettleDelay(t *testing.T) {
	defer func(previous time.Duration) { smartResumeSettleDelay = previous }(smartResumeSettleDelay)
	smartResumeSettleDelay = 30 * time.Second

	for _, testCase := range []struct {
		name   string
		period time.Duration
		want   time.Duration
	}{
		{name: "the host status sweep", period: 30 * time.Minute, want: 30 * time.Second},
		{name: "a period shorter than the settle delay", period: 5 * time.Second, want: 5 * time.Second},
		{name: "a degenerate period", period: 0, want: time.Millisecond},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if got := resumeDelayFor(testCase.period); got != testCase.want {
				t.Fatalf("resumeDelayFor(%v) = %v, want %v", testCase.period, got, testCase.want)
			}
		})
	}
}

// A task that came due while the device was paused used to be pushed a whole
// period into the future on resume, so a device that pauses more often than the
// task's interval postponed it forever. The interval here is an hour: under the
// old behaviour this test would time out rather than fail.
func TestSmartTaskScheduleRunsWhatCameDueWhilePaused(t *testing.T) {
	defer func(previous time.Duration) { smartResumeSettleDelay = previous }(smartResumeSettleDelay)
	smartResumeSettleDelay = time.Millisecond

	power.SetDevicePaused(true)
	defer power.SetDevicePaused(false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runs := make(chan struct{}, 4)
	done := make(chan struct{})
	go func() {
		defer close(done)
		runSmartTaskSchedule(ctx, []smartScheduledTask{{
			initialDelay: time.Millisecond, interval: time.Hour,
			run: func() { runs <- struct{}{} },
		}}, func() bool { return true }, time.Millisecond, func() time.Duration { return 0 })
	}()

	// Let the task fall due while the scheduler is parked on the pause.
	time.Sleep(20 * time.Millisecond)
	select {
	case <-runs:
		t.Fatal("maintenance ran while the device was paused")
	default:
	}

	power.SetDevicePaused(false)
	select {
	case <-runs:
	case <-time.After(2 * time.Second):
		t.Fatal("a task that came due while paused was deferred a whole period, so a device that pauses often never runs it")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("scheduler did not stop")
	}
}

// The stalled sweep used to scan every 15s for as long as the process ran. A
// pass that finds nothing waiting on a reply now sleeps until an upload.
func TestStalledSweepSleepsUntilUpload(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var mu sync.Mutex
		var upload chan struct{}
		arm := func() <-chan struct{} {
			mu.Lock()
			defer mu.Unlock()
			if upload == nil {
				upload = make(chan struct{})
			}
			return upload
		}
		fire := func() {
			mu.Lock()
			defer mu.Unlock()
			if upload != nil {
				close(upload)
				upload = nil
			}
		}
		var sweeps atomic.Int32
		var pending atomic.Bool
		// power's own channel lives outside the bubble, which would keep
		// synctest from ever seeing the loop as blocked.
		resumed := make(chan struct{})
		background := func() (bool, <-chan struct{}) { return false, resumed }
		go runStalledSweep(ctx, 15*time.Second, 0, background, arm, func() bool {
			sweeps.Add(1)
			return pending.Load()
		})

		time.Sleep(15 * time.Second)
		synctest.Wait()
		if got := sweeps.Load(); got != 1 {
			t.Fatalf("sweeps after first interval = %d, want 1", got)
		}
		time.Sleep(time.Hour)
		synctest.Wait()
		if got := sweeps.Load(); got != 1 {
			t.Fatalf("idle sweep kept waking: %d passes in an hour", got)
		}

		// An upload brings it back; while something is pending it keeps pacing.
		pending.Store(true)
		fire()
		synctest.Wait()
		time.Sleep(15 * time.Second)
		synctest.Wait()
		if got := sweeps.Load(); got != 2 {
			t.Fatalf("sweeps after upload = %d, want 2", got)
		}
		time.Sleep(30 * time.Second)
		synctest.Wait()
		if got := sweeps.Load(); got != 4 {
			t.Fatalf("sweeps while pending = %d, want 4", got)
		}

		// Once nothing is pending again it goes back to sleep.
		pending.Store(false)
		time.Sleep(15 * time.Second)
		synctest.Wait()
		time.Sleep(time.Hour)
		synctest.Wait()
		if got := sweeps.Load(); got != 5 {
			t.Fatalf("sweeps after going idle = %d, want 5", got)
		}
	})
}
