package log

import (
	"sync"
	"testing"
	"time"
)

func TestSlowLogSubscriberDoesNotBlockCore(t *testing.T) {
	previous := Level()
	SetLevel(SILENT)
	t.Cleanup(func() { SetLevel(previous) })
	subscriber := Subscribe()
	var drained sync.WaitGroup
	drained.Add(1)
	t.Cleanup(func() {
		go func() {
			defer drained.Done()
			for range subscriber {
			}
		}()
		UnSubscribe(subscriber)
		drained.Wait()
	})
	done := make(chan struct{})
	go func() {
		for index := range 5000 {
			Infoln("slow dashboard event %d", index)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("a stalled log subscriber blocked log producers")
	}
}

func TestInfoSubscriptionDoesNotEnableDebugFormatting(t *testing.T) {
	previous := Level()
	SetLevel(SILENT)
	t.Cleanup(func() { SetLevel(previous) })
	subscriber := SubscribeLevel(INFO)
	defer UnSubscribe(subscriber)
	probe := &formatProbe{}
	Debugln("%s", probe)
	if probe.calls != 0 || DebugEnabled() {
		t.Fatal("info-only dashboard enabled debug logging")
	}
	Infoln("%s", probe)
	select {
	case event := <-subscriber:
		if event.LogLevel != INFO || event.Payload != "formatted" {
			t.Fatalf("unexpected event: %+v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("info event was not delivered")
	}
	debug := SubscribeLevel(DEBUG)
	if !DebugEnabled() {
		t.Fatal("explicit debug subscription must enable debug logging")
	}
	UnSubscribe(debug)
	if DebugEnabled() {
		t.Fatal("removing debug subscriber did not restore the minimum level")
	}
}

func BenchmarkDisabledInfo(b *testing.B) {
	previous := Level()
	SetLevel(SILENT)
	b.Cleanup(func() { SetLevel(previous) })
	b.ReportAllocs()
	for b.Loop() {
		Infoln("connection %s -> %s", "source", "destination")
	}
}

func BenchmarkDisabledDebugParallel(b *testing.B) {
	previous := Level()
	SetLevel(INFO)
	b.Cleanup(func() { SetLevel(previous) })
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			DebugEnabled()
		}
	})
}

type formatProbe struct{ calls int }

func (p *formatProbe) String() string {
	p.calls++
	return "formatted"
}

func TestDisabledInfoSkipsFormattingButKeepsSubscribers(t *testing.T) {
	previous := Level()
	SetLevel(SILENT)
	t.Cleanup(func() { SetLevel(previous) })
	probe := &formatProbe{}
	Infoln("%s", probe)
	if probe.calls != 0 {
		t.Fatal("disabled info log still formatted its payload")
	}
	sub := Subscribe()
	defer UnSubscribe(sub)
	Infoln("%s", probe)
	select {
	case event := <-sub:
		if event.LogLevel != INFO || event.Payload != "formatted" || probe.calls != 1 {
			t.Fatalf("unexpected subscriber event: %+v; format calls: %d", event, probe.calls)
		}
	case <-time.After(time.Second):
		t.Fatal("silent output suppressed a live subscriber's info log")
	}
}

func TestDebugEnabledIncludesLiveSubscribers(t *testing.T) {
	oldLevel := Level()
	SetLevel(INFO)
	t.Cleanup(func() { SetLevel(oldLevel) })

	if DebugEnabled() {
		t.Fatal("debug unexpectedly enabled without a subscriber")
	}

	sub := Subscribe()
	if !DebugEnabled() {
		t.Fatal("debug subscriber must keep debug event construction enabled")
	}
	UnSubscribe(sub)

	if DebugEnabled() {
		t.Fatal("debug remained enabled after the last subscriber left")
	}
}
