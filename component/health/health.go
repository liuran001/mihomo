// Package health tracks recent per-proxy failures observed on real traffic
// (not just latency probes) so proxy groups can steer away from nodes that
// keep stalling. A node whose TCP handshake succeeds but never returns data
// looks perfectly healthy to url-test, yet every flow through it dies; the
// counters here give groups a way to notice that.
package health

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// window is how long a single incident keeps weighing on a proxy.
	window = 10 * time.Minute
	// penaltyPerEvent is the latency (ms) added per incident when ranking.
	penaltyPerEvent = 150
	// penaltyCap bounds the added latency so a bad node stays selectable
	// as a last resort instead of disappearing entirely.
	penaltyCap = 1500
	// maxEvents caps per-proxy bookkeeping.
	maxEvents = 32
	// addStoreAttempts bounds the retry when a concurrent sweep removes the
	// record between lookup and lock.
	addStoreAttempts = 8
)

type record struct {
	mu       sync.Mutex
	events   []time.Time
	lastUsed time.Time
}

var store sync.Map // stable proxy key -> *record

var sweepAccesses atomic.Uint64
var sweepRunning atomic.Uint32

const (
	sweepEvery = 256
	idleTTL    = window
)

// ProxyKey builds the key shared by connection tracking and proxy ranking.
// Provider names are included so identically named nodes from different
// providers do not inherit one another's stall history.
func ProxyKey(name, provider string) string {
	return fmt.Sprintf("%d:%s%d:%s", len(name), name, len(provider), provider)
}

func recordFor(name string) *record {
	if v, ok := store.Load(name); ok {
		return v.(*record)
	}
	v, _ := store.LoadOrStore(name, &record{})
	return v.(*record)
}

func add(name string) {
	if name == "" {
		return
	}
	now := time.Now()
	// A concurrent sweep may drop the record between recordFor and the lock,
	// which would append an incident to an unreachable object. Retry, but
	// bounded: losing one diagnostic incident is preferable to spinning on the
	// dial path if the store is ever contended pathologically.
	for attempt := 0; attempt < addStoreAttempts; attempt++ {
		r := recordFor(name)
		r.mu.Lock()
		current, loaded := store.Load(name)
		if !loaded || current != r {
			r.mu.Unlock()
			continue
		}
		r.events = append(r.events, now)
		if len(r.events) > maxEvents {
			r.events = r.events[len(r.events)-maxEvents:]
		}
		r.lastUsed = now
		r.mu.Unlock()
		return
	}
}

// RecordStall reports a connection that was established but carried no
// payload back before closing — the signature of a black-holed relay.
func RecordStall(name string) { add(name) }

// RecordFailure reports a proxy that could not establish a connection.
func RecordFailure(name string) { add(name) }

// Penalty returns extra latency in milliseconds to add when ranking this
// proxy, derived from incidents inside the sliding window.
func Penalty(name string) uint16 {
	if name == "" {
		return 0
	}
	v, ok := store.Load(name)
	if !ok {
		return 0
	}
	r := v.(*record)
	cutoff := time.Now().Add(-window)
	r.mu.Lock()
	live := r.events[:0]
	for _, t := range r.events {
		if t.After(cutoff) {
			live = append(live, t)
		}
	}
	r.events = live
	n := len(live)
	r.lastUsed = time.Now()
	r.mu.Unlock()
	// Reclamation is left to the asynchronous sweep: this call path just
	// refreshed lastUsed, so an inline idle check could never fire.
	maybeSweep()
	if n == 0 {
		return 0
	}
	p := n * penaltyPerEvent
	if p > penaltyCap {
		p = penaltyCap
	}
	return uint16(p)
}

// Incidents returns the number of live incidents, for diagnostics.
func Incidents(name string) int {
	v, ok := store.Load(name)
	if !ok {
		return 0
	}
	r := v.(*record)
	cutoff := time.Now().Add(-window)
	r.mu.Lock()
	n := 0
	live := r.events[:0]
	for _, t := range r.events {
		if t.After(cutoff) {
			n++
			live = append(live, t)
		}
	}
	r.events = live
	r.lastUsed = time.Now()
	r.mu.Unlock()
	maybeSweep()
	return n
}

func maybeSweep() {
	if sweepAccesses.Add(1)%sweepEvery != 0 ||
		!sweepRunning.CompareAndSwap(0, 1) {
		return
	}
	go func() {
		defer sweepRunning.Store(0)
		cutoff := time.Now().Add(-idleTTL)
		store.Range(func(key, value any) bool {
			r, ok := value.(*record)
			if !ok {
				return true
			}
			r.mu.Lock()
			live := r.events[:0]
			for _, event := range r.events {
				if event.After(cutoff) {
					live = append(live, event)
				}
			}
			r.events = live
			idle := len(live) == 0 && (r.lastUsed.IsZero() || r.lastUsed.Before(cutoff))
			r.mu.Unlock()
			if idle {
				if keyString, ok := key.(string); ok {
					removeIfIdle(keyString, r, cutoff)
				}
			}
			return true
		})
	}()
}

func removeIfIdle(key string, r *record, cutoff time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.events) == 0 && (r.lastUsed.IsZero() || r.lastUsed.Before(cutoff)) {
		store.CompareAndDelete(key, r)
	}
}
