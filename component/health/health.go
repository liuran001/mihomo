// Package health tracks recent per-proxy failures observed on real traffic
// (not just latency probes) so proxy groups can steer away from nodes that
// keep stalling. A node whose TCP handshake succeeds but never returns data
// looks perfectly healthy to url-test, yet every flow through it dies; the
// counters here give groups a way to notice that.
package health

import (
	"sync"
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
)

type record struct {
	mu     sync.Mutex
	events []time.Time
}

var store sync.Map // proxy name -> *record

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
	r := recordFor(name)
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, now)
	if len(r.events) > maxEvents {
		r.events = r.events[len(r.events)-maxEvents:]
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
	r.mu.Unlock()
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
	defer r.mu.Unlock()
	n := 0
	for _, t := range r.events {
		if t.After(cutoff) {
			n++
		}
	}
	return n
}
