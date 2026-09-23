package publisher

import (
	"sync"
	"time"
)

// leadingDebouncer implements docs/design.md §9's "publish ... at most
// every ttl seconds (or immediately if idle)": the first trigger for a
// key in a while fires right away; triggers that arrive before the
// per-key rate floor has reopened are coalesced into a single deferred
// fire timed for exactly when it reopens, so a burst of writes to the
// same list costs one publish, not one per write.
//
// The clock and timer are overridable so the coalescing/timing logic
// itself can be unit tested deterministically (see debounce_test.go)
// without depending on the real store or signing key that a real
// publish needs.
type leadingDebouncer struct {
	mu        sync.Mutex
	lastFired map[string]time.Time
	pending   map[string]bool

	now       func() time.Time
	afterFunc func(d time.Duration, f func())
}

func newLeadingDebouncer() *leadingDebouncer {
	return &leadingDebouncer{
		lastFired: make(map[string]time.Time),
		pending:   make(map[string]bool),
		now:       time.Now,
		afterFunc: func(d time.Duration, f func()) { time.AfterFunc(d, f) },
	}
}

// Trigger requests that fire eventually run for key, respecting floor as
// the minimum time between fires for that key. Safe to call concurrently
// and repeatedly; only the first call in a coalescing window schedules
// anything.
func (d *leadingDebouncer) Trigger(key string, floor time.Duration, fire func()) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.pending[key] {
		return // an earlier trigger already has this window covered
	}

	elapsed := d.now().Sub(d.lastFired[key]) // zero value -> effectively "never", so idle
	if elapsed >= floor {
		d.lastFired[key] = d.now()
		go fire()
		return
	}

	d.pending[key] = true
	delay := floor - elapsed
	d.afterFunc(delay, func() {
		d.mu.Lock()
		delete(d.pending, key)
		d.lastFired[key] = d.now()
		d.mu.Unlock()
		fire()
	})
}
