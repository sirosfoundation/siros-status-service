package publisher

import (
	"sync"
	"testing"
	"time"
)

// fakeClock and a manually-driven afterFunc make the debouncer's timing
// decisions fully deterministic — no real sleeps, no flakiness.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// scheduled records an afterFunc call so the test can fire it manually
// instead of waiting on a real timer.
type scheduled struct {
	delay time.Duration
	fn    func()
}

func newTestDebouncer() (*leadingDebouncer, *fakeClock, *[]scheduled) {
	clock := &fakeClock{now: time.Unix(0, 0)}
	var timers []scheduled
	d := &leadingDebouncer{
		lastFired: make(map[string]time.Time),
		pending:   make(map[string]bool),
		now:       clock.Now,
		afterFunc: func(delay time.Duration, f func()) {
			timers = append(timers, scheduled{delay: delay, fn: f})
		},
	}
	return d, clock, &timers
}

func TestNewLeadingDebouncer_FirstTriggerFiresImmediately(t *testing.T) {
	// Exercises the real constructor (production code path), unlike the
	// other tests here which build a leadingDebouncer literal so they can
	// inject a fake clock/timer.
	d := newLeadingDebouncer()
	fired := make(chan struct{}, 1)
	d.Trigger("list-1", time.Hour, func() { fired <- struct{}{} })
	select {
	case <-fired:
	case <-time.After(time.Second):
		t.Fatal("expected immediate fire from a freshly constructed debouncer")
	}
}

func TestLeadingDebouncer_FirstTriggerFiresImmediately(t *testing.T) {
	d, _, timers := newTestDebouncer()

	fired := make(chan struct{}, 1)
	d.Trigger("list-1", time.Minute, func() { fired <- struct{}{} })

	select {
	case <-fired:
	case <-time.After(time.Second):
		t.Fatal("expected immediate fire on first trigger for an idle key")
	}
	if len(*timers) != 0 {
		t.Fatalf("expected no timer scheduled for an immediate fire, got %d", len(*timers))
	}
}

func TestLeadingDebouncer_CoalescesBurstIntoOneDeferredFire(t *testing.T) {
	d, clock, timers := newTestDebouncer()

	fireCount := 0
	fire := func() { fireCount++ }

	// First trigger: idle, fires immediately (synchronously enough here
	// since we don't assert on it, just that it counted before we check
	// coalescing behavior).
	done := make(chan struct{})
	d.Trigger("list-1", time.Minute, func() { fire(); close(done) })
	<-done

	// A burst of triggers before the floor (1 minute) has elapsed must
	// coalesce into exactly one scheduled timer, not one per trigger.
	clock.Advance(10 * time.Second)
	d.Trigger("list-1", time.Minute, fire)
	d.Trigger("list-1", time.Minute, fire)
	d.Trigger("list-1", time.Minute, fire)

	if len(*timers) != 1 {
		t.Fatalf("expected exactly 1 scheduled timer for the coalesced burst, got %d", len(*timers))
	}
	wantDelay := 50 * time.Second // floor(60s) - elapsed(10s)
	if (*timers)[0].delay != wantDelay {
		t.Fatalf("scheduled delay = %v, want %v", (*timers)[0].delay, wantDelay)
	}

	// Firing the scheduled timer runs the deferred publish exactly once.
	(*timers)[0].fn()
	if fireCount != 2 { // one immediate + one coalesced
		t.Fatalf("fireCount = %d, want 2 (one immediate, one coalesced)", fireCount)
	}
}

// awaitFire waits (briefly) for an immediate fire's goroutine to run.
// Trigger's immediate-fire path deliberately runs `fire` via `go fire()`
// so a real publish never blocks the caller — tests that assert on an
// immediate fire's side effects must synchronize on it rather than
// checking state right after Trigger returns, or they race against that
// goroutine (as two earlier versions of these tests did).
func awaitFire(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("expected an immediate fire, none arrived")
	}
}

func TestLeadingDebouncer_FiresAgainImmediatelyOnceFloorReopens(t *testing.T) {
	d, clock, timers := newTestDebouncer()

	fired := make(chan struct{}, 2)
	d.Trigger("list-1", time.Minute, func() { fired <- struct{}{} })
	awaitFire(t, fired)

	clock.Advance(time.Minute) // floor fully elapsed
	d.Trigger("list-1", time.Minute, func() { fired <- struct{}{} })
	awaitFire(t, fired) // should fire immediately again, not defer

	if len(*timers) != 0 {
		t.Fatalf("expected no deferred timer once the floor has reopened, got %d", len(*timers))
	}
}

func TestLeadingDebouncer_IndependentKeysDoNotInterfere(t *testing.T) {
	d, clock, timers := newTestDebouncer()

	fireCount := map[string]int{}
	var mu sync.Mutex
	fire := func(key string) {
		mu.Lock()
		fireCount[key]++
		mu.Unlock()
	}

	fired1, fired2 := make(chan struct{}, 1), make(chan struct{}, 1)
	d.Trigger("list-1", time.Minute, func() { fire("list-1"); fired1 <- struct{}{} })
	d.Trigger("list-2", time.Minute, func() { fire("list-2"); fired2 <- struct{}{} })
	awaitFire(t, fired1)
	awaitFire(t, fired2)

	clock.Advance(10 * time.Second)
	d.Trigger("list-1", time.Minute, func() { fire("list-1") })
	// list-2 gets no further trigger — must not fire again on its own.

	if len(*timers) != 1 {
		t.Fatalf("expected exactly 1 pending timer (for list-1 only), got %d", len(*timers))
	}
	(*timers)[0].fn() // deferred fire runs synchronously in this goroutine

	mu.Lock()
	defer mu.Unlock()
	if fireCount["list-1"] != 2 {
		t.Fatalf("list-1 fireCount = %d, want 2", fireCount["list-1"])
	}
	if fireCount["list-2"] != 1 {
		t.Fatalf("list-2 fireCount = %d, want 1 (no extra trigger, no extra fire)", fireCount["list-2"])
	}
}

func TestLeadingDebouncer_RepeatedTriggersWithinWindowScheduleOnlyOnce(t *testing.T) {
	d, clock, timers := newTestDebouncer()

	d.Trigger("list-1", time.Minute, func() {})
	clock.Advance(5 * time.Second)

	for range 100 {
		d.Trigger("list-1", time.Minute, func() {})
	}

	if len(*timers) != 1 {
		t.Fatalf("100 triggers inside one coalescing window scheduled %d timers, want 1", len(*timers))
	}
}
