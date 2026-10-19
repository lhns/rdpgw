package web

import (
	"strconv"
	"sync"
	"testing"
	"time"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newTestLimiter(max int, window, lockout time.Duration) (*FailureLimiter, *fakeClock) {
	clock := &fakeClock{t: time.Unix(1700000000, 0)}
	l := NewFailureLimiter(max, window, lockout)
	l.now = clock.now
	return l, clock
}

func mustAcquire(t *testing.T, l *FailureLimiter, key string, wantOK, wantLockedNow bool) {
	t.Helper()
	ok, lockedNow := l.Acquire(key)
	if ok != wantOK || lockedNow != wantLockedNow {
		t.Fatalf("Acquire(%q) = (%t, %t), want (%t, %t)", key, ok, lockedNow, wantOK, wantLockedNow)
	}
}

func TestFailureLimiterLocksOutAfterMax(t *testing.T) {
	l, clock := newTestLimiter(3, 10*time.Minute, 5*time.Minute)
	for i := 0; i < 3; i++ {
		mustAcquire(t, l, "k", true, false)
	}
	mustAcquire(t, l, "k", false, true)
	mustAcquire(t, l, "k", false, false)
	mustAcquire(t, l, "other", true, false)

	clock.advance(5*time.Minute - time.Second)
	mustAcquire(t, l, "k", false, false)

	// The lockout ends on time even though the window has not.
	clock.advance(time.Second)
	for i := 0; i < 3; i++ {
		mustAcquire(t, l, "k", true, false)
	}
	mustAcquire(t, l, "k", false, true)
}

func TestFailureLimiterWindowResets(t *testing.T) {
	l, clock := newTestLimiter(2, time.Minute, time.Hour)
	mustAcquire(t, l, "k", true, false)
	mustAcquire(t, l, "k", true, false)
	clock.advance(time.Minute)
	mustAcquire(t, l, "k", true, false)
	mustAcquire(t, l, "k", true, false)
	mustAcquire(t, l, "k", false, true)
}

func TestFailureLimiterSucceeded(t *testing.T) {
	l, _ := newTestLimiter(2, time.Minute, time.Hour)

	// Handing back an attempt keeps successes from counting.
	for i := 0; i < 5; i++ {
		mustAcquire(t, l, "ip", true, false)
		l.Succeeded("ip", false)
	}

	mustAcquire(t, l, "user", true, false)
	mustAcquire(t, l, "user", true, false)
	l.Succeeded("user", true)
	mustAcquire(t, l, "user", true, false)
	mustAcquire(t, l, "user", true, false)
	mustAcquire(t, l, "user", false, true)

	// Success does not lift an active lockout.
	l.Succeeded("user", false)
	mustAcquire(t, l, "user", false, false)
}

func TestFailureLimiterConcurrentAttemptsCannotOvershoot(t *testing.T) {
	l, _ := newTestLimiter(5, time.Minute, time.Hour)
	var wg sync.WaitGroup
	var mu sync.Mutex
	admitted := 0
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ok, _ := l.Acquire("k"); ok {
				mu.Lock()
				admitted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if admitted != 5 {
		t.Fatalf("admitted %d attempts, want 5", admitted)
	}
}

func TestFailureLimiterDisabled(t *testing.T) {
	l := NewFailureLimiter(0, time.Minute, time.Hour)
	if l != nil {
		t.Fatal("max 0 should disable the limiter")
	}
	for i := 0; i < 100; i++ {
		mustAcquire(t, l, "k", true, false)
	}
	l.Succeeded("k", true)
}

func TestFailureLimiterBoundedMemory(t *testing.T) {
	l, clock := newTestLimiter(1, time.Minute, time.Hour)
	for i := 0; i < maxLimiterEntries; i++ {
		l.entries["filler-"+strconv.Itoa(i)] = &limiterEntry{windowStart: clock.t}
	}
	// Full table: new keys pass untracked.
	mustAcquire(t, l, "new", true, false)
	mustAcquire(t, l, "new", true, false)
	if len(l.entries) != maxLimiterEntries {
		t.Fatalf("table grew to %d", len(l.entries))
	}

	// Expired entries make room again.
	clock.advance(time.Minute)
	mustAcquire(t, l, "new", true, false)
	mustAcquire(t, l, "new", false, true)
}
