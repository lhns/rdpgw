package web

import (
	"log"
	"sync"
	"time"
)

// maxLimiterEntries bounds the memory a flood of distinct keys can take.
// Past it, untracked keys are let through rather than locking everyone out.
const maxLimiterEntries = 100000

// FailureLimiter locks a key (a client IP or a username) out after too many
// login attempts within a window. Attempts are counted when they start, so
// parallel requests cannot overshoot the limit; a successful attempt is
// handed back with Succeeded.
type FailureLimiter struct {
	max     int
	window  time.Duration
	lockout time.Duration
	now     func() time.Time

	mu        sync.Mutex
	entries   map[string]*limiterEntry
	full      bool
	lastSweep time.Time
}

type limiterEntry struct {
	attempts    int
	windowStart time.Time
	lockedUntil time.Time
}

// NewFailureLimiter returns nil, which never limits, if max is not positive.
func NewFailureLimiter(max int, window, lockout time.Duration) *FailureLimiter {
	if max <= 0 {
		return nil
	}
	return &FailureLimiter{
		max:     max,
		window:  window,
		lockout: lockout,
		now:     time.Now,
		entries: map[string]*limiterEntry{},
	}
}

// Acquire reserves an attempt for key. It is false while key is locked out;
// lockedNow is true for the attempt that starts the lockout.
func (l *FailureLimiter) Acquire(key string) (ok bool, lockedNow bool) {
	if l == nil {
		return true, false
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	e := l.entries[key]
	if e != nil && l.expired(e, now) {
		delete(l.entries, key)
		e = nil
	}
	if e == nil {
		if !l.makeRoom(now) {
			return true, false
		}
		e = &limiterEntry{windowStart: now}
		l.entries[key] = e
	}

	if !e.lockedUntil.IsZero() {
		return false, false
	}
	if e.attempts >= l.max {
		e.lockedUntil = now.Add(l.lockout)
		return false, true
	}
	e.attempts++
	return true, false
}

// Succeeded hands back the attempt reserved for key. With forget, the key's
// history is dropped as well.
func (l *FailureLimiter) Succeeded(key string, forget bool) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	e := l.entries[key]
	switch {
	case e == nil:
	case forget:
		delete(l.entries, key)
	case e.attempts > 0:
		e.attempts--
	}
}

// expired reports whether e's lockout is over or, if it never locked, its
// window has passed. Either way the key starts afresh.
func (l *FailureLimiter) expired(e *limiterEntry, now time.Time) bool {
	if !e.lockedUntil.IsZero() {
		return !now.Before(e.lockedUntil)
	}
	return now.Sub(e.windowStart) >= l.window
}

func (l *FailureLimiter) makeRoom(now time.Time) bool {
	if len(l.entries) < maxLimiterEntries {
		return true
	}
	// A full sweep holds the lock; under a flood, do it at most once a second.
	if now.Sub(l.lastSweep) < time.Second {
		return false
	}
	l.lastSweep = now
	for k, e := range l.entries {
		if l.expired(e, now) {
			delete(l.entries, k)
		}
	}
	if len(l.entries) < maxLimiterEntries {
		l.full = false
		return true
	}
	if !l.full {
		log.Printf("auth: lockout table full (%d keys), new keys are not limited", maxLimiterEntries)
		l.full = true
	}
	return false
}
