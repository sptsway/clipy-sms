// Package ratelimit implements the per-source-IP token bucket from
// PROTOCOL.md §4.7, using only sync and time — no third-party dependency.
package ratelimit

import (
	"sync"
	"time"
)

// Limiter is a per-key token bucket limiter, safe for concurrent use.
type Limiter struct {
	capacity   float64
	refillRate float64 // tokens per second
	idleAfter  time.Duration

	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens     float64
	lastRefill time.Time
	lastSeen   time.Time
}

// New creates a Limiter with the given bucket capacity and refill rate
// (tokens/second). Buckets untouched for idleAfter are swept on the next
// Allow call to bound memory use over a long-running daemon's lifetime.
func New(capacity, refillPerSecond float64, idleAfter time.Duration) *Limiter {
	return &Limiter{
		capacity:   capacity,
		refillRate: refillPerSecond,
		idleAfter:  idleAfter,
		buckets:    make(map[string]*bucket),
	}
}

// Allow reports whether a request from key (typically a source IP) may
// proceed right now, consuming one token if so.
func (l *Limiter) Allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.sweepLocked(now)

	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: l.capacity, lastRefill: now}
		l.buckets[key] = b
	}

	elapsed := now.Sub(b.lastRefill).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * l.refillRate
		if b.tokens > l.capacity {
			b.tokens = l.capacity
		}
		b.lastRefill = now
	}
	b.lastSeen = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// sweepLocked removes buckets idle longer than idleAfter. Caller must hold l.mu.
func (l *Limiter) sweepLocked(now time.Time) {
	if l.idleAfter <= 0 {
		return
	}
	for k, b := range l.buckets {
		if now.Sub(b.lastSeen) > l.idleAfter {
			delete(l.buckets, k)
		}
	}
}
