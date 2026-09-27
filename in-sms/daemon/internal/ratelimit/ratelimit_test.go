package ratelimit

import (
	"testing"
	"time"
)

func TestAllowUpToCapacityThenBlocks(t *testing.T) {
	l := New(3, 1, time.Minute)
	now := time.Unix(1000, 0)

	for i := 0; i < 3; i++ {
		if !l.Allow("1.2.3.4", now) {
			t.Fatalf("request %d unexpectedly blocked", i)
		}
	}
	if l.Allow("1.2.3.4", now) {
		t.Fatal("expected the 4th immediate request to be blocked")
	}
}

func TestRefillOverTime(t *testing.T) {
	l := New(2, 1, time.Minute) // 1 token/sec
	now := time.Unix(1000, 0)

	if !l.Allow("1.2.3.4", now) || !l.Allow("1.2.3.4", now) {
		t.Fatal("expected the first two requests to succeed")
	}
	if l.Allow("1.2.3.4", now) {
		t.Fatal("expected bucket to be empty")
	}

	later := now.Add(1500 * time.Millisecond) // ~1.5 tokens refilled
	if !l.Allow("1.2.3.4", later) {
		t.Fatal("expected a token to have refilled after 1.5s at 1 token/sec")
	}
	if l.Allow("1.2.3.4", later) {
		t.Fatal("expected only one token to have been available")
	}
}

func TestBucketsAreIndependentPerKey(t *testing.T) {
	l := New(1, 1, time.Minute)
	now := time.Unix(1000, 0)

	if !l.Allow("a", now) {
		t.Fatal("expected first request for key a to succeed")
	}
	if !l.Allow("b", now) {
		t.Fatal("expected first request for a different key b to succeed independently")
	}
	if l.Allow("a", now) {
		t.Fatal("expected second immediate request for key a to be blocked")
	}
}

func TestIdleBucketsAreSwept(t *testing.T) {
	l := New(1, 1, time.Second)
	now := time.Unix(1000, 0)
	l.Allow("a", now)

	l.mu.Lock()
	n := len(l.buckets)
	l.mu.Unlock()
	if n != 1 {
		t.Fatalf("expected 1 bucket, got %d", n)
	}

	much := now.Add(time.Hour)
	l.Allow("b", much) // triggers a sweep as a side effect

	l.mu.Lock()
	_, aStillPresent := l.buckets["a"]
	n = len(l.buckets)
	l.mu.Unlock()
	if aStillPresent {
		t.Fatal("expected idle bucket 'a' to have been swept")
	}
	if n != 1 {
		t.Fatalf("expected only bucket 'b' to remain, got %d buckets", n)
	}
}
