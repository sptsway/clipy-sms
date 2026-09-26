// Package messages holds the daemon's in-memory message history, so the IPC
// layer (messages.list/messages.get/history.clear) has something real to
// serve immediately.
//
// This is intentionally NOT the durable, encrypted-at-rest store described
// in ARCHITECTURE.md §3.4 (messages.enc, AES-GCM under storage_key) — that
// depends on the identity/key storage the crypto/pairing implementation
// owns (see docs/CRYPTO_IMPLEMENTATION.md). Once the /v1/msg HTTP handler
// exists and successfully decrypts+validates an incoming SMS, it should
// call Store.Append here (or a persisted equivalent built the same way) as
// its last step; Store's FIFO/pagination behavior can stay as-is either way.
package messages

import (
	"sync"
	"time"
)

// Message is one stored SMS record (ARCHITECTURE.md §3.4's message shape).
type Message struct {
	ID         string
	ReceivedAt time.Time
	Sender     string
	Body       string
	Code       string
	Sim        int
}

// Store is a FIFO-capped, in-memory message history, safe for concurrent use.
type Store struct {
	mu    sync.Mutex
	items []Message // oldest first
}

// NewStore returns an empty Store.
func NewStore() *Store {
	return &Store{}
}

// Append adds msg, then evicts the oldest entries FIFO-style once the count
// exceeds max (a max <= 0 means unbounded).
func (s *Store) Append(msg Message, max int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items = append(s.items, msg)
	if max > 0 && len(s.items) > max {
		s.items = s.items[len(s.items)-max:]
	}
}

// List returns up to limit messages starting at offset, newest first (so
// offset 0 is the most recent — matching the menu's "latest 5" then "Older"
// chunks-of-20 layout), plus the total count.
func (s *Store) List(offset, limit int) ([]Message, int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	total := len(s.items)
	// s.items is oldest-first; reverse the slice logically to serve newest-first.
	if offset < 0 {
		offset = 0
	}
	if offset >= total {
		return nil, total
	}
	end := offset + limit
	if limit <= 0 || end > total {
		end = total
	}

	out := make([]Message, 0, end-offset)
	for i := offset; i < end; i++ {
		out = append(out, s.items[total-1-i])
	}
	return out, total
}

// Get returns the message with the given id, if present.
func (s *Store) Get(id string) (Message, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, m := range s.items {
		if m.ID == id {
			return m, true
		}
	}
	return Message{}, false
}

// Clear removes all stored messages.
func (s *Store) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items = nil
}
