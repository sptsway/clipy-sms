// Package messages holds the daemon's message history: an in-memory,
// FIFO-capped Store backing the IPC layer (messages.list/messages.get/
// history.clear), plus encrypted-at-rest persistence to messages.enc
// (ARCHITECTURE.md §3.4) via persist.go. The /v1/msg HTTP handler calls
// Store.Append after a message passes validation, then persists a snapshot;
// LoadOrCreate reloads that snapshot at startup.
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

// Snapshot returns a copy of all stored messages, oldest first — the shape
// persist.go encrypts to disk.
func (s *Store) Snapshot() []Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Message(nil), s.items...)
}

// Restore replaces the store's contents with items (oldest first), as
// loaded from disk by LoadOrCreate. It does not re-apply FIFO eviction —
// callers are expected to pass in an already-capped list (as SaveEncrypted
// always writes).
func (s *Store) Restore(items []Message) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items = append([]Message(nil), items...)
}
