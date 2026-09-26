package messages

import (
	"testing"
	"time"
)

func TestFIFOEviction(t *testing.T) {
	s := NewStore()
	for i := 0; i < 5; i++ {
		s.Append(Message{
			ID:         string(rune('a' + i)),
			ReceivedAt: time.Unix(int64(i), 0),
		}, 3)
	}

	items, total := s.List(0, 100)
	if total != 3 {
		t.Fatalf("expected 3 messages after eviction, got %d", total)
	}
	// Newest first: e, d, c (a and b were evicted).
	want := []string{"e", "d", "c"}
	for i, m := range items {
		if m.ID != want[i] {
			t.Fatalf("items[%d].ID = %q, want %q", i, m.ID, want[i])
		}
	}
}

func TestListPagination(t *testing.T) {
	s := NewStore()
	for i := 0; i < 10; i++ {
		s.Append(Message{ID: string(rune('a' + i))}, 0)
	}

	page1, total := s.List(0, 3)
	if total != 10 {
		t.Fatalf("total = %d, want 10", total)
	}
	if got := ids(page1); got != "j,i,h" {
		t.Fatalf("page1 = %q, want j,i,h", got)
	}

	page2, _ := s.List(3, 3)
	if got := ids(page2); got != "g,f,e" {
		t.Fatalf("page2 = %q, want g,f,e", got)
	}

	tail, _ := s.List(9, 5)
	if got := ids(tail); got != "a" {
		t.Fatalf("tail = %q, want a", got)
	}

	beyond, _ := s.List(20, 5)
	if len(beyond) != 0 {
		t.Fatalf("expected no items past the end, got %d", len(beyond))
	}
}

func ids(msgs []Message) string {
	out := ""
	for i, m := range msgs {
		if i > 0 {
			out += ","
		}
		out += m.ID
	}
	return out
}

func TestGetAndClear(t *testing.T) {
	s := NewStore()
	s.Append(Message{ID: "a", Body: "hi"}, 0)

	m, ok := s.Get("a")
	if !ok || m.Body != "hi" {
		t.Fatalf("Get(a) = %+v, %v", m, ok)
	}
	if _, ok := s.Get("missing"); ok {
		t.Fatal("expected Get(missing) to report not found")
	}

	s.Clear()
	if _, total := s.List(0, 10); total != 0 {
		t.Fatalf("expected empty store after Clear, got %d", total)
	}
}
