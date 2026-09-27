package messages

import (
	"testing"
	"time"

	otpcrypto "otpforwarder/internal/crypto"
)

func TestPersistRoundTrip(t *testing.T) {
	dir := t.TempDir()
	key, err := otpcrypto.RandomBytes(otpcrypto.SessionKeySize)
	if err != nil {
		t.Fatalf("RandomBytes: %v", err)
	}

	s, err := LoadOrCreate(dir, key)
	if err != nil {
		t.Fatalf("LoadOrCreate (empty): %v", err)
	}
	if _, total := s.List(0, 10); total != 0 {
		t.Fatalf("expected empty store on first load, got %d", total)
	}

	s.Append(Message{ID: "a", ReceivedAt: time.Unix(1, 0), Sender: "1234", Body: "hi"}, 0)
	s.Append(Message{ID: "b", ReceivedAt: time.Unix(2, 0), Sender: "5678", Body: "yo"}, 0)
	if err := SaveEncrypted(dir, key, s); err != nil {
		t.Fatalf("SaveEncrypted: %v", err)
	}

	reloaded, err := LoadOrCreate(dir, key)
	if err != nil {
		t.Fatalf("LoadOrCreate (reload): %v", err)
	}
	items, total := reloaded.List(0, 10)
	if total != 2 {
		t.Fatalf("expected 2 messages after reload, got %d", total)
	}
	if items[0].ID != "b" || items[1].ID != "a" {
		t.Fatalf("unexpected order after reload: %+v", items)
	}
}

func TestPersistWrongKeyFails(t *testing.T) {
	dir := t.TempDir()
	key1, _ := otpcrypto.RandomBytes(otpcrypto.SessionKeySize)
	key2, _ := otpcrypto.RandomBytes(otpcrypto.SessionKeySize)

	s, err := LoadOrCreate(dir, key1)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	s.Append(Message{ID: "a"}, 0)
	if err := SaveEncrypted(dir, key1, s); err != nil {
		t.Fatalf("SaveEncrypted: %v", err)
	}

	if _, err := LoadOrCreate(dir, key2); err == nil {
		t.Fatal("expected LoadOrCreate with the wrong key to fail")
	}
}

func TestPersistRespectsFIFOEviction(t *testing.T) {
	dir := t.TempDir()
	key, _ := otpcrypto.RandomBytes(otpcrypto.SessionKeySize)

	s, err := LoadOrCreate(dir, key)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	for i := 0; i < 5; i++ {
		s.Append(Message{ID: string(rune('a' + i))}, 3)
		if err := SaveEncrypted(dir, key, s); err != nil {
			t.Fatalf("SaveEncrypted(%d): %v", i, err)
		}
	}

	reloaded, err := LoadOrCreate(dir, key)
	if err != nil {
		t.Fatalf("LoadOrCreate (reload): %v", err)
	}
	_, total := reloaded.List(0, 10)
	if total != 3 {
		t.Fatalf("expected 3 persisted messages after FIFO eviction, got %d", total)
	}
}
