package identity

import (
	"testing"

	otpcrypto "otpforwarder/internal/crypto"
)

func TestCreateSaveUnpair(t *testing.T) {
	dir := t.TempDir()

	id, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	if len(id.StorageKey) != otpcrypto.SessionKeySize {
		t.Fatalf("expected a %d-byte storage key, got %d", otpcrypto.SessionKeySize, len(id.StorageKey))
	}
	if id.Pairing != nil {
		t.Fatal("expected a freshly created identity to be unpaired")
	}
	storageKey := append([]byte(nil), id.StorageKey...)

	again, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("LoadOrCreate (second call): %v", err)
	}
	if string(again.StorageKey) != string(storageKey) {
		t.Fatal("storage key changed across reloads")
	}

	id.Pairing = &Pairing{
		Version:    1,
		MacPriv:    []byte{1, 2, 3},
		PhonePub:   []byte{4, 5, 6},
		DeviceName: "Test Phone",
		KP2M:       []byte{7, 8, 9},
		KM2P:       []byte{10, 11, 12},
		KeyID:      []byte{13, 14, 15, 16, 17, 18, 19, 20},
		LastCtr:    -1,
	}
	if err := Save(dir, id); err != nil {
		t.Fatalf("Save: %v", err)
	}

	reloaded, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("LoadOrCreate after pairing: %v", err)
	}
	if reloaded.Pairing == nil || reloaded.Pairing.DeviceName != "Test Phone" || reloaded.Pairing.LastCtr != -1 {
		t.Fatalf("pairing state did not round-trip: %+v", reloaded.Pairing)
	}
	if string(reloaded.StorageKey) != string(storageKey) {
		t.Fatal("storage key changed after saving pairing state")
	}

	if err := Unpair(dir, reloaded); err != nil {
		t.Fatalf("Unpair: %v", err)
	}
	afterUnpair, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("LoadOrCreate after unpair: %v", err)
	}
	if afterUnpair.Pairing != nil {
		t.Fatal("expected pairing state to be cleared after Unpair")
	}
	if string(afterUnpair.StorageKey) != string(storageKey) {
		t.Fatal("storage key should survive Unpair")
	}
}
