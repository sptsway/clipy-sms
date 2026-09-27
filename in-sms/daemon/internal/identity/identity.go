// Package identity persists the daemon's pairing secrets: the Mac's P-256
// keypair, the pinned phone public key, the derived session keys, and the
// message-store encryption key.
//
// Per an explicit, deliberate simplification: there is no macOS Keychain use
// here. Everything lives in one file, identity.json, protected only by Unix
// file permissions (0600, owner-only) — see ARCHITECTURE.md §3.4 for the
// accepted tradeoff (no biometric/login gating, readable by any process
// running as the same user, plaintext on disk unless FileVault is on).
package identity

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	otpcrypto "otpforwarder/internal/crypto"
)

// Pairing holds everything derived from a completed pairing exchange
// (PROTOCOL.md §3.4). It is nil in Identity when the daemon is not paired.
type Pairing struct {
	Version    int    `json:"pairing_version"`
	MacPriv    []byte `json:"mac_priv"`
	PhonePub   []byte `json:"phone_pub"`
	DeviceName string `json:"device_name"`
	KP2M       []byte `json:"k_p2m"`
	KM2P       []byte `json:"k_m2p"`
	KeyID      []byte `json:"key_id"`
	// LastCtr is the last accepted message counter, or -1 if no message has
	// been accepted yet under this pairing — the first valid ctr, 0, must
	// still be greater than LastCtr. See PROTOCOL.md §4.4/§5 and
	// docs/CRYPTO_IMPLEMENTATION.md's "counter sentinel gotcha".
	LastCtr int64 `json:"last_ctr"`
}

// Identity is the on-disk contents of identity.json. StorageKey is generated
// once at first run, before any pairing exists, and is never rotated;
// Pairing is nil until the first successful pairing.
type Identity struct {
	StorageKey []byte   `json:"storage_key"`
	Pairing    *Pairing `json:"pairing,omitempty"`
}

func path(dir string) string { return filepath.Join(dir, "identity.json") }

// LoadOrCreate loads identity.json from dir, or creates a fresh, unpaired
// Identity with a new random storage key if none exists yet.
func LoadOrCreate(dir string) (*Identity, error) {
	data, err := os.ReadFile(path(dir))
	if os.IsNotExist(err) {
		key, err := otpcrypto.RandomBytes(otpcrypto.SessionKeySize)
		if err != nil {
			return nil, err
		}
		id := &Identity{StorageKey: key}
		if err := Save(dir, id); err != nil {
			return nil, err
		}
		return id, nil
	}
	if err != nil {
		return nil, err
	}
	var id Identity
	if err := json.Unmarshal(data, &id); err != nil {
		return nil, err
	}
	if len(id.StorageKey) != otpcrypto.SessionKeySize {
		return nil, errors.New("identity: identity.json has an invalid storage_key")
	}
	return &id, nil
}

// Save atomically writes id to identity.json in dir, mode 0600.
func Save(dir string, id *Identity) error {
	data, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path(dir), data, 0o600)
}

// Unpair clears any pairing state (wiping the pinned phone key and derived
// session keys) while keeping the storage key, and persists the result.
func Unpair(dir string, id *Identity) error {
	id.Pairing = nil
	return Save(dir, id)
}

// writeFileAtomic writes data to a temp file in the same directory as p,
// then renames it over p, so a crash mid-write never leaves a truncated
// secrets file behind.
func writeFileAtomic(p string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(p)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, perm); err != nil {
		return err
	}
	return os.Rename(tmpPath, p)
}
