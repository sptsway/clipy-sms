package messages

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"

	otpcrypto "otpforwarder/internal/crypto"
)

func path(dir string) string { return filepath.Join(dir, "messages.enc") }

// messagesAAD binds the encrypted message store to its purpose, so the
// ciphertext can never be silently swapped for a different file type
// encrypted under the same storage key.
var messagesAAD = []byte("otpforwarder-messages-v1")

// LoadOrCreate reads and decrypts messages.enc under dir with storageKey,
// returning a Store pre-populated with its contents. A missing file is
// treated as an empty history, not an error.
func LoadOrCreate(dir string, storageKey []byte) (*Store, error) {
	msgs, err := loadEncrypted(dir, storageKey)
	if err != nil {
		return nil, err
	}
	s := NewStore()
	s.Restore(msgs)
	return s, nil
}

func loadEncrypted(dir string, storageKey []byte) ([]Message, error) {
	data, err := os.ReadFile(path(dir))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(data) < otpcrypto.NonceSize {
		return nil, io.ErrUnexpectedEOF
	}
	nonce, ciphertext := data[:otpcrypto.NonceSize], data[otpcrypto.NonceSize:]
	plaintext, err := otpcrypto.Open(storageKey, nonce, messagesAAD, ciphertext)
	if err != nil {
		return nil, err
	}
	var msgs []Message
	if err := json.Unmarshal(plaintext, &msgs); err != nil {
		return nil, err
	}
	return msgs, nil
}

// SaveEncrypted encrypts s's current contents and atomically writes them to
// messages.enc under dir. Call this after every mutation (a new message
// accepted, or history cleared) that should survive a daemon restart.
func SaveEncrypted(dir string, storageKey []byte, s *Store) error {
	msgs := s.Snapshot()
	if msgs == nil {
		msgs = []Message{}
	}
	plaintext, err := json.Marshal(msgs)
	if err != nil {
		return err
	}
	nonce, ciphertext, err := otpcrypto.Seal(storageKey, messagesAAD, plaintext)
	if err != nil {
		return err
	}
	out := make([]byte, 0, len(nonce)+len(ciphertext))
	out = append(out, nonce...)
	out = append(out, ciphertext...)
	return writeFileAtomic(path(dir), out, 0o600)
}

// writeFileAtomic writes data to a temp file in the same directory as p,
// then renames it over p, so a crash mid-write never leaves a truncated
// message store behind.
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
