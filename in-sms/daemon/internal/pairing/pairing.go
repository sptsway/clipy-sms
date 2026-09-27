// Package pairing implements the pairing-window state machine from
// PROTOCOL.md §3: a 120-second window allowing at most 5 verification
// attempts, generating and checking the ECDH+token exchange. It is
// deliberately independent of HTTP and storage so it can be unit-tested
// directly against the clock and the attempt limit.
package pairing

import (
	"crypto/ecdh"
	"errors"
	"time"

	otpcrypto "otpforwarder/internal/crypto"
)

const (
	// Window is the pairing window duration (PROTOCOL.md §3.5).
	Window = 120 * time.Second
	// MaxAttempts is the number of verification attempts allowed per window.
	MaxAttempts = 5
)

var (
	ErrNoWindow       = errors.New("pairing: no pairing window is open")
	ErrWindowExpired  = errors.New("pairing: window has expired")
	ErrAttemptsUsedUp = errors.New("pairing: attempt limit reached")
	ErrBadMAC         = errors.New("pairing: mac verification failed")
)

// Session is one open pairing window. All fields are set at Start and are
// immutable except AttemptsLeft and Closed, which Verify mutates.
type Session struct {
	MacPriv      *ecdh.PrivateKey
	MacPubBytes  []byte // cached PrivateKey.PublicKey().Bytes()
	Token        []byte // 32 random bytes
	StartedAt    time.Time
	ExpiresAt    time.Time
	AttemptsLeft int
	Closed       bool // true once paired successfully; a closed session accepts no more attempts
}

// Start generates a fresh Mac keypair and pairing token and opens a new
// 120-second, 5-attempt window. Per PROTOCOL.md §3.5, starting a session
// always discards any previous one — callers should simply replace whatever
// *Session they were holding with this new one.
func Start(now time.Time) (*Session, error) {
	macPriv, err := otpcrypto.GenerateMacKeypair()
	if err != nil {
		return nil, err
	}
	token, err := otpcrypto.RandomBytes(32)
	if err != nil {
		return nil, err
	}
	return &Session{
		MacPriv:      macPriv,
		MacPubBytes:  macPriv.PublicKey().Bytes(),
		Token:        token,
		StartedAt:    now,
		ExpiresAt:    now.Add(Window),
		AttemptsLeft: MaxAttempts,
	}, nil
}

// Expired reports whether the window is no longer open at time now, either
// because it was closed by a successful pairing, its time ran out, or its
// attempts were exhausted.
func (s *Session) Expired(now time.Time) bool {
	return s.Closed || !now.Before(s.ExpiresAt) || s.AttemptsLeft <= 0
}

// Result is the outcome of a successfully verified pairing attempt.
type Result struct {
	PhonePubBytes []byte
	DeviceName    string
	Keys          *otpcrypto.SessionKeys
	Confirm       []byte
}

// Verify checks one pairing attempt against the session. It always consumes
// one attempt (win or lose), matching PROTOCOL.md §3.4 step 2. On success it
// closes the session (so it can't be reused) and returns the derived keys
// and confirm value; on failure it returns one of the Err* sentinels above —
// callers must map every one of them to the same generic 400 (PROTOCOL.md
// §3.6) and must never reveal which one occurred.
func (s *Session) Verify(now time.Time, phonePubBytes []byte, deviceName string, mac []byte) (*Result, error) {
	if s == nil {
		return nil, ErrNoWindow
	}
	if s.Closed {
		return nil, ErrWindowExpired
	}
	if !now.Before(s.ExpiresAt) {
		s.Closed = true
		return nil, ErrWindowExpired
	}
	if s.AttemptsLeft <= 0 {
		s.Closed = true
		return nil, ErrAttemptsUsedUp
	}

	s.AttemptsLeft--

	phonePub, err := otpcrypto.ParsePublicKey(phonePubBytes)
	if err != nil {
		if s.AttemptsLeft <= 0 {
			s.Closed = true
		}
		return nil, ErrBadMAC // fold invalid-point into the same generic failure
	}

	if !otpcrypto.VerifyPairingMAC(s.Token, s.MacPubBytes, phonePubBytes, mac) {
		if s.AttemptsLeft <= 0 {
			s.Closed = true
		}
		return nil, ErrBadMAC
	}

	keys, err := otpcrypto.DeriveSessionKeys(s.MacPriv, phonePub, s.Token)
	if err != nil {
		s.Closed = true
		return nil, err
	}

	s.Closed = true
	return &Result{
		PhonePubBytes: phonePubBytes,
		DeviceName:    deviceName,
		Keys:          keys,
		Confirm:       otpcrypto.ConfirmMAC(keys.KM2P[:]),
	}, nil
}
