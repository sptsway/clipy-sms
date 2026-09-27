package pairing

import (
	"testing"
	"time"

	otpcrypto "otpforwarder/internal/crypto"
)

// newPhone returns a fresh P-256 public key's raw 65-byte bytes, standing in
// for whatever key the phone would generate.
func newPhone(t *testing.T) []byte {
	t.Helper()
	k, err := otpcrypto.GenerateMacKeypair() // any P-256 keypair works for the phone too
	if err != nil {
		t.Fatalf("phone keypair: %v", err)
	}
	return k.PublicKey().Bytes()
}

func TestSessionSuccessfulPairing(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s, err := Start(now)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if s.AttemptsLeft != MaxAttempts {
		t.Fatalf("expected %d attempts, got %d", MaxAttempts, s.AttemptsLeft)
	}
	if s.Expired(now) {
		t.Fatal("freshly started session should not be expired")
	}

	phonePub := newPhone(t)
	mac := otpcrypto.PairingMAC(s.Token, s.MacPubBytes, phonePub)

	res, err := s.Verify(now.Add(time.Second), phonePub, "Test Phone", mac)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.DeviceName != "Test Phone" {
		t.Errorf("DeviceName = %q", res.DeviceName)
	}
	if res.Keys.KP2M == res.Keys.KM2P {
		t.Error("k_p2m and k_m2p must differ")
	}
	if !s.Closed {
		t.Error("session should be closed after a successful pairing")
	}
	if !s.Expired(now) {
		t.Error("a closed session must report itself as expired")
	}

	// A second attempt against the same (now closed) session must fail.
	if _, err := s.Verify(now.Add(2*time.Second), phonePub, "Test Phone", mac); err != ErrWindowExpired {
		t.Fatalf("expected ErrWindowExpired for a reused session, got %v", err)
	}
}

func TestSessionRejectsBadMAC(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s, err := Start(now)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	phonePub := newPhone(t)
	badMAC := make([]byte, 32)

	_, err = s.Verify(now, phonePub, "Test Phone", badMAC)
	if err != ErrBadMAC {
		t.Fatalf("expected ErrBadMAC, got %v", err)
	}
	if s.AttemptsLeft != MaxAttempts-1 {
		t.Fatalf("expected one attempt consumed, got %d left", s.AttemptsLeft)
	}
	if s.Closed {
		t.Fatal("session should remain open after a single failed attempt")
	}
}

func TestSessionAttemptLimit(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s, err := Start(now)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	phonePub := newPhone(t)
	badMAC := make([]byte, 32)

	for i := 0; i < MaxAttempts; i++ {
		if _, err := s.Verify(now, phonePub, "x", badMAC); err != ErrBadMAC {
			t.Fatalf("attempt %d: expected ErrBadMAC, got %v", i, err)
		}
	}
	if !s.Closed {
		t.Fatal("session should close once attempts are exhausted")
	}

	// A correct MAC after the limit is reached must still be rejected.
	mac := otpcrypto.PairingMAC(s.Token, s.MacPubBytes, phonePub)
	if _, err := s.Verify(now, phonePub, "x", mac); err != ErrWindowExpired {
		t.Fatalf("expected ErrWindowExpired once attempts are exhausted, got %v", err)
	}
}

func TestSessionExpiresAfterWindow(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s, err := Start(now)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	phonePub := newPhone(t)
	mac := otpcrypto.PairingMAC(s.Token, s.MacPubBytes, phonePub)

	late := now.Add(Window + time.Second)
	if !s.Expired(late) {
		t.Fatal("expected session to report expired past the 120s window")
	}
	if _, err := s.Verify(late, phonePub, "x", mac); err != ErrWindowExpired {
		t.Fatalf("expected ErrWindowExpired past the window, got %v", err)
	}
}

func TestSessionRejectsMalformedPhonePub(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s, err := Start(now)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, err := s.Verify(now, []byte("not a point"), "x", make([]byte, 32)); err != ErrBadMAC {
		t.Fatalf("expected malformed phone_pub to fold into ErrBadMAC, got %v", err)
	}
}
