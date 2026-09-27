package crypto

import (
	"bytes"
	"testing"
)

func TestPairingRoundTrip(t *testing.T) {
	macPriv, err := GenerateMacKeypair()
	if err != nil {
		t.Fatalf("GenerateMacKeypair: %v", err)
	}
	phonePriv, err := GenerateMacKeypair() // any P-256 key works for the phone side too
	if err != nil {
		t.Fatalf("phone keypair: %v", err)
	}
	token, err := RandomBytes(32)
	if err != nil {
		t.Fatalf("token: %v", err)
	}

	macPubBytes := macPriv.PublicKey().Bytes()
	phonePubBytes := phonePriv.PublicKey().Bytes()
	if len(macPubBytes) != 65 || macPubBytes[0] != 0x04 {
		t.Fatalf("expected 65-byte uncompressed point, got %d bytes prefix %x", len(macPubBytes), macPubBytes[0])
	}

	mac := PairingMAC(token, macPubBytes, phonePubBytes)
	if len(mac) != 32 {
		t.Fatalf("expected 32-byte HMAC, got %d", len(mac))
	}
	if !VerifyPairingMAC(token, macPubBytes, phonePubBytes, mac) {
		t.Fatal("VerifyPairingMAC rejected a valid mac")
	}

	tampered := append([]byte(nil), mac...)
	tampered[0] ^= 0xff
	if VerifyPairingMAC(token, macPubBytes, phonePubBytes, tampered) {
		t.Fatal("VerifyPairingMAC accepted a tampered mac")
	}

	phonePub, err := ParsePublicKey(phonePubBytes)
	if err != nil {
		t.Fatalf("ParsePublicKey(phone): %v", err)
	}
	macPub, err := ParsePublicKey(macPubBytes)
	if err != nil {
		t.Fatalf("ParsePublicKey(mac): %v", err)
	}

	macSide, err := DeriveSessionKeys(macPriv, phonePub, token)
	if err != nil {
		t.Fatalf("DeriveSessionKeys (mac side): %v", err)
	}

	// Simulate the phone's side of the exchange: it computes the same shared
	// secret from the opposite key pair (ECDH(phone_priv, mac_pub) ==
	// ECDH(mac_priv, phone_pub)), then feeds it through the same
	// ECDH-independent derivation to confirm both sides land on identical keys.
	phoneIKM, err := phonePriv.ECDH(macPub)
	if err != nil {
		t.Fatalf("phone-side ECDH: %v", err)
	}
	phoneSide, err := deriveSessionKeysFromSharedSecret(phoneIKM, token, macPubBytes, phonePubBytes)
	if err != nil {
		t.Fatalf("DeriveSessionKeys (phone side): %v", err)
	}

	if macSide.KP2M != phoneSide.KP2M {
		t.Fatal("k_p2m does not match between mac and phone sides")
	}
	if macSide.KM2P != phoneSide.KM2P {
		t.Fatal("k_m2p does not match between mac and phone sides")
	}
	if macSide.KP2M == macSide.KM2P {
		t.Fatal("k_p2m and k_m2p must not be equal")
	}
	if macSide.KeyID != phoneSide.KeyID {
		t.Fatal("key_id does not match between mac and phone sides")
	}

	confirm := ConfirmMAC(macSide.KM2P[:])
	if len(confirm) != 32 {
		t.Fatalf("expected 32-byte confirm, got %d", len(confirm))
	}
}

func TestParsePublicKeyRejectsCompressed(t *testing.T) {
	priv, err := GenerateMacKeypair()
	if err != nil {
		t.Fatalf("GenerateMacKeypair: %v", err)
	}
	uncompressed := priv.PublicKey().Bytes()
	compressed := append([]byte{0x02}, uncompressed[1:33]...)
	if _, err := ParsePublicKey(compressed); err == nil {
		t.Fatal("expected ParsePublicKey to reject compressed point encoding")
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	aad := []byte("aad")
	plaintext := []byte("hello world")

	nonce, ciphertext, err := Seal(key, aad, plaintext)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if len(nonce) != NonceSize {
		t.Fatalf("expected %d-byte nonce, got %d", NonceSize, len(nonce))
	}

	got, err := Open(key, nonce, aad, ciphertext)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("Open returned %q, want %q", got, plaintext)
	}
}

func TestOpenRejectsTamperedCiphertext(t *testing.T) {
	key := bytes.Repeat([]byte{0x24}, 32)
	aad := []byte("aad")
	nonce, ciphertext, err := Seal(key, aad, []byte("secret"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	tampered := append([]byte(nil), ciphertext...)
	tampered[0] ^= 0xff
	if _, err := Open(key, nonce, aad, tampered); err != ErrAuthFailed {
		t.Fatalf("expected ErrAuthFailed for tampered ciphertext, got %v", err)
	}
}

func TestOpenRejectsWrongAAD(t *testing.T) {
	key := bytes.Repeat([]byte{0x24}, 32)
	nonce, ciphertext, err := Seal(key, []byte("aad-a"), []byte("secret"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := Open(key, nonce, []byte("aad-b"), ciphertext); err != ErrAuthFailed {
		t.Fatalf("expected ErrAuthFailed for wrong AAD, got %v", err)
	}
}

func TestOpenRejectsWrongKey(t *testing.T) {
	key1 := bytes.Repeat([]byte{0x01}, 32)
	key2 := bytes.Repeat([]byte{0x02}, 32)
	nonce, ciphertext, err := Seal(key1, nil, []byte("secret"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := Open(key2, nonce, nil, ciphertext); err != ErrAuthFailed {
		t.Fatalf("expected ErrAuthFailed for wrong key, got %v", err)
	}
}

func TestEnvelopeRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 32)
	keyID := [KeyIDSize]byte{1, 2, 3, 4, 5, 6, 7, 8}
	plaintext := []byte(`{"id":"abc","ctr":1}`)

	env, err := SealEnvelope(key, keyID, plaintext)
	if err != nil {
		t.Fatalf("SealEnvelope: %v", err)
	}
	if env[0] != Version {
		t.Fatalf("expected version byte %d, got %d", Version, env[0])
	}

	got, err := OpenEnvelope(key, keyID, env)
	if err != nil {
		t.Fatalf("OpenEnvelope: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("OpenEnvelope returned %q, want %q", got, plaintext)
	}
}

func TestEnvelopeRejectsKeyIDMismatch(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 32)
	keyID := [KeyIDSize]byte{1, 2, 3, 4, 5, 6, 7, 8}
	otherKeyID := [KeyIDSize]byte{9, 9, 9, 9, 9, 9, 9, 9}

	env, err := SealEnvelope(key, keyID, []byte("hi"))
	if err != nil {
		t.Fatalf("SealEnvelope: %v", err)
	}
	if _, err := OpenEnvelope(key, otherKeyID, env); err != ErrKeyIDMismatch {
		t.Fatalf("expected ErrKeyIDMismatch, got %v", err)
	}
}

func TestEnvelopeRejectsTruncated(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 32)
	keyID := [KeyIDSize]byte{1, 2, 3, 4, 5, 6, 7, 8}
	env, err := SealEnvelope(key, keyID, []byte("hi"))
	if err != nil {
		t.Fatalf("SealEnvelope: %v", err)
	}
	if _, err := OpenEnvelope(key, keyID, env[:len(env)-20]); err != ErrEnvelope {
		t.Fatalf("expected ErrEnvelope for truncated data, got %v", err)
	}
}

func TestEnvelopeNonceIsRandomPerCall(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 32)
	keyID := [KeyIDSize]byte{}
	a, err := SealEnvelope(key, keyID, []byte("hi"))
	if err != nil {
		t.Fatalf("SealEnvelope: %v", err)
	}
	b, err := SealEnvelope(key, keyID, []byte("hi"))
	if err != nil {
		t.Fatalf("SealEnvelope: %v", err)
	}
	nonceA := a[1+KeyIDSize : 1+KeyIDSize+NonceSize]
	nonceB := b[1+KeyIDSize : 1+KeyIDSize+NonceSize]
	if bytes.Equal(nonceA, nonceB) {
		t.Fatal("two calls to SealEnvelope produced the same nonce")
	}
}
