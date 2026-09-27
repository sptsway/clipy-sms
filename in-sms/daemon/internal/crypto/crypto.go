// Package crypto implements the cryptographic primitives from docs/PROTOCOL.md
// using only the Go standard library: crypto/ecdh (P-256), crypto/hkdf,
// crypto/hmac, crypto/sha256, crypto/aes+cipher.NewGCM, crypto/rand,
// crypto/subtle. See docs/CRYPTO_IMPLEMENTATION.md for the design notes this
// follows.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
)

const (
	// NonceSize is the AES-GCM nonce length used throughout the message path.
	NonceSize = 12
	// KeyIDSize is the length of the envelope's key_id field.
	KeyIDSize = 8
	// SessionKeySize is the length of k_p2m and k_m2p.
	SessionKeySize = 32
)

var (
	ErrBadPoint      = errors.New("crypto: invalid P-256 point")
	ErrAuthFailed    = errors.New("crypto: authentication failed")
	ErrEnvelope      = errors.New("crypto: malformed envelope")
	ErrKeyIDMismatch = errors.New("crypto: key_id mismatch")
)

// curve is the single elliptic curve used throughout the protocol.
func curve() ecdh.Curve { return ecdh.P256() }

// GenerateMacKeypair generates a fresh Mac P-256 keypair for a new pairing.
func GenerateMacKeypair() (*ecdh.PrivateKey, error) {
	return curve().GenerateKey(rand.Reader)
}

// RandomBytes returns n cryptographically random bytes.
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// ParsePrivateKey reloads a Mac private key from its raw scalar bytes
// (as produced by PrivateKey.Bytes()).
func ParsePrivateKey(raw []byte) (*ecdh.PrivateKey, error) {
	k, err := curve().NewPrivateKey(raw)
	if err != nil {
		return nil, ErrBadPoint
	}
	return k, nil
}

// ParsePublicKey parses a 65-byte uncompressed P-256 point. It rejects the
// compressed form and the point at infinity, per PROTOCOL.md §1.
func ParsePublicKey(raw []byte) (*ecdh.PublicKey, error) {
	k, err := curve().NewPublicKey(raw)
	if err != nil {
		return nil, ErrBadPoint
	}
	return k, nil
}

// PairingMAC computes mac = HMAC-SHA256(token, "pair-v1" || mac_pub || phone_pub)
// as specified in PROTOCOL.md §3.3. macPub and phonePub must be the raw
// 65-byte uncompressed point encodings.
func PairingMAC(token, macPub, phonePub []byte) []byte {
	h := hmac.New(sha256.New, token)
	h.Write([]byte("pair-v1"))
	h.Write(macPub)
	h.Write(phonePub)
	return h.Sum(nil)
}

// VerifyPairingMAC reports whether mac matches the expected value, comparing
// in constant time.
func VerifyPairingMAC(token, macPub, phonePub, mac []byte) bool {
	expected := PairingMAC(token, macPub, phonePub)
	return subtle.ConstantTimeCompare(expected, mac) == 1
}

// ConfirmMAC computes confirm = HMAC-SHA256(k_m2p, "confirm-v1") as specified
// in PROTOCOL.md §3.4.
func ConfirmMAC(kM2P []byte) []byte {
	h := hmac.New(sha256.New, kM2P)
	h.Write([]byte("confirm-v1"))
	return h.Sum(nil)
}

// SessionKeys holds the derived per-pairing key material.
type SessionKeys struct {
	KP2M  [SessionKeySize]byte
	KM2P  [SessionKeySize]byte
	KeyID [KeyIDSize]byte
}

// DeriveSessionKeys implements PROTOCOL.md §3.4 for the daemon's side of the
// exchange:
//
//	ikm  = ECDH(mac_priv, phone_pub)
//	salt = token
//	info = "otpfwd-v1" || mac_pub || phone_pub
//	okm  = HKDF-SHA256(ikm, salt, info, 64)
//	k_p2m = okm[0:32], k_m2p = okm[32:64]
//	key_id = SHA-256("otpfwd-key-id" || k_p2m || k_m2p)[0:8]
func DeriveSessionKeys(macPriv *ecdh.PrivateKey, phonePub *ecdh.PublicKey, token []byte) (*SessionKeys, error) {
	ikm, err := macPriv.ECDH(phonePub)
	if err != nil {
		return nil, err
	}
	return deriveSessionKeysFromSharedSecret(ikm, token, macPriv.PublicKey().Bytes(), phonePub.Bytes())
}

// DeriveSessionKeysFromIKM is the ECDH-independent half of
// DeriveSessionKeys, exported so the *other* side of the exchange — a phone
// (or, in this repo, the fakephone CLI and its tests) — can derive the same
// keys from its own ECDH(phone_priv, mac_pub) result, which is numerically
// identical to the daemon's ECDH(mac_priv, phone_pub) but can't be computed
// by calling DeriveSessionKeys itself (that function is hardwired to do the
// mac-side ECDH). macPub and phonePub must be the raw 65-byte uncompressed
// point encodings, in that order, regardless of which side is calling this.
func DeriveSessionKeysFromIKM(ikm, token, macPub, phonePub []byte) (*SessionKeys, error) {
	return deriveSessionKeysFromSharedSecret(ikm, token, macPub, phonePub)
}

// deriveSessionKeysFromSharedSecret is the shared implementation behind both
// DeriveSessionKeys and DeriveSessionKeysFromIKM.
func deriveSessionKeysFromSharedSecret(ikm, token, macPub, phonePub []byte) (*SessionKeys, error) {
	info := make([]byte, 0, len("otpfwd-v1")+65+65)
	info = append(info, "otpfwd-v1"...)
	info = append(info, macPub...)
	info = append(info, phonePub...)

	okm, err := hkdf.Key(sha256.New, ikm, token, string(info), 2*SessionKeySize)
	if err != nil {
		return nil, err
	}

	sk := &SessionKeys{}
	copy(sk.KP2M[:], okm[:SessionKeySize])
	copy(sk.KM2P[:], okm[SessionKeySize:2*SessionKeySize])
	sk.KeyID = ComputeKeyID(sk.KP2M[:], sk.KM2P[:])
	return sk, nil
}

// ComputeKeyID derives the envelope's key_id tag from the two session keys.
func ComputeKeyID(kP2M, kM2P []byte) [KeyIDSize]byte {
	h := sha256.New()
	h.Write([]byte("otpfwd-key-id"))
	h.Write(kP2M)
	h.Write(kM2P)
	sum := h.Sum(nil)
	var id [KeyIDSize]byte
	copy(id[:], sum[:KeyIDSize])
	return id
}

// aead builds an AES-256-GCM cipher for the given 32-byte key.
func aead(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Seal encrypts plaintext under key with a fresh random nonce and the given
// AAD, returning the nonce and the ciphertext-plus-tag separately.
func Seal(key, aad, plaintext []byte) (nonce, ciphertext []byte, err error) {
	gcm, err := aead(key)
	if err != nil {
		return nil, nil, err
	}
	nonce, err = RandomBytes(NonceSize)
	if err != nil {
		return nil, nil, err
	}
	ciphertext = gcm.Seal(nil, nonce, plaintext, aad)
	return nonce, ciphertext, nil
}

// Open decrypts ciphertext (with its trailing GCM tag) under key, nonce and
// aad. Any failure — wrong key, tampered ciphertext, wrong AAD, wrong nonce
// length — is reported as the single ErrAuthFailed so callers never leak
// which check failed.
func Open(key, nonce, aad, ciphertext []byte) ([]byte, error) {
	gcm, err := aead(key)
	if err != nil {
		return nil, ErrAuthFailed
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, ErrAuthFailed
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrAuthFailed
	}
	return plaintext, nil
}
