package crypto

import "crypto/subtle"

// Version is the message envelope's version byte (PROTOCOL.md §4.2).
const Version byte = 1

// minEnvelopeSize is version(1) + key_id(8) + nonce(12) + tag(16); anything
// shorter cannot possibly contain a valid GCM tag.
const minEnvelopeSize = 1 + KeyIDSize + NonceSize + 16

// SealEnvelope builds the binary envelope defined in PROTOCOL.md §4.2:
//
//	version(1) | key_id(8) | nonce(12) | ciphertext++tag
//
// with AAD = version || key_id.
func SealEnvelope(key []byte, keyID [KeyIDSize]byte, plaintext []byte) ([]byte, error) {
	aad := make([]byte, 0, 1+KeyIDSize)
	aad = append(aad, Version)
	aad = append(aad, keyID[:]...)

	nonce, ciphertext, err := Seal(key, aad, plaintext)
	if err != nil {
		return nil, err
	}

	out := make([]byte, 0, len(aad)+len(nonce)+len(ciphertext))
	out = append(out, aad...)
	out = append(out, nonce...)
	out = append(out, ciphertext...)
	return out, nil
}

// OpenEnvelope parses and decrypts a binary envelope, verifying that its
// key_id matches expectedKeyID before attempting to decrypt. Any failure —
// too short, wrong version, key_id mismatch, or AEAD failure — is reported
// generically so callers can return an indistinguishable rejection
// (PROTOCOL.md §4.6).
func OpenEnvelope(key []byte, expectedKeyID [KeyIDSize]byte, data []byte) ([]byte, error) {
	if len(data) < minEnvelopeSize {
		return nil, ErrEnvelope
	}
	if data[0] != Version {
		return nil, ErrEnvelope
	}
	var keyID [KeyIDSize]byte
	copy(keyID[:], data[1:1+KeyIDSize])
	if subtle.ConstantTimeCompare(keyID[:], expectedKeyID[:]) != 1 {
		return nil, ErrKeyIDMismatch
	}

	nonce := data[1+KeyIDSize : 1+KeyIDSize+NonceSize]
	ciphertext := data[1+KeyIDSize+NonceSize:]
	aad := data[:1+KeyIDSize]

	return Open(key, nonce, aad, ciphertext)
}
