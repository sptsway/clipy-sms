package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"testing"
)

// TestDocumentedVectors locks in the exact values published in
// docs/PROTOCOL.md §6, generated from this package. If this test ever fails
// after a code change, docs/PROTOCOL.md's test vectors need to be
// regenerated and republished — the two must never silently drift apart,
// since the Android sender is implemented against the documented values.
func TestDocumentedVectors(t *testing.T) {
	macPrivBytes := hexRepeat(t, "01", 32)
	phonePrivBytes := hexRepeat(t, "02", 32)
	token := hexRepeat(t, "03", 32)

	macPriv, err := ParsePrivateKey(macPrivBytes)
	if err != nil {
		t.Fatalf("ParsePrivateKey(mac): %v", err)
	}
	phonePriv, err := ParsePrivateKey(phonePrivBytes)
	if err != nil {
		t.Fatalf("ParsePrivateKey(phone): %v", err)
	}

	macPub := macPriv.PublicKey().Bytes()
	phonePub := phonePriv.PublicKey().Bytes()
	wantMacPub := mustHex(t, "046ff03b949241ce1dadd43519e6960e0a85b41a69a05c328103aa2bce1594ca163c4f753a55bf01dc53f6c0b0c7eee78b40c6ff7d25a96e2282b989cef71c144a")
	wantPhonePub := mustHex(t, "04550f471003f3df97c3df506ac797f6721fb1a1fb7b8f6f83d224498a65c88e24136093d7012e509a73715cbd0b00a3cc0ff4b5c01b3ffa196ab1fb327036b8e6")
	assertEqual(t, "mac_pub", macPub, wantMacPub)
	assertEqual(t, "phone_pub", phonePub, wantPhonePub)

	mac := PairingMAC(token, macPub, phonePub)
	assertEqual(t, "mac", mac, mustHex(t, "0243e701d05438855ac7f39e76977236a45dec668e47eb0107263fc7dddc1294"))

	keys, err := DeriveSessionKeys(macPriv, phonePriv.PublicKey(), token)
	if err != nil {
		t.Fatalf("DeriveSessionKeys: %v", err)
	}
	assertEqual(t, "k_p2m", keys.KP2M[:], mustHex(t, "7cde3a20477d5bd7ee84aea6fe96dc7fe230d24dda556ec7769d0752d78ecec4"))
	assertEqual(t, "k_m2p", keys.KM2P[:], mustHex(t, "1cbd40e7fd5b57ccc4bfbffd01d8d9fad8bf9502eb2d1ab6fc0b394af5a0c765"))
	assertEqual(t, "key_id", keys.KeyID[:], mustHex(t, "92fbce47412a0f01"))

	confirm := ConfirmMAC(keys.KM2P[:])
	assertEqual(t, "confirm", confirm, mustHex(t, "a47be19aa070cd2f31baaa8c48027aee3edcc8c49a82e862d4545974676d8db7"))

	// Message envelope, PROTOCOL.md §6.2 — fixed nonce, built with the raw
	// primitives (not SealEnvelope, which always randomizes the nonce) so
	// the ciphertext is directly comparable to the published vector.
	nonce := make([]byte, NonceSize)
	for i := range nonce {
		nonce[i] = byte(i)
	}
	plaintext := []byte(`{"id":"11111111-1111-1111-1111-111111111111","ts":1735689600000,"ctr":0,"sender":"38221","body":"Your OTP is 123456."}`)
	aad := append([]byte{Version}, keys.KeyID[:]...)
	ciphertext := sealFixed(t, keys.KP2M[:], nonce, plaintext, aad)
	assertEqual(t, "message ciphertext+tag", ciphertext, mustHex(t,
		"fbe0658149d62940ce1664e3097a73c23e628f03521fe6876e29dd00758991642d2b3f82957fdda84f0b86990a25b11dd0448058561962e3a618720620e8e3c54c73d8caf260f56007fc58c0d1ad3c6500834a13336d03a446eec8e948fb9559f00904138877292d74331f8c1d36ea16e1596d15dd9d744687dd388c4432722b7998d4b7e49c"))

	// Ack envelope, PROTOCOL.md §6.3.
	ackNonce := make([]byte, NonceSize)
	for i := range ackNonce {
		ackNonce[i] = byte(0x10 + i)
	}
	ackPlaintext := []byte(`{"id":"11111111-1111-1111-1111-111111111111","ctr":0}`)
	ackCiphertext := sealFixed(t, keys.KM2P[:], ackNonce, ackPlaintext, aad)
	assertEqual(t, "ack ciphertext+tag", ackCiphertext, mustHex(t,
		"c5a0aac12441e323f4660d1071f4642636fd7b9802b0713f3ded5a82a1c5ad61bcd76e535d2db6e550fcf781d70926df32cc3e9456f14b9ae0acb3bece77bcc0504deebb72"))
}

func sealFixed(t *testing.T, key, nonce, plaintext, aad []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM: %v", err)
	}
	return gcm.Seal(nil, nonce, plaintext, aad)
}

func hexRepeat(t *testing.T, pair string, n int) []byte {
	t.Helper()
	s := ""
	for i := 0; i < n; i++ {
		s += pair
	}
	return mustHex(t, s)
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q): %v", s, err)
	}
	return b
}

func assertEqual(t *testing.T, name string, got, want []byte) {
	t.Helper()
	if hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Errorf("%s = %s, want %s", name, hex.EncodeToString(got), hex.EncodeToString(want))
	}
}
