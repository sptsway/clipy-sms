package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	otpcrypto "otpforwarder/internal/crypto"
	"otpforwarder/internal/daemon"
	"otpforwarder/internal/messages"
	"otpforwarder/internal/ratelimit"
)

func newTestServer(t *testing.T) (*httptest.Server, *daemon.Handler) {
	t.Helper()
	dir := t.TempDir()
	h, err := daemon.New(dir, messages.NewStore())
	if err != nil {
		t.Fatalf("daemon.New: %v", err)
	}
	srv := New(h)
	ts := httptest.NewServer(srv.Mux())
	t.Cleanup(ts.Close)
	return ts, h
}

// pair performs a full pairing exchange against ts, exactly as a real phone
// would over HTTP, and returns the derived session keys.
func pair(t *testing.T, ts *httptest.Server, h *daemon.Handler, deviceName string) *otpcrypto.SessionKeys {
	t.Helper()
	start, err := h.PairStart(t.Context())
	if err != nil {
		t.Fatalf("PairStart: %v", err)
	}
	u, err := url.Parse(start.URI)
	if err != nil {
		t.Fatalf("parsing pairing URI: %v", err)
	}
	q := u.Query()
	macPubBytes := mustDecode(t, q.Get("mac_pub"))
	token := mustDecode(t, q.Get("token"))

	phonePriv, err := otpcrypto.GenerateMacKeypair()
	if err != nil {
		t.Fatalf("phone keypair: %v", err)
	}
	phonePubBytes := phonePriv.PublicKey().Bytes()
	mac := otpcrypto.PairingMAC(token, macPubBytes, phonePubBytes)

	reqBody, _ := json.Marshal(map[string]any{
		"v":           1,
		"phone_pub":   base64.RawURLEncoding.EncodeToString(phonePubBytes),
		"device_name": deviceName,
		"mac":         base64.RawURLEncoding.EncodeToString(mac),
	})
	resp, err := http.Post(ts.URL+"/v1/pair", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("POST /v1/pair: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /v1/pair status = %d, want 200", resp.StatusCode)
	}
	var respBody struct {
		OK      bool   `json:"ok"`
		Confirm string `json:"confirm"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&respBody); err != nil {
		t.Fatalf("decoding /v1/pair response: %v", err)
	}
	confirm := mustDecode(t, respBody.Confirm)

	macPub, err := otpcrypto.ParsePublicKey(macPubBytes)
	if err != nil {
		t.Fatalf("ParsePublicKey(mac): %v", err)
	}
	ikm, err := phonePriv.ECDH(macPub)
	if err != nil {
		t.Fatalf("phone ECDH: %v", err)
	}
	keys, err := otpcrypto.DeriveSessionKeysFromIKM(ikm, token, macPubBytes, phonePubBytes)
	if err != nil {
		t.Fatalf("DeriveSessionKeysFromIKM: %v", err)
	}
	if string(confirm) != string(otpcrypto.ConfirmMAC(keys.KM2P[:])) {
		t.Fatal("confirm value did not match the phone's independently derived k_m2p")
	}
	return keys
}

func mustDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64url decode %q: %v", s, err)
	}
	return b
}

func sealMsg(t *testing.T, keys *otpcrypto.SessionKeys, id string, ts time.Time, ctr uint64, sender, body string) []byte {
	t.Helper()
	plaintext, err := json.Marshal(map[string]any{
		"id": id, "ts": ts.UnixMilli(), "ctr": ctr, "sender": sender, "body": body,
	})
	if err != nil {
		t.Fatalf("marshal plaintext: %v", err)
	}
	env, err := otpcrypto.SealEnvelope(keys.KP2M[:], keys.KeyID, plaintext)
	if err != nil {
		t.Fatalf("SealEnvelope: %v", err)
	}
	return env
}

func postMsg(t *testing.T, ts *httptest.Server, env []byte) *http.Response {
	t.Helper()
	resp, err := http.Post(ts.URL+"/v1/msg", "application/octet-stream", bytes.NewReader(env))
	if err != nil {
		t.Fatalf("POST /v1/msg: %v", err)
	}
	return resp
}

func TestPairAndSendMessage(t *testing.T) {
	ts, h := newTestServer(t)
	keys := pair(t, ts, h, "Test Phone")

	env := sealMsg(t, keys, "id-1", time.Now(), 0, "1234", "Your OTP is 555555")
	resp := postMsg(t, ts, env)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /v1/msg status = %d, want 200", resp.StatusCode)
	}
	ackBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading ack body: %v", err)
	}
	plaintext, err := otpcrypto.OpenEnvelope(keys.KM2P[:], keys.KeyID, ackBody)
	if err != nil {
		t.Fatalf("opening ack: %v", err)
	}
	var ack struct {
		ID  string `json:"id"`
		Ctr uint64 `json:"ctr"`
	}
	if err := json.Unmarshal(plaintext, &ack); err != nil {
		t.Fatalf("unmarshal ack: %v", err)
	}
	if ack.ID != "id-1" || ack.Ctr != 0 {
		t.Fatalf("unexpected ack: %+v", ack)
	}
}

func TestPairBadMacGeneric400(t *testing.T) {
	ts, h := newTestServer(t)
	if _, err := h.PairStart(t.Context()); err != nil {
		t.Fatalf("PairStart: %v", err)
	}

	phonePriv, _ := otpcrypto.GenerateMacKeypair()
	body, _ := json.Marshal(map[string]any{
		"v": 1, "phone_pub": base64.RawURLEncoding.EncodeToString(phonePriv.PublicKey().Bytes()),
		"device_name": "x", "mac": base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	})
	resp, err := http.Post(ts.URL+"/v1/pair", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestMsgReplayRejected(t *testing.T) {
	ts, h := newTestServer(t)
	keys := pair(t, ts, h, "Test Phone")
	now := time.Now()

	env := sealMsg(t, keys, "id-1", now, 0, "1234", "code 1111")
	resp := postMsg(t, ts, env)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first send status = %d, want 200", resp.StatusCode)
	}

	env2 := sealMsg(t, keys, "id-1", now, 1, "1234", "code 1111")
	resp2 := postMsg(t, ts, env2)
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("replay status = %d, want 400", resp2.StatusCode)
	}
}

func TestMsgNonIncreasingCounterRejected(t *testing.T) {
	ts, h := newTestServer(t)
	keys := pair(t, ts, h, "Test Phone")
	now := time.Now()

	resp := postMsg(t, ts, sealMsg(t, keys, "id-1", now, 5, "1234", "code 1"))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first send status = %d, want 200", resp.StatusCode)
	}

	resp2 := postMsg(t, ts, sealMsg(t, keys, "id-2", now, 5, "1234", "code 2"))
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("non-increasing ctr status = %d, want 400", resp2.StatusCode)
	}
}

func TestMsgStaleTimestampRejected(t *testing.T) {
	ts, h := newTestServer(t)
	keys := pair(t, ts, h, "Test Phone")

	stale := time.Now().Add(-200 * time.Second)
	resp := postMsg(t, ts, sealMsg(t, keys, "id-1", stale, 0, "1234", "code 1"))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("stale timestamp status = %d, want 400", resp.StatusCode)
	}
}

func TestMsgTamperedCiphertextRejected(t *testing.T) {
	ts, h := newTestServer(t)
	keys := pair(t, ts, h, "Test Phone")

	env := sealMsg(t, keys, "id-1", time.Now(), 0, "1234", "code 1")
	env[len(env)-1] ^= 0xff
	resp := postMsg(t, ts, env)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("tampered ciphertext status = %d, want 400", resp.StatusCode)
	}
}

func TestMsgOversizedBodyRejected(t *testing.T) {
	ts, _ := newTestServer(t)
	oversized := bytes.Repeat([]byte{0x01}, MaxBodyBytes+1)
	resp := postMsg(t, ts, oversized)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("oversized body status = %d, want 400", resp.StatusCode)
	}
}

func TestMsgWrongMethodRejected(t *testing.T) {
	ts, _ := newTestServer(t)
	resp, err := http.Get(ts.URL + "/v1/msg")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", resp.StatusCode)
	}
}

func TestMsgUnpairedRejected(t *testing.T) {
	ts, _ := newTestServer(t)
	fakeKeys := &otpcrypto.SessionKeys{}
	resp := postMsg(t, ts, sealMsg(t, fakeKeys, "id-1", time.Now(), 0, "1234", "code 1"))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestMsgRateLimited(t *testing.T) {
	dir := t.TempDir()
	h, err := daemon.New(dir, messages.NewStore())
	if err != nil {
		t.Fatalf("daemon.New: %v", err)
	}
	srv := NewWithLimiter(h, ratelimit.New(1, 0, time.Minute)) // 1 token, no refill
	ts := httptest.NewServer(srv.Mux())
	defer ts.Close()

	keys := pair(t, ts, h, "Test Phone")

	resp1 := postMsg(t, ts, sealMsg(t, keys, "id-1", time.Now(), 0, "1234", "code 1"))
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("first request status = %d, want 200", resp1.StatusCode)
	}

	resp2 := postMsg(t, ts, sealMsg(t, keys, "id-2", time.Now(), 1, "1234", "code 2"))
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("rate-limited request status = %d, want 400", resp2.StatusCode)
	}
}
