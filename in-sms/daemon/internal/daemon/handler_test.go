package daemon

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"testing"
	"time"

	otpcrypto "otpforwarder/internal/crypto"
	"otpforwarder/internal/ipc"
	"otpforwarder/internal/messages"
)

func newTestHandler(t *testing.T) *Handler {
	t.Helper()
	dir := t.TempDir()
	h, err := New(dir, messages.NewStore())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return h
}

// fakeBroadcaster records every event pushed by the Handler under test.
type fakeBroadcaster struct {
	events []string
}

func (f *fakeBroadcaster) Broadcast(event string, data interface{}) {
	f.events = append(f.events, event)
}

// pairPhoneSide drives a full pairing attempt against h exactly as a real
// phone would: parse the QR URI, generate its own keypair, compute the mac,
// and call VerifyPairingAttempt directly (standing in for the HTTP layer).
// It then reads back the resulting session keys from h's own state (this
// test file is package daemon, so that's allowed) to hand back to the
// caller for building test messages.
func pairPhoneSide(t *testing.T, h *Handler, deviceName string) *otpcrypto.SessionKeys {
	t.Helper()
	ctx := context.Background()

	start, err := h.PairStart(ctx)
	if err != nil {
		t.Fatalf("PairStart: %v", err)
	}
	u, err := url.Parse(start.URI)
	if err != nil {
		t.Fatalf("parsing pairing URI: %v", err)
	}
	q := u.Query()
	macPubBytes := decodeB64(t, q.Get("mac_pub"))
	token := decodeB64(t, q.Get("token"))

	phonePriv, err := otpcrypto.GenerateMacKeypair()
	if err != nil {
		t.Fatalf("phone keypair: %v", err)
	}
	phonePubBytes := phonePriv.PublicKey().Bytes()
	mac := otpcrypto.PairingMAC(token, macPubBytes, phonePubBytes)

	confirm, err := h.VerifyPairingAttempt(phonePubBytes, deviceName, mac)
	if err != nil {
		t.Fatalf("VerifyPairingAttempt: %v", err)
	}
	if h.id.Pairing == nil {
		t.Fatal("expected identity.Pairing to be set after a successful attempt")
	}

	var keys otpcrypto.SessionKeys
	copy(keys.KP2M[:], h.id.Pairing.KP2M)
	copy(keys.KM2P[:], h.id.Pairing.KM2P)
	copy(keys.KeyID[:], h.id.Pairing.KeyID)

	expectedConfirm := otpcrypto.ConfirmMAC(keys.KM2P[:])
	if string(confirm) != string(expectedConfirm) {
		t.Fatal("confirm value did not match the stored k_m2p")
	}
	return &keys
}

func decodeB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64url decode %q: %v", s, err)
	}
	return b
}

// sealTestMessage builds a plaintext {id,ts,ctr,sender,body} and encrypts it
// into a binary envelope with kP2M/keyID, standing in for what a phone would
// send to POST /v1/msg.
func sealTestMessage(t *testing.T, kP2M []byte, keyID [otpcrypto.KeyIDSize]byte, id string, ts time.Time, ctr uint64, sender, body string) []byte {
	t.Helper()
	plaintext, err := json.Marshal(struct {
		ID     string `json:"id"`
		Ts     int64  `json:"ts"`
		Ctr    uint64 `json:"ctr"`
		Sender string `json:"sender"`
		Body   string `json:"body"`
	}{ID: id, Ts: ts.UnixMilli(), Ctr: ctr, Sender: sender, Body: body})
	if err != nil {
		t.Fatalf("marshal plaintext: %v", err)
	}
	env, err := otpcrypto.SealEnvelope(kP2M, keyID, plaintext)
	if err != nil {
		t.Fatalf("SealEnvelope: %v", err)
	}
	return env
}

func TestPairingFlowEndToEnd(t *testing.T) {
	h := newTestHandler(t)
	ctx := context.Background()
	bcast := &fakeBroadcaster{}
	h.SetBroadcaster(bcast)

	status, err := h.PairStatus(ctx)
	if err != nil || status.State != ipc.PairingIdle {
		t.Fatalf("expected idle status before pairing, got %+v, %v", status, err)
	}

	pairPhoneSide(t, h, "Test Phone")

	status, err = h.PairStatus(ctx)
	if err != nil || status.State != ipc.PairingPaired {
		t.Fatalf("expected paired status after pairing, got %+v, %v", status, err)
	}

	dev, err := h.DeviceStatus(ctx)
	if err != nil || !dev.Paired || dev.DeviceName != "Test Phone" {
		t.Fatalf("DeviceStatus after pairing = %+v, %v", dev, err)
	}

	foundPairingEvent := false
	for _, e := range bcast.events {
		if e == ipc.EventPairingStatus {
			foundPairingEvent = true
		}
	}
	if !foundPairingEvent {
		t.Fatal("expected at least one pairing.status broadcast")
	}

	if err := h.DeviceUnpair(ctx); err != nil {
		t.Fatalf("DeviceUnpair: %v", err)
	}
	dev, _ = h.DeviceStatus(ctx)
	if dev.Paired {
		t.Fatal("expected unpaired status after DeviceUnpair")
	}
}

func TestPairingBadMACRejected(t *testing.T) {
	h := newTestHandler(t)
	ctx := context.Background()

	if _, err := h.PairStart(ctx); err != nil {
		t.Fatalf("PairStart: %v", err)
	}
	phonePriv, _ := otpcrypto.GenerateMacKeypair()
	phonePubBytes := phonePriv.PublicKey().Bytes()

	if _, err := h.VerifyPairingAttempt(phonePubBytes, "x", make([]byte, 32)); err == nil {
		t.Fatal("expected a bad mac to be rejected")
	}

	dev, _ := h.DeviceStatus(ctx)
	if dev.Paired {
		t.Fatal("a failed attempt must not result in a paired device")
	}
}

func TestPairCancel(t *testing.T) {
	h := newTestHandler(t)
	ctx := context.Background()

	if _, err := h.PairStart(ctx); err != nil {
		t.Fatalf("PairStart: %v", err)
	}
	if err := h.PairCancel(ctx); err != nil {
		t.Fatalf("PairCancel: %v", err)
	}
	status, _ := h.PairStatus(ctx)
	if status.State != ipc.PairingIdle {
		t.Fatalf("expected idle status after cancel, got %+v", status)
	}
}

func TestAcceptMessageValidatesAndStores(t *testing.T) {
	h := newTestHandler(t)
	keys := pairPhoneSide(t, h, "Test Phone")
	now := time.Now()

	env := sealTestMessage(t, keys.KP2M[:], keys.KeyID, "id-1", now, 0, "1234", "Your OTP is 555555")
	ack, err := h.AcceptMessage(env, now)
	if err != nil {
		t.Fatalf("AcceptMessage: %v", err)
	}
	plaintext, err := otpcrypto.OpenEnvelope(keys.KM2P[:], keys.KeyID, ack)
	if err != nil {
		t.Fatalf("opening ack: %v", err)
	}
	var ackMsg struct {
		ID  string `json:"id"`
		Ctr uint64 `json:"ctr"`
	}
	if err := json.Unmarshal(plaintext, &ackMsg); err != nil {
		t.Fatalf("unmarshal ack: %v", err)
	}
	if ackMsg.ID != "id-1" || ackMsg.Ctr != 0 {
		t.Fatalf("unexpected ack contents: %+v", ackMsg)
	}

	list, _ := h.MessagesList(context.Background(), ipc.MessagesListParams{Offset: 0, Limit: 10})
	if list.Total != 1 || list.Messages[0].Body != "Your OTP is 555555" {
		t.Fatalf("expected the message to be stored with its full body, got %+v", list)
	}
}

func TestAcceptMessageRejectsReplay(t *testing.T) {
	h := newTestHandler(t)
	keys := pairPhoneSide(t, h, "Test Phone")
	now := time.Now()

	env := sealTestMessage(t, keys.KP2M[:], keys.KeyID, "id-1", now, 0, "1234", "code 1111")
	if _, err := h.AcceptMessage(env, now); err != nil {
		t.Fatalf("first send: %v", err)
	}

	env2 := sealTestMessage(t, keys.KP2M[:], keys.KeyID, "id-1", now, 1, "1234", "code 1111")
	if _, err := h.AcceptMessage(env2, now); err == nil {
		t.Fatal("expected a replayed id to be rejected even with a higher ctr")
	}
}

func TestAcceptMessageRejectsNonIncreasingCounter(t *testing.T) {
	h := newTestHandler(t)
	keys := pairPhoneSide(t, h, "Test Phone")
	now := time.Now()

	env := sealTestMessage(t, keys.KP2M[:], keys.KeyID, "id-1", now, 5, "1234", "code 1111")
	if _, err := h.AcceptMessage(env, now); err != nil {
		t.Fatalf("first send: %v", err)
	}
	env2 := sealTestMessage(t, keys.KP2M[:], keys.KeyID, "id-2", now, 5, "1234", "code 2222")
	if _, err := h.AcceptMessage(env2, now); err == nil {
		t.Fatal("expected a non-increasing ctr to be rejected")
	}
}

func TestAcceptMessageRejectsStaleTimestamp(t *testing.T) {
	h := newTestHandler(t)
	keys := pairPhoneSide(t, h, "Test Phone")
	now := time.Now()
	stale := now.Add(-200 * time.Second)

	env := sealTestMessage(t, keys.KP2M[:], keys.KeyID, "id-1", stale, 0, "1234", "code 1111")
	if _, err := h.AcceptMessage(env, now); err == nil {
		t.Fatal("expected a stale timestamp to be rejected")
	}
}

func TestAcceptMessageRejectsTamperedCiphertext(t *testing.T) {
	h := newTestHandler(t)
	keys := pairPhoneSide(t, h, "Test Phone")
	now := time.Now()

	env := sealTestMessage(t, keys.KP2M[:], keys.KeyID, "id-1", now, 0, "1234", "code 1111")
	env[len(env)-1] ^= 0xff
	if _, err := h.AcceptMessage(env, now); err == nil {
		t.Fatal("expected tampered ciphertext to be rejected")
	}
}

func TestAcceptMessageRejectsWhenUnpaired(t *testing.T) {
	h := newTestHandler(t)
	now := time.Now()
	env := sealTestMessage(t, make([]byte, 32), [otpcrypto.KeyIDSize]byte{}, "id-1", now, 0, "1234", "code 1111")
	if _, err := h.AcceptMessage(env, now); err == nil {
		t.Fatal("expected AcceptMessage to reject when not paired")
	}
}

func TestSettingsRoundTrip(t *testing.T) {
	h := newTestHandler(t)
	ctx := context.Background()

	got, err := h.SettingsGet(ctx)
	if err != nil {
		t.Fatalf("SettingsGet: %v", err)
	}
	if got.MaxMessages != 100 || got.Port != 47820 {
		t.Fatalf("expected documented defaults, got %+v", got)
	}

	updated, err := h.SettingsSet(ctx, ipc.Settings{
		MaxMessages:           5, // below the 10 minimum, should be clamped
		ClipboardClearSeconds: 60,
		Port:                  47821,
		NotificationsEnabled:  true,
	})
	if err != nil {
		t.Fatalf("SettingsSet: %v", err)
	}
	if updated.MaxMessages != 10 {
		t.Fatalf("expected MaxMessages clamped to 10, got %d", updated.MaxMessages)
	}

	again, err := h.SettingsGet(ctx)
	if err != nil {
		t.Fatalf("SettingsGet after set: %v", err)
	}
	if again != updated {
		t.Fatalf("SettingsGet after SettingsSet = %+v, want %+v", again, updated)
	}
}

func TestMessagesFlow(t *testing.T) {
	dir := t.TempDir()
	store := messages.NewStore()
	h, err := New(dir, store)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()

	store.Append(messages.Message{ID: "a", Sender: "1234", Body: "hi"}, 0)

	list, err := h.MessagesList(ctx, ipc.MessagesListParams{Offset: 0, Limit: 10})
	if err != nil {
		t.Fatalf("MessagesList: %v", err)
	}
	if list.Total != 1 || len(list.Messages) != 1 || list.Messages[0].ID != "a" {
		t.Fatalf("unexpected list: %+v", list)
	}

	got, err := h.MessagesGet(ctx, ipc.MessagesGetParams{ID: "a"})
	if err != nil || got.Body != "hi" {
		t.Fatalf("MessagesGet: %+v, %v", got, err)
	}

	if err := h.HistoryClear(ctx); err != nil {
		t.Fatalf("HistoryClear: %v", err)
	}
	list, _ = h.MessagesList(ctx, ipc.MessagesListParams{Offset: 0, Limit: 10})
	if list.Total != 0 {
		t.Fatalf("expected empty history after clear, got %d", list.Total)
	}
}
