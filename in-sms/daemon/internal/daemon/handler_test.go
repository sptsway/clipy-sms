package daemon

import (
	"context"
	"testing"

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

func TestPairingMethodsAreStubs(t *testing.T) {
	h := newTestHandler(t)
	ctx := context.Background()

	if _, err := h.PairStart(ctx); err == nil {
		t.Error("expected PairStart to report not-implemented")
	}
	if err := h.PairCancel(ctx); err == nil {
		t.Error("expected PairCancel to report not-implemented")
	}
	if err := h.DeviceUnpair(ctx); err == nil {
		t.Error("expected DeviceUnpair to report not-implemented")
	}

	status, err := h.DeviceStatus(ctx)
	if err != nil || status.Paired {
		t.Errorf("expected an unpaired status with no error, got %+v, %v", status, err)
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

	store.Append(messages.Message{ID: "a", Sender: "1234", Body: "hi", Code: "1234"}, 0)

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
