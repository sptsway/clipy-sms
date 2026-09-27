package main

import (
	"net/http/httptest"
	"path/filepath"
	"testing"

	"otpforwarder/internal/daemon"
	"otpforwarder/internal/ipc"
	"otpforwarder/internal/messages"
	"otpforwarder/internal/server"
)

func startTestDaemon(t *testing.T) (*httptest.Server, *daemon.Handler) {
	t.Helper()
	dir := t.TempDir()
	h, err := daemon.New(dir, messages.NewStore())
	if err != nil {
		t.Fatalf("daemon.New: %v", err)
	}
	srv := server.New(h)
	ts := httptest.NewServer(srv.Mux())
	t.Cleanup(ts.Close)
	return ts, h
}

// pairingURIFor starts a pairing window on h and rewrites the URI's host to
// point at the httptest server's actual address (a real otpd would put its
// LAN IP there; httptest listens on 127.0.0.1 with a random port).
func pairingURIFor(t *testing.T, ts *httptest.Server, h *daemon.Handler) string {
	t.Helper()
	start, err := h.PairStart(t.Context())
	if err != nil {
		t.Fatalf("PairStart: %v", err)
	}
	hp, err := parseTestServerURL(ts.URL)
	if err != nil {
		t.Fatalf("parsing httptest URL: %v", err)
	}
	rewritten, err := rewriteHostsAndPort(start.URI, hp.host, hp.port)
	if err != nil {
		t.Fatalf("rewriteHostsAndPort: %v", err)
	}
	return rewritten
}

func TestFakephonePairAndSend(t *testing.T) {
	ts, h := startTestDaemon(t)
	uri := pairingURIFor(t, ts, h)

	statePath := filepath.Join(t.TempDir(), "state.json")
	if err := doPair(uri, "Fakephone Test", statePath); err != nil {
		t.Fatalf("doPair: %v", err)
	}

	if err := doSend(sendOpts{sender: "1234", body: "Your OTP is 999999"}, statePath); err != nil {
		t.Fatalf("doSend: %v", err)
	}

	list, err := h.MessagesList(t.Context(), ipc.MessagesListParams{Offset: 0, Limit: 10})
	if err != nil {
		t.Fatalf("MessagesList: %v", err)
	}
	if list.Total != 1 || list.Messages[0].Body != "Your OTP is 999999" {
		t.Fatalf("unexpected stored message: %+v", list)
	}
}

func TestFakephoneNegativeCases(t *testing.T) {
	ts, h := startTestDaemon(t)
	uri := pairingURIFor(t, ts, h)
	statePath := filepath.Join(t.TempDir(), "state.json")
	if err := doPair(uri, "Fakephone Test", statePath); err != nil {
		t.Fatalf("doPair: %v", err)
	}

	// Each of these is expected to print a rejection and return nil (not a
	// Go error) — doSend only errors on things that would indicate a real
	// bug (e.g. a 200 whose ack fails to decrypt).
	cases := []sendOpts{
		{sender: "1234", body: "a", tamper: true},
		{sender: "1234", body: "a", tsOffset: -300},
	}
	for i, opts := range cases {
		if err := doSend(opts, statePath); err != nil {
			t.Fatalf("case %d: doSend returned an error (expected a clean rejection): %v", i, err)
		}
	}

	// Replay: send a real id twice.
	if err := doSend(sendOpts{sender: "1234", body: "a", idOverride: "dup"}, statePath); err != nil {
		t.Fatalf("first send: %v", err)
	}
	if err := doSend(sendOpts{sender: "1234", body: "a", idOverride: "dup"}, statePath); err != nil {
		t.Fatalf("replay send: %v", err)
	}

	list, err := h.MessagesList(t.Context(), ipc.MessagesListParams{Offset: 0, Limit: 10})
	if err != nil {
		t.Fatalf("MessagesList: %v", err)
	}
	if list.Total != 1 {
		t.Fatalf("expected only the one legitimately-accepted message to be stored, got %d", list.Total)
	}
}
