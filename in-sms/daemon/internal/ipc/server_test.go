package ipc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fakeHandler is a minimal, in-test ipc.Handler used to exercise the
// transport (request/response correlation, unknown methods, broadcast)
// independently of any real daemon logic.
type fakeHandler struct {
	settings Settings
}

func (h *fakeHandler) PairStart(ctx context.Context) (PairStartResult, error) {
	return PairStartResult{URI: "otpfwd://pair?v=1", ExpiresAt: 123}, nil
}
func (h *fakeHandler) PairStatus(ctx context.Context) (PairStatusResult, error) {
	return PairStatusResult{State: PairingWaiting, AttemptsLeft: 5}, nil
}
func (h *fakeHandler) PairCancel(ctx context.Context) error { return nil }
func (h *fakeHandler) DeviceStatus(ctx context.Context) (DeviceStatusResult, error) {
	return DeviceStatusResult{Paired: false}, nil
}
func (h *fakeHandler) DeviceUnpair(ctx context.Context) error { return nil }
func (h *fakeHandler) MessagesList(ctx context.Context, p MessagesListParams) (MessagesListResult, error) {
	return MessagesListResult{Messages: []Message{{ID: "m1"}}, Total: 1}, nil
}
func (h *fakeHandler) MessagesGet(ctx context.Context, p MessagesGetParams) (Message, error) {
	if p.ID != "m1" {
		return Message{}, errors.New("not found")
	}
	return Message{ID: "m1", Body: "hello"}, nil
}
func (h *fakeHandler) HistoryClear(ctx context.Context) error { return nil }
func (h *fakeHandler) SettingsGet(ctx context.Context) (Settings, error) {
	return h.settings, nil
}
func (h *fakeHandler) SettingsSet(ctx context.Context, s Settings) (Settings, error) {
	h.settings = s
	return s, nil
}

// testClient is a tiny newline-delimited-JSON client, standing in for the
// SwiftUI app's IPC client, used only to exercise the server from the wire.
type testClient struct {
	nc     net.Conn
	reader *bufio.Reader
}

func dial(t *testing.T, path string) *testClient {
	t.Helper()
	nc, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	return &testClient{nc: nc, reader: bufio.NewReader(nc)}
}

func (c *testClient) call(t *testing.T, id, method string, params interface{}) response {
	t.Helper()
	var raw json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			t.Fatalf("marshal params: %v", err)
		}
		raw = b
	}
	req := request{ID: id, Method: method, Params: raw}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	if _, err := c.nc.Write(append(data, '\n')); err != nil {
		t.Fatalf("write: %v", err)
	}
	c.nc.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := c.reader.ReadBytes('\n')
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var resp response
	if err := json.Unmarshal(line, &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	return resp
}

func startTestServer(t *testing.T) (*Server, string) {
	t.Helper()
	// Deliberately not t.TempDir(): that nests under a long $TMPDIR path plus
	// the test name plus a random suffix, which routinely blows past AF_UNIX's
	// ~104-byte sun_path limit on macOS. /tmp is short and always available.
	dir, err := os.MkdirTemp("/tmp", "otpd-ipc-test-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sockPath := filepath.Join(dir, "otpd.sock")

	l, err := Listen(sockPath)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	s := NewServer(&fakeHandler{})
	go s.Serve(l)
	t.Cleanup(func() { l.Close() })
	return s, sockPath
}

func TestRequestResponseRoundTrip(t *testing.T) {
	_, sockPath := startTestServer(t)
	c := dial(t, sockPath)

	resp := c.call(t, "1", MethodMessagesList, MessagesListParams{Offset: 0, Limit: 10})
	if resp.ID != "1" || resp.Error != "" {
		t.Fatalf("unexpected response: %+v", resp)
	}

	var result MessagesListResult
	remarshal(t, resp.Result, &result)
	if result.Total != 1 || len(result.Messages) != 1 || result.Messages[0].ID != "m1" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestSettingsRoundTrip(t *testing.T) {
	_, sockPath := startTestServer(t)
	c := dial(t, sockPath)

	in := Settings{MaxMessages: 200, Port: 47821, NotificationsEnabled: true}
	setResp := c.call(t, "a", MethodSettingsSet, in)
	if setResp.Error != "" {
		t.Fatalf("settings.set error: %s", setResp.Error)
	}

	getResp := c.call(t, "b", MethodSettingsGet, nil)
	var got Settings
	remarshal(t, getResp.Result, &got)
	if got != in {
		t.Fatalf("settings.get = %+v, want %+v", got, in)
	}
}

func TestUnknownMethod(t *testing.T) {
	_, sockPath := startTestServer(t)
	c := dial(t, sockPath)

	resp := c.call(t, "x", "not.a.method", nil)
	if resp.Error == "" {
		t.Fatal("expected an error for an unknown method")
	}
}

func TestMalformedJSONDoesNotCrashServer(t *testing.T) {
	_, sockPath := startTestServer(t)
	nc, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if _, err := nc.Write([]byte("{not json\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	nc.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := bufio.NewReader(nc).ReadBytes('\n')
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var resp response
	if err := json.Unmarshal(line, &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.Error == "" {
		t.Fatal("expected an error response for malformed JSON")
	}

	// The server (and its listener/other connections) must still work.
	c2 := dial(t, sockPath)
	resp2 := c2.call(t, "ok", MethodDeviceStatus, nil)
	if resp2.Error != "" {
		t.Fatalf("server appears broken after malformed input: %+v", resp2)
	}
}

func TestBroadcastReachesAllConnections(t *testing.T) {
	s, sockPath := startTestServer(t)
	c1 := dial(t, sockPath)
	c2 := dial(t, sockPath)

	// Give both connections a moment to register with the server.
	time.Sleep(50 * time.Millisecond)

	s.Broadcast(EventMessageNew, Message{ID: "new1", Body: "hi"})

	for i, c := range []*testClient{c1, c2} {
		c.nc.SetReadDeadline(time.Now().Add(5 * time.Second))
		line, err := c.reader.ReadBytes('\n')
		if err != nil {
			t.Fatalf("conn %d: read event: %v", i, err)
		}
		var env eventEnvelope
		if err := json.Unmarshal(line, &env); err != nil {
			t.Fatalf("conn %d: unmarshal event: %v", i, err)
		}
		if env.Type != "event" || env.Event != EventMessageNew {
			t.Fatalf("conn %d: unexpected event envelope: %+v", i, env)
		}
	}
}

func remarshal(t *testing.T, from interface{}, to interface{}) {
	t.Helper()
	data, err := json.Marshal(from)
	if err != nil {
		t.Fatalf("remarshal: %v", err)
	}
	if err := json.Unmarshal(data, to); err != nil {
		t.Fatalf("remarshal unmarshal: %v", err)
	}
}
