// Package daemon wires the process-level pieces (config, in-memory message
// history) into an ipc.Handler that the Unix socket server can dispatch to.
//
// The pairing-related methods are stubs on purpose: this package has no
// dependency on crypto/pairing at all. Once that implementation exists
// (docs/CRYPTO_IMPLEMENTATION.md), swap Handler's PairStart/PairStatus/
// PairCancel/DeviceStatus/DeviceUnpair bodies (and the /v1/pair, /v1/msg
// HTTP handlers + mDNS advertiser from ARCHITECTURE.md §3.2/§3.5, which
// don't exist here yet either) for the real thing — the IPC schema and
// Settings/Messages/History behavior don't need to change at all.
package daemon

import (
	"context"
	"errors"
	"sync"
	"time"

	"otpforwarder/internal/config"
	"otpforwarder/internal/ipc"
	"otpforwarder/internal/messages"
)

var errNotImplemented = errors.New("pairing is not implemented yet")

// Handler implements ipc.Handler.
type Handler struct {
	dir  string
	msgs *messages.Store

	mu  sync.Mutex
	cfg config.Config
}

// New loads (or creates, with defaults) config.json from dir and returns a
// Handler backed by msgs for message history.
func New(dir string, msgs *messages.Store) (*Handler, error) {
	cfg, err := config.Load(dir)
	if err != nil {
		return nil, err
	}
	return &Handler{dir: dir, msgs: msgs, cfg: cfg}, nil
}

var _ ipc.Handler = (*Handler)(nil)

func (h *Handler) PairStart(ctx context.Context) (ipc.PairStartResult, error) {
	return ipc.PairStartResult{}, errNotImplemented
}

func (h *Handler) PairStatus(ctx context.Context) (ipc.PairStatusResult, error) {
	return ipc.PairStatusResult{State: ipc.PairingIdle}, nil
}

func (h *Handler) PairCancel(ctx context.Context) error {
	return errNotImplemented
}

func (h *Handler) DeviceStatus(ctx context.Context) (ipc.DeviceStatusResult, error) {
	return ipc.DeviceStatusResult{Paired: false}, nil
}

func (h *Handler) DeviceUnpair(ctx context.Context) error {
	return errNotImplemented
}

func (h *Handler) MessagesList(ctx context.Context, p ipc.MessagesListParams) (ipc.MessagesListResult, error) {
	items, total := h.msgs.List(p.Offset, p.Limit)
	out := make([]ipc.Message, len(items))
	for i, m := range items {
		out[i] = toIPCMessage(m)
	}
	return ipc.MessagesListResult{Messages: out, Total: total}, nil
}

func (h *Handler) MessagesGet(ctx context.Context, p ipc.MessagesGetParams) (ipc.Message, error) {
	m, ok := h.msgs.Get(p.ID)
	if !ok {
		return ipc.Message{}, errors.New("message not found")
	}
	return toIPCMessage(m), nil
}

func (h *Handler) HistoryClear(ctx context.Context) error {
	h.msgs.Clear()
	return nil
}

func (h *Handler) SettingsGet(ctx context.Context) (ipc.Settings, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return toIPCSettings(h.cfg), nil
}

func (h *Handler) SettingsSet(ctx context.Context, s ipc.Settings) (ipc.Settings, error) {
	cfg := fromIPCSettings(s)
	cfg.Clamp()
	if err := config.Save(h.dir, cfg); err != nil {
		return ipc.Settings{}, err
	}

	h.mu.Lock()
	h.cfg = cfg
	h.mu.Unlock()

	return toIPCSettings(cfg), nil
}

// CurrentConfig returns the daemon's current settings, e.g. for the HTTP
// server (default port) or message store (max messages) to consult at
// startup and after every settings.set.
func (h *Handler) CurrentConfig() config.Config {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.cfg
}

func toIPCMessage(m messages.Message) ipc.Message {
	return ipc.Message{
		ID:         m.ID,
		ReceivedAt: m.ReceivedAt.Format(time.RFC3339),
		Sender:     m.Sender,
		Body:       m.Body,
		Code:       m.Code,
		Sim:        m.Sim,
	}
}

func toIPCSettings(c config.Config) ipc.Settings {
	return ipc.Settings{
		MaxMessages:           c.MaxMessages,
		AutoCopyNewest:        c.AutoCopyNewest,
		ClipboardClearSeconds: c.ClipboardClearSeconds,
		Port:                  c.Port,
		LaunchAtLogin:         c.LaunchAtLogin,
		NotificationsEnabled:  c.NotificationsEnabled,
	}
}

func fromIPCSettings(s ipc.Settings) config.Config {
	return config.Config{
		MaxMessages:           s.MaxMessages,
		AutoCopyNewest:        s.AutoCopyNewest,
		ClipboardClearSeconds: s.ClipboardClearSeconds,
		Port:                  s.Port,
		LaunchAtLogin:         s.LaunchAtLogin,
		NotificationsEnabled:  s.NotificationsEnabled,
	}
}
