// Package daemon is the single mutex-guarded state struct ARCHITECTURE.md
// §3.3 describes: pairing window, pinned phone key material, message
// counter, and dedupe cache, shared between the IPC layer (ipc.Handler,
// this file) and the HTTP layer (internal/server, which calls
// VerifyPairingAttempt and AcceptMessage directly).
package daemon

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"otpforwarder/internal/config"
	otpcrypto "otpforwarder/internal/crypto"
	"otpforwarder/internal/identity"
	"otpforwarder/internal/ipc"
	"otpforwarder/internal/messages"
	"otpforwarder/internal/pairing"
	"otpforwarder/internal/sysinfo"
)

// errRejected is returned for every /v1/msg validation failure. The HTTP
// layer maps ALL errors from AcceptMessage to the same generic 400
// regardless of which one this is (PROTOCOL.md §4.6) — it exists as a single
// sentinel purely so validation-failure branches read clearly here.
var errRejected = errors.New("daemon: message rejected")

// dedupeTTL is how long an accepted message id is remembered for replay
// detection: 2x the ±120s timestamp tolerance, since anything older than
// that is already rejected by the timestamp check regardless of the dedupe
// cache (PROTOCOL.md §4.5).
const dedupeTTL = 240 * time.Second

// Broadcaster pushes an IPC event to every connected UI (implemented by
// *ipc.Server). A Handler with no broadcaster set silently drops events,
// which is fine for tests that don't care about them.
type Broadcaster interface {
	Broadcast(event string, data interface{})
}

type noopBroadcaster struct{}

func (noopBroadcaster) Broadcast(string, interface{}) {}

// Handler implements ipc.Handler and additionally exposes
// VerifyPairingAttempt and AcceptMessage for internal/server's HTTP handlers
// to call — all of it behind the one mutex below.
type Handler struct {
	dir     string
	msgs    *messages.Store
	macName string

	mu           sync.Mutex
	cfg          config.Config
	id           *identity.Identity
	session      *pairing.Session
	pairStatus   ipc.PairStatusResult
	dedupe       map[string]time.Time
	lastSeenUnix int64 // 0 means never
	broadcaster  Broadcaster
}

// New loads (or creates, with defaults) config.json and identity.json from
// dir, and returns a Handler backed by msgs for message history.
func New(dir string, msgs *messages.Store) (*Handler, error) {
	cfg, err := config.Load(dir)
	if err != nil {
		return nil, err
	}
	id, err := identity.LoadOrCreate(dir)
	if err != nil {
		return nil, err
	}
	return &Handler{
		dir:         dir,
		msgs:        msgs,
		macName:     sysinfo.ComputerName(),
		cfg:         cfg,
		id:          id,
		pairStatus:  ipc.PairStatusResult{State: ipc.PairingIdle},
		dedupe:      make(map[string]time.Time),
		broadcaster: noopBroadcaster{},
	}, nil
}

var _ ipc.Handler = (*Handler)(nil)

// SetBroadcaster wires up event delivery, e.g. to the real *ipc.Server once
// it's constructed (see cmd/otpd/main.go).
func (h *Handler) SetBroadcaster(b Broadcaster) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.broadcaster = b
}

// CurrentConfig returns the daemon's current settings, e.g. for the HTTP
// server (default port) to consult at startup and after every settings.set.
func (h *Handler) CurrentConfig() config.Config {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.cfg
}

// --- Pairing (ipc.Handler methods) ---

func (h *Handler) PairStart(ctx context.Context) (ipc.PairStartResult, error) {
	now := time.Now()

	h.mu.Lock()
	session, err := pairing.Start(now)
	if err != nil {
		h.mu.Unlock()
		return ipc.PairStartResult{}, err
	}
	h.session = session
	status := ipc.PairStatusResult{
		State:        ipc.PairingWaiting,
		AttemptsLeft: session.AttemptsLeft,
		ExpiresAt:    session.ExpiresAt.Unix(),
	}
	h.pairStatus = status
	port := h.cfg.Port
	name := h.macName
	broadcaster := h.broadcaster
	h.mu.Unlock()

	broadcaster.Broadcast(ipc.EventPairingStatus, status)

	hosts, _ := sysinfo.LANAddresses() // best-effort; an empty list still yields a (unusable) URI rather than failing pairing outright
	uri := buildPairingURI(session, hosts, port, name)

	time.AfterFunc(pairing.Window+time.Second, func() { h.expireSessionIfCurrent(session) })

	return ipc.PairStartResult{URI: uri, ExpiresAt: session.ExpiresAt.Unix()}, nil
}

func (h *Handler) expireSessionIfCurrent(s *pairing.Session) {
	h.mu.Lock()
	if h.session != s || s.Closed {
		h.mu.Unlock()
		return
	}
	s.Closed = true
	h.pairStatus = ipc.PairStatusResult{State: ipc.PairingFailed}
	status := h.pairStatus
	broadcaster := h.broadcaster
	h.mu.Unlock()

	broadcaster.Broadcast(ipc.EventPairingStatus, status)
}

func (h *Handler) PairStatus(ctx context.Context) (ipc.PairStatusResult, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.pairStatus, nil
}

func (h *Handler) PairCancel(ctx context.Context) error {
	h.mu.Lock()
	if h.session != nil {
		h.session.Closed = true
	}
	h.pairStatus = ipc.PairStatusResult{State: ipc.PairingIdle}
	status := h.pairStatus
	broadcaster := h.broadcaster
	h.mu.Unlock()

	broadcaster.Broadcast(ipc.EventPairingStatus, status)
	return nil
}

func (h *Handler) DeviceStatus(ctx context.Context) (ipc.DeviceStatusResult, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.id.Pairing == nil {
		return ipc.DeviceStatusResult{Paired: false}, nil
	}
	var lastSeen *int64
	if h.lastSeenUnix != 0 {
		v := h.lastSeenUnix
		lastSeen = &v
	}
	return ipc.DeviceStatusResult{
		Paired:     true,
		DeviceName: h.id.Pairing.DeviceName,
		LastSeen:   lastSeen,
	}, nil
}

func (h *Handler) DeviceUnpair(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := identity.Unpair(h.dir, h.id); err != nil {
		return err
	}
	h.lastSeenUnix = 0
	h.pairStatus = ipc.PairStatusResult{State: ipc.PairingIdle}
	return nil
}

// VerifyPairingAttempt processes one POST /v1/pair attempt (PROTOCOL.md
// §3.4). On success it pins the phone's key, persists identity.json, and
// returns the confirm value to send back. Any returned error must be mapped
// to the same generic 400 by the caller (PROTOCOL.md §3.6).
func (h *Handler) VerifyPairingAttempt(phonePubBytes []byte, deviceName string, mac []byte) ([]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.session == nil {
		return nil, pairing.ErrNoWindow
	}

	result, err := h.session.Verify(time.Now(), phonePubBytes, deviceName, mac)
	if err != nil {
		if h.session.Closed {
			h.pairStatus = ipc.PairStatusResult{State: ipc.PairingFailed}
		} else {
			h.pairStatus = ipc.PairStatusResult{
				State:        ipc.PairingWaiting,
				AttemptsLeft: h.session.AttemptsLeft,
				ExpiresAt:    h.session.ExpiresAt.Unix(),
			}
		}
		h.broadcaster.Broadcast(ipc.EventPairingStatus, h.pairStatus)
		return nil, err
	}

	h.id.Pairing = &identity.Pairing{
		Version:    1,
		MacPriv:    h.session.MacPriv.Bytes(),
		PhonePub:   result.PhonePubBytes,
		DeviceName: result.DeviceName,
		KP2M:       result.Keys.KP2M[:],
		KM2P:       result.Keys.KM2P[:],
		KeyID:      result.Keys.KeyID[:],
		LastCtr:    -1,
	}
	if err := identity.Save(h.dir, h.id); err != nil {
		return nil, err
	}

	h.pairStatus = ipc.PairStatusResult{State: ipc.PairingPaired}
	h.broadcaster.Broadcast(ipc.EventPairingStatus, h.pairStatus)

	return result.Confirm, nil
}

// --- Messages / History / Settings (ipc.Handler methods, unchanged from before) ---

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
	h.mu.Lock()
	storageKey := h.id.StorageKey
	dir := h.dir
	h.mu.Unlock()
	return messages.SaveEncrypted(dir, storageKey, h.msgs)
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

// --- Message path (called by internal/server, not part of ipc.Handler) ---

// AcceptMessage validates and stores one /v1/msg envelope (PROTOCOL.md §4.4)
// and returns the binary ack envelope to send back. Every failure returns a
// single opaque error — the HTTP layer must map all of them to the same
// generic 400 (PROTOCOL.md §4.6) without inspecting which one occurred.
func (h *Handler) AcceptMessage(envelope []byte, now time.Time) ([]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.id.Pairing == nil {
		return nil, errRejected
	}
	p := h.id.Pairing

	var keyID [otpcrypto.KeyIDSize]byte
	copy(keyID[:], p.KeyID)

	plaintext, err := otpcrypto.OpenEnvelope(p.KP2M, keyID, envelope)
	if err != nil {
		return nil, errRejected
	}

	var msg struct {
		ID     string `json:"id"`
		Ts     int64  `json:"ts"`
		Ctr    uint64 `json:"ctr"`
		Sender string `json:"sender"`
		Body   string `json:"body"`
		Sim    int    `json:"sim,omitempty"`
	}
	if err := json.Unmarshal(plaintext, &msg); err != nil {
		return nil, errRejected
	}

	diff := now.UnixMilli() - msg.Ts
	if diff > 120_000 || diff < -120_000 {
		return nil, errRejected
	}
	if int64(msg.Ctr) <= p.LastCtr {
		return nil, errRejected
	}
	h.sweepDedupeLocked(now)
	if _, seen := h.dedupe[msg.ID]; seen {
		return nil, errRejected
	}

	p.LastCtr = int64(msg.Ctr)
	if err := identity.Save(h.dir, h.id); err != nil {
		return nil, err
	}
	h.dedupe[msg.ID] = now

	stored := messages.Message{
		ID:         msg.ID,
		ReceivedAt: now,
		Sender:     msg.Sender,
		Body:       msg.Body,
		Code:       messages.ExtractCode(msg.Body),
		Sim:        msg.Sim,
	}
	h.msgs.Append(stored, h.cfg.MaxMessages)
	if err := messages.SaveEncrypted(h.dir, h.id.StorageKey, h.msgs); err != nil {
		// The message is already accepted and in memory; a persistence
		// hiccup here shouldn't fail a request the phone already got a
		// correctly-derived ack for. It'll be picked up on next successful save.
		_ = err
	}

	nowUnix := now.Unix()
	h.lastSeenUnix = nowUnix
	deviceName := p.DeviceName

	ackPlaintext, err := json.Marshal(struct {
		ID  string `json:"id"`
		Ctr uint64 `json:"ctr"`
	}{ID: msg.ID, Ctr: msg.Ctr})
	if err != nil {
		return nil, err
	}
	ack, err := otpcrypto.SealEnvelope(p.KM2P, keyID, ackPlaintext)
	if err != nil {
		return nil, err
	}

	h.broadcaster.Broadcast(ipc.EventMessageNew, toIPCMessage(stored))
	h.broadcaster.Broadcast(ipc.EventDeviceLastSeen, ipc.DeviceLastSeenEvent{DeviceName: deviceName, LastSeen: nowUnix})

	return ack, nil
}

// KeyIDFor returns the current pairing's key_id, and whether one is paired
// at all — used by internal/server to fail fast before even attempting to
// decrypt a /v1/msg body against a nonexistent pairing.
func (h *Handler) KeyIDFor() (id [otpcrypto.KeyIDSize]byte, paired bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.id.Pairing == nil {
		return id, false
	}
	copy(id[:], h.id.Pairing.KeyID)
	return id, true
}

func (h *Handler) sweepDedupeLocked(now time.Time) {
	for id, t := range h.dedupe {
		if now.Sub(t) > dedupeTTL {
			delete(h.dedupe, id)
		}
	}
}

func buildPairingURI(session *pairing.Session, hosts []string, port int, name string) string {
	v := url.Values{}
	v.Set("v", "1")
	v.Set("mac_pub", base64.RawURLEncoding.EncodeToString(session.MacPubBytes))
	v.Set("token", base64.RawURLEncoding.EncodeToString(session.Token))
	v.Set("hosts", strings.Join(hosts, ","))
	v.Set("port", strconv.Itoa(port))
	v.Set("name", name)
	v.Set("exp", strconv.FormatInt(session.ExpiresAt.Unix(), 10))
	return "otpfwd://pair?" + v.Encode()
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
