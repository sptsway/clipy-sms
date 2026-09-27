// Package ipc implements the UI <-> daemon Unix socket protocol from
// ARCHITECTURE.md §3.6/§4: newline-delimited JSON, request/response plus
// pushed events, over ~/Library/Application Support/OTPForwarder/otpd.sock.
//
// This package is transport + schema only. It knows nothing about crypto,
// pairing, or how messages get encrypted at rest — those live behind the
// Handler interface (handler.go) so the pairing/message-path implementation
// can be dropped in independently later.
package ipc

import "encoding/json"

// request is one line sent by the UI.
type request struct {
	ID     string          `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

// response is one line sent back for a given request ID. Exactly one of
// Result / Error is set.
type response struct {
	ID     string      `json:"id"`
	Result interface{} `json:"result,omitempty"`
	Error  string      `json:"error,omitempty"`
}

// eventEnvelope is one unsolicited line pushed by the daemon.
type eventEnvelope struct {
	Type  string      `json:"type"` // always "event"
	Event string      `json:"event"`
	Data  interface{} `json:"data,omitempty"`
}

// Method names (ARCHITECTURE.md §3.6).
const (
	MethodPairStart    = "pair.start"
	MethodPairStatus   = "pair.status"
	MethodPairCancel   = "pair.cancel"
	MethodDeviceStatus = "device.status"
	MethodDeviceUnpair = "device.unpair"
	MethodMessagesList = "messages.list"
	MethodMessagesGet  = "messages.get"
	MethodHistoryClear = "history.clear"
	MethodSettingsGet  = "settings.get"
	MethodSettingsSet  = "settings.set"
)

// Event names (ARCHITECTURE.md §3.6).
const (
	EventMessageNew     = "message.new"
	EventPairingStatus  = "pairing.status"
	EventDeviceLastSeen = "device.lastSeen"
)

// PairingState is the pairing window's externally-visible state.
type PairingState string

const (
	PairingIdle    PairingState = "idle"
	PairingWaiting PairingState = "waiting"
	PairingPaired  PairingState = "paired"
	PairingFailed  PairingState = "failed"
)

// PairStartResult is returned by pair.start.
type PairStartResult struct {
	URI       string `json:"uri"`
	ExpiresAt int64  `json:"expires_at"` // unix seconds
}

// PairStatusResult is returned by pair.status and pushed as pairing.status data.
type PairStatusResult struct {
	State        PairingState `json:"state"`
	AttemptsLeft int          `json:"attempts_left"`
	ExpiresAt    int64        `json:"expires_at,omitempty"`
}

// DeviceStatusResult is returned by device.status.
type DeviceStatusResult struct {
	Paired     bool   `json:"paired"`
	DeviceName string `json:"device_name,omitempty"`
	LastSeen   *int64 `json:"last_seen,omitempty"` // unix seconds
}

// DeviceLastSeenEvent is pushed as device.lastSeen data.
type DeviceLastSeenEvent struct {
	DeviceName string `json:"device_name"`
	LastSeen   int64  `json:"last_seen"`
}

// Message is one stored SMS record (ARCHITECTURE.md §3.4's message shape).
type Message struct {
	ID         string `json:"id"`
	ReceivedAt string `json:"received_at"` // RFC3339
	Sender     string `json:"sender"`
	Body       string `json:"body"`
	Code       string `json:"code"`
	Sim        int    `json:"sim,omitempty"`
}

// MessagesListParams paginates the "Older" chunked submenus.
type MessagesListParams struct {
	Offset int `json:"offset"`
	Limit  int `json:"limit"`
}

// MessagesListResult is returned by messages.list.
type MessagesListResult struct {
	Messages []Message `json:"messages"`
	Total    int       `json:"total"`
}

// MessagesGetParams identifies one message.
type MessagesGetParams struct {
	ID string `json:"id"`
}

// Settings mirrors the daemon's config.Config (ARCHITECTURE.md §3.4), exposed
// over IPC for the Settings window.
type Settings struct {
	MaxMessages           int  `json:"max_messages"`
	AutoCopyNewest        bool `json:"auto_copy_newest"`
	ClipboardClearSeconds int  `json:"clipboard_clear_seconds"`
	Port                  int  `json:"port"`
	LaunchAtLogin         bool `json:"launch_at_login"`
	NotificationsEnabled  bool `json:"notifications_enabled"`
}
