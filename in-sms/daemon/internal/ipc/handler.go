package ipc

import "context"

// Handler is everything the IPC server needs from the rest of the daemon.
// The transport (server.go) knows nothing about pairing or crypto; it just
// decodes a method name + params and calls the matching Handler method.
//
// The pairing methods (PairStart/PairStatus/PairCancel/DeviceStatus/
// DeviceUnpair) are expected to be backed by the pairing/crypto
// implementation once it exists — see docs/CRYPTO_IMPLEMENTATION.md. Until
// then, a stub implementation can return a "not implemented" error for those
// and still serve Settings/Messages/History correctly.
type Handler interface {
	PairStart(ctx context.Context) (PairStartResult, error)
	PairStatus(ctx context.Context) (PairStatusResult, error)
	PairCancel(ctx context.Context) error

	DeviceStatus(ctx context.Context) (DeviceStatusResult, error)
	DeviceUnpair(ctx context.Context) error

	MessagesList(ctx context.Context, p MessagesListParams) (MessagesListResult, error)
	MessagesGet(ctx context.Context, p MessagesGetParams) (Message, error)
	HistoryClear(ctx context.Context) error

	SettingsGet(ctx context.Context) (Settings, error)
	SettingsSet(ctx context.Context, s Settings) (Settings, error)
}
