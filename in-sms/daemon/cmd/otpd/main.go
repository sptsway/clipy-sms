// Command otpd is the OTP Forwarder background daemon. Today it starts the
// Unix socket IPC server that the SwiftUI menu bar app talks to (schema in
// internal/ipc), backed by settings + an in-memory message history
// (internal/daemon, internal/messages).
//
// Not implemented yet, on purpose (see docs/CRYPTO_IMPLEMENTATION.md):
//   - the /v1/pair and /v1/msg HTTP server (ARCHITECTURE.md §3.5)
//   - the mDNS advertiser (ARCHITECTURE.md §3.2)
//   - anything involving keys, pairing, or message decryption
//
// Wiring those in later means constructing them here in main() next to the
// IPC server, and calling ipcServer.Broadcast(ipc.EventMessageNew, ...) from
// the /v1/msg handler once a message is accepted.
package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"otpforwarder/internal/config"
	"otpforwarder/internal/daemon"
	"otpforwarder/internal/ipc"
	"otpforwarder/internal/messages"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("otpd: %v", err)
	}
}

func run() error {
	dir, err := config.DefaultDir()
	if err != nil {
		return err
	}
	log.Printf("otpd: using data directory %s", dir)

	msgStore := messages.NewStore()
	handler, err := daemon.New(dir, msgStore)
	if err != nil {
		return err
	}

	socketPath := dir + "/otpd.sock"
	listener, err := ipc.Listen(socketPath)
	if err != nil {
		return err
	}
	defer os.Remove(socketPath)
	log.Printf("otpd: IPC socket listening at %s", socketPath)

	server := ipc.NewServer(handler)

	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(listener) }()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-serveErr:
		return err
	case s := <-sig:
		log.Printf("otpd: received %s, shutting down", s)
		return listener.Close()
	}
}
