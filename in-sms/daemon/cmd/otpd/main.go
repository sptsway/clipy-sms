// Command otpd is the OTP Forwarder background daemon: it owns pairing,
// message decryption/storage, and networking (ARCHITECTURE.md "who does
// what"). It runs three things concurrently:
//   - the Unix socket IPC server the SwiftUI menu bar app talks to
//   - the LAN-only HTTP server serving POST /v1/pair and POST /v1/msg
//   - an mDNS advertiser for _otpfwd._tcp
//
// Known limitation: changing the port via settings.set takes effect for the
// QR code's `port` field immediately, but the HTTP listener itself is only
// (re)bound at startup — changing the port currently requires restarting
// otpd. Not fixed here; dynamic rebinding would be a reasonable follow-up.
package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"otpforwarder/internal/config"
	"otpforwarder/internal/daemon"
	"otpforwarder/internal/identity"
	"otpforwarder/internal/ipc"
	"otpforwarder/internal/mdns"
	"otpforwarder/internal/messages"
	"otpforwarder/internal/server"
	"otpforwarder/internal/sysinfo"
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

	// Loaded once here just to get the storage key for the message store;
	// daemon.New below loads it again for its own use. Both reads see the
	// same file — the second is a cheap, harmless re-read, not a race.
	id, err := identity.LoadOrCreate(dir)
	if err != nil {
		return err
	}
	msgStore, err := messages.LoadOrCreate(dir, id.StorageKey)
	if err != nil {
		return err
	}

	handler, err := daemon.New(dir, msgStore)
	if err != nil {
		return err
	}
	cfg := handler.CurrentConfig()

	socketPath := dir + "/otpd.sock"
	ipcListener, err := ipc.Listen(socketPath)
	if err != nil {
		return err
	}
	defer os.Remove(socketPath)
	log.Printf("otpd: IPC socket listening at %s", socketPath)

	ipcServer := ipc.NewServer(handler)
	handler.SetBroadcaster(ipcServer)

	ipcServeErr := make(chan error, 1)
	go func() { ipcServeErr <- ipcServer.Serve(ipcListener) }()

	httpListeners, err := server.Listeners(cfg.Port)
	if err != nil {
		return err
	}
	if len(httpListeners) == 0 {
		log.Printf("otpd: no LAN interfaces found; pairing and message forwarding are unavailable until one is")
	} else {
		for _, l := range httpListeners {
			log.Printf("otpd: HTTP listening at %s", l.Addr())
		}
	}
	httpServer := server.New(handler)
	stopHTTP := server.Serve(httpServer.Mux(), httpListeners)
	defer stopHTTP()

	macName := sysinfo.ComputerName()
	advertiser := mdns.Start(macName, cfg.Port)
	defer advertiser.Stop()
	log.Printf("otpd: advertising _otpfwd._tcp as %q on port %d", macName, cfg.Port)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-ipcServeErr:
		return err
	case s := <-sig:
		log.Printf("otpd: received %s, shutting down", s)
		return ipcListener.Close()
	}
}
