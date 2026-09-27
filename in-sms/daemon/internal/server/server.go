// Package server implements the LAN-facing HTTP endpoints from
// PROTOCOL.md §3-§4: POST /v1/pair and POST /v1/msg. It is thin plumbing —
// all crypto/pairing/validation logic lives in internal/daemon.Handler; this
// package only handles HTTP framing (body size limits, base64url JSON for
// /v1/pair, the binary envelope for /v1/msg, rate limiting, and the
// generic-400-on-any-failure posture PROTOCOL.md §3.6/§4.6 require).
package server

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"otpforwarder/internal/daemon"
	"otpforwarder/internal/ratelimit"
	"otpforwarder/internal/sysinfo"
)

// MaxBodyBytes is the request body size cap for both endpoints (PROTOCOL.md §4.1).
const MaxBodyBytes = 8192

// Server holds the HTTP handlers for /v1/pair and /v1/msg.
type Server struct {
	handler *daemon.Handler
	limiter *ratelimit.Limiter
}

// New creates a Server with the documented rate-limit defaults: a 20-token
// bucket refilling at 10 tokens/sec per source IP (PROTOCOL.md §4.7).
func New(handler *daemon.Handler) *Server {
	return NewWithLimiter(handler, ratelimit.New(20, 10, 5*time.Minute))
}

// NewWithLimiter is New with an injectable limiter, mainly so tests can use
// a small capacity to exercise rate limiting deterministically.
func NewWithLimiter(handler *daemon.Handler, limiter *ratelimit.Limiter) *Server {
	return &Server{handler: handler, limiter: limiter}
}

// Mux returns the HTTP handler serving /v1/pair and /v1/msg.
func (s *Server) Mux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/pair", s.handlePair)
	mux.HandleFunc("/v1/msg", s.handleMsg)
	return mux
}

// pairRequest/pairResponse mirror PROTOCOL.md §3.3/§3.4's JSON bodies, with
// base64url-without-padding fields decoded/encoded explicitly (Go's default
// []byte JSON encoding is standard base64, which is not what the wire
// protocol specifies).
type pairRequest struct {
	V          int    `json:"v"`
	PhonePub   string `json:"phone_pub"`
	DeviceName string `json:"device_name"`
	Mac        string `json:"mac"`
}

type pairResponse struct {
	OK      bool   `json:"ok"`
	Confirm string `json:"confirm"`
}

func (s *Server) handlePair(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	body, ok := readLimitedBody(w, r)
	if !ok {
		return
	}

	var req pairRequest
	if err := json.Unmarshal(body, &req); err != nil {
		genericBadRequest(w)
		return
	}
	phonePub, err1 := base64.RawURLEncoding.DecodeString(req.PhonePub)
	mac, err2 := base64.RawURLEncoding.DecodeString(req.Mac)
	if err1 != nil || err2 != nil {
		genericBadRequest(w)
		return
	}

	confirm, err := s.handler.VerifyPairingAttempt(phonePub, req.DeviceName, mac)
	if err != nil {
		genericBadRequest(w) // PROTOCOL.md §3.6: never reveal why pairing failed
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(pairResponse{
		OK:      true,
		Confirm: base64.RawURLEncoding.EncodeToString(confirm),
	})
}

func (s *Server) handleMsg(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if !s.limiter.Allow(sourceIP(r), time.Now()) {
		genericBadRequest(w) // PROTOCOL.md §4.6: rate-limited looks like any other rejection
		return
	}

	body, ok := readLimitedBody(w, r)
	if !ok {
		return
	}

	ack, err := s.handler.AcceptMessage(body, time.Now())
	if err != nil {
		genericBadRequest(w)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(ack)
}

// readLimitedBody enforces MaxBodyBytes (PROTOCOL.md §4.1) before returning
// the body; on any read error (including "body too large") it writes the
// generic 400 itself and returns ok=false.
func readLimitedBody(w http.ResponseWriter, r *http.Request) (body []byte, ok bool) {
	r.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		genericBadRequest(w)
		return nil, false
	}
	return body, true
}

func genericBadRequest(w http.ResponseWriter) {
	w.WriteHeader(http.StatusBadRequest)
}

func sourceIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// Listeners opens one TCP listener per LAN-facing IPv4 address on port,
// never binding 0.0.0.0 or loopback (ARCHITECTURE.md §3.5).
func Listeners(port int) ([]net.Listener, error) {
	hosts, err := sysinfo.LANAddresses()
	if err != nil {
		return nil, err
	}

	listeners := make([]net.Listener, 0, len(hosts))
	for _, host := range hosts {
		l, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
		if err != nil {
			for _, opened := range listeners {
				opened.Close()
			}
			return nil, err
		}
		listeners = append(listeners, l)
	}
	return listeners, nil
}

// Serve runs handler on every listener concurrently and returns a stop
// function that closes them all and waits for their goroutines to exit.
func Serve(handler http.Handler, listeners []net.Listener) (stop func()) {
	var wg sync.WaitGroup
	for _, l := range listeners {
		wg.Add(1)
		go func(l net.Listener) {
			defer wg.Done()
			_ = http.Serve(l, handler)
		}(l)
	}
	return func() {
		for _, l := range listeners {
			l.Close()
		}
		wg.Wait()
	}
}
