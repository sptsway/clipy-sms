package ipc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
)

// Listen opens the Unix domain socket at path, mode 0600 (ARCHITECTURE.md
// §3.6). Any stale socket file left behind by a previous unclean shutdown is
// removed first.
func Listen(path string) (net.Listener, error) {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("ipc: removing stale socket: %w", err)
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// Server dispatches incoming requests to a Handler and lets the rest of the
// daemon push events to every connected UI.
type Server struct {
	handler Handler

	mu    sync.Mutex
	conns map[*serverConn]struct{}
}

type serverConn struct {
	nc      net.Conn
	writeMu sync.Mutex
}

func (c *serverConn) writeLine(data []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if _, err := c.nc.Write(data); err != nil {
		return err
	}
	_, err := c.nc.Write([]byte("\n"))
	return err
}

// NewServer creates a Server backed by handler.
func NewServer(handler Handler) *Server {
	return &Server{
		handler: handler,
		conns:   make(map[*serverConn]struct{}),
	}
}

// Serve accepts connections from l until it is closed. Each connection is
// served on its own goroutine; Serve itself blocks until Accept fails
// (typically because l was closed for shutdown), at which point it returns
// nil.
func (s *Server) Serve(l net.Listener) error {
	for {
		nc, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		c := &serverConn{nc: nc}
		s.addConn(c)
		go s.handleConn(c)
	}
}

func (s *Server) addConn(c *serverConn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.conns[c] = struct{}{}
}

func (s *Server) removeConn(c *serverConn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.conns, c)
}

func (s *Server) handleConn(c *serverConn) {
	defer func() {
		s.removeConn(c)
		c.nc.Close()
	}()

	reader := bufio.NewReader(c.nc)
	for {
		line, err := reader.ReadBytes('\n')
		if len(bytes.TrimSpace(line)) > 0 {
			resp := s.dispatch(context.Background(), line)
			data, merr := json.Marshal(resp)
			if merr != nil {
				log.Printf("ipc: marshaling response: %v", merr)
			} else if werr := c.writeLine(data); werr != nil {
				return
			}
		}
		if err != nil {
			return // EOF or connection error: client disconnected
		}
	}
}

// dispatch parses one request line and calls the matching Handler method.
// It never panics or returns a distinguishable error type to the wire for
// malformed input — bad JSON and unknown methods both come back as a plain
// {"error": "..."} response with whatever request ID could be recovered.
func (s *Server) dispatch(ctx context.Context, line []byte) response {
	var req request
	if err := json.Unmarshal(line, &req); err != nil {
		return response{Error: "invalid request"}
	}

	result, err := s.call(ctx, req.Method, req.Params)
	if err != nil {
		return response{ID: req.ID, Error: err.Error()}
	}
	return response{ID: req.ID, Result: result}
}

func (s *Server) call(ctx context.Context, method string, params json.RawMessage) (interface{}, error) {
	switch method {
	case MethodPairStart:
		return s.handler.PairStart(ctx)
	case MethodPairStatus:
		return s.handler.PairStatus(ctx)
	case MethodPairCancel:
		return nil, s.handler.PairCancel(ctx)
	case MethodDeviceStatus:
		return s.handler.DeviceStatus(ctx)
	case MethodDeviceUnpair:
		return nil, s.handler.DeviceUnpair(ctx)
	case MethodMessagesList:
		var p MessagesListParams
		if err := unmarshalParams(params, &p); err != nil {
			return nil, err
		}
		return s.handler.MessagesList(ctx, p)
	case MethodMessagesGet:
		var p MessagesGetParams
		if err := unmarshalParams(params, &p); err != nil {
			return nil, err
		}
		return s.handler.MessagesGet(ctx, p)
	case MethodHistoryClear:
		return nil, s.handler.HistoryClear(ctx)
	case MethodSettingsGet:
		return s.handler.SettingsGet(ctx)
	case MethodSettingsSet:
		var p Settings
		if err := unmarshalParams(params, &p); err != nil {
			return nil, err
		}
		return s.handler.SettingsSet(ctx, p)
	default:
		return nil, fmt.Errorf("unknown method %q", method)
	}
}

func unmarshalParams(raw json.RawMessage, v interface{}) error {
	if len(raw) == 0 {
		return errors.New("missing params")
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return errors.New("invalid params")
	}
	return nil
}

// Broadcast pushes an event to every currently connected UI client
// (ARCHITECTURE.md §3.6). It is safe to call concurrently with Serve and
// with other Broadcast calls, and never blocks on a slow/stuck client
// beyond that client's own TCP-equivalent write buffering.
func (s *Server) Broadcast(event string, data interface{}) {
	env := eventEnvelope{Type: "event", Event: event, Data: data}
	out, err := json.Marshal(env)
	if err != nil {
		log.Printf("ipc: marshaling event %q: %v", event, err)
		return
	}

	s.mu.Lock()
	conns := make([]*serverConn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()

	for _, c := range conns {
		_ = c.writeLine(out) // best-effort; a dead conn is cleaned up by its own read loop
	}
}
