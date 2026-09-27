package main

import (
	"fmt"
	"net/url"
)

type hostPort struct {
	host string
	port string
}

// parseTestServerURL extracts the host and port httptest.Server is actually
// listening on (e.g. "127.0.0.1" and "54321" from "http://127.0.0.1:54321").
func parseTestServerURL(rawURL string) (hostPort, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return hostPort{}, err
	}
	host := u.Hostname()
	port := u.Port()
	if host == "" || port == "" {
		return hostPort{}, fmt.Errorf("could not extract host/port from %q", rawURL)
	}
	return hostPort{host: host, port: port}, nil
}

// rewriteHostsAndPort replaces a pairing URI's hosts/port query params —
// PairStart's real LAN-address discovery doesn't know about httptest's
// loopback listener, so tests point the URI at it manually here, the same
// way a real phone would just use whatever hosts/port the QR code said.
func rewriteHostsAndPort(uri, host, port string) (string, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("hosts", host)
	q.Set("port", port)
	u.RawQuery = q.Encode()
	return u.String(), nil
}
