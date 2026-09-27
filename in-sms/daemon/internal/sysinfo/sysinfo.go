// Package sysinfo provides the two bits of machine-local information the
// protocol needs but the Go standard library doesn't hand over directly: the
// Mac's human-readable computer name (for the QR code's `name` field and the
// mDNS service name) and its LAN-facing IPv4 addresses (for the QR code's
// `hosts` field and for binding the HTTP listener to LAN interfaces only,
// per ARCHITECTURE.md §3.5).
package sysinfo

import (
	"net"
	"os"
	"os/exec"
	"strings"
)

// ComputerName returns the Mac's user-facing computer name (e.g. "Sam's
// MacBook Pro"), via `scutil --get ComputerName`. Falls back to
// os.Hostname() (e.g. "Sams-MacBook-Pro.local") if that fails, and finally
// to a fixed placeholder if even that is unavailable.
func ComputerName() string {
	if out, err := exec.Command("scutil", "--get", "ComputerName").Output(); err == nil {
		if name := strings.TrimSpace(string(out)); name != "" {
			return name
		}
	}
	if host, err := os.Hostname(); err == nil && host != "" {
		return host
	}
	return "Mac"
}

// LANAddresses returns the dotted-quad IPv4 addresses of every up,
// non-loopback interface — i.e. real LAN interfaces, per PROTOCOL.md §3.2's
// IPv4-only assumption. IPv6 addresses are skipped entirely.
func LANAddresses() ([]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var out []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue // best-effort: skip interfaces we can't query
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipNet.IP.To4()
			if ip4 == nil || ip4.IsLoopback() || ip4.IsLinkLocalUnicast() || ip4.IsUnspecified() {
				continue
			}
			out = append(out, ip4.String())
		}
	}
	return out, nil
}
