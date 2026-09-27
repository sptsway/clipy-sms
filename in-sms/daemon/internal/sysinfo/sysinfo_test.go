package sysinfo

import (
	"net"
	"strings"
	"testing"
)

func TestComputerNameIsNonEmpty(t *testing.T) {
	name := ComputerName()
	if strings.TrimSpace(name) == "" {
		t.Fatal("expected a non-empty computer name")
	}
}

func TestLANAddressesAreValidNonLoopbackIPv4(t *testing.T) {
	addrs, err := LANAddresses()
	if err != nil {
		t.Fatalf("LANAddresses: %v", err)
	}
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip == nil {
			t.Fatalf("returned %q, which is not a valid IP", a)
		}
		if ip.To4() == nil {
			t.Fatalf("returned %q, which is not IPv4", a)
		}
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			t.Fatalf("returned %q, which should have been filtered out", a)
		}
	}
	// Not asserting len(addrs) > 0: a CI sandbox may have no active LAN
	// interface at all, which is a valid (if inconvenient) machine state.
}
