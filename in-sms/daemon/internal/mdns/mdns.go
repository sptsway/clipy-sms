// Package mdns advertises the daemon's _otpfwd._tcp service by shelling out
// to macOS's built-in dns-sd tool (ARCHITECTURE.md §3.2) — no third-party
// mDNS library and no hand-rolled DNS wire code.
package mdns

import (
	"os/exec"
	"strconv"
	"time"
)

const (
	serviceType = "_otpfwd._tcp"
	domain      = "local"
	restartWait = time.Second
)

// newCmd builds the command to run; overridable in tests so they don't
// depend on the real dns-sd binary being present or on actually registering
// a service.
var newCmd = func(name string, port int) *exec.Cmd {
	return exec.Command("dns-sd", "-R", name, serviceType, domain, strconv.Itoa(port))
}

// Advertiser supervises a `dns-sd -R` subprocess for as long as the daemon
// is advertising its service, restarting it if it exits unexpectedly.
type Advertiser struct {
	stop chan struct{}
	done chan struct{}
}

// Start begins advertising name on the given port and returns immediately;
// the subprocess is supervised in the background until Stop is called.
func Start(name string, port int) *Advertiser {
	a := &Advertiser{
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}
	go a.run(name, port)
	return a
}

func (a *Advertiser) run(name string, port int) {
	defer close(a.done)
	for {
		select {
		case <-a.stop:
			return
		default:
		}

		cmd := newCmd(name, port)
		if err := cmd.Start(); err == nil {
			waitErr := make(chan error, 1)
			go func() { waitErr <- cmd.Wait() }()

			select {
			case <-a.stop:
				_ = cmd.Process.Kill()
				<-waitErr
				return
			case <-waitErr:
				// dns-sd exited on its own (e.g. network change); fall
				// through and restart after a short backoff.
			}
		}

		select {
		case <-a.stop:
			return
		case <-time.After(restartWait):
		}
	}
}

// Stop terminates the supervised dns-sd subprocess (if running) and waits
// for the supervisor goroutine to exit.
func (a *Advertiser) Stop() {
	close(a.stop)
	<-a.done
}
