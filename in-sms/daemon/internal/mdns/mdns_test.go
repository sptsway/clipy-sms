package mdns

import (
	"os/exec"
	"testing"
	"time"
)

func TestCommandArguments(t *testing.T) {
	cmd := newCmd("My Mac", 47820)
	want := []string{"dns-sd", "-R", "My Mac", "_otpfwd._tcp", "local", "47820"}
	if len(cmd.Args) != len(want) {
		t.Fatalf("Args = %v, want %v", cmd.Args, want)
	}
	for i := range want {
		if cmd.Args[i] != want[i] {
			t.Fatalf("Args[%d] = %q, want %q", i, cmd.Args[i], want[i])
		}
	}
}

func TestStartStopDoesNotHang(t *testing.T) {
	orig := newCmd
	defer func() { newCmd = orig }()
	newCmd = func(name string, port int) *exec.Cmd {
		return exec.Command("sleep", "30")
	}

	a := Start("Test Mac", 47820)
	time.Sleep(50 * time.Millisecond)

	done := make(chan struct{})
	go func() {
		a.Stop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop() did not return promptly; supervised process was not killed")
	}
}

func TestRestartsOnExit(t *testing.T) {
	orig := newCmd
	defer func() { newCmd = orig }()

	var mu = make(chan int, 1)
	mu <- 0
	newCmd = func(name string, port int) *exec.Cmd {
		n := <-mu
		mu <- n + 1
		return exec.Command("true")
	}

	a := Start("Test Mac", 47820)
	defer a.Stop()

	deadline := time.After(3 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatal("expected the supervisor to have restarted the command more than once")
		default:
		}
		n := <-mu
		mu <- n
		if n >= 2 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}
