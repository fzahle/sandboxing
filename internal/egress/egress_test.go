package egress

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func writeRaw(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}

// freeLoopbackAddr returns a 127.0.0.1 address with a port that was free a
// moment ago.
func freeLoopbackAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

func TestCommandArgs(t *testing.T) {
	got := CommandArgs(ServeOptions{Listen: "127.0.0.1:5000", PolicyPath: "/p.json", PIDFile: "/x.pid"})
	want := []string{"egress-proxy", "--listen", "127.0.0.1:5000", "--policy", "/p.json", "--pid-file", "/x.pid"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("CommandArgs() = %v, want %v", got, want)
	}
}

// TestServe_RefusesNonLoopback: the proxy must never be reachable from the
// LAN — it would hand anyone there the sandbox's allowlist.
func TestServe_RefusesNonLoopback(t *testing.T) {
	for _, listen := range []string{"0.0.0.0:0", ":0", "192.168.1.10:8080", "localhost:8080", "[::]:0"} {
		err := Serve(context.Background(), ServeOptions{Listen: listen, PIDFile: filepath.Join(t.TempDir(), "p.pid")})
		if err == nil || !strings.Contains(err.Error(), "loopback") {
			t.Errorf("Serve(listen=%q) error = %v, want a loopback-only refusal", listen, err)
		}
	}
}

func TestServe_LocksPIDFileForItsLifetime(t *testing.T) {
	dir := t.TempDir()
	opts := ServeOptions{
		Listen:     freeLoopbackAddr(t),
		PolicyPath: filepath.Join(dir, "egress-policy.json"),
		PIDFile:    filepath.Join(dir, "egress-proxy.pid"),
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, opts) }()

	waitFor(t, func() bool {
		c, err := net.Dial("tcp", opts.Listen)
		if err == nil {
			c.Close()
		}
		return err == nil
	})
	if running, err := Running(opts.PIDFile); err != nil || !running {
		t.Fatalf("Running() = %v, %v while Serve is up; want true", running, err)
	}
	data, _ := os.ReadFile(opts.PIDFile)
	if strings.TrimSpace(string(data)) != strconv.Itoa(os.Getpid()) {
		t.Errorf("pid file = %q, want this process's PID %d", data, os.Getpid())
	}

	second := opts
	second.Listen = freeLoopbackAddr(t)
	if err := Serve(context.Background(), second); !errors.Is(err, ErrAlreadyRunning) {
		t.Errorf("a second Serve on the same pid file = %v, want ErrAlreadyRunning", err)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve returned %v after cancel, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after its context was canceled")
	}
	if running, _ := Running(opts.PIDFile); running {
		t.Error("Running() = true after Serve returned")
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met within 5s")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
