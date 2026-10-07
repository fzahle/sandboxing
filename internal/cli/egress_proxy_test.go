package cli

import (
	"bytes"
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/apomonosi/sandboxing/internal/egress"
	"github.com/apomonosi/sandboxing/internal/provider"
	"github.com/apomonosi/sandboxing/internal/provider/fake"
)

func TestEgressProxyCmd_HiddenFromHelp(t *testing.T) {
	useIsolatedConfig(t)
	out, err := execute(t, fake.New(), "--help")
	if err != nil {
		t.Fatalf("--help: %v", err)
	}
	if strings.Contains(out, egress.CommandName) {
		t.Errorf("help output lists the internal %q command:\n%s", egress.CommandName, out)
	}
}

// TestEgressProxyCmd_ServesUntilCanceled runs the hidden command exactly
// as the Lima backend spawns it (same argument builder) and checks it
// comes up holding its pid file and exits cleanly when told to stop.
func TestEgressProxyCmd_ServesUntilCanceled(t *testing.T) {
	useIsolatedConfig(t)
	dir := t.TempDir()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listen := ln.Addr().String()
	ln.Close()
	opts := egress.ServeOptions{
		Listen:     listen,
		PolicyPath: filepath.Join(dir, "egress-policy.json"),
		PIDFile:    filepath.Join(dir, "egress-proxy.pid"),
	}

	reg := provider.NewRegistry()
	root := NewRootCmd(reg)
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(egress.CommandArgs(opts))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- root.ExecuteContext(ctx) }()

	deadline := time.Now().Add(5 * time.Second)
	for {
		if running, _ := egress.Running(opts.PIDFile); running {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("egress-proxy never came up; output:\n%s", out.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("egress-proxy returned %v after cancel, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("egress-proxy did not exit after its context was canceled")
	}
}

func TestEgressProxyCmd_RefusesNonLoopbackListen(t *testing.T) {
	useIsolatedConfig(t)
	dir := t.TempDir()
	reg := provider.NewRegistry()
	root := NewRootCmd(reg)
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(egress.CommandArgs(egress.ServeOptions{
		Listen:     "0.0.0.0:0",
		PolicyPath: filepath.Join(dir, "p.json"),
		PIDFile:    filepath.Join(dir, "p.pid"),
	}))
	if err := root.Execute(); err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Errorf("egress-proxy --listen 0.0.0.0:0 error = %v, want a loopback-only refusal", err)
	}
}
