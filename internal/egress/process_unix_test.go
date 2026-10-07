//go:build !windows

package egress

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// TestHelperProcess isn't a real test: Spawn re-executes the test binary
// with -test.run pointed here (and EGRESS_HELPER=1) to get a separate
// process running Serve, the same role `agentctl egress-proxy` plays in
// production.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("EGRESS_HELPER") != "1" {
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	err := Serve(ctx, ServeOptions{
		Listen:     os.Getenv("EGRESS_HELPER_LISTEN"),
		PolicyPath: os.Getenv("EGRESS_HELPER_POLICY"),
		PIDFile:    os.Getenv("EGRESS_HELPER_PIDFILE"),
		Log:        os.Stderr,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "helper:", err)
		os.Exit(1)
	}
	os.Exit(0)
}

type helperPaths struct {
	listen, policy, pidFile, log string
}

func spawnHelper(t *testing.T, dir string, pidFile string) (helperPaths, error) {
	t.Helper()
	hp := helperPaths{
		listen:  freeLoopbackAddr(t),
		policy:  filepath.Join(dir, "egress-policy.json"),
		pidFile: pidFile,
		log:     filepath.Join(dir, "egress-proxy.log"),
	}
	t.Setenv("EGRESS_HELPER", "1")
	t.Setenv("EGRESS_HELPER_LISTEN", hp.listen)
	t.Setenv("EGRESS_HELPER_POLICY", hp.policy)
	t.Setenv("EGRESS_HELPER_PIDFILE", hp.pidFile)
	err := Spawn(os.Args[0], []string{"-test.run=^TestHelperProcess$"}, hp.log, hp.listen, hp.pidFile)
	return hp, err
}

func TestSpawnRunningStop(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "egress-proxy.pid")
	hp, err := spawnHelper(t, dir, pidFile)
	if err != nil {
		t.Fatalf("Spawn: %v", err)
	}
	t.Cleanup(func() { _ = Stop(context.Background(), pidFile) })

	if running, err := Running(pidFile); err != nil || !running {
		t.Fatalf("Running() = %v, %v after Spawn; want true", running, err)
	}

	// A second proxy for the same pid file must refuse to start rather
	// than run alongside the first.
	if _, err := spawnHelper(t, dir, pidFile); err == nil || !strings.Contains(err.Error(), "already running") {
		t.Errorf("second Spawn error = %v, want it to report the proxy is already running", err)
	}

	if err := Stop(context.Background(), pidFile); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if running, _ := Running(pidFile); running {
		t.Error("Running() = true after Stop")
	}
	if err := Stop(context.Background(), pidFile); err != nil {
		t.Errorf("Stop on an already-stopped proxy = %v, want nil", err)
	}
	if !strings.Contains(logTail(hp.log), "egress proxy listening on") {
		t.Errorf("proxy log %q missing the startup line", logTail(hp.log))
	}
}

// TestStalePIDFile_IsNeverSignaled is the reason liveness goes by the
// lock rather than the PID file's contents: a PID left behind by a proxy
// that died may since have been reused by an unrelated process, which
// Stop must never kill. Here the "stale" PID is this test process itself.
func TestStalePIDFile_IsNeverSignaled(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "egress-proxy.pid")
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if running, err := Running(pidFile); err != nil || running {
		t.Fatalf("Running() = %v, %v for an unlocked pid file; want false", running, err)
	}
	if err := Stop(context.Background(), pidFile); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	// Still alive to assert this: Stop didn't signal us.
}

func TestRunning_MissingPIDFile(t *testing.T) {
	if running, err := Running(filepath.Join(t.TempDir(), "nope.pid")); err != nil || running {
		t.Errorf("Running(missing) = %v, %v; want false, nil", running, err)
	}
}

func TestSpawn_ReportsEarlyExitWithLogTail(t *testing.T) {
	dir := t.TempDir()
	err := Spawn("/bin/sh", []string{"-c", "echo proxy-boom >&2; exit 3"},
		filepath.Join(dir, "egress-proxy.log"), freeLoopbackAddr(t), filepath.Join(dir, "egress-proxy.pid"))
	if err == nil || !strings.Contains(err.Error(), "proxy-boom") {
		t.Errorf("Spawn error = %v, want it to include the log tail", err)
	}
}
