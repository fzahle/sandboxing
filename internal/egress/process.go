package egress

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Timings for process control. Package-level vars (not consts) so tests
// can shrink them — same pattern as the providers' readiness timeouts.
var (
	spawnTimeout = 10 * time.Second
	stopGrace    = 5 * time.Second
	killGrace    = 2 * time.Second
	pollInterval = 50 * time.Millisecond
)

// maxLogSize is how large a proxy log may grow before Spawn rotates it
// (keeping a single previous generation, <log>.1).
const maxLogSize = 10 << 20

// Running reports whether a live proxy holds pidFile.
func Running(pidFile string) (bool, error) {
	running, _, err := lockStatus(pidFile)
	return running, err
}

// Stop terminates the proxy holding pidFile, if there is one, and waits
// for it to exit: SIGTERM first, then SIGKILL if it hasn't exited within a
// few seconds. Stopping a proxy that isn't running is not an error.
func Stop(ctx context.Context, pidFile string) error {
	running, pid, err := lockStatus(pidFile)
	if err != nil || !running {
		return err
	}
	if pid <= 0 {
		return fmt.Errorf("the egress proxy holding %s did not record its PID", pidFile)
	}
	if err := terminate(pid, false); err != nil && !processGone(err) {
		return fmt.Errorf("stopping egress proxy (pid %d): %w", pid, err)
	}
	if waitStopped(ctx, pidFile, stopGrace) {
		return nil
	}
	if err := terminate(pid, true); err != nil && !processGone(err) {
		return fmt.Errorf("killing egress proxy (pid %d): %w", pid, err)
	}
	if waitStopped(ctx, pidFile, killGrace) {
		return nil
	}
	return fmt.Errorf("egress proxy (pid %d) did not exit", pid)
}

func waitStopped(ctx context.Context, pidFile string, within time.Duration) bool {
	deadline := time.Now().Add(within)
	for {
		if running, _ := Running(pidFile); !running {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(pollInterval):
		}
	}
}

// Spawn starts a proxy as a detached background process — binary run with
// args (normally agentctl itself with CommandArgs) in its own session, so
// it outlives the agentctl invocation that started it — appending its
// output to logPath. It returns once the proxy holds pidFile and accepts
// connections on listen, or with an error (including the log's tail) if it
// exits or doesn't come up in time.
func Spawn(binary string, args []string, logPath, listen, pidFile string) error {
	if err := os.MkdirAll(filepath.Dir(logPath), 0o700); err != nil {
		return fmt.Errorf("creating egress proxy log directory: %w", err)
	}
	rotateLog(logPath)
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("opening egress proxy log: %w", err)
	}
	cmd := exec.Command(binary, args...)
	cmd.Dir = "/" // don't keep whatever directory agentctl ran in busy
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = detachedProcAttr()
	err = cmd.Start()
	logFile.Close() // the child has its own copy
	if err != nil {
		return fmt.Errorf("starting egress proxy: %w", err)
	}

	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	deadline := time.Now().Add(spawnTimeout)
	for {
		select {
		case err := <-exited:
			return fmt.Errorf("egress proxy exited during startup (%v); log %s ends with:\n%s", err, logPath, logTail(logPath))
		default:
		}
		if conn, err := net.DialTimeout("tcp", listen, 250*time.Millisecond); err == nil {
			conn.Close()
			if running, _ := Running(pidFile); running {
				return nil
			}
		}
		if time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			return fmt.Errorf("egress proxy did not start listening on %s within %s; see %s", listen, spawnTimeout, logPath)
		}
		time.Sleep(pollInterval)
	}
}

func rotateLog(path string) {
	if fi, err := os.Stat(path); err == nil && fi.Size() > maxLogSize {
		_ = os.Rename(path, path+".1")
	}
}

// logTail returns the last few lines of the log at path, for error
// messages.
func logTail(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return "(log unavailable: " + err.Error() + ")"
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) > 10 {
		lines = lines[len(lines)-10:]
	}
	return strings.Join(lines, "\n")
}
