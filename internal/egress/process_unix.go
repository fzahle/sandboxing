//go:build !windows

package egress

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// lockPIDFile takes the exclusive flock that marks a live proxy, then
// records this process's PID in the same file. The lock lives exactly as
// long as the process (the kernel drops it on exit, however that happens),
// which is what makes it a trustworthy liveness signal.
func lockPIDFile(path string) (release func(), err error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("creating egress proxy state directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrAlreadyRunning
		}
		return nil, fmt.Errorf("locking %s: %w", path, err)
	}
	if err := f.Truncate(0); err != nil {
		f.Close()
		return nil, fmt.Errorf("writing %s: %w", path, err)
	}
	if _, err := f.WriteAt([]byte(strconv.Itoa(os.Getpid())+"\n"), 0); err != nil {
		f.Close()
		return nil, fmt.Errorf("writing %s: %w", path, err)
	}
	return func() {
		_ = f.Truncate(0)
		f.Close()
	}, nil
}

// lockStatus reports whether some process holds path's lock and, if so,
// the PID it recorded. A file that exists but isn't locked (left behind by
// a proxy that died) reads as not running, whatever PID it contains.
func lockStatus(path string) (running bool, pid int, err error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, 0, nil
	}
	if err != nil {
		return false, 0, err
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		return false, 0, nil
	} else if !errors.Is(err, syscall.EWOULDBLOCK) {
		return false, 0, fmt.Errorf("checking %s: %w", path, err)
	}
	// Held. The holder writes its PID right after locking, so retry
	// briefly in case this caught it in between.
	for i := 0; i < 20; i++ {
		data, _ := os.ReadFile(path)
		if pid, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && pid > 0 {
			return true, pid, nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return true, 0, nil
}

func terminate(pid int, kill bool) error {
	sig := syscall.SIGTERM
	if kill {
		sig = syscall.SIGKILL
	}
	return syscall.Kill(pid, sig)
}

func processGone(err error) bool { return errors.Is(err, syscall.ESRCH) }

// detachedProcAttr puts the proxy in its own session, so it isn't tied to
// (or signaled along with) the terminal that ran agentctl.
func detachedProcAttr() *syscall.SysProcAttr { return &syscall.SysProcAttr{Setsid: true} }
