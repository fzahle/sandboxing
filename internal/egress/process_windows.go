//go:build windows

package egress

import (
	"errors"
	"syscall"
)

// The egress proxy only backs the Lima provider's network confinement,
// which is macOS-only; these stubs just keep the package building on
// Windows.

var errUnsupported = errors.New("the agentctl egress proxy is not supported on Windows")

func lockPIDFile(string) (func(), error)     { return nil, errUnsupported }
func lockStatus(string) (bool, int, error)   { return false, 0, nil }
func terminate(int, bool) error              { return errUnsupported }
func processGone(error) bool                 { return false }
func detachedProcAttr() *syscall.SysProcAttr { return nil }
