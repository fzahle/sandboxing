// Package egress implements agentctl's host-side egress filtering proxy:
// a small HTTP forward proxy, run as a background process per sandbox,
// that only connects that sandbox to the destinations its network policy
// allows.
//
// It exists for backends whose platform has no native per-instance egress
// ACL (Incus has one; Lima doesn't). There, agentctl confines the
// backend's own processes so the sandbox's only route off the host is
// this proxy, and the proxy applies the same default-deny allowlist and
// deny-LAN semantics the Incus ACL does — see Policy, and
// internal/provider/lima/network.go for how the Lima backend wires it up.
//
// The proxy process is agentctl itself, re-executed with the hidden
// CommandName subcommand (internal/cli/egress_proxy.go), so there is no
// extra binary to install. CommandArgs is the single source of truth for
// that command line: the code that spawns the proxy and the code that
// previews it (--preview) both build it here.
package egress

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// CommandName is the hidden agentctl subcommand that runs a proxy in the
// foreground (internal/cli registers it; providers spawn it).
const CommandName = "egress-proxy"

// Flag names of CommandName, shared by the CLI definition and CommandArgs.
const (
	FlagListen  = "listen"
	FlagPolicy  = "policy"
	FlagPIDFile = "pid-file"
)

// ServeOptions configures one proxy process.
type ServeOptions struct {
	// Listen is the address to accept proxy connections on. It must be a
	// loopback address (e.g. 127.0.0.1:51234): the proxy is only ever
	// meant to be reached from the host itself.
	Listen string
	// PolicyPath is the policy file to enforce (see WritePolicy). It's
	// re-read whenever it changes; while it's missing, all egress is
	// denied.
	PolicyPath string
	// PIDFile is held under an exclusive lock for the proxy's whole
	// lifetime and contains its PID. The lock — not the file's mere
	// existence — is what Running and Stop go by, so a PID left behind by
	// a crashed proxy is never mistaken for a live one.
	PIDFile string
	// Log receives one line per policy decision plus lifecycle events.
	Log io.Writer
}

// CommandArgs returns the argument list (after the agentctl binary) that
// runs a proxy with opts.
func CommandArgs(opts ServeOptions) []string {
	return []string{
		CommandName,
		"--" + FlagListen, opts.Listen,
		"--" + FlagPolicy, opts.PolicyPath,
		"--" + FlagPIDFile, opts.PIDFile,
	}
}

// ErrAlreadyRunning is returned by Serve when another proxy already holds
// opts.PIDFile.
var ErrAlreadyRunning = errors.New("an egress proxy is already running for this pid file")

func requireLoopback(listen string) error {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Errorf("invalid listen address %q: %w", listen, err)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("refusing to listen on %q: the egress proxy only listens on a loopback IP address", listen)
	}
	return nil
}

// Serve runs a proxy until ctx is canceled. It returns ErrAlreadyRunning
// if another proxy holds opts.PIDFile.
func Serve(ctx context.Context, opts ServeOptions) error {
	if err := requireLoopback(opts.Listen); err != nil {
		return err
	}
	release, err := lockPIDFile(opts.PIDFile)
	if err != nil {
		return err
	}
	defer release()

	ln, err := net.Listen("tcp", opts.Listen)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", opts.Listen, err)
	}
	px := &Proxy{PolicyPath: opts.PolicyPath, Log: opts.Log}
	px.logf("egress proxy listening on %s, enforcing %s", ln.Addr(), opts.PolicyPath)
	px.currentPolicy() // load (and log) the policy up front

	srv := &http.Server{
		Handler:           px,
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       5 * time.Minute,
	}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ln) }()
	select {
	case <-ctx.Done():
		px.logf("egress proxy shutting down")
		srv.Close() // established CONNECT tunnels end when the process exits
		<-errCh
		return nil
	case err := <-errCh:
		return fmt.Errorf("egress proxy stopped unexpectedly: %w", err)
	}
}
