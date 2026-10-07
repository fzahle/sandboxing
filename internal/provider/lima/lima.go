// Package lima implements agentctl's macOS backend by shelling out to the
// `limactl` CLI — architecturally parallel to internal/provider/incus:
// Lima directly manages one VM per sandbox via `limactl`, the same way
// Incus manages one instance per sandbox via `incus`. See translate.go's
// package NOTE for the biggest unverified assumption (the `--set`
// mechanism `Create` relies on).
package lima

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/apomonosi/sandboxing/internal/egress"
	"github.com/apomonosi/sandboxing/internal/provider"
)

const binary = "limactl"

// readyTimeout and readyPollInterval bound how long Exec/Shell wait for
// the guest to become reachable before giving up. Package-level vars (not
// consts) so tests can shrink them instead of waiting out a real 30s
// timeout — same pattern as incus.go's agentReadyTimeout/agentPollInterval.
var (
	readyTimeout      = 30 * time.Second
	readyPollInterval = time.Second
)

type Provider struct {
	runner       provider.Runner
	capabilities provider.Table

	// confine is whether this provider enforces network policy by
	// confining Lima's processes (network.go). That needs macOS's
	// sandbox-exec, so it's on exactly when running on macOS; elsewhere
	// Start is a plain `limactl start` and the capability table reports
	// network policy as unavailable.
	confine bool
	// Seams for network.go's host-side machinery, defaulting to the real
	// thing; tests substitute fakes.
	proxy           egressProxy
	agentctlPath    func() (string, error)
	portFree        func(port int) bool
	autostartPlists func(name string) []string
}

// New builds the Lima provider using the real ExecRunner. It does not
// fail if the `limactl` binary is missing — that surfaces naturally as a
// command-not-found error the first time a method actually runs one,
// keeping New cheap enough to call during provider registration.
func New() (provider.Provider, error) {
	return NewWithRunner(provider.ExecRunner{}), nil
}

// NewWithRunner builds the Lima provider with an injected Runner, for
// tests that want to fake `limactl` invocations without a real install.
func NewWithRunner(r provider.Runner) provider.Provider {
	return newProvider(r, runtime.GOOS == "darwin")
}

func newProvider(r provider.Runner, confine bool) *Provider {
	return &Provider{
		runner:          r,
		capabilities:    buildCapabilities(confine),
		confine:         confine,
		proxy:           processEgressProxy{},
		agentctlPath:    os.Executable,
		portFree:        loopbackPortFree,
		autostartPlists: autostartPlists,
	}
}

func (p *Provider) Name() string { return "lima" }

func (p *Provider) Capabilities() provider.Table { return p.capabilities }

func (p *Provider) run(ctx context.Context, args ...string) ([]byte, []byte, error) {
	stdout, stderr, err := p.runner.Run(ctx, binary, args...)
	if err != nil {
		return stdout, stderr, fmt.Errorf("limactl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(stderr)))
	}
	return stdout, stderr, nil
}

// Create runs `limactl create` and returns the resulting instance's
// status. Unlike Incus, this never starts the instance: the non-root
// default user comes from Lima's own cloud-init `user:` handling at first
// boot, not from a bootstrap step Create() has to run against a running
// guest — so there's no start/exec/stop dance needed here, and `create`
// keeps its documented "does not start it" contract for free.
//
// On macOS it also records the instance's network policy, which its
// egress proxy enforces from the first start on (see network.go) — the
// same point at which Incus's Create applies its ACL.
func (p *Provider) Create(ctx context.Context, spec provider.InstanceSpec) (*provider.Instance, error) {
	if _, _, err := p.run(ctx, buildCreateArgs(spec)...); err != nil {
		return nil, err
	}
	if p.confine {
		if err := p.ApplyNetworkPolicy(ctx, spec.Name, spec.Overrides); err != nil {
			return nil, fmt.Errorf("applying network policy: %w", err)
		}
	}
	return p.Status(ctx, spec.Name)
}

// Start boots the instance. On macOS that means booting it confined, with
// its egress limited to what its network policy allows (startConfined in
// network.go); elsewhere it's a plain `limactl start`.
func (p *Provider) Start(ctx context.Context, name string) error {
	if p.confine {
		return p.startConfined(ctx, name)
	}
	_, _, err := p.run(ctx, buildStartArgs(name)...)
	return err
}

// Stop stops the instance, then (on macOS) its egress proxy.
func (p *Provider) Stop(ctx context.Context, name string, opts provider.StopOptions) error {
	if _, _, err := p.run(ctx, buildStopArgs(name, opts)...); err != nil {
		return err
	}
	if p.confine {
		return p.stopEgress(ctx, name)
	}
	return nil
}

// Delete removes the instance and best-effort prunes its entry from the
// local state file, so a reused instance name doesn't inherit a stale
// PendingAgentInstall marker or pinned ports. On macOS it also stops the
// instance's egress proxy and removes its policy and log.
func (p *Provider) Delete(ctx context.Context, name string, force bool) error {
	if _, _, err := p.run(ctx, buildDeleteArgs(name, force)...); err != nil {
		return err
	}
	var proxyErr error
	if p.confine {
		if paths, err := egressPathsFor(name); err == nil {
			if proxyErr = p.proxy.Stop(ctx, paths); proxyErr == nil {
				_ = os.RemoveAll(paths.Dir)
			}
		}
	}
	pruneInstanceState(name)
	if proxyErr != nil {
		return fmt.Errorf("instance %q deleted, but stopping its egress proxy failed: %w", name, proxyErr)
	}
	return nil
}

func (p *Provider) List(ctx context.Context) ([]provider.Instance, error) {
	stdout, _, err := p.run(ctx, buildListArgs()...)
	if err != nil {
		return nil, err
	}
	raw, err := parseLimaList(stdout)
	if err != nil {
		return nil, err
	}
	out := make([]provider.Instance, len(raw))
	for i, j := range raw {
		out[i] = toInstance(j)
	}
	return out, nil
}

func (p *Provider) Status(ctx context.Context, name string) (*provider.Instance, error) {
	j, err := p.inspect(ctx, name)
	if err != nil {
		return nil, err
	}
	inst := toInstance(j)
	return &inst, nil
}

// inspect returns name's entry from `limactl list <name> --json`, matched
// by name rather than taken on faith from the first line, since
// network.go makes security decisions from it.
func (p *Provider) inspect(ctx context.Context, name string) (limaInstanceJSON, error) {
	stdout, _, err := p.run(ctx, buildListOneArgs(name)...)
	if err != nil {
		return limaInstanceJSON{}, err
	}
	raw, err := parseLimaList(stdout)
	if err != nil {
		return limaInstanceJSON{}, err
	}
	for _, j := range raw {
		if j.Name == name {
			return j, nil
		}
	}
	return limaInstanceJSON{}, provider.ErrNotFound
}

func (p *Provider) Exec(ctx context.Context, name string, opts provider.ExecOptions) (int, error) {
	if err := p.waitForReady(ctx, name, opts.Stderr); err != nil {
		return -1, err
	}
	return p.runner.RunStream(ctx, binary, buildExecArgs(name, opts.Command, opts.Root), opts.Stdin, opts.Stdout, opts.Stderr)
}

func (p *Provider) Shell(ctx context.Context, name string, opts provider.ShellOptions) error {
	if err := p.waitForReady(ctx, name, opts.Stderr); err != nil {
		return err
	}
	_, err := p.runner.RunStream(ctx, binary, buildShellArgs(name, opts.Root), opts.Stdin, opts.Stdout, opts.Stderr)
	return err
}

// waitForReady blocks until a harmless probe command (`limactl shell
// <name> -- true`) succeeds, or readyTimeout elapses.
//
// Deliberate, documented deviation from incus.go's waitForAgent: since
// the real "not ready yet" error text `limactl shell` prints against a
// not-yet-booted guest hasn't been observed against a live install (unlike
// Incus's agentNotRunningMsg, which was empirically discovered in
// practice), this retries on *any* non-nil probe error rather than a
// substring match. That trades away "fail fast on a genuinely unrelated
// error" for robustness against not knowing the real string — a
// follow-up should reintroduce substring-based fast-fail once the real
// text is confirmed live (see translate.go's package NOTE and
// integration_test.go). notify, if non-nil, gets a one-line heads-up the
// first time the guest isn't ready yet, so a multi-second wait doesn't
// look like agentctl hanging.
func (p *Provider) waitForReady(ctx context.Context, name string, notify io.Writer) error {
	deadline := time.Now().Add(readyTimeout)
	notified := false
	var lastErr error
	for {
		_, _, err := p.run(ctx, buildExecArgs(name, []string{"true"}, false)...)
		if err == nil {
			return nil
		}
		lastErr = err
		if !notified && notify != nil {
			fmt.Fprintf(notify, "agentctl: waiting for the Lima guest %q to become reachable...\n", name)
			notified = true
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("Lima guest %q did not become reachable within %s: %w", name, readyTimeout, lastErr)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(readyPollInterval):
		}
	}
}

func (p *Provider) SnapshotCreate(ctx context.Context, name, snapshotName string) error {
	return p.err(provider.FeatureSnapshotCreate)
}

func (p *Provider) SnapshotList(ctx context.Context, name string) ([]provider.Snapshot, error) {
	return nil, p.err(provider.FeatureSnapshotList)
}

func (p *Provider) SnapshotRestore(ctx context.Context, name, snapshotName string) error {
	return p.err(provider.FeatureSnapshotRestore)
}

func (p *Provider) SnapshotDelete(ctx context.Context, name, snapshotName string) error {
	return p.err(provider.FeatureSnapshotDelete)
}

func (p *Provider) View(ctx context.Context, name string, opts provider.ViewOptions) error {
	return p.err(provider.FeatureView)
}

// ApplyNetworkPolicy records policy as the instance's egress policy (on
// macOS; see network.go). The instance's egress proxy enforces it from its
// next new connection on — there are no backend commands to run, and the
// policy file is re-read whenever it changes.
func (p *Provider) ApplyNetworkPolicy(ctx context.Context, name string, policy provider.NetworkPolicy) error {
	if !p.confine {
		return p.err(provider.FeatureNetworkACL)
	}
	paths, err := egressPathsFor(name)
	if err != nil {
		return err
	}
	return egress.WritePolicy(paths.Policy, toEgressPolicy(policy))
}

func (p *Provider) ImagePull(ctx context.Context, ref string) error {
	return p.err(provider.FeatureImagePull)
}

func (p *Provider) ImageBuild(ctx context.Context, spec provider.ImageBuildSpec) (string, error) {
	return "", p.err(provider.FeatureImageBuild)
}

func (p *Provider) Logs(ctx context.Context, name string, opts provider.LogOptions) (io.ReadCloser, error) {
	return nil, p.err(provider.FeatureLogsNetwork)
}

func (p *Provider) SetAgentRequested(ctx context.Context, name, agentName string) error {
	return setAgentRequested(name, agentName)
}

func (p *Provider) MarkAgentInstalled(ctx context.Context, name string) error {
	return markAgentInstalled(name)
}

func (p *Provider) PendingAgentInstall(ctx context.Context, name string) (string, error) {
	return pendingAgentInstall(name)
}

func (p *Provider) err(f provider.Feature) error {
	return provider.StatusError(p.capabilities.Get(f))
}
