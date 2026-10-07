package lima

import (
	"fmt"

	"github.com/apomonosi/sandboxing/internal/provider"
)

// NOTE: the exact `limactl` CLI flag/subcommand names used below follow
// Lima's documented conventions but have not been exercised against a
// live `limactl` install in this development environment (none is
// installed here) — same caveat internal/provider/incus/translate.go
// carries for `incus` flags. Before relying on this in production, verify
// each command against `limactl <subcommand> --help` on a real install;
// the gated integration test (integration_test.go, //go:build integration)
// is where a mismatch should be caught.
//
// buildCreateArgs's `--set <yq-expression>` mechanism was the biggest
// unverified assumption here; it's since been checked against Lima v2.2's
// source, though still not a live install. `create` (like `edit` and
// `start`) registers --set as a repeatable flag, and every --set on one
// invocation applies: Lima joins them with " | " into one expression for
// its embedded yqlib (v4.53). Evaluating this file's expressions that same
// way — same yqlib version, with Lima's env/file-operator restrictions on —
// shows `.mounts += [...]` works even when the template has no `mounts:`
// key, and that `.env.<name> = ...` paths are unaffected by the disabled
// `env` operator. If --set somehow isn't accepted by `create`,
// buildEditArgs below is the ready fallback: `limactl create` bare, then
// one `limactl edit --set <expr> <name>` call per expression before the
// first `start` — same one-VM-per-sandbox architecture, only the
// invocation count changes.

// defaultUsername mirrors Incus's own default ("agent"), applied whenever
// InstanceSpec.DefaultUser is empty. Lima's own default templates already
// provision a non-root user (named after the host macOS username) with
// passwordless sudo, so forcing this isn't strictly required the way
// Incus's bootstrap script is — but leaving it to the template's own
// default would make the username vary per developer machine, breaking
// cross-provider consistency with docs like agent-provisioning.md
// ("--agent=claude creates and runs as a claude user" — true regardless
// of provider). Create() always sets .user.name explicitly.
const defaultUsername = "agent"

// buildCreateArgs returns the args for `limactl create`, translating spec
// into one --set expression per structured field via buildSetExpressions.
// spec.Image is a Lima template reference (its own doc comment in
// provider.go already anticipates this: "OCI/simplestreams ref, Lima
// template, or Hyper-V VHDX ref") and must be the final positional arg.
func buildCreateArgs(spec provider.InstanceSpec) []string {
	args := []string{"create", "--name=" + spec.Name, "--tty=false"}
	for _, expr := range buildSetExpressions(spec) {
		args = append(args, "--set", expr)
	}
	return append(args, spec.Image)
}

// buildEditArgs returns the args for one `limactl edit --set <expr> <name>`
// call — the fallback path if --set turns out not to be accepted directly
// on `create` (see the package NOTE above). Not used by the primary
// dispatch path yet, kept ready and tested so it doesn't bit-rot.
func buildEditArgs(name, expr string) []string {
	return []string{"edit", "--set", expr, name}
}

// buildSetExpressions returns one yq expression per structured
// InstanceSpec field, in a fixed order for deterministic output/testing:
// resources, forced user identity, mounts, port forwards.
//
// spec.Profiles is deliberately not translated to anything: by the time
// Provider.Create receives spec, internal/cli/create.go has already fully
// resolved profile effects into spec.Resources/spec.Mounts/spec.Overrides
// via spec.ResolvePolicy. Lima has no reusable named-profile object to
// attach post-hoc the way Incus's `-p` does, so there's nothing left to
// map spec.Profiles onto.
//
// spec.Overrides.DenyLAN/.Allow are likewise not translated here: Lima
// has no lima.yaml setting that could enforce them. On macOS, Create
// records them as the instance's egress policy and every start enforces
// it host-side, re-asserting the lima.yaml settings that depends on (see
// network.go's buildNetworkEditArgs) rather than baking them in once here.
func buildSetExpressions(spec provider.InstanceSpec) []string {
	var exprs []string

	if spec.Resources.CPUCores > 0 {
		exprs = append(exprs, fmt.Sprintf(".cpus = %d", spec.Resources.CPUCores))
	}
	if spec.Resources.Memory != "" {
		exprs = append(exprs, fmt.Sprintf(".memory = %q", spec.Resources.Memory))
	}
	if spec.Resources.DiskSize != "" {
		exprs = append(exprs, fmt.Sprintf(".disk = %q", spec.Resources.DiskSize))
	}

	username := spec.DefaultUser
	if username == "" {
		username = defaultUsername
	}
	exprs = append(exprs, fmt.Sprintf(".user.name = %q", username))
	// Forced unconditionally (not just when the template omits its own
	// default) so --root never hangs on an unexpected sudo password
	// prompt regardless of which template spec.Image points at.
	exprs = append(exprs, ".user.sudo = true")

	for _, m := range spec.Mounts {
		exprs = append(exprs, fmt.Sprintf(
			`.mounts += [{"location": %q, "mountPoint": %q, "writable": %t}]`,
			m.HostPath, m.GuestPath, !m.ReadOnly))
	}

	for _, pp := range spec.Overrides.Ports {
		proto := pp.Protocol
		if proto == "" {
			proto = "tcp"
		}
		exprs = append(exprs, fmt.Sprintf(
			`.portForwards += [{"guestPort": %d, "hostPort": %d, "proto": %q}]`,
			pp.GuestPort, pp.HostPort, proto))
	}

	return exprs
}

func buildStartArgs(name string) []string { return []string{"start", name} }

// buildStopArgs returns the args for `limactl stop`.
//
// NOTE: opts.Timeout is not translated to anything — `limactl stop` is
// not confirmed to accept a configurable graceful-shutdown timeout the
// way `incus stop --timeout` does. Verify against `limactl stop --help`;
// if a real flag exists, wire it in, otherwise the gap should be
// documented explicitly in lima-setup.md rather than silently ignored
// forever.
func buildStopArgs(name string, opts provider.StopOptions) []string {
	args := []string{"stop", name}
	if opts.Force {
		args = append(args, "--force")
	}
	return args
}

// buildDeleteArgs returns the args for `limactl delete`.
//
// NOTE: unverified whether --force is required to delete a *running*
// instance (auto-stop-then-delete) or only relaxes some other check —
// confirm against `limactl delete --help`.
func buildDeleteArgs(name string, force bool) []string {
	args := []string{"delete", name}
	if force {
		args = append(args, "--force")
	}
	return args
}

func buildListArgs() []string { return []string{"list", "--json"} }

// buildListOneArgs returns the args for a single-instance status query.
//
// NOTE: unverified that `limactl list <name> --json` accepts a positional
// instance-name filter the way `incus list <name>` does. If it doesn't,
// Status() must fetch the full --json output and filter client-side
// instead — a change local to lima.go; this builder's signature doesn't
// need to change either way.
func buildListOneArgs(name string) []string { return []string{"list", name, "--json"} }

// buildExecArgs returns the args for a one-shot `limactl shell` exec.
// root=true prefixes the command with `sudo -n` (fail rather than hang on
// an unexpected password prompt) rather than passing any uid/gid flags —
// unlike Incus, Lima's shell already resolves to the provisioned guest
// user on its own, so there is no execUser/uid/home readback step here.
func buildExecArgs(name string, command []string, root bool) []string {
	args := []string{"shell", name, "--"}
	if root {
		args = append(args, "sudo", "-n")
	}
	return append(args, command...)
}

// buildShellArgs returns the args for an interactive `limactl shell`.
//
// NOTE: assumes `limactl shell <name>` with no trailing command spawns an
// interactive login shell as the configured guest user, and that `--` is
// the correct/required separator before a trailing command the same way
// ssh/incus exec use it. Verify against `limactl shell --help`.
func buildShellArgs(name string, root bool) []string {
	if root {
		return []string{"shell", name, "--", "sudo", "-i"}
	}
	return []string{"shell", name}
}
