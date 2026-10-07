# CLI Reference

## Exit codes

Every `agentctl` command uses the same exit code convention, so scripts and
CI can branch on it instead of parsing text:

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Generic runtime error |
| `2` | Capability gap: the feature is **not available** or **under development** on the active provider |
| `3` | A **manual workaround** exists but wasn't applied (re-run with `--force-partial` after applying it, or apply it and re-run) |

Pass `--output=json` on any command to get machine-readable output, including
structured capability-gate outcomes (`status`, `feature`, `message`, `plan`,
`tracking_url`) instead of the human-readable text.

## Global flags

| Flag | Purpose |
|---|---|
| `--provider <name>` | Override the configured provider for this invocation |
| `--output <table\|json>` | Output format (default `table`) |
| `--profile-dir <path>` | Override the configured org-distributed profile directory |
| `--force-partial` | Proceed past a `ManualWorkaround` capability gap, accepting reduced protection |
| `--preview` / `--dry-run` | Print the backend command(s) this would run, instead of running them — see [Preview Mode](preview-mode.md) |

## Lifecycle

### `agentctl create <name>`

Creates an instance without starting it.

| Flag | Purpose |
|---|---|
| `--image <ref>` | Image reference (mutually exclusive with `--spec`) |
| `--spec <file>` | Path to a Spec YAML document (see [Profile Schema](../reference/profile-schema.md)) |
| `--profile <name>` | Named profile to apply (repeatable) |
| `--allow <entry>` | Egress allowlist entry: `host[:port,port]`, `*.domain[:ports]`, an IP address (`[v6]:port` with brackets), or an `http(s)://` URL, which allows its host on its port. One entry per flag (repeatable); hosts only, not URL paths — see [Egress allowlist](profiles-and-policies.md#egress-allowlist) |
| `--allow-preset <name>` | Allow a built-in group of hosts: package sources and git hosts (`apt`, `apk`, `pypi`, `npm`, `github`, `gitlab`) or a coding agent's (`claude`, `codex`, `opencode`, `pi`, the same hosts `--agent` allows). Repeatable or comma-separated — see [Allowing package sources and git hosts](profiles-and-policies.md#allowing-package-sources-and-git-hosts) |
| `--allow-file <path>` | Add the entries of an [allow file](profiles-and-policies.md#allow-files), one `--allow` entry per line (repeatable) |
| `--deny-lan` / `--allow-lan` | Block (default) or allow LAN egress |
| `--port <host:guest[/proto]>` | Publish a port (repeatable) |
| `--cpu-cores`, `--memory`, `--disk-size` | Resource overrides |
| `--agent <name>` | Just-in-time install a coding agent (`claude`, `codex`, `opencode`, `pi`) — implies `start`; see [Agent Provisioning](agent-provisioning.md) |

Supports `--preview`/`--dry-run` (see [Preview Mode](preview-mode.md)); with
`--agent` set, preview only shows the `create` command itself — the implied
`start` and the install step aren't previewed and don't run under
`--preview` either, since preview returns before `create` actually executes.

### `agentctl start <name>` / `agentctl stop <name> [--force] [--timeout <secs>]` / `agentctl delete <name> [--force]`

Standard lifecycle transitions. All three support `--preview`/`--dry-run`.

### `agentctl list` (alias `ls`) / `agentctl status <name>`

Show instances. `status` shows one instance's detail (IPs, image, profiles,
created time).

## Interactive access

### `agentctl shell <name> [--root]`

Opens an interactive session, as the instance's provisioned non-root user by
default (see [Profiles & Policies](profiles-and-policies.md#default-non-root-user)).
Pass `--root` for a root shell instead. (`login` also works, as a hidden
alias, for anyone used to that verb from an earlier design — but `shell` is
the documented name, since "login" implies credential auth against a remote
account, which this isn't.) Supports `--preview`/`--dry-run`.

### `agentctl exec <name> -- <command...>` / `agentctl exec --root <name> -- <command...>`

Runs one command and exits with its exit code, as the provisioned non-root
user by default. **`--root` must come before `<name>`**, not after — `exec`
turns off flag/positional interleaving past the first positional argument
so that flags meant for the *inner* command (e.g. `exec demo -- ls --root`)
are never mistaken for agentctl's own. Supports `--preview`/`--dry-run`.

### `agentctl view <name> [--read-only]`

Opens a console/display viewer. See [Viewing a Sandbox](view-and-console.md)
for why this never does raw X11 forwarding. Supports `--preview`/`--dry-run`.

## Images

### `agentctl image pull <ref>` / `agentctl image build <output-name> --base <ref> [--package <name>]...`

Pull a pre-baked image, or build one just-in-time from a base image plus a
cloud-init package list. `pull` supports `--preview`/`--dry-run`.

## Profiles

### `agentctl profile list` / `agentctl profile show <name>` / `agentctl profile set <name>`

List available profiles (built-in `default`/`strict` plus any file-based
ones), print one's resolved contents, or set the default profile applied
when `create` is given no `--profile`/`--spec`.

### `agentctl profile presets`

List the built-in allow presets (`--allow-preset`, `allowPresets`) with the
exact hosts and ports each one allows.

## Configuration

### `agentctl config set <key>=<value>` / `agentctl config get [key]`

Keys: `provider`, `profileDir`, `defaultProfile`.

## Logs

### `agentctl logs <name> [--network] [--exec] [--follow]`

Shows audit-relevant activity. Structured, correlated observability
(eBPF/ETW-based) is a larger, separate effort not built yet — this command
currently surfaces whatever the active provider natively exposes, which for
this milestone is nothing (`UnderDevelopment` on every provider). See
[Security & Threat Model](../admin/security-model.md).
