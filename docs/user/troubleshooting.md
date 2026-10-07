# Troubleshooting

## "not available" / "under development" / manual workaround — what do these mean?

`agentctl` checks whether the active provider actually supports what you
asked for before doing anything, and always tells you one of four things:

- **(nothing printed, command just runs)** — supported, proceeding normally.
- **"is under development for provider ..."** (exit code `2`) — agentctl
  knows how to build this, just hasn't yet. Not a platform limitation.
  Nothing to do but wait for it or use a different provider if one supports it.
- **"is not available on provider ..."** (exit code `2`) — the platform
  genuinely has no way to do this, and no workaround is known.
- **"has no native support on provider ..." followed by a numbered plan**
  (exit code `3`) — a manual procedure exists. Apply it by hand, then either
  re-run with `--force-partial` to proceed anyway (accepting that agentctl
  itself isn't enforcing this), or just run the manual steps and use the
  underlying tool directly for this one operation.

See the full [Capability Matrix](../admin/capability-matrix.md) for what's
supported on each provider today.

## `no provider configured`

Run `agentctl config set provider=<incus|lima|hyperv>`, or pass
`--provider=<name>` for a one-off override.

## `exec: "incus": executable file not found in $PATH`

The Incus backend shells out to the `incus` CLI rather than linking a Go SDK
— install and initialize Incus first. See
[Incus setup](../admin/providers/incus-setup.md).

## A LAN request I expected to succeed is being blocked

That's `--deny-lan` (on by default) doing its job — it blocks RFC1918 and
link-local ranges specifically so a sandbox can't reach other devices on your
network. If you genuinely need that, pass `--allow-lan` on `create`, or set
`denyLAN: false` in a profile, understanding the tradeoff.

## `start` fails with "incompatible with secureboot"

```
Error: The image used by this instance is incompatible with secureboot. Please set security.secureboot=false on the instance
```

This shouldn't happen on current `agentctl` — `create` disables Secure Boot
by default precisely because most public/community images aren't signed for
it (see [Incus setup](../admin/providers/incus-setup.md)). If you hit this
on an instance created by an older `agentctl` build, fix it directly:
`incus config set <name> security.secureboot=false`, then `agentctl start`
again.

## `create` fails during non-root user provisioning

`agentctl create` runs a bootstrap script inside the instance (right after
network policy is applied) to provision the non-root default user that
`shell`/`exec` use — see
[Profiles & Policies](profiles-and-policies.md#default-non-root-user). Two
ways this can fail:

- **Neither `useradd` nor `adduser` is present.** Some minimal/custom images
  ship neither tool. The bootstrap script fails with a clear error instead of
  silently leaving the instance root-only. There's no workaround short of
  using an image that includes one of them (any mainstream Debian/Ubuntu or
  Alpine-family image does).
- **`sudo` can't be installed.** The script tries `apt-get install -y sudo` or
  `apk add --no-cache sudo` if `sudo` is missing, which needs working network
  egress at create time. If your allowlist is unusually restrictive before
  the instance is fully up, this step can fail — check the instance's egress
  policy, or use an image that already includes `sudo` preinstalled.

Re-running the bootstrap step is safe: it's idempotent and a no-op if the
user already exists, so retrying `agentctl create` (after deleting the failed
instance) or a future retry mechanism won't double-provision anything.

## `shell`/`exec` say "Error: VM agent isn't currently running"

`agentctl shell`/`agentctl exec` need the in-guest `incus-agent` to have
connected, which normally happens within a few seconds of `start` but can
take longer depending on the image and hardware. `shell`/`exec` already
wait up to 30 seconds for it, printing "waiting for the VM agent... to
start" to stderr if it takes a moment — you shouldn't need to do anything
but wait.

If it still fails after 30 seconds, either the guest is taking unusually
long to boot (just retry `agentctl shell`/`exec` again), or the image
doesn't include incus-agent support at all (some minimal or custom images
don't) — in which case `exec`/`shell` won't work on that image, but
`agentctl view` (the console) still will, since it doesn't need the agent.

## `applying network policy` fails with "Duplicate of egress rule N"

```
Error: incus network acl rule add agentctl-<name> egress action=allow destination=<ip> protocol=tcp destination_port=443: exit status 1: Error: Duplicate of egress rule 4
```

This shouldn't happen on current `agentctl` — it was a real bug where two
different allow-domains that happened to resolve to the same IP (common
behind shared CDN infrastructure; e.g. `--agent=claude`'s `claude.ai` and
`*.anthropic.com` allow-domains can share an IP) produced two
byte-identical ACL rules, which Incus rejects on the second one. Fixed by
deduplicating identical rule commands before applying the policy. If you
still hit this on an older `agentctl` build, no workaround is needed beyond
upgrading — there's nothing to fix in your own profile or `--allow` flags.

## `provisioning default user: user bootstrap script exited 1: Error: Instance is not running`

This shouldn't happen on current `agentctl` — it was a real bug where
`create` tried to run the non-root user bootstrap step (which needs `incus
exec`, and `incus exec` requires a running instance) against a freshly
`init`'d instance, which is stopped by design. Fixed by having `create`
briefly start the instance around the bootstrap step and stop it again
afterward — see [Incus setup](../admin/providers/incus-setup.md) for what
that means for `create`'s timing. If you still hit this on an older
`agentctl` build, upgrade; there's nothing to change in your own command or
profile.

## Agent install fails or never finishes

`create --agent=<name>` runs that agent's install command (e.g. `curl ... |
bash`) as soon as the instance is up — see
[Agent Provisioning](agent-provisioning.md). This needs working egress at
install time, so a flaky network mid-install, or an unusually restrictive
`--allow`/profile combination that's missing a domain the install script
itself redirects through, can leave `create` reporting a failure with the
instance left running.

You don't need to redo anything by hand: the very next `agentctl start
<name>` — even a completely ordinary one, with no `--agent` flag — detects
the incomplete install and retries it automatically before doing anything
else. If it keeps failing, the error `create`/`start` printed is the actual
install script's output; check that against whatever domain it's trying to
reach and extend `--allow` if it's egress being blocked, same as any other
blocked-domain issue.

An already-successful install is never repeated: `create --agent=<name>`
records success once the install script exits `0`, and every subsequent
`start` is a no-op with respect to the agent.

## An `--allow` entry stopped working after a while

On Incus, domain-based allow rules are resolved to IP addresses when the
policy is applied — a snapshot, not dynamic DNS-aware filtering. If the
target rotates IPs (common behind a CDN), re-apply the policy (re-run
`create`'s network setup, or recreate the instance) to refresh it. (On
Lima this can't happen: its egress proxy resolves the hostname on every
connection.)

## Lima: a request from the sandbox gets `403` / "denied by agentctl network policy"

On Lima, the sandbox's traffic goes through a per-instance egress proxy
(see [Lima setup](../admin/providers/lima-setup.md#network-policy-enforcement)),
which answers a refused destination with `403 Forbidden` and the reason —
curl shows it as `CONNECT tunnel failed, response 403` for HTTPS. Every
decision is logged on the Mac in
`~/.config/agentctl/lima/<name>/egress-proxy.log`, so that's the quickest
way to see exactly which host:port was refused and why:

```
2026-10-07T19:08:50Z deny CONNECT downloads.example.com:443: not in the allowlist
```

Allow rules match the hostname the client asked for, so a site that
redirects to another hostname (a download CDN, say) needs that hostname
allowlisted too. Add it with `--allow` and recreate the instance — and the
same reasons as on Incus apply to "deny-LAN is on" refusals.

## Lima: a tool can't connect at all ("Connection refused"), even to an allowlisted host

That tool isn't using the instance's proxy. On Lima, the sandbox's only way
out is the egress proxy its `http_proxy`/`https_proxy` variables point at;
a connection that doesn't go through it is refused by design, allowlisted
destination or not (that's what stops a compromised agent from simply
ignoring the proxy). Configure the tool to use an HTTP proxy — the
`https_proxy` value in the sandbox's environment — or use a tool that
honors those variables. Some common cases: Node's built-in `fetch` and
`http`/`https` modules only honor them with `NODE_USE_ENV_PROXY=1` (or
`--use-env-proxy`; Node 22.21+/24.5+); `git` over SSH needs an ssh
`ProxyCommand` (or use the HTTPS remote); anything UDP-based has no way out.

## Lima: `agentctl start` refuses an instance that's "already running, but agentctl didn't start it under its network sandbox"

The instance was started some other way — a plain `limactl start`, for
instance — so its egress is unrestricted, and agentctl won't pretend
otherwise by adopting it. Stop it and start it with agentctl:

```console
$ agentctl stop <name>
$ agentctl start <name>
```

## Lima: `agentctl start` refuses an instance "registered with launchd to start automatically"

`limactl autostart enable` (formerly `start-at-login`) has launchd start the
instance at login — outside agentctl's sandbox, with unrestricted egress.
Unregister it with `limactl autostart disable <name>` and start it with
agentctl instead.

## Lima: `agentctl start` refuses because of the instance's configuration

agentctl checks Lima's effective configuration for the instance before
every start and refuses anything that would undermine its network policy:

- **"has additional networks configured"** — a vzNAT or socket_vmnet
  network, whose traffic doesn't go through the sandboxed Lima hostagent.
  agentctl removes these from the instance itself, so this means one is
  coming from `~/.lima/_config/default.yaml` or `override.yaml`; remove it
  there.
- **"ssh.localPort ...", "propagateProxyEnv ...", or an `http_proxy`/
  `https_proxy`/`no_proxy` mismatch** — the same files overriding
  settings agentctl pins for the instance; remove the override.
- **"uses vmType ..."** — the instance doesn't use Lima's `vz` VM type
  (the macOS default), and agentctl's enforcement is only verified for
  `vz`. Recreate it from a template that doesn't force another VM type.
- **"mounts ... writable, which overlaps agentctl's state directory"** —
  a writable mount (typically of your whole home directory) would let the
  guest edit its own egress policy in `~/.config/agentctl`. Make that
  mount read-only, or share a narrower directory instead.

## Lima: "network confinement check failed"

After every start, agentctl tries a direct connection out from inside the
guest, bypassing the proxy, to confirm it's refused. This error means it
got through — so Lima's processes weren't running under agentctl's macOS
sandbox as expected — and agentctl stopped the instance rather than leave
it running unprotected. Please report it, with your macOS version and
`limactl --version`.

## Lima: an instance created by an older agentctl has no network access

Instances created before Lima network enforcement existed have no recorded
egress policy, so their proxy denies everything (failing closed, as on
Incus with an empty allowlist). Recreate the instance with the `--allow`
flags or profile it should have.

## Exit code reference

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Generic runtime error |
| `2` | Capability gap (not available / under development) |
| `3` | Manual workaround available but not applied/forced |
