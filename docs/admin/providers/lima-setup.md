# Lima Setup (macOS)

This backend is fully implemented for the operations that map onto Lima's
own primitives — network ACL enforcement and snapshots are the two
remaining genuine platform gaps (see below), and a GUI console
(`agentctl view`) is deliberately not built yet.

## Install

```console
$ brew install lima
```

Current stable is Lima v2.2, which added Windows guest support alongside the
macOS/FreeBSD guest support introduced in v2.1.

## How agentctl customizes instances

`agentctl create` runs one `limactl create --name=<name> --tty=false --set
'<yq-expression>' [--set ...] <image>` invocation, where `<image>` is a Lima
template reference (`--image=template://ubuntu-lts`, a URL, or a local
template path) and each `--set` translates one structured field of the
create request: CPU/memory/disk limits, mounts, and published ports.

> **Not yet exercised against a live `limactl` install.** If a real install
> shows `--set` isn't accepted directly on `create`, agentctl falls back to
> `limactl create` (bare) followed by one `limactl edit --set '<expr>'
> <name>` call per field before the first `start` — same overall behavior,
> just more invocations. Either way, `agentctl create` never leaves the
> instance in a partially-configured state you'd need to fix by hand.

agentctl always forces one field regardless of what the template's own
cloud-init defaults are:

- `.user.name` — the sandbox's non-root default user (`agent` unless
  `--agent=<name>` or an explicit override sets it otherwise), for
  consistency with the Incus backend's own non-root-by-default behavior.

Passwordless sudo is *not* forced via a `.user.sudo` field — Lima's
`limayaml.User` type has no such field (only `name`/`comment`/`home`/
`shell`/`uid`), and an earlier version of agentctl that tried to set one
was rejected by `limactl` as an unknown field. It isn't needed anyway:
Lima's own cloud-init `user:` provisioning grants passwordless sudo to
whichever user it creates, regardless of the name given here, so
`agentctl exec/shell --root` works out of the box.

`agentctl exec`/`shell` run as that user via `limactl shell <name> --
<command>`; `--root` runs `sudo -n <command>` (exec) or `sudo -i` (shell)
on top of it. Unlike the Incus backend, there's no separate bootstrap
script or uid/home lookup — Lima's own cloud-init `user:` handling
provisions the non-root account at first boot, and `limactl shell` already
resolves to it.

## Known gaps versus Incus

| Gap | Detail |
|---|---|
| No native network ACL | Lima has no first-class allowlist/ACL object. `agentctl` reports `ManualWorkaround` for `--allow`/`--deny-lan` and prints a concrete `pf`-based procedure until this is built natively. |
| Snapshot support experimental | `limactl snapshot` is explicitly marked experimental/unstable upstream; `agentctl` won't build on it until it stabilizes (`NotAvailable`, not `UnderDevelopment`). |
| No local image store | Lima resolves a template's base image lazily, per-instance, inside `create`/`start` itself — there's no separate named store to pull into ahead of time the way `incus image copy` gives you, so `image.pull` is `NotAvailable` rather than `Supported`. |
| No first-class GUI console | Lima has historically targeted headless Linux VM use cases. `agentctl` plans a dedicated VNC bridge for `view`, not X11 forwarding — see [Viewing a Sandbox](../../user/view-and-console.md). |

## Worth reading before extending this further

Lima's v2.0 release was titled "expanding the focus to hardening AI" at
FOSDEM 2026 — a strong signal upstream is already working on problems
adjacent to this project. Before hand-building agentctl's own hardening
layer for a remaining gap above (particularly the network ACL workaround),
check what Lima itself now offers; it may cover part of the gap natively.

## What agentctl assumes exists

- A working `limactl` on `$PATH`.
- vzNAT or socket_vmnet networking configured, per Lima's own docs,
  depending on whether IP-addressable guest access is needed.
- Published ports (`--port host:guest`) reach the macOS host via Lima's own
  `portForwards:` mechanism. **Unverified:** whether Lima's default
  `hostIP` binding is loopback-only (LAN-unreachable, unlike Incus's
  `0.0.0.0` proxy-device default) — confirm against a live install before
  relying on LAN-reachability for a published port on this backend.

## Verify

```console
$ agentctl config set provider=lima
$ agentctl create test --image=template://ubuntu-lts --allow-lan
$ agentctl start test
$ agentctl exec test -- whoami        # -> agent (non-root default)
$ agentctl exec --root test -- whoami # -> root
$ agentctl delete test --force
```

`--allow-lan` is needed above because `--deny-lan` defaults to `true` and
`network.deny-lan` is still `ManualWorkaround` on this backend — without it
(or `--force-partial`), `create` blocks with an explanation instead of
silently creating an unprotected instance.

## Testing this backend for real

`internal/provider/lima/integration_test.go` (`//go:build integration`,
gated further at runtime by `AGENTCTL_INTEGRATION_LIMA=1`) exercises the
full create/start/exec/status/stop/delete lifecycle against a real
`limactl` install — this is where every "unverified" note above actually
gets resolved. Unlike the Incus integration suite (blocked from standard
GitHub-hosted Linux runners by no nested virtualization), Lima's default
`vz` backend works on standard `macos-latest` GitHub-hosted runners with no
special setup, so `.github/workflows/ci-integration-lima.yml` can run
there directly (currently `workflow_dispatch`-only while timing/flakiness
gets proven out).
