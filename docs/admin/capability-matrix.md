# Capability Matrix

This mirrors the `provider.Table` each backend actually returns from
`Capabilities()` (see `internal/provider/{incus,lima,hyperv}/capability.go`).
**Incus and Lima are both real implementations**; Hyper-V is still a
capability-table-driven stub, so almost everything on that row is a "not
wired up yet," not a platform limitation — see the notes below the table
for which cells are genuine platform gaps.

| Feature | Incus | Lima | Hyper-V |
|---|---|---|---|
| create / start / stop / delete / list / status | Supported | Supported | Under development |
| exec / shell | Supported | Supported | Under development |
| view (console) | Supported | Under development | Under development |
| snapshot create/list/restore/delete | Supported | **Not available** | Under development |
| network.acl (`--allow`) | Supported | Supported (macOS hosts) | Under development |
| network.deny-lan (`--deny-lan`) | Supported | Supported (macOS hosts) | Under development |
| network.port-publish (`--port`) | Supported | Supported | **Manual workaround** |
| image.pull | Supported | **Not available** | Under development |
| image.build | Supported | Under development | Under development |
| logs.network / logs.exec | Under development | Under development | Under development |

## Reading the "genuine platform gap" cells

These are the only entries where the gap is in the *platform*, not just in
agentctl's own wiring:

- **Lima: snapshot.\* → Not available.** `limactl snapshot` is explicitly
  experimental/unstable upstream; agentctl won't build on it until it
  stabilizes.
- **Lima: image.pull → Not available.** Lima has no local named image store
  to pull into ahead of `create`; a template's base image resolves lazily,
  per-instance, inside `create`/`start` itself — there's no daemon-side
  store to wire up to, unlike Incus's `incus image copy`.
- **Hyper-V: network.port-publish → Manual workaround.** Hyper-V has no
  built-in "publish a port" primitive; agentctl prints a NAT-switch +
  `netsh interface portproxy` procedure.

Lima's network.acl/network.deny-lan entries are `Supported` even though
Lima has no ACL object: agentctl enforces the same policy host-side by
confining Lima's own processes with a macOS sandbox profile and routing the
guest's egress through a per-instance filtering proxy — see
[Lima setup](providers/lima-setup.md#network-policy-enforcement) for how,
and for the one practical difference (clients must use the proxy). That
mechanism is macOS-specific, so on a Linux host the Lima backend reports
both as **Not available** (use Incus there). Lima's logs.network is `Under
development` rather than a gap: each instance's proxy already logs every
allowed and denied connection; `agentctl logs` just isn't wired to it yet.

Every other `Under development` cell reflects a backend that supports the
feature natively (New-VM/Start-VM, Extended Port ACLs, Standard/Production
checkpoints, VMConnect for Hyper-V) — agentctl just hasn't wired up the
integration yet. On Lima specifically, `view` stays `Under development` by
deliberate choice this milestone: a real GUI console needs a VNC bridge
that doesn't exist yet (Lima's default `vz` backend has no display concept
to attach to), which is a separately-scoped piece of work, not something
silently dropped.

## `--preview`/`--dry-run` availability

`--preview` shows the backend command(s) an operation would run, built from
the exact same code path the real dispatch uses (see
[Capability Model](../reference/capability-model.md#preview-and-drift)).
It only ever has something to show for an operation the active provider
actually supports — the capability gate above always runs first. Today
that means:

| Provider | `--preview` |
|---|---|
| Incus | Live — every command in the table above that's `Supported` |
| Lima | Live — every command in the table above that's `Supported` |
| Hyper-V | Nothing to preview yet (no operations are `Supported` yet) |

## Where this comes from

Run any command against an unsupported feature and agentctl prints the same
information live, plus (for manual-workaround cells) the actual copyable
procedure:

```console
$ agentctl --provider=lima image pull template://ubuntu-lts
agentctl: image.pull is not available on provider "lima": Lima has no local named image store to pull into ahead of create; a template's base image resolves lazily, per-instance, inside create/start itself.
```
