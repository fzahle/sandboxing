# Lima Network Enforcement — Design Record

**Status:** Implemented — but not with pf. This file started as a
brainstorm about automating a pf-anchor workaround for Lima's missing
network ACL; working through it against Lima's actual source turned up a
reason pf can't do the job, and the implemented design takes a different
route. Kept as a record of why, and of how the brainstorm's open questions
were resolved. The user-facing description is in
[docs/admin/providers/lima-setup.md](docs/admin/providers/lima-setup.md#network-policy-enforcement);
the code is `internal/provider/lima/network.go` and `internal/egress`.

## The original question

`network.acl`/`network.deny-lan` were `ManualWorkaround` on Lima: agentctl
printed a static pf-anchor procedure for the user to run by hand, because
Lima has no ACL object the way Incus does. The brainstorm asked whether
agentctl could manage those pf rules itself around the instance lifecycle
(apply on `Start()`, tear down on `Stop()`/`Delete()`), printing the exact
privileged commands rather than hiding `sudo` calls — in two tiers: Tier 1
generating the exact commands for the user, Tier 2 running them behind an
opt-in flag.

## Why pf doesn't work: the guest always has a second way out

Checked against Lima v2.2's source (and gvisor-tap-vsock v0.8.9, which it
embeds):

- Lima **always** attaches a user-mode NIC to the guest (`eth0`,
  192.168.5.15) — there's no setting to remove it
  (`pkg/driver/vz/vm_darwin.go`'s `attachNetwork`). A vzNAT or
  socket_vmnet NIC, which the pf plan relied on, is only ever an
  *additional* one.
- That NIC's traffic doesn't cross a host interface as guest traffic. The
  hostagent terminates each guest TCP/UDP flow in an in-process gvisor
  network stack and re-originates it from the host with a plain
  `net.Dial` (gvisor-tap-vsock's `pkg/services/forwarder/tcp.go`). pf sees
  the user's own traffic.
- Every agentctl guest has passwordless `sudo`. A compromised agent could
  just change its routes and leave via `eth0`, past any pf rule on the
  vzNAT interface. The same flaw has been hit in the wild: a
  similar host-firewall-plus-Lima design
  ([kurtb/safeclaude#23](https://github.com/kurtb/safeclaude/pull/23)) was
  abandoned because "the default SLIRP NIC bypasses host filtering".
- Separately, the pf plan's IP lookup couldn't have worked as written:
  `limactl list` has no IP address field at all (`limatype.Instance`), so
  the `{{.IPAddress}}` template in the old `Plan` text would have errored.
  And even with the IP, vzNAT guests share one subnet with any other vzNAT
  VM on the Mac, and a guest with root can change its own address, so a
  rule keyed on the guest's source IP is easy to step outside of.

Lima has no egress filter of its own to use instead: a native one has been
proposed ([lima-vm/lima#4326](https://github.com/lima-vm/lima/pull/4326),
filtering in the user-v2 network) but it's an unmerged draft.

## What was built instead

The hostagent re-originating all of the guest's traffic is also what makes
it a single, host-side choke point. So agentctl enforces policy on that
process:

1. **Seatbelt confinement.** `limactl start` runs under
   `/usr/bin/sandbox-exec` with a profile denying all outbound connections
   except to Unix sockets and two loopback ports (the instance's pinned
   SSH forward and its egress proxy). The hostagent and everything it
   spawns inherit it. A guest connection anywhere else makes the
   hostagent's `connect()` fail and the guest sees it refused — whatever
   root in the guest does, since none of it runs in the guest. No root is
   needed on the host. The profile uses only constructs that Bazel's
   darwin sandbox and Anthropic's sandbox-runtime rely on in production.
2. **A per-instance egress proxy.** Seatbelt can only match a remote host
   of `localhost` or `*`, never an IP, so the allowlist lives in a small
   HTTP CONNECT/forward proxy (`internal/egress`), run as agentctl's own
   hidden `egress-proxy` command, which the guest reaches at 192.168.5.2
   via `http_proxy`/`https_proxy`. It enforces the Incus ACL semantics:
   default deny; allow rules by domain (wildcards included) and port; with
   deny-LAN, LAN/link-local addresses refused even when a rule matches —
   checked on the resolved address it then dials, so DNS can't change
   between check and connect; host loopback always refused.
3. **Re-assertion and verification on every start.** `limactl edit` drops
   extra NICs, pins the SSH port, and sets the proxy environment;
   `limactl list --json` then confirms Lima's *effective* config (after
   `~/.lima/_config/default.yaml`/`override.yaml`) still matches, and that
   no writable mount exposes agentctl's state directory (where the policy
   lives) to the guest; after boot, an in-guest probe confirms a direct
   connection out is refused, and the instance is stopped if it isn't.

## The brainstorm's open questions, resolved

1. **Tier 1 only, or Tier 2 too?** Neither, as framed: both were pf-based.
   Enforcement is automatic on every `agentctl start`, like Incus, and
   needs no privileges at all, so there's no opt-in flag and no sudo.
2. **One-time passwordless-sudo setup?** Not needed — nothing runs as root.
3. **Does `Status` gain a value?** No. `network.acl`/`network.deny-lan`
   are plain `Supported` on macOS: enforcement is automatic and host-side,
   the same claim `Supported` makes for Incus. The remaining difference
   (clients must use the proxy) is documented rather than encoded. Off
   macOS they're `NotAvailable`, since there's no Seatbelt to confine the
   hostagent with.
4. **Reusable for proxy Mode B (`proxy.plan.md`)?** Partly, by
   construction: an org edge proxy could become the egress proxy's
   upstream (instead of it dialing out directly), keeping per-instance
   allowlist enforcement on the host. Not built.
5. **Instance IPs changing across restarts?** Moot — nothing is keyed on
   the guest's IP. The pinned ports are re-checked on every start and
   re-picked if something else took them.

## Known limits

- Only proxy-aware clients get out (raw TCP, UDP, SSH without a
  `ProxyCommand` are refused even to allowlisted destinations). On Incus,
  any TCP client can reach an allowlisted address.
- An instance started outside agentctl (`limactl start`, launchd via
  `limactl autostart`) isn't confined. agentctl refuses to start a
  launchd-registered instance and to adopt a running one it didn't start,
  but can't prevent direct `limactl` use.
- Only the `vz` VM type is supported for enforcement (the macOS default);
  others are refused rather than assumed to behave the same.
- Not yet run against a live Lima install from this repo: the gated
  integration test (`TestIntegration_NetworkPolicy_EnforcedHostSide`) is
  where that happens, and the post-start probe catches a confinement
  failure in the field either way.
