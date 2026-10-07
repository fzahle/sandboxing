# Security & Threat Model

## What agentctl defends against

Two distinct threats, both taken seriously:

1. **Host escape.** The agent (or something it's tricked into running)
   breaking out of its sandbox onto the machine running it. This is the
   threat most "run an agent safely" tooling focuses on, and it's why
   `agentctl` uses real hardware-virtualized isolation (Incus VMs — not
   containers, not gVisor-style syscall interception) rather than a weaker
   boundary.
2. **Lateral movement against the local network.** The agent attacking other
   devices on the same network as the machine it's running on — printers,
   NAS boxes, internal admin panels, coworkers' laptops. Multiple sources in
   this space converge on the same point: **isolation alone doesn't stop
   this.** Two sandboxes sharing no kernel is great against kernel exploits,
   but if the sandbox has network reach, a compromised agent can still scan
   or attack other hosts on the LAN unless egress is locked down
   independently of the isolation layer itself.

That second threat is why `agentctl` treats network policy as a first-class,
independently capability-gated concern (`ApplyNetworkPolicy` is its own
`Provider` method, not folded into `Create`), and why the defaults are:

## Default-deny egress, LAN blocked by default

- **`--deny-lan` defaults to on.** Every sandbox blocks egress to
  RFC1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) and link-local
  (`169.254.0.0/16`) ranges unless explicitly opted out (`--allow-lan`).
  Opting out should be a deliberate, reviewed decision — see
  [Distributing Profiles Org-Wide](distributing-profiles.md).
- **Internet egress is default-deny with an explicit allowlist.** A sandbox
  can only reach domains listed in `--allow`/a profile's `allow` entries
  (or added by an allow preset, an allow file, or `--agent`);
  everything else is rejected.
- **How domain-based allow rules are matched depends on the backend.**
  - *Incus*: its ACLs (like any IP-based mechanism) can only match resolved
    IP addresses, not domain names. `agentctl` resolves each allowed domain
    at policy-apply time; if the target rotates IPs (common behind a CDN),
    the rule goes stale until the policy is re-applied, and anything else
    served from an allowlisted IP is reachable too.
  - *Lima*: egress goes through a per-instance filtering proxy (see
    [Lima's network enforcement](#lima-network-enforcement-host-side-without-an-acl-object)),
    which matches the hostname the client asked for and resolves it at
    connection time — no staleness, and `*.example.com` really covers every
    subdomain. The flip side: only clients that use the proxy get out at
    all.
- **Neither backend inspects TLS.** Filtering is by destination (address or
  requested hostname), so domain fronting through a CDN shared with an
  allowlisted domain isn't prevented on either.

## Lima network enforcement: host-side without an ACL object

Lima has no per-instance ACL to put this policy in, and a host `pf` rule on
the VM's network interface would be bypassable: Lima always gives the guest
a user-mode NIC whose traffic the hostagent process re-creates as ordinary
connections *from the host*, invisible to `pf` as guest traffic — a guest
with root could just route around such a filter. So agentctl puts the
enforcement on that process instead: `limactl start` (and with it the
hostagent) runs under a macOS sandbox profile that refuses every outbound
connection except to the instance's own egress proxy and SSH forward on the
host's loopback, and the proxy applies the allowlist and deny-LAN rules.
None of it runs inside the guest, so root in the guest doesn't help; and
agentctl checks after every start that a direct connection out from the
guest fails, stopping the instance if it doesn't. Details and trade-offs:
[Lima setup](providers/lima-setup.md#network-policy-enforcement).

The one way around it is not starting the instance through agentctl: a
plain `limactl start`, or launchd via `limactl autostart`, runs the
instance with unrestricted egress. agentctl refuses to start an instance
registered with launchd and refuses to adopt a running instance it didn't
start, but treat starting agentctl's Lima instances by other means as
switching their network policy off.

## Non-root by default inside the guest

`shell`/`exec` run as a provisioned non-root user by default, not root — see
[Profiles & Policies](../user/profiles-and-policies.md#default-non-root-user)
for the mechanism. This is defense-in-depth, not a replacement for the VM
boundary: if the agent process itself is compromised, it shouldn't
automatically inherit root inside the guest. Be precise about what this does
and doesn't buy: the provisioned user has passwordless `sudo`, so it's
hygiene and an audit signal (a `sudo` invocation is a distinct, loggable
event a future observability pipeline could act on), **not** a hard security
boundary — a genuinely malicious agent can still escalate via `sudo`. Root
remains available as an explicit, visible opt-out (`--root`), never removed.

## `--agent` widens the egress allowlist, visibly

`agentctl create --agent=<name>` (see
[Agent Provisioning](../user/agent-provisioning.md)) merges that agent's
required install/runtime domains into the instance's egress allowlist
before applying network policy — the same default-deny-with-explicit-allow
mechanism `--allow` already uses, not a separate or looser path. This is a
deliberate, visible widening tied to the specific agent you asked for
(e.g. `--agent=claude` allows `claude.ai`, `downloads.claude.ai`,
`platform.claude.com` and `api.anthropic.com`), not a
silent one: `agentctl status`/`profile show`-style introspection of the
resulting policy shows exactly what was added, same as any other `--allow`
entry. The full per-agent lists are in
[Agent Provisioning](../user/agent-provisioning.md#built-in-registry). Note
that some are broad: `--agent=opencode` allows `github.com`, because that's
where opencode's releases are downloaded from, and with it everything else
on GitHub. Two multi-provider agents (`opencode`, `pi`) are documented as only
guaranteeing their install (plus, for `pi`, its default provider) —
extending the allowlist further for a different model
provider is on you, the same as it would be without `--agent`.

## Presets and allow files are allowlist entries too

`--allow-preset`/`allowPresets` (named groups of package-source and git
hosts, e.g. `apt`, `pypi`, `github`) and `--allow-file`/`allowFile` expand
to ordinary allow rules — they're conveniences for writing an allowlist,
not a different enforcement path. Two things to keep in mind when
approving one:

- **A preset opens whole hosts, both directions.** Filtering is by host
  and port, never by URL path or by what's sent, so the `github` preset
  lets the sandbox *push* to any GitHub repository it has credentials for,
  not just clone public ones; `pypi`/`npm` allow uploads to those
  registries if the sandbox holds a publishing token. Treat any
  allowlisted host that accepts writes as a possible exfiltration channel.
- **`agentctl profile presets` prints exactly what each preset expands
  to**, and `profile show` prints a profile's allow file already merged
  in — review those, not just the preset names, when vetting a profile.

## Why raw X11 forwarding is excluded

`agentctl view` never forwards X11. An X server has no isolation between
clients — any client on a display can generally read the keystrokes and
screen contents of every other client on that display. Forwarding a
potentially-compromised agent's X session onto a shared display would hand
it exactly the cross-boundary access this tool exists to prevent. See
[Viewing a Sandbox](../user/view-and-console.md) for what `agentctl view`
does instead per provider.

## What's honest about current limitations

`agentctl` is explicit, via its [capability model](../reference/capability-model.md),
about what it can and can't yet enforce per backend — see the
[capability matrix](capability-matrix.md). Hyper-V is still a stub this
milestone; treat any claim of protection on that platform as not yet real
until its capability entries say `Supported`. On Lima, `network.acl` and
`network.deny-lan` are `Supported` on macOS hosts (see
[above](#lima-network-enforcement-host-side-without-an-acl-object) for the
mechanism and its one bypass: starting an instance outside agentctl), and
`Not available` on Linux hosts, where agentctl can't confine Lima's
processes — use Incus there.

## Observability is explicitly postponed

Structured, correlated audit tooling — connecting an agent's high-level
intent (from LLM prompts/tool calls) to its low-level system effects
(network connections, file access, processes spawned) via boundary tracing —
is a substantial, separate effort (the kind of thing eBPF-based tools like
AgentSight do on Linux, with ETW/Sysmon as the natural analog on Windows and
Apple's Endpoint Security Framework on macOS). It is **not built in this
milestone.** `agentctl logs` exists as a command surface today, but every
provider currently reports it `UnderDevelopment`. This is deliberate scoping,
not an oversight — see the project's stated out-of-scope list.

## Auth/RBAC

`agentctl` does not implement its own authentication or access control for
who may operate a shared backend. On Incus, this means whatever OS/Incus
group membership (`incus-admin`) already governs who can run `incus`
commands governs who can run `agentctl` against it.
