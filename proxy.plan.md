# Egress Proxy Support — Design Notes (Not Yet Implemented)

**Status:** Brainstorm/design discussion only. Nothing described here has been
implemented, no code has been written, and no decision has been made on the
open questions at the bottom. This file exists purely to preserve the
discussion so it can be picked up again later without re-deriving it.

## Motivation

`--deny-lan` (default on) already gives sandboxes "internet yes, local
network neighborhood no" — but many organizations don't just want LAN
blocked, they mandate that *all* external traffic go through an edge proxy
(Squid or similar): a service that itself sits where it can reach the
outside but not the inside of the network. Clients are configured to use the
proxy for external access and nothing else. The idea: let `agentctl`
auto-configure sandboxes to use such a proxy, the same way it already
auto-configures the non-root default user and (for Lima) the guest identity.

## Relationship to profiles: additive, not a replacement

Proxy config is a new opt-in field, not a mode that displaces
`network.allow`/`denyLAN`. It would be a fourth field on `NetworkPolicy` in
`internal/profile/schema.go`, alongside `DenyLAN`/`Allow`/`Ports`:

```yaml
spec:
  network:
    denyLAN: true
    proxy:
      host: "proxy.corp.example.com"   # DNS name or literal IP
      port: 3128
      noProxy: ["localhost", "127.0.0.1", "169.254.169.254"]
      caCert: "/path/to/corp-ca.pem"   # optional, only for intercepting proxies
```

It would flow through `profile.Merge` exactly like `Console.Viewer` does
today (override wins if non-empty, otherwise keep base), with matching
`create` flags (`--proxy-host`/`--proxy-port`/`--proxy-no-proxy`/
`--proxy-cacert`) shadowing the profile fields the same way `--allow`/
`--deny-lan` already do. An org profile can bake in "always use the edge
proxy," and an individual `create` can still override or add to it.

Naming note: the original idea used `--proxy-ip`, but `--proxy-host` reads
better — orgs often front Squid with a DNS name for HA/failover, not a
literal IP.

## Open design decision: does a configured proxy change the network ACL?

This is the one decision that actually changes enforcement semantics, not
just guest convenience — it should be made deliberately before any
implementation starts.

**Mode A — additive only.** The ACL keeps working exactly as today
(`--allow` resolves domains to IPs, builds per-IP rules); proxy config only
drops env vars/config files in the guest so tools *can* use the proxy.
Safe, fully backward-compatible, zero interaction with existing ACL code —
but doesn't fix the CDN-shared-IP staleness problem `network.acl` already
hit once (two domains resolving to the same IP producing duplicate rules),
since domain-level filtering still lives in agentctl's own resolved-IP
allowlist.

**Mode B — proxy narrows the ACL (recommended, pending sign-off).** When a
proxy is configured, the ACL's allow side collapses to a single rule: "TCP
to `<proxy-host-ip>:<proxy-port>`." Domain-level filtering moves entirely to
the proxy's own ACLs, which is where these organizations already enforce it
in practice. `denyLAN` still applies independently (LAN-neighbor blocking is
a separate concern from WAN-via-proxy). `--allow` would still be honored
additively for anything that needs to bypass the proxy (mixed environments
aren't unusual). Side benefit: since a CONNECT-based proxy receives the
target *hostname*, not a pre-resolved IP, a fully-proxied guest may not need
outbound DNS at all — a further reduction in exfil surface, though this
needs verifying against how the capability gate should behave when
`--proxy-host` is set with no `--allow` at all.

**Decision needed:** Mode A vs. Mode B before this becomes an implementation
plan.

## Tools to auto-configure

Two tiers, because tool support for `http_proxy`/`https_proxy` env vars is
inconsistent in practice.

**Tier 1 — env vars, catches most tools for free.** Write both casings
(`http_proxy`/`HTTP_PROXY`, `https_proxy`/`HTTPS_PROXY`, `no_proxy`/
`NO_PROXY`) to `/etc/environment` (system-wide, survives `sudo -i`, picked
up in most non-interactive contexts) and `/etc/profile.d/agentctl-proxy.sh`
(interactive login shells). Covers `curl`, `wget` (most default builds),
`pip` (via `requests`/`urllib3`), and most language HTTP clients for free.

**Tier 2 — explicit config, for tools known to be unreliable about env
vars:**

| Tool | File | Why it needs its own entry |
|---|---|---|
| `apt`/`apt-get` (Debian/Ubuntu) | `/etc/apt/apt.conf.d/95agentctl-proxy` — `Acquire::http::Proxy "http://host:port";` (+ https) | doesn't reliably honor env vars in all invocation contexts |
| `dnf`/`yum` (Fedora/RHEL) | `/etc/dnf/dnf.conf` (and `/etc/yum.conf` for legacy yum) — `proxy=http://host:port` | same reason, historically inconsistent |
| `apk` (Alpine) | no native proxy directive — env vars only | document as a known limitation, don't silently pretend it's covered |
| `npm` | `npm config set proxy/https-proxy` → `~/.npmrc` | npm has historically not read `http_proxy` reliably |
| `git` | `git config --global http.proxy/https.proxy` | inconsistent across git/libcurl build versions |
| `pip` | `/etc/pip.conf` (`[global] proxy = ...`) | belt-and-suspenders on top of Tier 1 |

`go`/`cargo`/`gem` left to Tier 1 only for v1 — they generally honor env
vars, and `GOPROXY` in particular is a *different* concept (Go's module
proxy, not an HTTP forward proxy) that's easy to conflate and worth
explicitly not touching.

## Per-provider provisioning

Follows the pattern `internal/provider/incus/embedded/bootstrap-user.sh`
already established: a new embedded, idempotent script
(`configure-proxy.sh`), run via the same "pipe over stdin, never template
into a command line" mechanism as `bootstrapUserCommand`/
`buildBootstrapUserArgs` in `internal/provider/incus/translate.go`,
detecting the package manager the same way (`command -v apt-get` /
`command -v dnf` / `command -v apk`) before deciding which Tier 2 file(s)
to write.

- **Incus**: would run during `Create()`'s existing start → provision →
  stop sequence, alongside the non-root-user bootstrap step — same
  already-open running-instance window, no new lifecycle cost.
- **Lima**: the one real asymmetry. Lima's `Create()` deliberately does
  *not* start the instance (cloud-init handles user provisioning at first
  boot instead — see `internal/provider/lima/lima.go`'s `Create` doc
  comment), so there's no running-instance window at `Create()` time for a
  post-boot exec-based provisioning step. Two options:
  1. Move proxy provisioning to first-`Start()`, mirroring how
     `PendingAgentInstall` already retries post-boot work on `start`.
  2. Express it as a `provision:` script block appended via the same
     `--set` mechanism `Create()` already uses for mounts/ports
     (`buildSetExpressions` in `internal/provider/lima/translate.go`), so
     it runs as part of Lima's own first-boot cloud-init instead of a
     separate agentctl-driven exec call.
  Option 2 is likely the better fit for Lima specifically, since it avoids
  a second provisioning code path with different timing semantics from
  Incus's.

  **Update:** Lima guests now always have `http_proxy`/`https_proxy`
  pointed at a per-instance agentctl egress proxy on the host — that's how
  network policy is enforced on Lima at all (see
  `lima-pf-firewall.plan.md`). On Lima, then, the org proxy can't be the
  guest's proxy; it would have to be that egress proxy's *upstream*
  (agentctl's proxy forwarding allowed CONNECTs through the org proxy
  instead of dialing out directly), which also makes Mode B's "narrow the
  ACL to the proxy" largely automatic there.

**CA cert (TLS-interception proxies)** has no existing primitive to build
on — neither backend currently has a "push a file into the guest"
operation (confirmed: no `file push`/`FilePush` anywhere in
`internal/provider`). Getting a cert in requires either:
- (a) a new `Provider` method / `translate.go` builder for it (Incus has
  `incus file push`; Lima would need its own mechanism — e.g. referencing a
  template-side file via `--set` plus a provisioning step that trusts and
  removes it), or
- (b) base64-embedding the cert content into the same stdin payload as the
  provisioning script, appended after a delimiter — no new plumbing, but an
  uglier script.

Recommendation: treat CA-cert support as a distinct, optional follow-on
(`--proxy-cacert`) rather than a v1 requirement — a non-intercepting
(pure CONNECT-tunnel) proxy needs none of this and is very likely the
majority case.

## Open questions to resolve before this becomes an implementation plan

1. **Mode A vs. Mode B** for the ACL (see above) — changes enforcement
   semantics, needs explicit sign-off.
2. **Flag shape**: discrete `--proxy-host`/`--proxy-port`/`--proxy-no-proxy`/
   `--proxy-cacert` vs. a single combined `--proxy=host:port` (the
   codebase's existing `--port host:guest` convention leans toward
   compact, but a 4-field proxy config reads more clearly as discrete
   flags).
3. **CA-cert support**: in scope for v1, or deferred as a follow-on?
4. **Failure mode on unsupported images**: should provisioning skip
   silently on an image with no recognized package manager (matching how
   `bootstrap-user.sh` degrades gracefully today), or is a proxy
   misconfiguration security-relevant enough to warrant a hard error
   instead of a silent partial application?

## Where this fits once resolved

Once the open questions above are answered, this should go through the same
plan-mode workflow the Lima backend and non-root-user/JIT-agent features
did: explore existing patterns (`bootstrap-user.sh`, `translate.go`,
`capability.go`, `profile/schema.go` + `merge.go`), design a concrete
file-by-file plan, and get it reviewed before any code is written.
