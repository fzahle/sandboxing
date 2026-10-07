# Authoring Profiles & Policies

A **profile** is a named, reusable bundle of network policy, resource limits,
and mount policy — author it once, reference it by name from `create
--profile=<name>`. See [Profile Schema](../reference/profile-schema.md) for
the full field reference; this page walks through the important parts.

## Network policy

```yaml
spec:
  network:
    denyLAN: true
    allow:
      - domain: "pypi.org"
        ports: [443]
    ports:
      - host: 8080
        guest: 8080
        protocol: tcp
```

- **`denyLAN: true`** (the default) blocks egress to RFC1918 and link-local
  ranges, so the sandbox can't reach other devices on your network — printers,
  NAS boxes, internal admin panels, coworkers' laptops. Only set this to
  `false` (or pass `--allow-lan`) if you specifically need the sandbox to
  reach something on your LAN, and understand the tradeoff.
- **`allow`** is an egress allowlist; everything not matched is denied. On
  Incus, domains are resolved to IP addresses when the policy is applied —
  a snapshot of the domain's current IPs, not dynamic DNS-aware filtering;
  if a target rotates IPs (common behind a CDN), re-apply the policy to
  refresh it. On Lima, the sandbox's traffic goes through a filtering proxy
  that matches the requested hostname on every connection instead, so only
  clients that use the proxy (most do — see
  [Lima setup](../admin/providers/lima-setup.md#what-this-means-in-practice))
  get out at all.
- **`ports`** are Docker-style host:guest port publishes, for when you need to
  reach something the sandbox is running (e.g. a web UI) from your host.

## Resources and mounts

```yaml
spec:
  resources:
    cpuCores: 2
    memory: "4GiB"
    diskSize: "20GiB"
  mounts:
    - hostPath: "~/agentctl/workspaces/{{.Name}}"
      guestPath: "/workspace"
      readOnly: false
```

`hostPath` supports `~` expansion and a `{{.Name}}` template substituted with
the instance name — the built-in profiles use this so each instance gets its
own workspace directory automatically.

## Default non-root user

`agentctl create` provisions a non-root user inside every new instance and
makes it the default for `shell`/`exec` — not root. This is defense-in-depth:
the VM boundary is still the primary protection against host escape, but if
the agent *process itself* is compromised (a malicious dependency, a
prompt-injected shell command), it shouldn't automatically get root inside
the guest.

- The user has passwordless `sudo`, so anything that genuinely needs root
  (`apt install`, service management, ...) still works — this is hygiene and
  an audit signal (a `sudo` invocation is a distinct, loggable event), **not**
  a hard security boundary against a truly malicious agent.
- The username is `agent` by default, or matches the agent name if you used
  `--agent=<name>` (see [Agent Provisioning](agent-provisioning.md)) — so
  `--agent=claude` provisions and runs as a `claude` user.
- Root is always an explicit, visible opt-out, never removed:
  `agentctl shell <name> --root` / `agentctl exec --root <name> -- <cmd>`.
- This only affects `shell`/`exec` (the agent-mediated command channel).
  `agentctl view`'s console access is unaffected — it doesn't go through a
  guest user context at all.

## Combining a profile with ad-hoc flags

Flags on `create` always win over a profile's settings, and list-valued
fields (`allow`, `ports`, `mounts`) accumulate rather than replace:

```console
$ agentctl create demo --profile=default --allow=github.com:443 --port=9000:9000
```

This applies the `default` profile's full allowlist plus `github.com:443`,
and publishes port 9000 in addition to anything the profile already defined.

## Where profiles live

`agentctl profile list`/`show`/`set` search, in order:

1. `./.agentctl/profiles/<name>.yaml` (project-local)
2. `~/.config/agentctl/profiles/<name>.yaml` (personal)
3. the configured `profileDir` (org-distributed — see
   [Distributing Profiles Org-Wide](../admin/distributing-profiles.md))
4. embedded built-ins (`default`, `strict`)

## Strict decoding

Profile YAML is parsed with unknown fields rejected as an error — a typo like
`denyLan` instead of `denyLAN` fails to load rather than silently being
ignored. This is a security policy file; failing loudly on a typo is the
correct default.
