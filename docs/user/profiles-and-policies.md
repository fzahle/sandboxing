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
      - domain: "api.anthropic.com"
        ports: [443]
    allowPresets: [apt, pypi, github]
    allowFile: team-hosts.txt
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
- **`allowPresets`** adds built-in groups of hosts for common package
  sources and git hosts — see
  [Allowing package sources and git hosts](#allowing-package-sources-and-git-hosts).
- **`allowFile`** adds the entries of a plain-text file, one per line — see
  [Allow files](#allow-files).
- **`ports`** are Docker-style host:guest port publishes, for when you need to
  reach something the sandbox is running (e.g. a web UI) from your host.

## Egress allowlist

On the command line, each `--allow` takes one entry; in an allow file, each
line is one entry:

| Entry | Allows |
|---|---|
| `example.com:443` | `example.com`, port 443 |
| `example.com:80,443` | `example.com`, ports 80 and 443 |
| `example.com` | `example.com`, any TCP port |
| `*.example.com:443` | on Lima, `example.com` and all its subdomains; on Incus, `example.com` only (see below) |
| `203.0.113.7:443`, `[2001:db8::1]:443` | one IP address |
| `https://gitlab.example.com` | `gitlab.example.com`, port 443 — a URL's host, on the URL's port, or 443 for `https://` and 80 for `http://` |

In a profile, the same thing is written as `domain:` plus `ports:` (see the
example above).

- **Hosts, not URLs.** Egress is filtered by destination host and port,
  never by URL path (with HTTPS, nothing between the sandbox and the
  server can even see the path), so an allow rule can't be narrower than a
  whole host. An entry with a path,
  like `https://github.com/org/repo`, is rejected with the host-level entry
  to use instead (`github.com:443`) — rather than silently allowing all of
  GitHub while looking like it allows one repository.
- **Redirects count.** Downloads are often served from a different host
  than the one you request: GitHub release downloads, for instance,
  redirect to `release-assets.githubusercontent.com`. Every host in the
  chain needs to be allowed — the presets below already include them for
  the sources they cover.
- **Wildcards differ by backend.** On Lima the proxy matches hostnames, so
  `*.example.com` covers every subdomain. On Incus, allow rules become IP
  addresses, and only the wildcard's apex (`example.com`) is resolved, so
  list the subdomains you need by name if you use Incus or want a profile
  to work on both.
- **Internal hosts need `--allow-lan`.** Deny-LAN refuses private
  (RFC1918/link-local) addresses even when they're on the allowlist, so a
  self-hosted GitLab or package mirror at a `10.x.x.x` address stays
  unreachable until you create the instance with `--allow-lan` (or
  `denyLAN: false`). Egress stays default-deny either way: the sandbox can
  then reach the internal hosts you allowlisted, not the rest of your
  network.

## Allowing package sources and git hosts

Installing packages or cloning code usually involves more hosts than the
one you'd think of — `pip install` downloads from `files.pythonhosted.org`,
not `pypi.org`. **Allow presets** are named, built-in groups of those
hosts:

| Preset | For | Hosts (ports) |
|---|---|---|
| `apt` | Ubuntu and Debian packages, default mirrors | `archive.ubuntu.com`, `security.ubuntu.com`, `ports.ubuntu.com` (arm64, e.g. Apple silicon), `deb.debian.org`, `security.debian.org` (80, 443) |
| `apk` | Alpine packages | `dl-cdn.alpinelinux.org` (80, 443) |
| `pypi` | pip, uv, poetry | `pypi.org`, `files.pythonhosted.org` (443) |
| `npm` | npm, pnpm, yarn | `registry.npmjs.org`, `registry.yarnpkg.com` (443) |
| `github` | git over HTTPS, the API and `gh`, raw files, archives, release downloads | `github.com`, `api.github.com`, `codeload.github.com`, `raw.githubusercontent.com`, `release-assets.githubusercontent.com` (443) |
| `gitlab` | the same, for GitLab.com | `gitlab.com` (443) |
| `claude`, `codex`, `opencode`, `pi` | a coding agent's installer, sign-in and default model provider — exactly what `--agent=<name>` allows | see [Agent Provisioning](agent-provisioning.md#built-in-registry) |

Use them on `create` (repeatable, or comma-separated), in a profile, or in a
spec's `overrides`, and mix them freely with `--allow`:

```console
$ agentctl create demo --image=images:ubuntu/24.04 --agent=claude \
    --allow-preset=apt,pypi,github --allow=https://gitlab.example.com
```

```yaml
spec:
  network:
    allowPresets: [apt, pypi, github]
```

`agentctl profile presets` prints exactly which hosts and ports each preset
allows (add `--output=json` for a machine-readable list). What presets
don't cover:

- **Other mirrors and repositories.** `apt` covers the mirrors stock
  Ubuntu and Debian images use. An image configured for a regional mirror
  (`us.archive.ubuntu.com`), a PPA, or a vendor's apt repository needs
  those hosts added with `--allow` — `apt-get update`'s errors name them.
  Fedora's `dnf` picks mirrors dynamically from a mirror list, so no fixed
  set of hosts covers it; point it at a fixed mirror and allow that one.
- **Git over SSH.** `github`/`gitlab` are HTTPS only — use HTTPS remotes,
  or add `--allow=github.com:22` (on Lima, ssh also needs a `ProxyCommand`;
  see [Troubleshooting](troubleshooting.md#lima-a-tool-cant-connect-at-all-connection-refused-even-to-an-allowlisted-host)).
  Git LFS objects and GitHub's container and package registries (`ghcr.io`,
  `*.pkg.github.com`) are served from other hosts too.
- **Self-hosted servers.** For your own GitLab, Gitea, Artifactory or
  Nexus, allow the host itself — `--allow=https://gitlab.example.com` —
  plus `--allow-lan` if it has a private address (see above).

Allowing a host allows everything on it, uploads included — the `github`
preset lets the sandbox push to any repository it has credentials for. See
the [Security & Threat Model](../admin/security-model.md#presets-and-allow-files-are-allowlist-entries-too).

## Allow files

An allow file is a plain-text list of allowlist entries, one per line, in
the same forms `--allow` takes. Blank lines are ignored, and `#` starts a
comment:

```text
# team-hosts.txt
nexus.example.com:8443          # internal package mirror
https://gitlab.example.com
```

Use one with `--allow-file=team-hosts.txt` on `create` (repeatable; a
relative path is relative to the current directory), or with
`allowFile: team-hosts.txt` in a profile or a spec's `overrides`, where a
relative path is relative to *that profile or spec file's* directory, so it
keeps working wherever `agentctl` runs from (`~/` means your home directory
in either). Every entry is checked when the file is read: a bad line fails
the `create` with the file name and line number, rather than being
skipped. `agentctl profile show` prints a profile with its allow file's
entries already merged into `allow`.

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
fields (`allow` — including presets and allow files — `ports`, `mounts`)
accumulate rather than replace:

```console
$ agentctl create demo --profile=default --allow-preset=github --port=9000:9000
```

This applies the `default` profile's full allowlist plus the `github`
preset's hosts, and publishes port 9000 in addition to anything the profile
already defined.

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
