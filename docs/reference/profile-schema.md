# Profile Schema Reference

Source of truth: `internal/profile/schema.go`. This page mirrors it field by
field; if they drift, the Go source wins.

```yaml
apiVersion: agentctl.dev/v1   # required, must be exactly this value
kind: Profile                 # required, must be exactly this value
metadata:
  name: string                # required
  description: string         # optional
spec:
  network:
    denyLAN: bool              # default true in the embedded built-ins; blocks
                                # RFC1918 (10/8, 172.16/12, 192.168/16) and
                                # link-local (169.254/16) egress
    allow:                      # egress allowlist; everything unmatched is denied
      - domain: string          # hostname, "*.example.com" wildcard (on Incus
                                 # only the apex domain gets resolved and
                                 # matched — see the security model doc), or
                                 # IP address; not a URL
        ports: [int]            # optional; TCP ports allowed for this domain
                                 # (omitted: any port)
    allowPresets: [string]       # optional; built-in host groups added to the
                                  # allowlist: apk, apt, github, gitlab, npm,
                                  # pypi, and claude, codex, opencode, pi
                                  # (`agentctl profile presets` lists them;
                                  # mirrors --allow-preset)
    allowFile: string            # optional; an allow file whose entries are
                                  # added to `allow` when this file is loaded
                                  # (format below; mirrors --allow-file)
    ports:                       # host:guest port publishes, Docker-style
      - host: int
        guest: int
        protocol: string        # "tcp" (default) or "udp"
  resources:
    cpuCores: int               # must be >= 0
    memory: string              # size string, e.g. "4GiB", "512MiB", "20GB"
    diskSize: string            # size string, same format as memory
  mounts:
    - hostPath: string           # supports "~" expansion and a "{{.Name}}"
                                  # template substituted with the instance name
      guestPath: string          # must be an absolute path
      readOnly: bool
  console:
    viewer: string               # advisory: "spice" | "vnc" | "native" — the
                                  # provider decides the actual mechanism it's
                                  # capable of; see view-and-console.md
```

## Allow presets

Each `allowPresets` name stands for a fixed list of allow rules, defined in
`internal/profile/presets.go` and added after the profile's own `allow`
entries when the policy is applied. Run `agentctl profile presets` to see
every preset's hosts and ports; [Profiles & Policies](../user/profiles-and-policies.md#allowing-package-sources-and-git-hosts)
covers what each is for. A profile shows (`profile show`) and merges presets
by name, so a newer `agentctl` that updates a preset's hosts applies the
update to existing profiles.

## Allow file format

`allowFile` (and `create --allow-file`) name a plain-text file with one
allowlist entry per line, in the same forms `--allow` accepts
(`example.com:443`, `example.com:80,443`, `*.example.com`,
`[2001:db8::1]:443`, `https://example.com`, ...; see
[Profiles & Policies](../user/profiles-and-policies.md#egress-allowlist)).
Blank lines are ignored and `#` starts a comment.

- A relative `allowFile` path is resolved against the directory of the
  profile or spec file that names it, and `~/` against your home
  directory. (`--allow-file` paths are relative to the current directory.)
- The file is read when the profile or spec is loaded: its entries are
  appended to `allow`, and `allowFile` is cleared — so `agentctl profile
  show` prints the merged rules — and a missing file or invalid line is a
  load error naming the file and line.
- An embedded built-in profile can't use `allowFile`; there's no
  directory for a relative path to be relative to.

## Size string format

Parsed by `internal/profile.ParseSize`. Accepts binary units (`KiB`, `MiB`,
`GiB`, `TiB`), decimal units (`KB`, `MB`, `GB`, `TB`), or a plain integer
byte count. Must be positive; zero and negative sizes are rejected.

## Validation

`internal/profile.Validate` aggregates every problem found in one pass
(rather than stopping at the first) and checks:

- `apiVersion`/`kind` match the constants above
- `metadata.name` is non-empty
- Every `allow[].domain` is a valid hostname, `*.`-wildcard hostname, or IP
  address — not a URL, address range, or `host:port` (all of which no
  backend could ever match); every `allow[].ports` entry is in `1..65535`
- Every `allowPresets` entry names a built-in preset
- Every `ports[].host`/`ports[].guest` is in `1..65535`; `protocol` is `tcp`
  or `udp`; no two `ports` entries publish the same host port + protocol
- `resources.cpuCores >= 0`; `resources.memory`/`diskSize`, if set, parse via
  `ParseSize`
- Every `mounts[].hostPath` is non-empty; every `mounts[].guestPath` is
  absolute

## Strict decoding

Profiles are decoded with unknown fields rejected — see
[Profiles & Policies](../user/profiles-and-policies.md#strict-decoding) for
why.

## Merging

`internal/profile.Merge(base, override Policy) Policy` combines a loaded
profile with ad-hoc `create` flags:

- `network.allow`, `network.ports`, `mounts`: **additive union** — override
  entries are appended after base's
- `network.allowPresets`: **union**, each preset once
- `network.allowFile` doesn't take part: by the time profiles are merged,
  each one's allow file has already been read into its `allow`
- `network.denyLAN`: override's value is taken as-is (the CLI resolves
  `--deny-lan`/`--allow-lan` against the profile's value before calling Merge)
- `resources.*`, `console.viewer`: override's value wins whenever it's
  non-zero/non-empty, otherwise base's value survives

## The Spec document (`create --spec=<file>`)

A separate, smaller document (`internal/spec.Spec`) describes one specific
`create` invocation rather than a reusable profile:

```yaml
apiVersion: agentctl.dev/v1
kind: Spec
metadata:
  name: string          # informational; the CLI's <name> argument always wins
spec:
  image: string          # required
  profiles: [string]     # named profiles to apply, in order
  overrides: Policy       # same Policy shape as a profile's spec, layered on
                          # top of the named profiles via Merge
```

`overrides` is validated with the same rules as a profile's `spec`, and its
`network.allowFile`, if set, is resolved against the spec file's directory.
