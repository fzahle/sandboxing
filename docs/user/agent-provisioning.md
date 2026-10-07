# Agent Provisioning

`agentctl create --agent=<name>` just-in-time installs a coding agent into a
freshly created sandbox, instead of you hand-typing its install command
after `shell`-ing in.

```console
$ agentctl create demo --image=images:ubuntu/24.04 --agent=claude
agentctl: installing claude...
...
$ agentctl shell demo
$ claude --version
```

## What `--agent` does

1. Looks up `<name>` in agentctl's built-in registry (see below). An
   unrecognized name fails immediately, before anything is created, and
   lists the valid names.
2. Merges that agent's required egress allow-domains into the instance's
   network policy, so the install and the agent's own runtime API calls
   aren't blocked by the default-deny egress policy — no separate `--allow`
   needed for the common case.
3. Sets the instance's [default non-root user](profiles-and-policies.md#default-non-root-user)
   to the agent's name (e.g. `--agent=claude` creates and runs as a `claude`
   user), unless you're already relying on a different default elsewhere.
4. Because installing requires a *running*, agent-ready instance while
   `create` normally leaves the instance stopped, `--agent` implies
   `start` — you get back a running instance, not a stopped one.
5. Runs the agent's install command as that non-root user, streaming its
   output to your terminal.

## Built-in registry

| `--agent` value | Installs | Host API key it expects | Egress allowed (port 443) |
|---|---|---|---|
| `claude` | Claude Code | `ANTHROPIC_API_KEY` | `claude.ai`, `downloads.claude.ai`, `platform.claude.com`, `api.anthropic.com`, `*.anthropic.com` |
| `codex` | OpenAI Codex CLI | `OPENAI_API_KEY` | `chatgpt.com`, `releases.openai.com`, `auth.openai.com`, `api.openai.com` |
| `opencode` | opencode | *(multi-provider — none)* | `opencode.ai`, `github.com`, `api.github.com`, `release-assets.githubusercontent.com`, `models.opencode.ai` |
| `pi` | pi | `ANTHROPIC_API_KEY` *(default provider)* | `pi.dev`, `registry.npmjs.org`, `nodejs.org`, `api.anthropic.com`, `*.anthropic.com` |

Each list covers what the installer itself fetches — install scripts
typically download the actual program from a *different* host, which is
why there's more here than one domain per agent — plus what the agent needs
to sign in and talk to its default model provider:

- **claude**: `claude.ai/install.sh` downloads Claude Code from
  `downloads.claude.ai` (also where its auto-updates come from). Signing in
  with either a claude.ai or a Console account exchanges and refreshes its
  OAuth token with `platform.claude.com`; the API itself is
  `api.anthropic.com`. Source: Claude Code's
  [network access requirements](https://code.claude.com/docs/en/network-config#network-access-requirements).
- **codex**: the installer downloads from `releases.openai.com`; signing in
  with ChatGPT goes through `auth.openai.com`, ChatGPT-plan usage through
  `chatgpt.com`, API-key usage through `api.openai.com`.
- **opencode**: the installer looks the latest release up on
  `api.github.com` and downloads it from `github.com`, which redirects to
  `release-assets.githubusercontent.com`; opencode fetches its model
  catalog from `models.opencode.ai` at startup.
- **pi**: the installer installs pi from the npm registry, installing
  Node.js first if the image doesn't have it (stock Ubuntu images don't).
  `nodejs.org` is agentctl's assumption about where that Node.js download
  comes from, not something read out of pi's installer — if `--agent=pi`
  fails on a blocked host, the install output names it; add it with
  `--allow`.

Wildcards (`*.anthropic.com`) only help on Lima, whose egress proxy matches
hostnames; Incus resolves just the wildcard's apex domain (see
[Profiles & Policies](profiles-and-policies.md#egress-allowlist)), which is
why every host a step needs is also listed by name.

`opencode` and `pi` are explicitly multi-provider tools: `opencode` connects
to whichever model backend you configure inside the sandbox, and `pi`
defaults to Anthropic but also supports others. Their table entries above
only guarantee installing them (`pi` additionally covers its
default provider) — if you point either at a different
model provider, extend the allowlist the same way you would for anything
else: `agentctl create demo --agent=opencode --allow=<your-provider-domain>:443`.

`--agent` only opens what the agent needs. If it will also install
packages or clone repositories, allow those sources too — e.g.
`--allow-preset=github,pypi` (see
[Profiles & Policies](profiles-and-policies.md#allowing-package-sources-and-git-hosts)).

## Allowing an agent without `--agent`

Each agent's hosts are also an allow preset of the same name, so
`--allow-preset=claude` (or `allowPresets: [claude]` in a profile) allows
exactly what `--agent=claude` does without installing anything — for an
image that already has the agent, installing it some other way, or an
org profile meant for Claude Code work:

```console
$ agentctl create demo --image=images:ubuntu/24.04 --allow-preset=claude,apt,github
$ agentctl start demo
$ agentctl exec demo -- sh -c 'curl -fsSL https://claude.ai/install.sh | bash'
```

## What it doesn't do (yet)

Forwarding a host API key (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, ...) into
the guest is a separate, not-yet-built mechanism — `--agent` installs the
agent binary, it doesn't configure credentials for you. Set the key inside
the sandbox the same way you would on any machine (an env var, a config
file, whatever the agent's own docs say) after `shell`-ing in.

## If install fails partway

A transient failure during install (e.g. a flaky network mid-`curl`) isn't
silently swallowed: `create --agent=<name>` returns a real error, and the
instance is left running with the failure recorded. The next
`agentctl start <name>` (even a completely ordinary one, with no `--agent`
flag) detects the incomplete install and retries it automatically before
doing anything else — see
[Troubleshooting](troubleshooting.md#agent-install-fails-or-never-finishes)
for details. A plain `create` (no `--agent`) is entirely unaffected by any
of this.

Where that "was an install requested, did it finish" state actually lives
differs per provider: on Incus it's recorded on the instance itself (via
`incus config get <name> user.agentctl-agent`), so the backend's own
per-instance config stays the single source of truth. Lima has no
equivalent per-instance custom-metadata primitive, so on Lima this state
lives in a small local file instead, `~/.config/agentctl/lima-state.yaml`
(or next to whatever `AGENTCTL_CONFIG` points at) — see
`internal/provider/lima/state.go`. This only matters if you're inspecting
or scripting around this state directly; `agentctl start`'s retry
behavior above is identical either way.
