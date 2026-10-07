# Distributing Profiles Org-Wide

There's no dedicated profile registry or signing service in this milestone —
the convention is deliberately simple: a shared directory (or a git repo
checked out to a known path) of profile YAML files, referenced via
`agentctl`'s `profileDir` config.

## Setup

1. Create a directory (or repo) of profile YAML files, one per use case:

   ```text
   org-profiles/
     default.yaml       # baseline for most users
     strict.yaml         # no pre-approved allowlist at all
     data-science.yaml   # broader package-registry access
     browser-agent.yaml  # console viewer defaults tuned for GUI agents
   ```

   Each file follows the schema in [Profile Schema](../reference/profile-schema.md).

2. Distribute the path to users (a shared network mount, or a documented
   `git clone` location) and have them run:

   ```console
   $ agentctl config set profileDir=/path/to/org-profiles
   $ agentctl config set defaultProfile=default
   ```

3. `agentctl profile list` / `agentctl profile show <name>` then resolve
   against this directory (after project-local and personal profile
   directories — see [Authoring Profiles & Policies](../user/profiles-and-policies.md#where-profiles-live)
   — and before the embedded built-ins).

## Recommended practice

- Version the profile directory in git so changes are reviewable and
  revertible, same as any other security policy.
- Treat `denyLAN: false` (or `--allow-lan`) profiles as requiring extra
  review — they're the one setting that opts out of the LAN
  lateral-movement protection this whole tool exists to provide.
- Keep a `strict` profile (empty allowlist) available as the safe default for
  anyone unsure what a task needs, and let users add `--allow` entries
  per-invocation rather than widening a shared profile for one use case.
- Prefer `allowPresets` (e.g. `[apt, pypi, github]`) to hand-copied host
  lists for public package sources; for hosts of your own (internal
  mirrors, a self-hosted GitLab), keep one
  [allow file](../user/profiles-and-policies.md#allow-files) in the profile
  directory and point several profiles at it with `allowFile:` — a
  relative path resolves against the profile's own directory, so it works
  wherever the directory is checked out.

## Not built yet

A signed/verified profile distribution mechanism, automatic profile-directory
sync, and any kind of central audit of who's using which profile are all out
of scope for this milestone. The directory-of-YAML-files convention above is
the whole mechanism for now.
