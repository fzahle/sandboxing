// Package agent holds agentctl's static registry of coding agents that
// can be just-in-time installed into a freshly created sandbox via
// `agentctl create --agent=<name>`, instead of hand-typing an install
// command after `shell`-ing in. Shape mirrors internal/image: a small,
// static table, no external registry lookups.
package agent

import (
	"sort"

	"github.com/apomonosi/sandboxing/internal/profile"
)

// Spec describes one installable coding agent.
type Spec struct {
	Name string
	// InstallScript is a full shell command line (piped to `sh -c`, not
	// stdin) — each agent's own documented one-liner, verbatim.
	InstallScript string
	// EnvVar is the host API key environment variable this agent expects,
	// where the project has one obvious default. Unused until a future
	// mechanism forwards host env vars into the guest (out of scope for
	// this milestone); empty for agents with no single default provider.
	EnvVar string
	// AllowDomains are the extra egress allowlist entries this agent's
	// install and/or runtime needs, merged into the instance's network
	// policy by `create --agent=<name>` before the ACL is applied.
	AllowDomains []profile.AllowRule
}

// Registry is the static table of installable agents, keyed by the name
// passed to --agent. Install commands come from each project's own docs
// (https://code.claude.com/docs/en/quickstart,
// https://learn.chatgpt.com/docs/codex/cli, https://opencode.ai/download,
// https://pi.dev/).
//
// The hosts each agent needs live in the built-in allow preset of the same
// name (internal/profile/presets.go, which also records where each host
// list was checked), so `--allow-preset=<name>` allows exactly what
// `--agent=<name>` does, for when the agent gets installed some other way.
var Registry = map[string]Spec{
	"claude": {
		Name:          "claude",
		InstallScript: "curl -fsSL https://claude.ai/install.sh | bash",
		EnvVar:        "ANTHROPIC_API_KEY",
		AllowDomains:  presetRules("claude"),
	},
	"codex": {
		Name:          "codex",
		InstallScript: "curl -fsSL https://chatgpt.com/codex/install.sh | sh",
		EnvVar:        "OPENAI_API_KEY",
		AllowDomains:  presetRules("codex"),
	},
	"opencode": {
		Name:          "opencode",
		InstallScript: "curl -fsSL https://opencode.ai/install | bash",
		EnvVar:        "",
		AllowDomains:  presetRules("opencode"),
	},
	"pi": {
		Name:          "pi",
		InstallScript: "curl -fsSL https://pi.dev/install.sh | sh",
		EnvVar:        "ANTHROPIC_API_KEY",
		AllowDomains:  presetRules("pi"),
	},
}

// presetRules returns the allow rules of the built-in preset called name.
// The registry and the preset table are both static, so a missing preset
// is a build defect (and TestLookup_KnownAgents catches it), not a runtime
// condition.
func presetRules(name string) []profile.AllowRule {
	p, ok := profile.LookupPreset(name)
	if !ok {
		panic("agent: no built-in allow preset " + name)
	}
	return p.Allow
}

// Lookup returns the Spec for name and whether it was found.
func Lookup(name string) (Spec, bool) {
	s, ok := Registry[name]
	return s, ok
}

// Names returns every valid --agent value, sorted, for error messages.
func Names() []string {
	names := make([]string, 0, len(Registry))
	for n := range Registry {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
