package agent

import (
	"net/url"
	"regexp"
	"slices"
	"testing"

	"github.com/apomonosi/sandboxing/internal/profile"
)

// allowsExactly reports whether rules has an entry naming host itself (not
// via a wildcard: on Incus "*.example.com" only resolves the apex) with
// port 443 among its ports.
func allowsExactly(rules []profile.AllowRule, host string) bool {
	for _, r := range rules {
		if r.Domain == host && slices.Contains(r.Ports, 443) {
			return true
		}
	}
	return false
}

// TestRegistry_InstallHostAllowlisted guards the failure mode where an
// agent's own installer can't be fetched under default-deny egress: the
// host in each InstallScript's URL must be on that agent's allowlist.
func TestRegistry_InstallHostAllowlisted(t *testing.T) {
	urlRE := regexp.MustCompile(`https://[^\s|]+`)
	for name, spec := range Registry {
		raw := urlRE.FindString(spec.InstallScript)
		if raw == "" {
			t.Errorf("%s: no https:// URL in InstallScript %q", name, spec.InstallScript)
			continue
		}
		u, err := url.Parse(raw)
		if err != nil {
			t.Errorf("%s: parsing %q: %v", name, raw, err)
			continue
		}
		if !allowsExactly(spec.AllowDomains, u.Hostname()) {
			t.Errorf("%s: install host %s:443 is not in AllowDomains %+v", name, u.Hostname(), spec.AllowDomains)
		}
	}
}

// TestRegistry_RequiredHosts pins the hosts each agent's installer
// downloads from or its sign-in depends on (see Registry's doc comment for
// where each comes from) — every one of them was missing once, which made
// `create --agent` fail with egress enforced.
func TestRegistry_RequiredHosts(t *testing.T) {
	required := map[string][]string{
		"claude":   {"claude.ai", "downloads.claude.ai", "platform.claude.com", "api.anthropic.com"},
		"codex":    {"chatgpt.com", "releases.openai.com", "auth.openai.com", "api.openai.com"},
		"opencode": {"opencode.ai", "github.com", "api.github.com", "release-assets.githubusercontent.com"},
		"pi":       {"pi.dev", "registry.npmjs.org", "nodejs.org", "api.anthropic.com"},
	}
	for name, hosts := range required {
		spec, ok := Lookup(name)
		if !ok {
			t.Fatalf("Lookup(%q): not found", name)
		}
		for _, h := range hosts {
			if !allowsExactly(spec.AllowDomains, h) {
				t.Errorf("%s: %s:443 is not in AllowDomains %+v", name, h, spec.AllowDomains)
			}
		}
	}
}

func TestLookup_KnownAgents(t *testing.T) {
	for _, name := range []string{"claude", "codex", "opencode", "pi"} {
		spec, ok := Lookup(name)
		if !ok {
			t.Fatalf("Lookup(%q): expected ok=true", name)
		}
		if spec.Name != name {
			t.Errorf("Lookup(%q).Name = %q", name, spec.Name)
		}
		if spec.InstallScript == "" {
			t.Errorf("Lookup(%q).InstallScript is empty", name)
		}
		if len(spec.AllowDomains) == 0 {
			t.Errorf("Lookup(%q).AllowDomains is empty", name)
		}
		for _, rule := range spec.AllowDomains {
			if rule.Domain == "" {
				t.Errorf("Lookup(%q): AllowRule with empty domain", name)
			}
			if len(rule.Ports) == 0 {
				t.Errorf("Lookup(%q): AllowRule %q has no ports", name, rule.Domain)
			}
		}
	}
}

func TestLookup_Unknown(t *testing.T) {
	if _, ok := Lookup("nonexistent"); ok {
		t.Error("Lookup(\"nonexistent\") should return ok=false")
	}
}

func TestNames_SortedAndComplete(t *testing.T) {
	got := Names()
	want := []string{"claude", "codex", "opencode", "pi"}
	if len(got) != len(want) {
		t.Fatalf("Names() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Names()[%d] = %q, want %q (must be sorted)", i, got[i], want[i])
		}
	}
}
