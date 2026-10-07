package profile

import (
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestPresets_WellFormed(t *testing.T) {
	names := PresetNames()
	if !slices.IsSorted(names) {
		t.Errorf("PresetNames() = %v, want sorted", names)
	}
	if len(slices.Compact(slices.Clone(names))) != len(names) {
		t.Errorf("PresetNames() = %v has duplicates", names)
	}
	for _, p := range Presets() {
		if p.Description == "" {
			t.Errorf("preset %q has no description", p.Name)
		}
		if len(p.Allow) == 0 {
			t.Errorf("preset %q allows nothing", p.Name)
		}
		for _, r := range p.Allow {
			if err := checkDomain(r.Domain); err != nil {
				t.Errorf("preset %q: %v", p.Name, err)
			}
			// Incus resolves a wildcard's apex only, so a preset that
			// relied on one would silently do less there than on Lima: a
			// wildcard may only be an extra on top of the hosts under it
			// that the preset needs, listed by name.
			if apex, ok := strings.CutPrefix(r.Domain, "*."); ok {
				named := slices.ContainsFunc(p.Allow, func(o AllowRule) bool {
					return !strings.HasPrefix(o.Domain, "*.") && strings.HasSuffix(o.Domain, "."+apex)
				})
				if !named {
					t.Errorf("preset %q: wildcard %q with no host under it listed by name; on Incus it would only cover %s", p.Name, r.Domain, apex)
				}
			}
			if len(r.Ports) == 0 {
				t.Errorf("preset %q: %s allows every port; presets should name theirs", p.Name, r.Domain)
			}
		}
	}
}

// TestPresets_Hosts pins what the presets the docs promise cover — e.g.
// pip needs files.pythonhosted.org as well as pypi.org, and GitHub release
// downloads redirect to release-assets.githubusercontent.com.
func TestPresets_Hosts(t *testing.T) {
	want := map[string][]string{
		"apt":    {"archive.ubuntu.com:80", "security.ubuntu.com:80", "ports.ubuntu.com:80", "deb.debian.org:80"},
		"apk":    {"dl-cdn.alpinelinux.org:443"},
		"pypi":   {"pypi.org:443", "files.pythonhosted.org:443"},
		"npm":    {"registry.npmjs.org:443"},
		"github": {"github.com:443", "api.github.com:443", "codeload.github.com:443", "raw.githubusercontent.com:443", "release-assets.githubusercontent.com:443"},
		"gitlab": {"gitlab.com:443"},
	}
	for name, hostPorts := range want {
		p, ok := LookupPreset(name)
		if !ok {
			t.Errorf("preset %q missing", name)
			continue
		}
		for _, hp := range hostPorts {
			host, portStr, _ := strings.Cut(hp, ":")
			port, err := strconv.Atoi(portStr)
			if err != nil {
				t.Fatalf("bad test entry %q", hp)
			}
			if !slices.ContainsFunc(p.Allow, func(r AllowRule) bool {
				return r.Domain == host && slices.Contains(r.Ports, port)
			}) {
				t.Errorf("preset %q doesn't allow %s", name, hp)
			}
		}
	}
}

func TestLookupPreset_ReturnsACopy(t *testing.T) {
	p, _ := LookupPreset("pypi")
	p.Allow[0].Domain = "evil.example.com"
	p.Allow[0].Ports[0] = 1
	again, _ := LookupPreset("pypi")
	if again.Allow[0].Domain != "pypi.org" || again.Allow[0].Ports[0] != 443 {
		t.Errorf("modifying a looked-up preset changed the built-in table: %+v", again.Allow[0])
	}
	if _, ok := LookupPreset("PyPI"); ok {
		t.Error("preset names should match exactly")
	}
}

func TestAllowRules_ExpandsPresetsAfterExplicitRules(t *testing.T) {
	n := NetworkPolicy{
		Allow:        []AllowRule{{Domain: "example.com", Ports: []int{443}}},
		AllowPresets: []string{"pypi", "no-such-preset"},
	}
	got := n.AllowRules()
	want := []AllowRule{
		{Domain: "example.com", Ports: []int{443}},
		{Domain: "pypi.org", Ports: []int{443}},
		{Domain: "files.pythonhosted.org", Ports: []int{443}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("AllowRules() = %+v, want %+v", got, want)
	}

	pnp := n.ToProviderNetworkPolicy()
	if len(pnp.Allow) != len(want) || pnp.Allow[1].Domain != "pypi.org" {
		t.Errorf("ToProviderNetworkPolicy().Allow = %+v, want the presets expanded", pnp.Allow)
	}
}

func TestValidate_UnknownPreset(t *testing.T) {
	p := &Profile{
		APIVersion: APIVersion, Kind: Kind, Metadata: Metadata{Name: "x"},
		Spec: Policy{Network: NetworkPolicy{AllowPresets: []string{"pypi", "pipy"}}},
	}
	err := Validate(p)
	if err == nil {
		t.Fatal("Validate accepted an unknown preset")
	}
	if !strings.Contains(err.Error(), `"pipy"`) || !strings.Contains(err.Error(), "pypi") {
		t.Errorf("error %q should name the bad preset and list the valid ones", err)
	}
}

func TestMerge_UnionsPresets(t *testing.T) {
	base := Policy{Network: NetworkPolicy{AllowPresets: []string{"apt", "pypi"}}}
	override := Policy{Network: NetworkPolicy{AllowPresets: []string{"pypi", "github"}}}
	got := Merge(base, override).Network.AllowPresets
	if want := []string{"apt", "pypi", "github"}; !reflect.DeepEqual(got, want) {
		t.Errorf("merged AllowPresets = %v, want %v", got, want)
	}
	if !reflect.DeepEqual(base.Network.AllowPresets, []string{"apt", "pypi"}) {
		t.Errorf("Merge modified base: %v", base.Network.AllowPresets)
	}
}
