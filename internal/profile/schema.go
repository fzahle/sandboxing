// Package profile defines the YAML schema for agentctl's reusable,
// named security profiles: bundles of network policy, resource limits,
// and mount policy that admins author once and users reference by name
// (agentctl create --profile=default). A profile is the org-wide,
// distributable policy artifact; internal/spec's InstanceSpec is what one
// specific `create` invocation produces after merging a profile with any
// ad-hoc flags.
package profile

import "github.com/apomonosi/sandboxing/internal/provider"

// APIVersion and Kind are the only accepted values today. Checking them on
// load is a forward-compatibility guard, not current versioning support.
const (
	APIVersion = "agentctl.dev/v1"
	Kind       = "Profile"
)

// Profile is the top-level YAML document.
type Profile struct {
	APIVersion string   `yaml:"apiVersion"`
	Kind       string   `yaml:"kind"`
	Metadata   Metadata `yaml:"metadata"`
	Spec       Policy   `yaml:"spec"`
}

type Metadata struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
}

// Policy is the reusable payload: everything a Profile bundles, and also
// what an ad-hoc `create` invocation's flags produce as an override layer
// (see Merge).
type Policy struct {
	Network   NetworkPolicy `yaml:"network"`
	Resources Resources     `yaml:"resources"`
	Mounts    []Mount       `yaml:"mounts"`
	Console   Console       `yaml:"console"`
}

type NetworkPolicy struct {
	// DenyLAN blocks egress to RFC1918/link-local ranges so a sandbox
	// can't reach other devices on the same network. Defaults to true;
	// profiles/flags must opt out explicitly (--allow-lan).
	DenyLAN bool `yaml:"denyLAN"`
	// Allow is the egress allowlist; everything not matched is denied.
	Allow []AllowRule `yaml:"allow"`
	// AllowPresets names built-in groups of allow rules (see Presets),
	// added to Allow when the policy is applied (--allow-preset).
	AllowPresets []string `yaml:"allowPresets"`
	// AllowFile optionally points at an allow file (see ReadAllowFile)
	// whose entries are appended to Allow when the profile or spec naming
	// it is loaded (see ExpandAllowFile), so it's empty after loading. A
	// relative path is relative to that profile or spec file's directory.
	AllowFile string `yaml:"allowFile"`
	// Ports are host:guest port publishes, Docker-style.
	Ports []PortPublish `yaml:"ports"`
}

type AllowRule struct {
	Domain string `yaml:"domain"`
	Ports  []int  `yaml:"ports"`
}

type PortPublish struct {
	Host     int    `yaml:"host"`
	Guest    int    `yaml:"guest"`
	Protocol string `yaml:"protocol"` // "tcp" (default) or "udp"
}

type Resources struct {
	CPUCores int    `yaml:"cpuCores"`
	Memory   string `yaml:"memory"`   // e.g. "4GiB"
	DiskSize string `yaml:"diskSize"` // e.g. "20GiB"
}

type Mount struct {
	// HostPath supports "~" expansion and a "{{.Name}}" template
	// substituted with the instance name at create time.
	HostPath  string `yaml:"hostPath"`
	GuestPath string `yaml:"guestPath"`
	ReadOnly  bool   `yaml:"readOnly"`
}

type Console struct {
	// Viewer is advisory ("spice" | "vnc" | "native"); the provider
	// decides the actual mechanism it's capable of.
	Viewer string `yaml:"viewer"`
}

// AllowRules returns the complete egress allowlist: the Allow rules, then
// those of each preset in AllowPresets. An unknown preset name adds
// nothing (Validate reports those).
func (n NetworkPolicy) AllowRules() []AllowRule {
	rules := append([]AllowRule(nil), n.Allow...)
	for _, name := range n.AllowPresets {
		if p, ok := LookupPreset(name); ok {
			rules = append(rules, p.Allow...)
		}
	}
	return rules
}

// ToProviderNetworkPolicy converts the profile's network section into the
// provider-agnostic type Provider.ApplyNetworkPolicy expects, with
// AllowPresets expanded (see AllowRules).
func (n NetworkPolicy) ToProviderNetworkPolicy() provider.NetworkPolicy {
	rules := n.AllowRules()
	allow := make([]provider.AllowRule, len(rules))
	for i, a := range rules {
		allow[i] = provider.AllowRule{Domain: a.Domain, Ports: append([]int(nil), a.Ports...)}
	}
	ports := make([]provider.PortPublish, len(n.Ports))
	for i, p := range n.Ports {
		proto := p.Protocol
		if proto == "" {
			proto = "tcp"
		}
		ports[i] = provider.PortPublish{HostPort: p.Host, GuestPort: p.Guest, Protocol: proto}
	}
	return provider.NetworkPolicy{DenyLAN: n.DenyLAN, Allow: allow, Ports: ports}
}

// ToProviderResourceLimits converts Resources into provider.ResourceLimits.
func (r Resources) ToProviderResourceLimits() provider.ResourceLimits {
	return provider.ResourceLimits{CPUCores: r.CPUCores, Memory: r.Memory, DiskSize: r.DiskSize}
}

// ToProviderMounts converts a Mount slice into provider.Mount.
func ToProviderMounts(mounts []Mount) []provider.Mount {
	out := make([]provider.Mount, len(mounts))
	for i, m := range mounts {
		out[i] = provider.Mount{HostPath: m.HostPath, GuestPath: m.GuestPath, ReadOnly: m.ReadOnly}
	}
	return out
}
