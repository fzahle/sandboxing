// Package spec defines the per-instance "what to create" document used by
// `agentctl create --spec=file.yaml`, and the glue that resolves it (plus
// any named --profile references and ad-hoc flags) into a
// provider.InstanceSpec ready to hand to a Provider.
//
// A profile.Profile is the reusable, admin-authored policy bundle; a Spec
// is what one specific `create` invocation asks for — an image, a name,
// which profile(s) to apply, and any instance-specific overrides layered
// on top via profile.Merge.
package spec

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/apomonosi/sandboxing/internal/profile"
	"github.com/apomonosi/sandboxing/internal/provider"
)

const (
	APIVersion = "agentctl.dev/v1"
	Kind       = "Spec"
)

// Spec is the top-level YAML document for --spec=file.yaml.
type Spec struct {
	APIVersion string   `yaml:"apiVersion"`
	Kind       string   `yaml:"kind"`
	Metadata   Metadata `yaml:"metadata"`
	Body       Body     `yaml:"spec"`
}

type Metadata struct {
	Name string `yaml:"name"`
}

type Body struct {
	Image     string         `yaml:"image"`
	Profiles  []string       `yaml:"profiles"`
	Overrides profile.Policy `yaml:"overrides"`
}

// LoadFile parses a Spec document from path with strict decoding,
// validating its overrides the way a profile's spec is validated and
// expanding their allowFile, if any (see profile.LoadFile).
func LoadFile(path string) (*Spec, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading spec %s: %w", path, err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var s Spec
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("parsing spec %s: %w", path, err)
	}
	if s.APIVersion != APIVersion {
		return nil, fmt.Errorf("%s: apiVersion must be %q, got %q", path, APIVersion, s.APIVersion)
	}
	if s.Kind != Kind {
		return nil, fmt.Errorf("%s: kind must be %q, got %q", path, Kind, s.Kind)
	}
	if s.Metadata.Name == "" {
		return nil, fmt.Errorf("%s: metadata.name is required", path)
	}
	if s.Body.Image == "" {
		return nil, fmt.Errorf("%s: spec.image is required", path)
	}
	if err := profile.ValidatePolicy(s.Body.Overrides); err != nil {
		return nil, fmt.Errorf("%s: spec.overrides: %w", path, err)
	}
	// A relative allowFile is relative to the spec's own directory, the
	// same rule profiles follow.
	if err := s.Body.Overrides.Network.ExpandAllowFile(filepath.Dir(path)); err != nil {
		return nil, fmt.Errorf("%s: spec.overrides: %w", path, err)
	}
	return &s, nil
}

// ResolvePolicy loads each named profile (in order, from profileDir's
// search paths) and merges them, then layers overrides on top. Later
// profiles and overrides win on conflicting scalar fields; list fields
// (allow rules, ports, mounts) accumulate — see profile.Merge.
func ResolvePolicy(profileNames []string, profileDir string, overrides profile.Policy) (profile.Policy, error) {
	var merged profile.Policy
	for _, name := range profileNames {
		p, err := profile.LoadNamed(name, profileDir)
		if err != nil {
			return profile.Policy{}, fmt.Errorf("resolving profile %q: %w", name, err)
		}
		merged = profile.Merge(merged, p.Spec)
	}
	merged = profile.Merge(merged, overrides)
	return merged, nil
}

// ToInstanceSpec converts a resolved name/image/policy into the
// provider-facing InstanceSpec.
func ToInstanceSpec(name, image string, profileNames []string, policy profile.Policy) provider.InstanceSpec {
	return provider.InstanceSpec{
		Name:      name,
		Image:     image,
		Profiles:  profileNames,
		Overrides: policy.Network.ToProviderNetworkPolicy(),
		Resources: policy.Resources.ToProviderResourceLimits(),
		Mounts:    profile.ToProviderMounts(policy.Mounts),
	}
}
