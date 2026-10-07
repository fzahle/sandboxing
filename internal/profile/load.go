package profile

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// LoadBytes parses a Profile from raw YAML using strict decoding: unknown
// fields are a load error, not silently ignored. This is a security policy
// file — a typo'd field (e.g. "denyLan" instead of "denyLAN") should never
// fail open.
//
// Raw YAML has no location for a relative allowFile to be resolved
// against, so LoadBytes leaves it unexpanded; LoadFile expands it.
func LoadBytes(data []byte) (*Profile, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var p Profile
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("parsing profile: %w", err)
	}
	if err := Validate(&p); err != nil {
		return nil, err
	}
	return &p, nil
}

// LoadFile reads and parses a Profile from a path, appending the entries
// of its allowFile, if it names one (resolved relative to the profile's
// own directory), to its allow rules.
func LoadFile(path string) (*Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading profile %s: %w", path, err)
	}
	p, err := LoadBytes(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := p.Spec.Network.ExpandAllowFile(filepath.Dir(path)); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return p, nil
}

// SearchPaths returns the ordered list of directories LoadNamed checks for
// "<name>.yaml", before falling back to embedded built-ins. profileDir is
// the org-distributed directory from config (empty if unset).
func SearchPaths(profileDir string) []string {
	paths := []string{filepath.Join(".", ".agentctl", "profiles")}
	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths, filepath.Join(home, ".config", "agentctl", "profiles"))
	}
	if profileDir != "" {
		paths = append(paths, profileDir)
	}
	return paths
}

// LoadNamed resolves "name" against SearchPaths(profileDir) in order, then
// falls back to the embedded built-in profiles (Builtin).
func LoadNamed(name, profileDir string) (*Profile, error) {
	for _, dir := range SearchPaths(profileDir) {
		candidate := filepath.Join(dir, name+".yaml")
		if _, err := os.Stat(candidate); err == nil {
			return LoadFile(candidate)
		}
	}
	if data, ok := builtinProfiles[name]; ok {
		return LoadBytes(data)
	}
	return nil, fmt.Errorf("profile %q not found (searched %v, and built-ins)", name, SearchPaths(profileDir))
}
