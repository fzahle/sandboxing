package cli

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/apomonosi/sandboxing/internal/profile"
)

// parsePortFlag parses a Docker-style "--port host:guest[/proto]" value.
func parsePortFlag(s string) (profile.PortPublish, error) {
	proto := "tcp"
	spec := s
	if i := strings.LastIndex(s, "/"); i != -1 {
		proto = s[i+1:]
		spec = s[:i]
	}
	parts := strings.SplitN(spec, ":", 2)
	if len(parts) != 2 {
		return profile.PortPublish{}, fmt.Errorf("invalid --port %q: want host:guest[/proto]", s)
	}
	host, err := strconv.Atoi(parts[0])
	if err != nil {
		return profile.PortPublish{}, fmt.Errorf("invalid --port %q: host port %q is not a number", s, parts[0])
	}
	guest, err := strconv.Atoi(parts[1])
	if err != nil {
		return profile.PortPublish{}, fmt.Errorf("invalid --port %q: guest port %q is not a number", s, parts[1])
	}
	return profile.PortPublish{Host: host, Guest: guest, Protocol: proto}, nil
}

// allowFlagRules turns create's egress flags into allow rules and preset
// names: each --allow entry (see profile.ParseAllowEntry) and the entries
// of each --allow-file, in that order, plus the --allow-preset names,
// checked against the built-in presets. Everything is checked before
// create does anything, so a typo can't leave a half-made instance.
func allowFlagRules(allow, allowFiles, presets []string) ([]profile.AllowRule, []string, error) {
	var rules []profile.AllowRule
	for _, a := range allow {
		rule, err := profile.ParseAllowEntry(a)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid --allow %q: %w", a, err)
		}
		rules = append(rules, rule)
	}
	for _, f := range allowFiles {
		path, err := profile.ResolvePath(f, "")
		if err != nil {
			return nil, nil, fmt.Errorf("--allow-file: %w", err)
		}
		fileRules, err := profile.ReadAllowFile(path)
		if err != nil {
			return nil, nil, fmt.Errorf("--allow-file: %w", err)
		}
		rules = append(rules, fileRules...)
	}
	for _, name := range presets {
		if _, ok := profile.LookupPreset(name); !ok {
			return nil, nil, fmt.Errorf("unknown --allow-preset %q (valid: %s; see `agentctl profile presets`)", name, strings.Join(profile.PresetNames(), ", "))
		}
	}
	return rules, presets, nil
}
