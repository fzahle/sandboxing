package profile

import (
	"errors"
	"fmt"
	"path"
	"strings"
)

// Validate checks a Profile for structural and semantic errors. It
// aggregates every problem found (via errors.Join) rather than stopping at
// the first, so a profile author sees the full list of issues in one pass.
func Validate(p *Profile) error {
	var errs []error

	if p.APIVersion != APIVersion {
		errs = append(errs, fmt.Errorf("apiVersion must be %q, got %q", APIVersion, p.APIVersion))
	}
	if p.Kind != Kind {
		errs = append(errs, fmt.Errorf("kind must be %q, got %q", Kind, p.Kind))
	}
	if strings.TrimSpace(p.Metadata.Name) == "" {
		errs = append(errs, errors.New("metadata.name is required"))
	}

	errs = append(errs, policyErrors(p.Spec)...)

	return errors.Join(errs...)
}

// ValidatePolicy checks a Policy on its own, outside a Profile document —
// e.g. a Spec's overrides — with the same rules Validate applies to a
// profile's spec.
func ValidatePolicy(p Policy) error {
	return errors.Join(policyErrors(p)...)
}

func policyErrors(p Policy) []error {
	var errs []error
	errs = append(errs, validateNetwork(p.Network)...)
	errs = append(errs, validateResources(p.Resources)...)
	errs = append(errs, validateMounts(p.Mounts)...)
	return errs
}

func validateNetwork(n NetworkPolicy) []error {
	var errs []error
	for _, rule := range n.Allow {
		d := rule.Domain
		if err := checkDomain(d); err != nil {
			errs = append(errs, fmt.Errorf("network.allow: %w", err))
		}
		for _, port := range rule.Ports {
			if port < 1 || port > 65535 {
				errs = append(errs, fmt.Errorf("network.allow: domain %q has out-of-range port %d", d, port))
			}
		}
	}
	for _, name := range n.AllowPresets {
		if _, ok := LookupPreset(name); !ok {
			errs = append(errs, fmt.Errorf("network.allowPresets: unknown preset %q (valid: %s)", name, strings.Join(PresetNames(), ", ")))
		}
	}

	seenHostPorts := make(map[string]bool)
	for _, pp := range n.Ports {
		if pp.Host < 1 || pp.Host > 65535 {
			errs = append(errs, fmt.Errorf("network.ports: host port %d out of range", pp.Host))
		}
		if pp.Guest < 1 || pp.Guest > 65535 {
			errs = append(errs, fmt.Errorf("network.ports: guest port %d out of range", pp.Guest))
		}
		proto := pp.Protocol
		if proto == "" {
			proto = "tcp"
		}
		if proto != "tcp" && proto != "udp" {
			errs = append(errs, fmt.Errorf("network.ports: unsupported protocol %q (want tcp or udp)", pp.Protocol))
		}
		key := fmt.Sprintf("%d/%s", pp.Host, proto)
		if seenHostPorts[key] {
			errs = append(errs, fmt.Errorf("network.ports: host port %d/%s published more than once", pp.Host, proto))
		}
		seenHostPorts[key] = true
	}
	return errs
}

func validateResources(r Resources) []error {
	var errs []error
	if r.CPUCores < 0 {
		errs = append(errs, fmt.Errorf("resources.cpuCores must not be negative, got %d", r.CPUCores))
	}
	if r.Memory != "" {
		if _, err := ParseSize(r.Memory); err != nil {
			errs = append(errs, fmt.Errorf("resources.memory: %w", err))
		}
	}
	if r.DiskSize != "" {
		if _, err := ParseSize(r.DiskSize); err != nil {
			errs = append(errs, fmt.Errorf("resources.diskSize: %w", err))
		}
	}
	return errs
}

func validateMounts(mounts []Mount) []error {
	var errs []error
	for i, m := range mounts {
		if strings.TrimSpace(m.HostPath) == "" {
			errs = append(errs, fmt.Errorf("mounts[%d]: hostPath must not be empty", i))
		}
		if !path.IsAbs(m.GuestPath) {
			errs = append(errs, fmt.Errorf("mounts[%d]: guestPath %q must be absolute", i, m.GuestPath))
		}
	}
	return errs
}
