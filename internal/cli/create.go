package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/apomonosi/sandboxing/internal/agent"
	"github.com/apomonosi/sandboxing/internal/profile"
	"github.com/apomonosi/sandboxing/internal/provider"
	"github.com/apomonosi/sandboxing/internal/spec"
)

func newCreateCmd() *cobra.Command {
	var (
		image        string
		specFile     string
		profiles     []string
		allow        []string
		allowFiles   []string
		allowPresets []string
		denyLAN      bool
		allowLAN     bool
		ports        []string
		cpuCores     int
		memory       string
		diskSize     string
		agentName    string
	)

	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a sandbox instance (does not start it)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			p, providerName, err := resolveProvider(cmd)
			if err != nil {
				return err
			}

			if err := gateOrBlock(cmd.OutOrStdout(), providerName, p.Capabilities().Get(provider.FeatureCreate), forcePartial(cmd)); err != nil {
				return err
			}

			var baseOverrides profile.Policy
			profileNames := profiles
			resolvedImage := image
			if specFile != "" {
				if image != "" || len(profiles) > 0 {
					return fmt.Errorf("--spec cannot be combined with --image or --profile")
				}
				s, err := spec.LoadFile(specFile)
				if err != nil {
					return err
				}
				resolvedImage = s.Body.Image
				profileNames = s.Body.Profiles
				baseOverrides = s.Body.Overrides
			}
			if resolvedImage == "" {
				return fmt.Errorf("either --image or --spec is required")
			}
			if len(profileNames) == 0 {
				if def := configFromContext(cmd.Context()).DefaultProfile; def != "" {
					profileNames = []string{def}
				}
			}

			var agentSpec agent.Spec
			if agentName != "" {
				var ok bool
				agentSpec, ok = agent.Lookup(agentName)
				if !ok {
					return fmt.Errorf("unknown agent %q (valid: %s)", agentName, strings.Join(agent.Names(), ", "))
				}
			}

			var flagOverrides profile.Policy
			flagOverrides.Network.DenyLAN = denyLAN && !allowLAN
			flagOverrides.Network.Allow, flagOverrides.Network.AllowPresets, err = allowFlagRules(allow, allowFiles, allowPresets)
			if err != nil {
				return err
			}
			flagOverrides.Network.Allow = append(flagOverrides.Network.Allow, agentSpec.AllowDomains...)
			for _, portSpec := range ports {
				pp, err := parsePortFlag(portSpec)
				if err != nil {
					return err
				}
				flagOverrides.Network.Ports = append(flagOverrides.Network.Ports, pp)
			}
			if cpuCores > 0 {
				flagOverrides.Resources.CPUCores = cpuCores
			}
			if memory != "" {
				flagOverrides.Resources.Memory = memory
			}
			if diskSize != "" {
				flagOverrides.Resources.DiskSize = diskSize
			}

			overrides := profile.Merge(baseOverrides, flagOverrides)
			policy, err := spec.ResolvePolicy(profileNames, profileDirFlag(cmd), overrides)
			if err != nil {
				return err
			}

			fp := forcePartial(cmd)
			w := cmd.OutOrStdout()
			if policy.Network.DenyLAN {
				if err := gateOrBlock(w, providerName, p.Capabilities().Get(provider.FeatureDenyLAN), fp); err != nil {
					return err
				}
			}
			if len(policy.Network.AllowRules()) > 0 {
				if err := gateOrBlock(w, providerName, p.Capabilities().Get(provider.FeatureNetworkACL), fp); err != nil {
					return err
				}
			}
			if len(policy.Network.Ports) > 0 {
				if err := gateOrBlock(w, providerName, p.Capabilities().Get(provider.FeaturePortPublish), fp); err != nil {
					return err
				}
			}

			instSpec := spec.ToInstanceSpec(name, resolvedImage, profileNames, policy)
			if agentName != "" {
				instSpec.DefaultUser = agentName
			}

			if handled, err := tryPreview(cmd, providerName, p, func(pv provider.CommandPreviewer) []provider.Command {
				return pv.PreviewCreate(instSpec)
			}); handled {
				return err
			}

			inst, err := p.Create(cmd.Context(), instSpec)
			if err != nil {
				return err
			}

			if agentName != "" {
				if err := gateOrBlock(w, providerName, p.Capabilities().Get(provider.FeatureStart), fp); err != nil {
					return err
				}
				if err := p.SetAgentRequested(cmd.Context(), name, agentName); err != nil {
					return fmt.Errorf("recording requested agent %q: %w", agentName, err)
				}
				if err := p.Start(cmd.Context(), name); err != nil {
					return fmt.Errorf("starting instance to install agent %q: %w", agentName, err)
				}
				if updated, err := p.Status(cmd.Context(), name); err == nil {
					inst = updated
				}
				if err := installAgent(cmd.Context(), w, p, name, agentSpec); err != nil {
					return err
				}
			}
			return RenderInstance(w, inst, jsonOutput(cmd))
		},
	}

	cmd.Flags().StringVar(&image, "image", "", "image reference to create the instance from")
	cmd.Flags().StringVar(&specFile, "spec", "", "path to a Spec YAML file (see docs/reference); mutually exclusive with --image/--profile")
	cmd.Flags().StringSliceVar(&profiles, "profile", nil, "named security profile(s) to apply, in order (repeatable)")
	// StringArray, not StringSlice, for --allow and --allow-file: a slice
	// flag splits its value at commas, which would cut "host:80,443" in two.
	cmd.Flags().StringArrayVar(&allow, "allow", nil, "egress allowlist entry: \"host[:port,port]\", \"*.domain[:ports]\", or an http(s):// URL (repeatable)")
	cmd.Flags().StringArrayVar(&allowFiles, "allow-file", nil, "file of egress allowlist entries, one --allow value per line, # for comments (repeatable)")
	cmd.Flags().StringSliceVar(&allowPresets, "allow-preset", nil, "allow a built-in group of package-source/git hosts: "+strings.Join(profile.PresetNames(), ", ")+" (repeatable; \"agentctl profile presets\" lists their hosts)")
	cmd.Flags().BoolVar(&denyLAN, "deny-lan", true, "block egress to RFC1918/link-local ranges")
	cmd.Flags().BoolVar(&allowLAN, "allow-lan", false, "opt out of --deny-lan for this instance")
	cmd.Flags().StringSliceVar(&ports, "port", nil, "publish a port \"host:guest[/proto]\" (repeatable)")
	cmd.Flags().IntVar(&cpuCores, "cpu-cores", 0, "override CPU core limit")
	cmd.Flags().StringVar(&agentName, "agent", "", "just-in-time install a coding agent after create (valid: "+strings.Join(agent.Names(), ", ")+")")
	cmd.Flags().StringVar(&memory, "memory", "", "override memory limit, e.g. 4GiB")
	cmd.Flags().StringVar(&diskSize, "disk-size", "", "override root disk size, e.g. 20GiB")

	return cmd
}
