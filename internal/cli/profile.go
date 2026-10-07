package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/apomonosi/sandboxing/internal/config"
	"github.com/apomonosi/sandboxing/internal/profile"
)

func newProfileCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "profile",
		Short: "Manage named security profiles (network/resource/mount policy bundles)",
	}
	cmd.AddCommand(newProfileListCmd(), newProfileShowCmd(), newProfileSetCmd(), newProfilePresetsCmd())
	return cmd
}

// newProfilePresetsCmd lists the built-in allow presets (--allow-preset,
// allowPresets) with every host each one allows, so what a preset opens is
// never a guess.
func newProfilePresetsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "presets",
		Short: "List the built-in allow presets (--allow-preset, allowPresets) and the hosts each allows",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			presets := profile.Presets()
			w := cmd.OutOrStdout()
			if jsonOutput(cmd) {
				type rule struct {
					Domain string `json:"domain"`
					Ports  []int  `json:"ports"`
				}
				type preset struct {
					Name        string `json:"name"`
					Description string `json:"description"`
					Allow       []rule `json:"allow"`
				}
				out := make([]preset, len(presets))
				for i, p := range presets {
					out[i] = preset{Name: p.Name, Description: p.Description, Allow: make([]rule, len(p.Allow))}
					for j, r := range p.Allow {
						out[i].Allow[j] = rule{Domain: r.Domain, Ports: r.Ports}
					}
				}
				enc := json.NewEncoder(w)
				enc.SetIndent("", "  ")
				return enc.Encode(out)
			}
			for i, p := range presets {
				if i > 0 {
					fmt.Fprintln(w)
				}
				fmt.Fprintf(w, "%s: %s\n", p.Name, p.Description)
				for _, r := range p.Allow {
					fmt.Fprintf(w, "  %s\n", formatAllowRule(r))
				}
			}
			return nil
		},
	}
}

// formatAllowRule renders r the way --allow takes it.
func formatAllowRule(r profile.AllowRule) string {
	host := r.Domain
	if strings.Contains(host, ":") {
		host = "[" + host + "]" // IPv6
	}
	if len(r.Ports) == 0 {
		return host + " (any port)"
	}
	ports := make([]string, len(r.Ports))
	for i, p := range r.Ports {
		ports[i] = strconv.Itoa(p)
	}
	return host + ":" + strings.Join(ports, ",")
}

func newProfileListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List available profiles (embedded built-ins plus file-based ones)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			names := map[string]bool{}
			for _, n := range profile.BuiltinNames() {
				names[n] = true
			}
			for _, dir := range profile.SearchPaths(profileDirFlag(cmd)) {
				entries, err := os.ReadDir(dir)
				if err != nil {
					continue // directory may not exist; that's fine
				}
				for _, e := range entries {
					if !e.IsDir() && strings.HasSuffix(e.Name(), ".yaml") {
						names[strings.TrimSuffix(e.Name(), ".yaml")] = true
					}
				}
			}
			sorted := make([]string, 0, len(names))
			for n := range names {
				sorted = append(sorted, n)
			}
			sort.Strings(sorted)

			if jsonOutput(cmd) {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(sorted)
			}
			for _, n := range sorted {
				fmt.Fprintln(cmd.OutOrStdout(), n)
			}
			return nil
		},
	}
}

func newProfileShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <name>",
		Short: "Print a profile's resolved contents",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := profile.LoadNamed(args[0], profileDirFlag(cmd))
			if err != nil {
				return err
			}
			if jsonOutput(cmd) {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(p)
			}
			data, err := yaml.Marshal(p)
			if err != nil {
				return err
			}
			_, err = cmd.OutOrStdout().Write(data)
			return err
		},
	}
}

func newProfileSetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "set <name>",
		Short: "Set the default profile applied when create is given no --profile/--spec",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if _, err := profile.LoadNamed(name, profileDirFlag(cmd)); err != nil {
				return fmt.Errorf("cannot set default profile: %w", err)
			}
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			cfg.DefaultProfile = name
			return config.Save(cfg)
		},
	}
}
