package lima

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/apomonosi/sandboxing/internal/config"
)

// Lima has no per-instance custom-metadata CLI verb the way Incus's
// `config set <name> user.*` gives agentctl (see incus.go's
// provisionDefaultUser/SetAgentRequested for that pattern) — there's
// nowhere on the limactl side to persist "an agent install was requested
// but hasn't finished" across process invocations. This file is a
// deliberate, minimal, documented deviation from "the backend is the sole
// source of truth": a small local YAML file, no daemon, no new
// dependency (reuses gopkg.in/yaml.v3, already pulled in by
// internal/config), and no file locking — agentctl is a short-lived CLI
// process, not a long-running daemon, so a read-modify-write race is an
// accepted, documented limitation, not something to solve here. See
// docs/user/agent-provisioning.md for the user-facing note.

// instanceState is one instance's JIT-agent-install bookkeeping, plus the
// network-confinement bookkeeping network.go keeps for the same reason —
// limactl has nowhere to put it.
type instanceState struct {
	AgentRequested string `yaml:"agentRequested,omitempty"`
	AgentInstalled bool   `yaml:"agentInstalled,omitempty"`
	// SSHLocalPort and EgressProxyPort are the host loopback ports pinned
	// for this instance's SSH forward and egress proxy (see pickPorts).
	SSHLocalPort    int `yaml:"sshLocalPort,omitempty"`
	EgressProxyPort int `yaml:"egressProxyPort,omitempty"`
	// ConfinedHostAgentPID is the hostagent agentctl last started under its
	// network sandbox, while it's running.
	ConfinedHostAgentPID int `yaml:"confinedHostAgentPID,omitempty"`
}

// stateFile is the on-disk shape of lima-state.yaml.
type stateFile struct {
	Instances map[string]instanceState `yaml:"instances"`
}

// statePath places lima-state.yaml next to config.yaml — reusing
// internal/config.Path()'s own AGENTCTL_CONFIG-relative resolution rather
// than inventing a new env var, so tests can reuse the exact same
// t.Setenv("AGENTCTL_CONFIG", ...) pattern config_test.go already uses.
func statePath() (string, error) {
	cfgPath, err := config.Path()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(cfgPath), "lima-state.yaml"), nil
}

// loadState reads lima-state.yaml. A missing file is not an error: it
// returns a zero-value stateFile, mirroring internal/config.Load's own
// "no file yet" handling.
func loadState() (*stateFile, error) {
	path, err := statePath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &stateFile{Instances: map[string]instanceState{}}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading lima state %s: %w", path, err)
	}
	var s stateFile
	if err := yaml.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parsing lima state %s: %w", path, err)
	}
	if s.Instances == nil {
		s.Instances = map[string]instanceState{}
	}
	return &s, nil
}

// saveState writes lima-state.yaml, creating its parent directory if
// needed — mirrors internal/config.Save's shape exactly.
func saveState(s *stateFile) error {
	path, err := statePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("creating lima state directory: %w", err)
	}
	data, err := yaml.Marshal(s)
	if err != nil {
		return fmt.Errorf("encoding lima state: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("writing lima state %s: %w", path, err)
	}
	return nil
}

// setAgentRequested records that name was created with agentName
// requested for JIT install.
func setAgentRequested(name, agentName string) error {
	s, err := loadState()
	if err != nil {
		return err
	}
	inst := s.Instances[name]
	inst.AgentRequested = agentName
	inst.AgentInstalled = false
	s.Instances[name] = inst
	return saveState(s)
}

// markAgentInstalled records that name's requested agent finished
// installing successfully.
func markAgentInstalled(name string) error {
	s, err := loadState()
	if err != nil {
		return err
	}
	inst := s.Instances[name]
	inst.AgentInstalled = true
	s.Instances[name] = inst
	return saveState(s)
}

// pendingAgentInstall returns the agent name requested for name if JIT
// install hasn't completed yet, or "" if no agent was ever requested, or
// installation already completed.
func pendingAgentInstall(name string) (string, error) {
	s, err := loadState()
	if err != nil {
		return "", err
	}
	inst, ok := s.Instances[name]
	if !ok || inst.AgentRequested == "" || inst.AgentInstalled {
		return "", nil
	}
	return inst.AgentRequested, nil
}

// updateInstanceState applies fn to name's entry and saves the result.
func updateInstanceState(name string, fn func(*instanceState)) error {
	s, err := loadState()
	if err != nil {
		return err
	}
	inst := s.Instances[name]
	fn(&inst)
	s.Instances[name] = inst
	return saveState(s)
}

// pruneInstanceState best-effort removes name's entry after a successful
// Delete, so a reused instance name doesn't inherit a stale
// PendingAgentInstall marker. Errors are intentionally not surfaced to
// the caller — mirrors how incus.go's ApplyNetworkPolicy ignores its own
// best-effort ACL-delete-before-recreate.
func pruneInstanceState(name string) {
	s, err := loadState()
	if err != nil {
		return
	}
	if _, ok := s.Instances[name]; !ok {
		return
	}
	delete(s.Instances, name)
	_ = saveState(s)
}
