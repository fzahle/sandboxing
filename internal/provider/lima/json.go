package lima

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/apomonosi/sandboxing/internal/provider"
)

// limaInstanceJSON is a deliberately lenient, partial view of `limactl
// list --json` output: only the fields agentctl actually needs are
// declared, and every conversion in toInstance is defensive
// (missing/malformed fields degrade to zero values rather than erroring)
// — same posture as internal/provider/incus/json.go's instanceJSON.
//
// NOTE: the network-confinement fields (vmType through config) were
// checked against the JSON tags of Lima v2.2's limatype.Instance source,
// though not yet against a live `limactl list --json`. That same source
// shows the output has no guest IP address field at all (so Instance.IPs
// stays unpopulated on this backend), and no creation time either:
// CreatedAt below always comes back empty and degrades to a zero time.
type limaInstanceJSON struct {
	Name      string `json:"name"`
	Status    string `json:"status"`
	CreatedAt string `json:"createdAt"`

	// VMType, Networks (Lima's additional NICs, after merging
	// ~/.lima/_config/default.yaml and override.yaml), and SSHLocalPort
	// are what network.go's checkConfinable verifies before every start.
	VMType       string            `json:"vmType"`
	Networks     []json.RawMessage `json:"network"`
	SSHLocalPort int               `json:"sshLocalPort"`
	// HostAgentPID is the running hostagent's PID (0 when stopped);
	// AutoStartedIdentifier is non-empty when launchd started it.
	HostAgentPID          int    `json:"hostAgentPID"`
	AutoStartedIdentifier string `json:"autoStartedIdentifier"`
	// Config is the instance's effective (merged) lima.yaml.
	Config *limaConfigJSON `json:"config"`
}

// limaConfigJSON is the part of an instance's effective lima.yaml that
// network confinement depends on.
type limaConfigJSON struct {
	PropagateProxyEnv *bool             `json:"propagateProxyEnv"`
	Env               map[string]string `json:"env"`
	Mounts            []limaMountJSON   `json:"mounts"`
}

// limaMountJSON is one host directory shared into the guest. In the
// effective config, Location is absolute (Lima expands "~") and Writable
// is filled in (default false).
type limaMountJSON struct {
	Location string `json:"location"`
	Writable *bool  `json:"writable"`
}

func toInstance(j limaInstanceJSON) provider.Instance {
	inst := provider.Instance{
		Name:     j.Name,
		Provider: "lima",
		Status:   toInstanceStatus(j.Status),
	}
	if t, err := time.Parse(time.RFC3339, j.CreatedAt); err == nil {
		inst.CreatedAt = t
	}
	return inst
}

func toInstanceStatus(s string) provider.InstanceStatus {
	switch strings.ToLower(s) {
	case "running":
		return provider.StatusRunning
	case "stopped":
		return provider.StatusStopped
	default:
		return provider.StatusUnknown
	}
}

// parseLimaList parses `limactl list --json` output, hedging a real open
// question about its exact shape: whether limactl emits one top-level
// JSON array, or JSON Lines (one object per line, a convention several
// other CLIs use for --json output). It tries the array shape first and
// falls back to line-by-line parsing, so it's correct regardless of which
// shape is real — verify against a live install and simplify once
// confirmed.
func parseLimaList(stdout []byte) ([]limaInstanceJSON, error) {
	trimmed := bytes.TrimSpace(stdout)
	if len(trimmed) == 0 {
		return nil, nil
	}

	var arr []limaInstanceJSON
	if err := json.Unmarshal(trimmed, &arr); err == nil {
		return arr, nil
	}

	var out []limaInstanceJSON
	for _, line := range bytes.Split(trimmed, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var j limaInstanceJSON
		if err := json.Unmarshal(line, &j); err != nil {
			return nil, fmt.Errorf("parsing limactl list output: %w", err)
		}
		out = append(out, j)
	}
	return out, nil
}
