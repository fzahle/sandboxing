package profile

import (
	"strings"
	"testing"
)

const testdataDir = "../../testdata/profiles/"

func TestLoadFile_Valid(t *testing.T) {
	p, err := LoadFile(testdataDir + "valid.yaml")
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if p.Metadata.Name != "valid" {
		t.Errorf("Name = %q, want %q", p.Metadata.Name, "valid")
	}
	if !p.Spec.Network.DenyLAN {
		t.Error("DenyLAN = false, want true")
	}
	if len(p.Spec.Network.Allow) != 1 || p.Spec.Network.Allow[0].Domain != "example.com" {
		t.Errorf("Allow = %+v, want one rule for example.com", p.Spec.Network.Allow)
	}
}

func TestLoadFile_RejectsUnknownField(t *testing.T) {
	_, err := LoadFile(testdataDir + "invalid-typo-field.yaml")
	if err == nil {
		t.Fatal("expected an error for a typo'd field, got nil")
	}
}

func TestLoadFile_RejectsOutOfRangePort(t *testing.T) {
	_, err := LoadFile(testdataDir + "invalid-port-range.yaml")
	if err == nil {
		t.Fatal("expected an error for an out-of-range port, got nil")
	}
	if !strings.Contains(err.Error(), "out-of-range") {
		t.Errorf("error %q does not mention out-of-range port", err.Error())
	}
}

func TestLoadFile_RejectsPortCollision(t *testing.T) {
	_, err := LoadFile(testdataDir + "invalid-port-collision.yaml")
	if err == nil {
		t.Fatal("expected an error for a duplicate host port, got nil")
	}
	if !strings.Contains(err.Error(), "published more than once") {
		t.Errorf("error %q does not mention the collision", err.Error())
	}
}

func TestLoadFile_RejectsBadResources(t *testing.T) {
	_, err := LoadFile(testdataDir + "invalid-resources.yaml")
	if err == nil {
		t.Fatal("expected errors for negative cpuCores and bad memory size, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "cpuCores") {
		t.Errorf("error %q missing cpuCores complaint", msg)
	}
	if !strings.Contains(msg, "memory") {
		t.Errorf("error %q missing memory complaint", msg)
	}
}

func TestLoadNamed_FallsBackToBuiltin(t *testing.T) {
	p, err := LoadNamed("default", "")
	if err != nil {
		t.Fatalf("LoadNamed(default): %v", err)
	}
	if p.Metadata.Name != "default" {
		t.Errorf("Name = %q, want %q", p.Metadata.Name, "default")
	}

	if _, err := LoadNamed("strict", ""); err != nil {
		t.Fatalf("LoadNamed(strict): %v", err)
	}

	if _, err := LoadNamed("does-not-exist", ""); err == nil {
		t.Fatal("expected an error for an unknown profile name")
	}
}

// The built-in default profile is meant to let an agent reach the Claude
// API; on Incus only a wildcard's apex is resolved, so it has to name
// api.anthropic.com itself.
func TestBuiltinDefault_AllowsClaudeAPIByName(t *testing.T) {
	p, err := LoadNamed("default", "")
	if err != nil {
		t.Fatalf("LoadNamed(default): %v", err)
	}
	for _, r := range p.Spec.Network.AllowRules() {
		if r.Domain == "api.anthropic.com" {
			return
		}
	}
	t.Errorf("default profile allowlist %+v doesn't name api.anthropic.com", p.Spec.Network.Allow)
}
