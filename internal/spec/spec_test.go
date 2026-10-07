package spec

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/apomonosi/sandboxing/internal/profile"
)

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoadFile_ExpandsOverridesAllowFile(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "hosts.txt"), "https://gitlab.example.com\n")
	specPath := filepath.Join(dir, "demo.yaml")
	write(t, specPath, `apiVersion: agentctl.dev/v1
kind: Spec
metadata:
  name: demo
spec:
  image: images:ubuntu/24.04
  overrides:
    network:
      denyLAN: true
      allowPresets: [pypi]
      allowFile: hosts.txt
`)

	t.Chdir(t.TempDir()) // the allow file is found relative to the spec, not the working directory
	s, err := LoadFile(specPath)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	net := s.Body.Overrides.Network
	if want := []profile.AllowRule{{Domain: "gitlab.example.com", Ports: []int{443}}}; !reflect.DeepEqual(net.Allow, want) {
		t.Errorf("Allow = %+v, want %+v", net.Allow, want)
	}
	if net.AllowFile != "" {
		t.Errorf("AllowFile = %q after loading, want it consumed", net.AllowFile)
	}
	if !reflect.DeepEqual(net.AllowPresets, []string{"pypi"}) {
		t.Errorf("AllowPresets = %v", net.AllowPresets)
	}
}

func TestLoadFile_ValidatesOverrides(t *testing.T) {
	specPath := filepath.Join(t.TempDir(), "demo.yaml")
	write(t, specPath, `apiVersion: agentctl.dev/v1
kind: Spec
metadata:
  name: demo
spec:
  image: images:ubuntu/24.04
  overrides:
    network:
      allowPresets: [pipy]
      allow:
        - domain: https://example.com/path
`)
	_, err := LoadFile(specPath)
	if err == nil {
		t.Fatal("LoadFile accepted invalid overrides")
	}
	for _, want := range []string{`unknown preset "pipy"`, "not by URL path"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q should mention %q", err, want)
		}
	}
}
