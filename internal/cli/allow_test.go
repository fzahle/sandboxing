package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/apomonosi/sandboxing/internal/provider"
	"github.com/apomonosi/sandboxing/internal/provider/fake"
)

func ruleFor(rules []provider.AllowRule, domain string) (provider.AllowRule, bool) {
	for _, r := range rules {
		if r.Domain == domain {
			return r, true
		}
	}
	return provider.AllowRule{}, false
}

// "host:80,443" is one entry with two ports. --allow used to be a
// comma-splitting flag, which turned it into host:80 plus a rule for a
// host named "443".
func TestCLI_Create_AllowWithSeveralPorts(t *testing.T) {
	useIsolatedConfig(t)
	p := &capturingProvider{Provider: fake.New()}

	if _, err := executeWith(t, p, "create", "demo", "--image=ubuntu", "--allow=example.com:80,443"); err != nil {
		t.Fatalf("create: %v", err)
	}
	want := []provider.AllowRule{{Domain: "example.com", Ports: []int{80, 443}}}
	if got := p.lastCreateSpec.Overrides.Allow; !reflect.DeepEqual(got, want) {
		t.Errorf("Allow = %+v, want %+v", got, want)
	}
}

func TestCLI_Create_AllowURL(t *testing.T) {
	useIsolatedConfig(t)
	p := &capturingProvider{Provider: fake.New()}

	if _, err := executeWith(t, p, "create", "demo", "--image=ubuntu",
		"--allow=https://gitlab.example.com/", "--allow", "http://mirror.example.com:8080"); err != nil {
		t.Fatalf("create: %v", err)
	}
	want := []provider.AllowRule{
		{Domain: "gitlab.example.com", Ports: []int{443}},
		{Domain: "mirror.example.com", Ports: []int{8080}},
	}
	if got := p.lastCreateSpec.Overrides.Allow; !reflect.DeepEqual(got, want) {
		t.Errorf("Allow = %+v, want %+v", got, want)
	}
}

func TestCLI_Create_AllowURLWithPath_ErrorsBeforeCreating(t *testing.T) {
	useIsolatedConfig(t)
	p := fake.New()

	_, err := execute(t, p, "create", "demo", "--image=ubuntu", "--allow=https://github.com/org/repo")
	if err == nil {
		t.Fatal("expected an error for an --allow URL with a path")
	}
	if !strings.Contains(err.Error(), "not by URL path") || !strings.Contains(err.Error(), "github.com:443") {
		t.Errorf("error %q should explain host-level filtering and suggest github.com:443", err)
	}
	if _, statusErr := p.Status(context.Background(), "demo"); statusErr == nil {
		t.Error("instance should not have been created")
	}
}

func TestCLI_Create_AllowPreset(t *testing.T) {
	useIsolatedConfig(t)
	p := &capturingProvider{Provider: fake.New()}

	if _, err := executeWith(t, p, "create", "demo", "--image=ubuntu", "--allow-preset=github,pypi", "--allow-preset", "apt"); err != nil {
		t.Fatalf("create: %v", err)
	}
	allow := p.lastCreateSpec.Overrides.Allow
	for _, domain := range []string{"github.com", "release-assets.githubusercontent.com", "pypi.org", "files.pythonhosted.org", "archive.ubuntu.com"} {
		if _, ok := ruleFor(allow, domain); !ok {
			t.Errorf("allowlist %+v is missing %s", allow, domain)
		}
	}
	if r, _ := ruleFor(allow, "archive.ubuntu.com"); !reflect.DeepEqual(r.Ports, []int{80, 443}) {
		t.Errorf("archive.ubuntu.com ports = %v, want [80 443] (apt uses plain HTTP)", r.Ports)
	}
}

func TestCLI_Create_UnknownAllowPreset_ErrorsBeforeCreating(t *testing.T) {
	useIsolatedConfig(t)
	p := fake.New()

	_, err := execute(t, p, "create", "demo", "--image=ubuntu", "--allow-preset=pipy")
	if err == nil {
		t.Fatal("expected an error for an unknown preset")
	}
	if !strings.Contains(err.Error(), `"pipy"`) || !strings.Contains(err.Error(), "pypi") {
		t.Errorf("error %q should name the bad preset and list the valid ones", err)
	}
	if _, statusErr := p.Status(context.Background(), "demo"); statusErr == nil {
		t.Error("instance should not have been created")
	}
}

func TestCLI_Create_AllowFile(t *testing.T) {
	useIsolatedConfig(t)
	p := &capturingProvider{Provider: fake.New()}
	path := filepath.Join(t.TempDir(), "allow.txt")
	if err := os.WriteFile(path, []byte("# team hosts\nnexus.example.com:8443\nhttps://gitlab.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := executeWith(t, p, "create", "demo", "--image=ubuntu", "--allow-file="+path, "--allow=example.com:443"); err != nil {
		t.Fatalf("create: %v", err)
	}
	want := []provider.AllowRule{
		{Domain: "example.com", Ports: []int{443}},
		{Domain: "nexus.example.com", Ports: []int{8443}},
		{Domain: "gitlab.example.com", Ports: []int{443}},
	}
	if got := p.lastCreateSpec.Overrides.Allow; !reflect.DeepEqual(got, want) {
		t.Errorf("Allow = %+v, want %+v", got, want)
	}
}

func TestCLI_Create_BadAllowFile_ErrorsBeforeCreating(t *testing.T) {
	useIsolatedConfig(t)
	p := fake.New()
	path := filepath.Join(t.TempDir(), "allow.txt")
	if err := os.WriteFile(path, []byte("ok.example.com\nnot a host\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := execute(t, p, "create", "demo", "--image=ubuntu", "--allow-file="+path)
	if err == nil || !strings.Contains(err.Error(), path+":2:") {
		t.Fatalf("err = %v, want one pointing at %s:2", err, path)
	}
	if _, statusErr := p.Status(context.Background(), "demo"); statusErr == nil {
		t.Error("instance should not have been created")
	}
}

// A preset alone is an allowlist, so it must hit the same capability gate
// as --allow on a provider that can't enforce one.
func TestCLI_Create_AllowPresetIsGatedLikeAllow(t *testing.T) {
	useIsolatedConfig(t)
	p := fake.New().WithCapability(provider.Capability{
		Feature: provider.FeatureNetworkACL, Status: provider.NotAvailable, Message: "no ACLs here",
	})

	_, err := execute(t, p, "create", "demo", "--image=ubuntu", "--allow-preset=pypi")
	if err == nil {
		t.Fatal("expected the network.acl capability gate to block a preset-only allowlist")
	}
	if _, statusErr := p.Status(context.Background(), "demo"); statusErr == nil {
		t.Error("instance should not have been created")
	}
}

func TestCLI_ProfilePresets(t *testing.T) {
	useIsolatedConfig(t)
	p := fake.New()

	out, err := execute(t, p, "profile", "presets")
	if err != nil {
		t.Fatalf("profile presets: %v", err)
	}
	for _, want := range []string{"apt:", "github:", "pypi:", "  files.pythonhosted.org:443", "  archive.ubuntu.com:80,443"} {
		if !strings.Contains(out, want) {
			t.Errorf("profile presets output missing %q:\n%s", want, out)
		}
	}

	out, err = execute(t, p, "--output=json", "profile", "presets")
	if err != nil {
		t.Fatalf("profile presets --output=json: %v", err)
	}
	var presets []struct {
		Name  string `json:"name"`
		Allow []struct {
			Domain string `json:"domain"`
			Ports  []int  `json:"ports"`
		} `json:"allow"`
	}
	if err := json.Unmarshal([]byte(out), &presets); err != nil {
		t.Fatalf("parsing JSON output: %v\n%s", err, out)
	}
	if len(presets) == 0 || presets[0].Name != "apk" || presets[0].Allow[0].Domain != "dl-cdn.alpinelinux.org" {
		t.Errorf("unexpected JSON output: %+v", presets)
	}
}
