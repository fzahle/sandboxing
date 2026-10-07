package profile

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseAllowEntry_Valid(t *testing.T) {
	cases := []struct {
		in   string
		want AllowRule
	}{
		{"example.com", AllowRule{Domain: "example.com"}},
		{"example.com:443", AllowRule{Domain: "example.com", Ports: []int{443}}},
		{"example.com:80,443", AllowRule{Domain: "example.com", Ports: []int{80, 443}}},
		{" Example.COM:80, 443 ", AllowRule{Domain: "example.com", Ports: []int{80, 443}}},
		{"*.example.com:443", AllowRule{Domain: "*.example.com", Ports: []int{443}}},
		{"internal_host.corp:8443", AllowRule{Domain: "internal_host.corp", Ports: []int{8443}}},
		{"203.0.113.7:443", AllowRule{Domain: "203.0.113.7", Ports: []int{443}}},
		{"203.0.113.7", AllowRule{Domain: "203.0.113.7"}},
		{"2001:db8::1", AllowRule{Domain: "2001:db8::1"}},
		{"[2001:db8::1]", AllowRule{Domain: "2001:db8::1"}},
		{"[2001:db8::1]:443", AllowRule{Domain: "2001:db8::1", Ports: []int{443}}},
		// URLs: the host, on the URL's port or the scheme's default.
		{"https://gitlab.example.com", AllowRule{Domain: "gitlab.example.com", Ports: []int{443}}},
		{"https://gitlab.example.com/", AllowRule{Domain: "gitlab.example.com", Ports: []int{443}}},
		{"http://mirror.example.com", AllowRule{Domain: "mirror.example.com", Ports: []int{80}}},
		{"HTTPS://Registry.Example.com:8443", AllowRule{Domain: "registry.example.com", Ports: []int{8443}}},
		{"https://[2001:db8::1]:8443/", AllowRule{Domain: "2001:db8::1", Ports: []int{8443}}},
		{"https://*.example.com", AllowRule{Domain: "*.example.com", Ports: []int{443}}},
	}
	for _, c := range cases {
		got, err := ParseAllowEntry(c.in)
		if err != nil {
			t.Errorf("ParseAllowEntry(%q): unexpected error %v", c.in, err)
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("ParseAllowEntry(%q) = %+v, want %+v", c.in, got, c.want)
		}
	}
}

func TestParseAllowEntry_Invalid(t *testing.T) {
	cases := []struct {
		in      string
		wantErr string
	}{
		{"", "empty"},
		{"   ", "empty"},
		{"example.com:", "not a number"},
		{"example.com:https", "not a number"},
		{"example.com:0", "out of range"},
		{"example.com:70000", "out of range"},
		// A URL path can't be allowed on its own: say so, and say what
		// the host-wide entry would be.
		{"https://github.com/org/repo", `use "github.com:443"`},
		{"https://example.com/?q=1", "not by URL path"},
		{"github.com/org/repo", "not by URL path"},
		{"https://user:secret@example.com", "credentials"},
		{"ftp://example.com", "unsupported URL scheme"},
		{"https://", "no host"},
		// Two hosts in one entry (what a comma-splitting flag used to
		// produce from "a.com,b.com").
		{"a.example.com,b.example.com", "one host per entry"},
		{"10.0.0.0/8", "address range"},
		{"*", "not a valid hostname"},
		{"*.203.0.113.7", "wildcard can't apply to an IP"},
		{"foo.*.example.com", "not a valid hostname"},
		{"git@github.com:org/repo.git", "not a valid hostname"},
		{"-bad.example.com", "not a valid hostname"},
		{"[2001:db8::1", `missing "]"`},
		{"[example.com]:443", "not an IPv6 address"},
		{"[2001:db8::1]443", "unexpected"},
	}
	for _, c := range cases {
		got, err := ParseAllowEntry(c.in)
		if err == nil {
			t.Errorf("ParseAllowEntry(%q) = %+v, want an error mentioning %q", c.in, got, c.wantErr)
			continue
		}
		if !strings.Contains(err.Error(), c.wantErr) {
			t.Errorf("ParseAllowEntry(%q) error %q, want it to mention %q", c.in, err, c.wantErr)
		}
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestReadAllowFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allow.txt")
	writeFile(t, path, "# package mirrors\n"+
		"mirror.example.com:80,443\r\n"+ // CRLF line endings are fine
		"\n"+
		"   \n"+
		"https://gitlab.example.com   # self-hosted GitLab\n"+
		"*.example.org\n")

	got, err := ReadAllowFile(path)
	if err != nil {
		t.Fatalf("ReadAllowFile: %v", err)
	}
	want := []AllowRule{
		{Domain: "mirror.example.com", Ports: []int{80, 443}},
		{Domain: "gitlab.example.com", Ports: []int{443}},
		{Domain: "*.example.org"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ReadAllowFile = %+v, want %+v", got, want)
	}
}

func TestReadAllowFile_ReportsEveryBadLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allow.txt")
	writeFile(t, path, "ok.example.com\nexample.com:http\nok2.example.com:443\nhttps://example.com/path\n")

	rules, err := ReadAllowFile(path)
	if err == nil {
		t.Fatalf("ReadAllowFile = %+v, want an error", rules)
	}
	for _, want := range []string{path + ":2:", path + ":4:"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q should point at %s", err, want)
		}
	}
	if strings.Contains(err.Error(), ":1:") || strings.Contains(err.Error(), ":3:") {
		t.Errorf("error %q blames a valid line", err)
	}
}

func TestReadAllowFile_Missing(t *testing.T) {
	if _, err := ReadAllowFile(filepath.Join(t.TempDir(), "nope.txt")); err == nil {
		t.Fatal("expected an error for a missing allow file")
	}
}

func TestResolvePath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home) // os.UserHomeDir on Windows

	base := filepath.Join(home, "profiles")
	abs := filepath.Join(home, "elsewhere", "allow.txt")
	cases := []struct {
		path, baseDir, want string
	}{
		{"allow.txt", base, filepath.Join(base, "allow.txt")},
		{filepath.Join("lists", "allow.txt"), base, filepath.Join(base, "lists", "allow.txt")},
		{abs, base, abs},
		{"~/allow.txt", base, filepath.Join(home, "allow.txt")},
		{"allow.txt", "", "allow.txt"}, // command line: relative to the working directory
	}
	for _, c := range cases {
		got, err := ResolvePath(c.path, c.baseDir)
		if err != nil {
			t.Errorf("ResolvePath(%q, %q): %v", c.path, c.baseDir, err)
			continue
		}
		if got != c.want {
			t.Errorf("ResolvePath(%q, %q) = %q, want %q", c.path, c.baseDir, got, c.want)
		}
	}
}

func TestLoadFile_ExpandsAllowFileRelativeToProfile(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "lists", "team.txt"), "internal.example.com:443\n")
	profilePath := filepath.Join(dir, "team.yaml")
	writeFile(t, profilePath, `apiVersion: agentctl.dev/v1
kind: Profile
metadata:
  name: team
spec:
  network:
    denyLAN: true
    allow:
      - domain: example.com
        ports: [443]
    allowFile: lists/team.txt
`)

	// Load from a different working directory: the path must still
	// resolve against the profile's directory.
	t.Chdir(t.TempDir())
	p, err := LoadFile(profilePath)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	want := []AllowRule{
		{Domain: "example.com", Ports: []int{443}},
		{Domain: "internal.example.com", Ports: []int{443}},
	}
	if !reflect.DeepEqual(p.Spec.Network.Allow, want) {
		t.Errorf("Allow = %+v, want %+v", p.Spec.Network.Allow, want)
	}
	if p.Spec.Network.AllowFile != "" {
		t.Errorf("AllowFile = %q after loading, want it consumed", p.Spec.Network.AllowFile)
	}
}

func TestLoadFile_BadAllowFileFailsTheLoad(t *testing.T) {
	dir := t.TempDir()
	profilePath := filepath.Join(dir, "team.yaml")
	writeFile(t, profilePath, `apiVersion: agentctl.dev/v1
kind: Profile
metadata:
  name: team
spec:
  network:
    denyLAN: true
    allowFile: missing.txt
`)
	if _, err := LoadFile(profilePath); err == nil || !strings.Contains(err.Error(), "allowFile") {
		t.Errorf("LoadFile with a missing allowFile: err = %v, want an allowFile error", err)
	}

	writeFile(t, filepath.Join(dir, "bad.txt"), "https://example.com/some/path\n")
	writeFile(t, profilePath, `apiVersion: agentctl.dev/v1
kind: Profile
metadata:
  name: team
spec:
  network:
    denyLAN: true
    allowFile: bad.txt
`)
	if _, err := LoadFile(profilePath); err == nil || !strings.Contains(err.Error(), "bad.txt:1:") {
		t.Errorf("LoadFile with an invalid allowFile entry: err = %v, want it to name bad.txt:1", err)
	}
}

func TestValidate_RejectsDomainsThatCanNeverMatch(t *testing.T) {
	for _, domain := range []string{"https://example.com", "example.com/path", "example.com:443", "10.0.0.0/8", " example.com"} {
		p := &Profile{
			APIVersion: APIVersion, Kind: Kind, Metadata: Metadata{Name: "x"},
			Spec: Policy{Network: NetworkPolicy{Allow: []AllowRule{{Domain: domain, Ports: []int{443}}}}},
		}
		if err := Validate(p); err == nil {
			t.Errorf("Validate accepted allow domain %q, which no backend could ever match", domain)
		}
	}
}
