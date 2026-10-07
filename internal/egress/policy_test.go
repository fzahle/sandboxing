package egress

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPolicyPermits(t *testing.T) {
	pol := Policy{Allow: []AllowRule{
		{Domain: "pypi.org", Ports: []int{443}},
		{Domain: "*.anthropic.com", Ports: []int{443}},
		{Domain: "any-port.example", Ports: nil},
		{Domain: "93.184.216.34", Ports: []int{80}},
		{Domain: "2001:db8::1"},
	}}
	if err := pol.validateAndNormalize(); err != nil {
		t.Fatalf("validateAndNormalize: %v", err)
	}
	cases := []struct {
		host string
		port int
		want bool
	}{
		{"pypi.org", 443, true},
		{"pypi.org", 80, false},                // wrong port
		{"files.pythonhosted.org", 443, false}, // not listed
		{"evilpypi.org", 443, false},           // suffix of a non-wildcard rule must not match
		{"api.anthropic.com", 443, true},       // wildcard subdomain
		{"a.b.anthropic.com", 443, true},       // nested subdomain
		{"anthropic.com", 443, true},           // wildcard covers the apex (Incus parity)
		{"anthropic.com.evil.net", 443, false}, // not a subdomain
		{"evilanthropic.com", 443, false},      // label boundary respected
		{"any-port.example", 22, true},         // no ports = any port
		{"93.184.216.34", 80, true},            // IP-literal rule
		{"93.184.216.34", 443, false},          // ...with its port restriction
		{"2001:db8::1", 443, true},             // IPv6 literal, any port
		{"203.0.113.9", 443, false},            // unlisted IP literal
	}
	for _, c := range cases {
		if got := pol.permits(normalizeHost(c.host), c.port); got != c.want {
			t.Errorf("permits(%q, %d) = %v, want %v", c.host, c.port, got, c.want)
		}
	}
}

func TestNormalizeHost(t *testing.T) {
	cases := map[string]string{
		"PyPI.org.":            "pypi.org",
		" Example.COM ":        "example.com",
		"[2001:DB8::1]":        "2001:db8::1",
		"::ffff:10.0.0.1":      "10.0.0.1",
		"*.Anthropic.com":      "*.anthropic.com",
		"2001:0db8:0000::0001": "2001:db8::1",
	}
	for in, want := range cases {
		if got := normalizeHost(in); got != want {
			t.Errorf("normalizeHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBlockedReason(t *testing.T) {
	denyLAN := Policy{DenyLAN: true}
	allowLAN := Policy{DenyLAN: false}
	cases := []struct {
		ip           string
		blockedDeny  bool // with DenyLAN
		blockedAllow bool // without DenyLAN
	}{
		{"93.184.216.34", false, false},
		{"2606:4700::1111", false, false},
		// Always blocked: these reach the host the proxy runs on.
		{"127.0.0.1", true, true},
		{"127.8.9.10", true, true},
		{"::1", true, true},
		{"0.0.0.0", true, true},
		{"0.1.2.3", true, true},
		{"::", true, true},
		{"224.0.0.1", true, true},
		{"ff02::1", true, true},
		{"255.255.255.255", true, true},
		{"::ffff:127.0.0.1", true, true},
		// LAN: blocked only with DenyLAN — the same four ranges Incus rejects...
		{"10.1.2.3", true, false},
		{"172.16.0.1", true, false},
		{"172.31.255.255", true, false},
		{"192.168.1.1", true, false},
		{"169.254.169.254", true, false},
		// ...plus their IPv6 counterparts, and LAN addresses in disguise.
		{"fd00::1", true, false},
		{"fe80::1", true, false},
		{"::ffff:192.168.1.1", true, false},
		{"64:ff9b::a00:1", true, false},      // NAT64 for 10.0.0.1
		{"64:ff9b::7f00:1", true, true},      // NAT64 for 127.0.0.1
		{"64:ff9b::5db8:d822", false, false}, // NAT64 for 93.184.216.34
		// Just outside the LAN ranges.
		{"172.32.0.1", false, false},
		{"11.0.0.1", false, false},
	}
	for _, c := range cases {
		ip := net.ParseIP(c.ip)
		if ip == nil {
			t.Fatalf("bad test IP %q", c.ip)
		}
		if got := denyLAN.blockedReason(ip) != ""; got != c.blockedDeny {
			t.Errorf("DenyLAN: blocked(%s) = %v, want %v (reason %q)", c.ip, got, c.blockedDeny, denyLAN.blockedReason(ip))
		}
		if got := allowLAN.blockedReason(ip) != ""; got != c.blockedAllow {
			t.Errorf("allow-LAN: blocked(%s) = %v, want %v (reason %q)", c.ip, got, c.blockedAllow, allowLAN.blockedReason(ip))
		}
	}
}

func TestWritePolicy_LoadPolicy_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "egress-policy.json")
	want := Policy{DenyLAN: true, Allow: []AllowRule{{Domain: "PyPI.org", Ports: []int{443}}}}
	if err := WritePolicy(path, want); err != nil {
		t.Fatalf("WritePolicy: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("policy file mode = %o, want 0600", perm)
	}
	got, err := LoadPolicy(path)
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	if !got.DenyLAN || len(got.Allow) != 1 || got.Allow[0].Domain != "pypi.org" || got.Allow[0].Ports[0] != 443 {
		t.Errorf("LoadPolicy() = %+v, want the written policy (with its domain normalized)", got)
	}
}

func TestWritePolicy_EmptyAllowIsAnEmptyList(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.json")
	if err := WritePolicy(path, Policy{DenyLAN: true}); err != nil {
		t.Fatalf("WritePolicy: %v", err)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), `"allow": []`) {
		t.Errorf("policy file = %s, want an explicit empty allow list", data)
	}
}

// TestLoadPolicy_RejectsDamagedFiles: a security policy must fail loudly
// (and the proxy then denies everything) rather than load as something
// looser than what agentctl wrote.
func TestLoadPolicy_RejectsDamagedFiles(t *testing.T) {
	cases := map[string]string{
		"unknown field": `{"denyLAN": true, "allow": [], "allowAll": true}`,
		"bad port":      `{"denyLAN": true, "allow": [{"domain": "pypi.org", "ports": [70000]}]}`,
		"empty domain":  `{"denyLAN": true, "allow": [{"domain": ""}]}`,
		"not json":      `allow: everything`,
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "p.json")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadPolicy(path); err == nil {
				t.Errorf("LoadPolicy(%s) succeeded, want an error", content)
			}
		})
	}
}
