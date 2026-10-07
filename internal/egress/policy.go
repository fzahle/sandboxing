package egress

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// Policy is the egress policy one proxy enforces. It carries the same two
// settings the Incus backend turns into a per-instance network ACL (see
// networkACLCommands in internal/provider/incus/translate.go), with the
// same meaning:
//
//   - Default deny: a destination is reachable only if an Allow rule
//     matches its hostname (or IP literal) and port.
//   - DenyLAN: LAN/link-local destinations are refused even when an allow
//     rule matches them, the same way Incus evaluates reject rules before
//     allow rules.
//
// On top of that, loopback, unspecified, multicast, and broadcast
// destinations are refused unconditionally: the proxy runs on the host, so
// unlike an Incus guest (whose loopback is its own), a proxied connection
// to 127.0.0.1 would reach the host's own services.
type Policy struct {
	DenyLAN bool        `json:"denyLAN"`
	Allow   []AllowRule `json:"allow"`
}

// AllowRule mirrors provider.AllowRule (this package deliberately doesn't
// import internal/provider, so it stays usable by any backend).
type AllowRule struct {
	// Domain is a hostname, a "*.example.com" wildcard, or an IP literal.
	// A wildcard matches example.com itself and every subdomain of it —
	// the apex is included for parity with the Incus backend, which
	// resolves (and so allows) the apex of a wildcard entry.
	Domain string `json:"domain"`
	// Ports restricts the rule to these TCP ports; empty means any port.
	Ports []int `json:"ports,omitempty"`
}

// denyAll is what a proxy enforces when its policy file is missing or
// unreadable: nothing is allowed, so a broken setup fails closed.
var denyAll = Policy{DenyLAN: true}

// lanNetworks is what DenyLAN refuses: the same IPv4 ranges the Incus
// backend rejects (rfc1918AndLinkLocal in internal/provider/incus), plus
// their IPv6 counterparts (unique-local fc00::/7 and link-local fe80::/10),
// since the host the proxy runs on may have IPv6 reachability into the LAN
// even when the guest itself is IPv4-only.
var lanNetworks = mustParseCIDRs(
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"169.254.0.0/16",
	"fc00::/7",
	"fe80::/10",
)

// thisNetwork (0.0.0.0/8) addresses the local host on most stacks, so it
// is refused along with loopback.
var thisNetwork = mustParseCIDRs("0.0.0.0/8")

// nat64Prefix is the well-known NAT64 prefix (RFC 6052). On a NAT64
// network (e.g. an IPv6-only Wi-Fi) 64:ff9b::a00:1 reaches 10.0.0.1, so
// addresses under it are checked as the IPv4 address they embed.
var nat64Prefix = mustParseCIDRs("64:ff9b::/96")[0]

func mustParseCIDRs(cidrs ...string) []*net.IPNet {
	out := make([]*net.IPNet, len(cidrs))
	for i, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic("egress: invalid built-in CIDR " + c)
		}
		out[i] = n
	}
	return out
}

func inAny(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// normalizeHost canonicalizes a hostname or IP literal for matching:
// lowercase, no trailing dot or IPv6 brackets, and IP literals in their
// canonical text form (so "::FFFF:10.0.0.1" and "10.0.0.1" compare equal).
func normalizeHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.TrimSuffix(h, ".")
	h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	if ip := net.ParseIP(h); ip != nil {
		return ip.String()
	}
	return h
}

// permits reports whether some allow rule covers host:port. host must
// already be normalized (see normalizeHost); rule domains are normalized
// when the policy is loaded.
func (p Policy) permits(host string, port int) bool {
	for _, r := range p.Allow {
		if matchDomain(r.Domain, host) && portAllowed(r.Ports, port) {
			return true
		}
	}
	return false
}

func matchDomain(pattern, host string) bool {
	if apex, ok := strings.CutPrefix(pattern, "*."); ok {
		return host == apex || strings.HasSuffix(host, "."+apex)
	}
	return host == pattern
}

func portAllowed(ports []int, port int) bool {
	if len(ports) == 0 {
		return true
	}
	for _, p := range ports {
		if p == port {
			return true
		}
	}
	return false
}

// blockedReason returns why ip must not be dialed under p, or "" if it
// may be. It's applied to every address a hostname resolves to, at
// connection time, so a name that later starts resolving into the LAN
// (DNS rebinding) is refused too.
func (p Policy) blockedReason(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	} else if nat64Prefix.Contains(ip) {
		ip = net.IPv4(ip[12], ip[13], ip[14], ip[15]).To4()
	}
	switch {
	case ip.IsLoopback():
		return "loopback address (would reach the host itself)"
	case ip.IsUnspecified() || inAny(ip, thisNetwork):
		return "unspecified address (would reach the host itself)"
	case ip.IsMulticast() || ip.Equal(net.IPv4bcast):
		return "multicast or broadcast address"
	case p.DenyLAN && inAny(ip, lanNetworks):
		return "LAN or link-local address, refused because deny-LAN is on"
	}
	return ""
}

// validateAndNormalize checks p for values agentctl itself would never
// write, normalizing rule domains in place.
func (p *Policy) validateAndNormalize() error {
	for i := range p.Allow {
		r := &p.Allow[i]
		r.Domain = normalizeHost(r.Domain)
		if r.Domain == "" {
			return fmt.Errorf("allow rule %d: empty domain", i)
		}
		for _, port := range r.Ports {
			if port < 1 || port > 65535 {
				return fmt.Errorf("allow rule %d (%s): port %d out of range", i, r.Domain, port)
			}
		}
	}
	return nil
}

// LoadPolicy reads a policy file written by WritePolicy. Unknown fields
// and out-of-range values are errors rather than being ignored: this is a
// security policy, so a damaged file must not quietly turn into a looser
// one (callers fall back to denying everything).
func LoadPolicy(path string) (Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var p Policy
	if err := dec.Decode(&p); err != nil {
		return Policy{}, fmt.Errorf("parsing egress policy %s: %w", path, err)
	}
	if err := p.validateAndNormalize(); err != nil {
		return Policy{}, fmt.Errorf("invalid egress policy %s: %w", path, err)
	}
	return p, nil
}

// WritePolicy atomically replaces the policy file at path (write to a
// temporary file, then rename), so a running proxy never observes a
// half-written policy. The file and its directory are private to the
// user.
func WritePolicy(path string, p Policy) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating egress policy directory: %w", err)
	}
	if p.Allow == nil {
		p.Allow = []AllowRule{} // "allow": [] reads more clearly than null
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding egress policy: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".egress-policy-*.json")
	if err != nil {
		return fmt.Errorf("writing egress policy: %w", err)
	}
	defer os.Remove(tmp.Name()) // no-op once renamed
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return fmt.Errorf("writing egress policy: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("writing egress policy: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("writing egress policy %s: %w", path, err)
	}
	return nil
}
