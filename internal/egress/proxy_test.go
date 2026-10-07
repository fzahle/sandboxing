package egress

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
)

// fakeNet is a tiny fake internet: the proxy's resolver maps test hostnames
// to documentation-range addresses, and its dialer routes those addresses
// to servers on this machine's loopback. That keeps the proxy's real
// policy checks — which refuse loopback destinations — in play, while the
// tests never touch a real network.
type fakeNet struct {
	mu     sync.Mutex
	names  map[string][]string // hostname -> IPs
	routes map[string]string   // "ip:port" -> local address actually dialed
	dialed []string
}

func (f *fakeNet) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	ips, ok := f.names[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	out := make([]net.IPAddr, len(ips))
	for i, ip := range ips {
		out[i] = net.IPAddr{IP: net.ParseIP(ip)}
	}
	return out, nil
}

func (f *fakeNet) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	f.mu.Lock()
	f.dialed = append(f.dialed, addr)
	real, ok := f.routes[addr]
	f.mu.Unlock()
	if !ok {
		return nil, &net.OpError{Op: "dial", Net: network, Err: syscall.ECONNREFUSED}
	}
	var d net.Dialer
	return d.DialContext(ctx, network, real)
}

func (f *fakeNet) dialedAddrs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.dialed...)
}

// syncBuffer is a goroutine-safe log sink.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// startEcho starts a TCP echo server and returns its address.
func startEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().String()
}

type proxyFixture struct {
	proxy      *Proxy
	addr       string // host:port of the proxy listener
	url        *url.URL
	policyPath string
	log        *syncBuffer
	net        *fakeNet
}

// newProxyFixture runs a Proxy with the given policy (nil: no policy file
// at all) in front of a fake internet with:
//
//	echo.example     -> 203.0.113.10 (a TCP echo server, any port)
//	web.example      -> 203.0.113.20:80 (an HTTP server)
//	lan.example      -> 10.0.0.5, 203.0.113.10
//	onlylan.example  -> 192.168.1.20
//	loop.example     -> 127.0.0.1
//	localhost        -> 127.0.0.1, ::1
//	down.example     -> 203.0.113.99 (nothing listening)
func newProxyFixture(t *testing.T, pol *Policy) *proxyFixture {
	t.Helper()
	echo := startEcho(t)
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello from %s%s", r.Host, r.URL.Path)
	}))
	t.Cleanup(web.Close)
	webAddr := strings.TrimPrefix(web.URL, "http://")

	fn := &fakeNet{
		names: map[string][]string{
			"echo.example":    {"203.0.113.10"},
			"web.example":     {"203.0.113.20"},
			"lan.example":     {"10.0.0.5", "203.0.113.10"},
			"onlylan.example": {"192.168.1.20"},
			"loop.example":    {"127.0.0.1"},
			"localhost":       {"127.0.0.1", "::1"},
			"down.example":    {"203.0.113.99"},
		},
		routes: map[string]string{
			"203.0.113.10:443": echo,
			"203.0.113.10:22":  echo,
			"203.0.113.20:80":  webAddr,
			"10.0.0.5:443":     echo,
			"192.168.1.20:443": echo,
			"127.0.0.1:443":    echo,
		},
	}
	policyPath := filepath.Join(t.TempDir(), "egress-policy.json")
	if pol != nil {
		if err := WritePolicy(policyPath, *pol); err != nil {
			t.Fatal(err)
		}
	}
	log := &syncBuffer{}
	px := &Proxy{PolicyPath: policyPath, Resolver: fn, DialContext: fn.DialContext, Log: log}
	srv := httptest.NewServer(px)
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	return &proxyFixture{proxy: px, addr: u.Host, url: u, policyPath: policyPath, log: log, net: fn}
}

// connect issues a CONNECT for target through the proxy and returns the
// response plus, on success, a connection to use as the tunnel.
func (f *proxyFixture) connect(t *testing.T, target string) (*http.Response, net.Conn, *bufio.Reader) {
	t.Helper()
	c, err := net.Dial("tcp", f.addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("reading CONNECT response: %v", err)
	}
	return resp, c, br
}

func (f *proxyFixture) client() *http.Client {
	return &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(f.url)}}
}

func allowPolicy(denyLAN bool, rules ...AllowRule) *Policy {
	return &Policy{DenyLAN: denyLAN, Allow: rules}
}

func TestProxy_Connect_AllowedTunnelsBothWays(t *testing.T) {
	f := newProxyFixture(t, allowPolicy(true, AllowRule{Domain: "echo.example", Ports: []int{443}}))

	resp, c, br := f.connect(t, "echo.example:443")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d, want 200", resp.StatusCode)
	}
	fmt.Fprint(c, "ping\n")
	line, err := br.ReadString('\n')
	if err != nil || line != "ping\n" {
		t.Fatalf("echo through tunnel = %q, %v; want \"ping\\n\"", line, err)
	}
	if !strings.Contains(f.log.String(), "allow CONNECT echo.example:443 via 203.0.113.10") {
		t.Errorf("log %q missing the allow decision", f.log.String())
	}
}

func TestProxy_Connect_Denials(t *testing.T) {
	f := newProxyFixture(t, allowPolicy(true,
		AllowRule{Domain: "echo.example", Ports: []int{443}},
		AllowRule{Domain: "onlylan.example", Ports: []int{443}},
		AllowRule{Domain: "loop.example", Ports: []int{443}},
		AllowRule{Domain: "localhost"},
	))
	cases := map[string]string{
		"not in allowlist":         "web.example:80",
		"allowed host, wrong port": "echo.example:22",
		"resolves only into LAN":   "onlylan.example:443",
		"resolves to loopback":     "loop.example:443",
		"localhost by name":        "localhost:22",
		"loopback literal":         "127.0.0.1:443",
		"unspecified literal":      "0.0.0.0:443",
	}
	for name, target := range cases {
		t.Run(name, func(t *testing.T) {
			resp, _, _ := f.connect(t, target)
			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("CONNECT %s status = %d, want 403", target, resp.StatusCode)
			}
		})
	}
	for _, d := range f.net.dialedAddrs() {
		t.Errorf("a denied CONNECT still dialed %s", d)
	}
	if !strings.Contains(f.log.String(), "deny CONNECT web.example:80: not in the allowlist") {
		t.Errorf("log %q missing the deny decision", f.log.String())
	}
}

// TestProxy_DenyLAN_SkipsLANAddressesOfAnAllowedName mirrors Incus, where
// deny-LAN reject rules are evaluated before allow rules: an allowlisted
// name that resolves into the LAN must not reach the LAN, but its other
// (public) addresses remain usable.
func TestProxy_DenyLAN_SkipsLANAddressesOfAnAllowedName(t *testing.T) {
	f := newProxyFixture(t, allowPolicy(true, AllowRule{Domain: "lan.example", Ports: []int{443}}))
	resp, _, _ := f.connect(t, "lan.example:443")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d, want 200 via the public address", resp.StatusCode)
	}
	if got := f.net.dialedAddrs(); len(got) != 1 || got[0] != "203.0.113.10:443" {
		t.Errorf("dialed %v, want only the public address 203.0.113.10:443", got)
	}
}

// TestProxy_AllowLAN_OnlyExplicitlyAllowedLANHosts: with deny-LAN off, a
// LAN destination is reachable only if allowlisted — still default-deny,
// the same as Incus with --allow-lan.
func TestProxy_AllowLAN_OnlyExplicitlyAllowedLANHosts(t *testing.T) {
	f := newProxyFixture(t, allowPolicy(false,
		AllowRule{Domain: "onlylan.example", Ports: []int{443}},
		AllowRule{Domain: "loop.example", Ports: []int{443}},
	))
	if resp, _, _ := f.connect(t, "onlylan.example:443"); resp.StatusCode != http.StatusOK {
		t.Errorf("allowlisted LAN host with deny-LAN off: status = %d, want 200", resp.StatusCode)
	}
	if resp, _, _ := f.connect(t, "10.0.0.5:443"); resp.StatusCode != http.StatusForbidden {
		t.Errorf("non-allowlisted LAN address with deny-LAN off: status = %d, want 403", resp.StatusCode)
	}
	if resp, _, _ := f.connect(t, "loop.example:443"); resp.StatusCode != http.StatusForbidden {
		t.Errorf("loopback stays refused even with deny-LAN off: status = %d, want 403", resp.StatusCode)
	}
}

func TestProxy_Connect_IPLiteralRule(t *testing.T) {
	f := newProxyFixture(t, allowPolicy(true, AllowRule{Domain: "203.0.113.10", Ports: []int{443}}))
	if resp, _, _ := f.connect(t, "203.0.113.10:443"); resp.StatusCode != http.StatusOK {
		t.Errorf("allowlisted IP literal: status = %d, want 200", resp.StatusCode)
	}
	if resp, _, _ := f.connect(t, "echo.example:443"); resp.StatusCode != http.StatusForbidden {
		t.Errorf("a hostname isn't allowed just because it resolves to an allowlisted IP: status = %d, want 403", resp.StatusCode)
	}
}

func TestProxy_Connect_AllowedButUnreachableIs502(t *testing.T) {
	f := newProxyFixture(t, allowPolicy(true, AllowRule{Domain: "down.example"}))
	if resp, _, _ := f.connect(t, "down.example:443"); resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want 502 (allowed, but nothing listening)", resp.StatusCode)
	}
}

func TestProxy_HTTPForward(t *testing.T) {
	f := newProxyFixture(t, allowPolicy(true, AllowRule{Domain: "web.example", Ports: []int{80}}))

	resp, err := f.client().Get("http://web.example/hello")
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "hello from web.example/hello" {
		t.Errorf("GET = %d %q, want 200 from the upstream", resp.StatusCode, body)
	}

	resp, err = f.client().Get("http://echo.example/")
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("GET to a non-allowlisted host = %d, want 403", resp.StatusCode)
	}
}

func TestProxy_RejectsNonProxyRequests(t *testing.T) {
	f := newProxyFixture(t, allowPolicy(true, AllowRule{Domain: "web.example"}))
	resp, err := http.Get("http://" + f.addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("origin-form request to the proxy itself = %d, want 400", resp.StatusCode)
	}
}

func TestProxy_MissingPolicyDeniesEverything(t *testing.T) {
	f := newProxyFixture(t, nil)
	if resp, _, _ := f.connect(t, "echo.example:443"); resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403 with no policy file", resp.StatusCode)
	}
	if !strings.Contains(f.log.String(), "denying all egress") {
		t.Errorf("log %q should explain that a missing policy denies everything", f.log.String())
	}
}

func TestProxy_CorruptPolicyDeniesEverything(t *testing.T) {
	f := newProxyFixture(t, nil)
	if err := writeRaw(f.policyPath, `{"denyLAN": false, "allow": [{"domain": "echo.example"}], "extra": 1}`); err != nil {
		t.Fatal(err)
	}
	if resp, _, _ := f.connect(t, "echo.example:443"); resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for an unparseable policy", resp.StatusCode)
	}
}

// TestProxy_PicksUpPolicyChanges: ApplyNetworkPolicy rewrites the policy
// file; a running proxy must enforce the new policy from the next
// connection on, in both directions.
func TestProxy_PicksUpPolicyChanges(t *testing.T) {
	f := newProxyFixture(t, allowPolicy(true))
	if resp, _, _ := f.connect(t, "echo.example:443"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("before: status = %d, want 403", resp.StatusCode)
	}
	if err := WritePolicy(f.policyPath, *allowPolicy(true, AllowRule{Domain: "echo.example"})); err != nil {
		t.Fatal(err)
	}
	if resp, _, _ := f.connect(t, "echo.example:443"); resp.StatusCode != http.StatusOK {
		t.Fatalf("after widening: status = %d, want 200", resp.StatusCode)
	}
	if err := WritePolicy(f.policyPath, *allowPolicy(true)); err != nil {
		t.Fatal(err)
	}
	if resp, _, _ := f.connect(t, "echo.example:443"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("after narrowing: status = %d, want 403", resp.StatusCode)
	}
}

func TestDeniedError_UnwrapsThroughErrorsAs(t *testing.T) {
	var err error = fmt.Errorf("wrapped: %w", &DeniedError{Target: "x:1", Reason: "nope"})
	var denied *DeniedError
	if !errors.As(err, &denied) || denied.Reason != "nope" {
		t.Errorf("errors.As failed on %v", err)
	}
}
