package egress

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strconv"
	"sync"
	"time"
)

// Resolver is the subset of *net.Resolver the proxy uses, so tests can
// substitute fixed answers.
type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// DeniedError reports a destination refused by policy, as opposed to one
// that was allowed but couldn't be reached.
type DeniedError struct {
	Target string // host:port as requested
	Reason string
}

func (e *DeniedError) Error() string {
	return fmt.Sprintf("egress to %s denied by agentctl network policy: %s", e.Target, e.Reason)
}

// dialTimeout bounds each individual connection attempt to one resolved
// address of an allowed destination.
const dialTimeout = 15 * time.Second

// Proxy is an HTTP forward proxy that only connects to destinations the
// policy file at PolicyPath allows. It handles CONNECT (a TCP tunnel to
// any allowed host:port — HTTPS in practice) and absolute-form plain-HTTP
// requests, which together are what clients honoring http_proxy/
// https_proxy send.
//
// The policy is evaluated per connection, against the file's current
// contents: the file is re-read whenever it changes, and a missing or
// unreadable file denies everything. Hostnames are resolved at connection
// time and the proxy dials the exact address it checked, so there's no
// window for a DNS answer to change between the check and the connect.
type Proxy struct {
	PolicyPath string
	// Resolver and DialContext default to net.DefaultResolver and a plain
	// net.Dialer; tests override them.
	Resolver    Resolver
	DialContext func(ctx context.Context, network, address string) (net.Conn, error)
	// Log receives one line per allow/deny decision. Nil discards.
	Log io.Writer

	mu         sync.Mutex
	loadedFrom os.FileInfo // identity of the file p.policy was read from; nil if none
	policy     Policy
	noPolicy   bool // last check found no usable policy (logged once, not per request)

	logMu sync.Mutex

	forwardOnce sync.Once
	forward     *httputil.ReverseProxy
}

func (p *Proxy) logf(format string, args ...any) {
	if p.Log == nil {
		return
	}
	p.logMu.Lock()
	defer p.logMu.Unlock()
	fmt.Fprintf(p.Log, "%s %s\n", time.Now().UTC().Format(time.RFC3339), fmt.Sprintf(format, args...))
}

// currentPolicy returns the policy to enforce for a new connection,
// reloading the file if it has been replaced or modified since the last
// load. WritePolicy replaces the file by rename, so a new inode is the
// usual signal; size and mtime cover in-place edits.
func (p *Proxy) currentPolicy() Policy {
	p.mu.Lock()
	defer p.mu.Unlock()

	fi, err := os.Stat(p.PolicyPath)
	if err != nil {
		if !p.noPolicy {
			p.logf("policy %s unavailable (%v): denying all egress", p.PolicyPath, err)
		}
		p.loadedFrom, p.policy, p.noPolicy = nil, denyAll, true
		return p.policy
	}
	if p.loadedFrom != nil && os.SameFile(p.loadedFrom, fi) &&
		fi.ModTime().Equal(p.loadedFrom.ModTime()) && fi.Size() == p.loadedFrom.Size() {
		return p.policy
	}
	pol, err := LoadPolicy(p.PolicyPath)
	p.loadedFrom = fi
	if err != nil {
		p.logf("%v: denying all egress", err)
		p.policy, p.noPolicy = denyAll, true
		return p.policy
	}
	p.policy, p.noPolicy = pol, false
	p.logf("loaded policy %s: %d allow rule(s), denyLAN=%t", p.PolicyPath, len(pol.Allow), pol.DenyLAN)
	return p.policy
}

func (p *Proxy) resolver() Resolver {
	if p.Resolver != nil {
		return p.Resolver
	}
	return net.DefaultResolver
}

func (p *Proxy) dial(ctx context.Context, network, address string) (net.Conn, error) {
	if p.DialContext != nil {
		return p.DialContext(ctx, network, address)
	}
	d := net.Dialer{Timeout: dialTimeout}
	return d.DialContext(ctx, network, address)
}

// dialAllowed is the single enforcement point: both CONNECT tunnels and
// plain-HTTP forwarding get their upstream connections only from here.
func (p *Proxy) dialAllowed(ctx context.Context, kind, host, port string) (net.Conn, error) {
	target := net.JoinHostPort(host, port)
	portNum, err := strconv.Atoi(port)
	if err != nil || portNum < 1 || portNum > 65535 {
		return nil, p.deny(kind, target, "invalid port")
	}
	h := normalizeHost(host)
	if h == "" {
		return nil, p.deny(kind, target, "empty host")
	}
	pol := p.currentPolicy()
	if !pol.permits(h, portNum) {
		return nil, p.deny(kind, target, "not in the allowlist")
	}

	var ips []net.IP
	if ip := net.ParseIP(h); ip != nil {
		ips = []net.IP{ip}
	} else {
		addrs, err := p.resolver().LookupIPAddr(ctx, h)
		if err != nil {
			p.logf("error %s %s: resolving: %v", kind, target, err)
			return nil, fmt.Errorf("resolving %s: %w", h, err)
		}
		for _, a := range addrs {
			ips = append(ips, a.IP)
		}
	}

	var candidates []net.IP
	reason := "resolved to no addresses"
	for _, ip := range ips {
		if r := pol.blockedReason(ip); r != "" {
			reason = fmt.Sprintf("%s is a %s", ip, r)
			continue
		}
		candidates = append(candidates, ip)
	}
	if len(candidates) == 0 {
		return nil, p.deny(kind, target, reason)
	}

	var lastErr error
	for _, ip := range candidates {
		conn, err := p.dial(ctx, "tcp", net.JoinHostPort(ip.String(), port))
		if err == nil {
			p.logf("allow %s %s via %s", kind, target, ip)
			return conn, nil
		}
		lastErr = err
	}
	p.logf("error %s %s: allowed, but unreachable: %v", kind, target, lastErr)
	return nil, lastErr
}

func (p *Proxy) deny(kind, target, reason string) error {
	p.logf("deny %s %s: %s", kind, target, reason)
	return &DeniedError{Target: target, Reason: reason}
}

// writeDialError maps a dialAllowed failure onto the response the client
// sees: 403 for a policy refusal (with the reason, so whoever is debugging
// inside the sandbox can tell "blocked" from "down"), 502 otherwise.
func writeDialError(w http.ResponseWriter, err error) {
	var denied *DeniedError
	if errors.As(err, &denied) {
		http.Error(w, denied.Error(), http.StatusForbidden)
		return
	}
	http.Error(w, "agentctl egress proxy: "+err.Error(), http.StatusBadGateway)
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodConnect:
		p.serveConnect(w, r)
	case r.URL.IsAbs() && r.URL.Scheme == "http":
		p.forwarder().ServeHTTP(w, r)
	default:
		http.Error(w, "agentctl egress proxy: only CONNECT and absolute-form http:// proxy requests are supported", http.StatusBadRequest)
	}
}

func (p *Proxy) serveConnect(w http.ResponseWriter, r *http.Request) {
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		http.Error(w, "agentctl egress proxy: CONNECT target must be host:port", http.StatusBadRequest)
		return
	}
	upstream, err := p.dialAllowed(r.Context(), "CONNECT", host, port)
	if err != nil {
		writeDialError(w, err)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		upstream.Close()
		http.Error(w, "agentctl egress proxy: connection hijacking unsupported", http.StatusInternalServerError)
		return
	}
	client, rw, err := hj.Hijack()
	if err != nil {
		upstream.Close()
		return
	}
	if _, err := rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		client.Close()
		upstream.Close()
		return
	}
	if err := rw.Flush(); err != nil {
		client.Close()
		upstream.Close()
		return
	}
	// Anything the client pipelined right behind the CONNECT request
	// (typically a TLS ClientHello) is already sitting in rw's read
	// buffer rather than in the socket.
	if n := rw.Reader.Buffered(); n > 0 {
		buffered, _ := rw.Reader.Peek(n)
		if _, err := upstream.Write(buffered); err != nil {
			client.Close()
			upstream.Close()
			return
		}
	}
	tunnel(client, upstream)
}

// tunnel copies bytes both ways until both directions are done,
// half-closing each side as its peer finishes so protocols that rely on
// a FIN (e.g. TLS close_notify followed by EOF) see one.
func tunnel(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	pipe := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.Close()
		}
	}
	go pipe(a, b)
	go pipe(b, a)
	wg.Wait()
	a.Close()
	b.Close()
}

// forwarder returns the plain-HTTP forwarding handler. Its transport only
// ever gets connections from dialAllowed, never proxies onward (Proxy is
// left nil, so the host's own http_proxy settings are ignored), and never
// reuses a connection: every request is re-checked against the policy as
// it stands at that moment.
func (p *Proxy) forwarder() *httputil.ReverseProxy {
	p.forwardOnce.Do(func() {
		p.forward = &httputil.ReverseProxy{
			// The outgoing request is a clone of the incoming
			// absolute-form one, which already names its destination;
			// there's nothing to rewrite. (A non-nil Rewrite also makes
			// ReverseProxy strip any client-supplied Forwarded/
			// X-Forwarded-* headers instead of appending to them.)
			Rewrite: func(*httputil.ProxyRequest) {},
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
					host, port, err := net.SplitHostPort(addr)
					if err != nil {
						return nil, err
					}
					return p.dialAllowed(ctx, "HTTP", host, port)
				},
				DisableKeepAlives:     true,
				ResponseHeaderTimeout: 2 * time.Minute,
			},
			ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
				writeDialError(w, err)
			},
		}
	})
	return p.forward
}
