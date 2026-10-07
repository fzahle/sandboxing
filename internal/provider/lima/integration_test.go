//go:build integration

package lima

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/apomonosi/sandboxing/internal/provider"
)

// These tests exercise a real `limactl` install and are excluded from a
// plain `go test ./...` by the integration build tag above. They
// additionally check AGENTCTL_INTEGRATION_LIMA at runtime as a second,
// belt-and-suspenders gate. This is also where every "unverified against
// a live install" NOTE in translate.go/lima.go/json.go/network.go gets
// empirically resolved — required reading before this backend ships, not
// optional polish.
// Run via: AGENTCTL_INTEGRATION_LIMA=1 go test -tags=integration ./internal/provider/lima/...
func skipUnlessIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv("AGENTCTL_INTEGRATION_LIMA") != "1" {
		t.Skip("set AGENTCTL_INTEGRATION_LIMA=1 to run against a real limactl install")
	}
}

// agentctlBin is a freshly built agentctl. On macOS, starting an instance
// spawns `agentctl egress-proxy` (network.go), and inside a test binary
// os.Executable() is the test binary, not agentctl.
var agentctlBin string

func TestMain(m *testing.M) {
	code := func() int {
		if os.Getenv("AGENTCTL_INTEGRATION_LIMA") == "1" {
			dir, err := os.MkdirTemp("", "agentctl-it-")
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 1
			}
			defer os.RemoveAll(dir)
			agentctlBin = filepath.Join(dir, "agentctl")
			if out, err := exec.Command("go", "build", "-o", agentctlBin, "github.com/apomonosi/sandboxing/cmd/agentctl").CombinedOutput(); err != nil {
				fmt.Fprintf(os.Stderr, "building agentctl: %v\n%s", err, out)
				return 1
			}
		}
		return m.Run()
	}()
	os.Exit(code)
}

// newIntegrationProvider is the real provider, with its egress proxy run
// from the agentctl built above and its state kept out of the real
// ~/.config/agentctl.
func newIntegrationProvider(t *testing.T) *Provider {
	t.Helper()
	t.Setenv("AGENTCTL_CONFIG", filepath.Join(t.TempDir(), "config.yaml"))
	p := NewWithRunner(provider.ExecRunner{}).(*Provider)
	p.agentctlPath = func() (string, error) { return agentctlBin, nil }
	return p
}

func TestIntegration_CreateStartExecStatusStopDelete(t *testing.T) {
	skipUnlessIntegration(t)

	p := newIntegrationProvider(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	name := "agentctl-it-lifecycle"
	t.Cleanup(func() { _ = p.Delete(context.Background(), name, true) })

	if _, err := p.Create(ctx, provider.InstanceSpec{Name: name, Image: "template://ubuntu-lts"}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := p.Start(ctx, name); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if code, err := p.Exec(ctx, name, provider.ExecOptions{Command: []string{"true"}}); err != nil || code != 0 {
		t.Fatalf("Exec(true): code=%d err=%v", code, err)
	}
	if code, err := p.Exec(ctx, name, provider.ExecOptions{Command: []string{"whoami"}}); err != nil || code != 0 {
		t.Fatalf("Exec(whoami) as default non-root user: code=%d err=%v", code, err)
	}
	if code, err := p.Exec(ctx, name, provider.ExecOptions{Command: []string{"whoami"}, Root: true}); err != nil || code != 0 {
		t.Fatalf("Exec(whoami, --root): code=%d err=%v", code, err)
	}
	inst, err := p.Status(ctx, name)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if inst.Status != provider.StatusRunning {
		t.Errorf("Status = %q, want running", inst.Status)
	}
	if err := p.Stop(ctx, name, provider.StopOptions{Force: true}); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if err := p.Delete(ctx, name, false); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

// TestIntegration_NetworkPolicy_EnforcedHostSide is the test most
// directly tied to the security goal on this backend — the counterpart of
// the Incus suite's TestIntegration_ApplyNetworkPolicy_BlocksLAN. It
// checks the policy holds from inside a real guest, including against a
// root user deliberately going around the proxy, not just that the setup
// commands succeeded.
func TestIntegration_NetworkPolicy_EnforcedHostSide(t *testing.T) {
	skipUnlessIntegration(t)
	if runtime.GOOS != "darwin" {
		t.Skip("Lima network enforcement is macOS-only")
	}

	p := newIntegrationProvider(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	name := "agentctl-it-egress"
	t.Cleanup(func() { _ = p.Delete(context.Background(), name, true) })

	if _, err := p.Create(ctx, provider.InstanceSpec{
		Name:  name,
		Image: "template://ubuntu-lts",
		Overrides: provider.NetworkPolicy{
			DenyLAN: true,
			Allow:   []provider.AllowRule{{Domain: "example.com", Ports: []int{443}}},
		},
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Start includes agentctl's own in-guest check that direct egress is
	// blocked; it fails (and stops the instance) if it isn't.
	if err := p.Start(ctx, name); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// A service listening only on the host's loopback, which a stock Lima
	// guest could reach at 192.168.5.2. It answers with a valid HTTP
	// response, so reaching it would make curl succeed rather than fail
	// for some unrelated reason.
	hostLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer hostLn.Close()
	go func() {
		for {
			c, err := hostLn.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok"))
			c.Close()
		}
	}()
	hostPort := hostLn.Addr().(*net.TCPAddr).Port

	sh := func(root bool, script string) (int, string) {
		t.Helper()
		var out bytes.Buffer
		code, err := p.Exec(ctx, name, provider.ExecOptions{
			Command: []string{"sh", "-c", script}, Root: root, Stdout: &out, Stderr: &out,
		})
		if err != nil {
			t.Fatalf("Exec(%q): %v", script, err)
		}
		return code, out.String()
	}
	mustSucceed := func(what, script string) {
		t.Helper()
		if code, out := sh(false, script); code != 0 {
			t.Errorf("%s: exit %d, want success\n%s", what, code, out)
		}
	}
	mustFail := func(what string, root bool, script string) {
		t.Helper()
		if code, out := sh(root, script); code == 0 {
			t.Errorf("%s: succeeded, want it blocked\n%s", what, out)
		}
	}

	// curl -f, so an HTTP-level 403 from the proxy is a failure too, not
	// just a refused tunnel.
	mustSucceed("allowlisted HTTPS via the egress proxy",
		"curl -fsS -o /dev/null --max-time 30 https://example.com/")
	mustFail("non-allowlisted HTTPS via the proxy", false,
		"curl -fsS -o /dev/null --max-time 30 https://www.wikipedia.org/")
	mustFail("allowlisted host on a non-allowlisted port", false,
		"curl -fsS -o /dev/null --max-time 30 http://example.com/")
	mustFail("LAN address via the proxy", false,
		"curl -fsS -o /dev/null --max-time 10 http://192.168.1.1/")
	mustFail("direct egress, bypassing the proxy", false,
		"curl -fsS --noproxy '*' -o /dev/null --max-time 10 https://example.com/")
	mustFail("direct egress as root, after flushing the guest's own firewall", true,
		"(iptables -F 2>/dev/null; nft flush ruleset 2>/dev/null; true) && curl -fsS --noproxy '*' -o /dev/null --max-time 10 https://1.1.1.1/")
	mustFail("a host-loopback service at 192.168.5.2", false,
		fmt.Sprintf("curl -fsS --noproxy '*' -o /dev/null --max-time 10 http://192.168.5.2:%d/", hostPort))
	// A raw UDP DNS query to a public resolver: exits 0 only if an answer
	// comes back.
	mustFail("UDP straight to a public DNS resolver", true, `python3 - <<'EOF'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
s.sendto(b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01", ("1.1.1.1", 53))
try:
    s.recvfrom(512)
except Exception:
    sys.exit(1)
EOF`)
	mustSucceed("guest DNS still resolves (via the hostagent)",
		"getent hosts example.com")
}
