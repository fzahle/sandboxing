package lima

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/apomonosi/sandboxing/internal/config"
	"github.com/apomonosi/sandboxing/internal/egress"
	"github.com/apomonosi/sandboxing/internal/provider"
)

// Network policy enforcement on Lima (macOS)
//
// Lima has no per-instance egress ACL the way Incus does, and the obvious
// host-side substitute — a pf anchor on the guest's vzNAT/vmnet interface
// — can't be made to hold: Lima always also gives the guest a user-mode
// NIC (eth0, 192.168.5.15) whose traffic never crosses a host interface as
// guest traffic. The hostagent process (`limactl hostagent`, spawned by
// `limactl start`) terminates each of the guest's TCP/UDP flows in an
// in-process gvisor-tap-vsock network stack and re-originates it with an
// ordinary connect() from the host. pf sees that as the user's own
// traffic, so a guest with root (every agentctl guest has passwordless
// sudo) just routes around a vzNAT filter via eth0. (Verified against the
// Lima v2.2 / gvisor-tap-vsock v0.8.9 sources: pkg/driver/vz/vm_darwin.go
// always attaches that NIC, and its TCP forwarder dials with net.Dial.)
//
// That same design is what makes the hostagent a single, host-side choke
// point for all of the guest's egress, and that's where agentctl enforces
// policy:
//
//  1. `limactl start` runs under a macOS Seatbelt profile (sandbox-exec;
//     see sandboxProfile) that the hostagent and everything it spawns
//     inherit. It denies every outbound connection except to Unix
//     sockets and two host loopback ports: the instance's pinned SSH
//     forward and its egress proxy. A guest flow to anywhere else makes
//     the hostagent's connect() fail, and the guest sees the connection
//     refused — no matter what the guest does with its routes or
//     firewall, since none of this runs inside the guest.
//  2. Seatbelt can only match a remote host of "localhost" or "*", never a
//     particular IP, so the allowlist itself is applied by a per-instance
//     agentctl egress proxy (internal/egress) listening on that loopback
//     port, which the guest reaches at 192.168.5.2 (Lima NATs that to the
//     host's 127.0.0.1) and is pointed at via http_proxy/https_proxy. It
//     enforces the same default-deny allowlist and deny-LAN semantics as
//     the Incus ACL.
//  3. Before every start, agentctl re-asserts the instance configuration
//     this depends on (no extra NICs, the pinned SSH port, the proxy
//     environment) and checks Lima's effective configuration, so a
//     template or ~/.lima/_config/override.yaml can't quietly add a
//     bypass — or a writable mount of agentctl's state directory, where
//     the policy lives (see checkConfinable); after every start, it checks
//     from inside the guest that a direct connection out fails (see
//     egressProbeScript), and stops the instance if it doesn't.
//
// What this can't cover: an instance started some other way (plain
// `limactl start`, or launchd via `limactl autostart`) runs unconfined.
// agentctl refuses to start a launchd-registered instance, and refuses to
// adopt a running one it didn't start itself, but it can't stop someone
// from running limactl directly.

// sandboxExecBinary is invoked by absolute path, not looked up on $PATH.
const sandboxExecBinary = "/usr/bin/sandbox-exec"

// slirpGateway is where a Lima guest reaches the host's loopback: Lima's
// user-mode network NATs it to 127.0.0.1 (hardcoded upstream as
// networks.SlirpGateway).
const slirpGateway = "192.168.5.2"

// Pinned ports are drawn from the dynamic/private range — the same range
// Lima itself picks SSH ports from when left to its own devices.
const (
	pinnedPortMin = 49152
	pinnedPortMax = 65535
)

// egressPaths are the per-instance files behind an instance's egress
// proxy, under <agentctl config dir>/lima/<name>/.
type egressPaths struct {
	ConfigDir string // agentctl's config directory, holding every instance's state
	Dir       string
	Policy    string // egress policy the proxy enforces (egress.WritePolicy)
	PIDFile   string // held locked by the running proxy
	Log       string // one line per allowed/denied connection
}

func egressPathsFor(name string) (egressPaths, error) {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\`) {
		return egressPaths{}, fmt.Errorf("invalid instance name %q", name)
	}
	cfgPath, err := config.Path()
	if err != nil {
		return egressPaths{}, err
	}
	cfgDir := filepath.Dir(cfgPath)
	dir := filepath.Join(cfgDir, "lima", name)
	return egressPaths{
		ConfigDir: cfgDir,
		Dir:       dir,
		Policy:    filepath.Join(dir, "egress-policy.json"),
		PIDFile:   filepath.Join(dir, "egress-proxy.pid"),
		Log:       filepath.Join(dir, "egress-proxy.log"),
	}, nil
}

func toEgressPolicy(np provider.NetworkPolicy) egress.Policy {
	pol := egress.Policy{DenyLAN: np.DenyLAN, Allow: make([]egress.AllowRule, len(np.Allow))}
	for i, r := range np.Allow {
		pol.Allow[i] = egress.AllowRule{Domain: r.Domain, Ports: append([]int(nil), r.Ports...)}
	}
	return pol
}

// egressProxy controls an instance's proxy process. The real
// implementation spawns agentctl's hidden egress-proxy command; tests
// substitute a recorder.
type egressProxy interface {
	Running(paths egressPaths) (bool, error)
	Start(ctx context.Context, c provider.Command, paths egressPaths, port int) error
	Stop(ctx context.Context, paths egressPaths) error
}

type processEgressProxy struct{}

func (processEgressProxy) Running(paths egressPaths) (bool, error) {
	return egress.Running(paths.PIDFile)
}

func (processEgressProxy) Start(_ context.Context, c provider.Command, paths egressPaths, port int) error {
	return egress.Spawn(c.Binary, c.Args, paths.Log, proxyListenAddr(port), paths.PIDFile)
}

func (processEgressProxy) Stop(ctx context.Context, paths egressPaths) error {
	return egress.Stop(ctx, paths.PIDFile)
}

func proxyListenAddr(port int) string {
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
}

// proxyCommand is the single source of truth for how an instance's proxy
// is launched, shared by the real start path and PreviewStart.
func proxyCommand(agentctl string, paths egressPaths, port int) provider.Command {
	return provider.Command{Binary: agentctl, Args: egress.CommandArgs(egress.ServeOptions{
		Listen:     proxyListenAddr(port),
		PolicyPath: paths.Policy,
		PIDFile:    paths.PIDFile,
	})}
}

// startPlan is what a confined start needs besides limactl calls: the
// pinned ports and the proxy invocation. Start and PreviewStart compute it
// the same way (the preview just doesn't record the ports), so the
// preview shows the commands a start would actually run.
type startPlan struct {
	SSHPort, ProxyPort int
	Paths              egressPaths
	Proxy              provider.Command
}

func (p *Provider) planStart(name string, record bool) (*startPlan, error) {
	paths, err := egressPathsFor(name)
	if err != nil {
		return nil, err
	}
	s, err := loadState()
	if err != nil {
		return nil, err
	}
	// The instance's own proxy may still be up (e.g. after a plain
	// `limactl stop`); Start restarts it, so its port counts as free.
	ownProxyUp, _ := p.proxy.Running(paths)
	sshPort, proxyPort, err := pickPorts(name, s, p.portFree, ownProxyUp)
	if err != nil {
		return nil, err
	}
	if record {
		st := s.Instances[name]
		st.SSHLocalPort, st.EgressProxyPort = sshPort, proxyPort
		s.Instances[name] = st
		if err := saveState(s); err != nil {
			return nil, err
		}
	}
	agentctl, err := p.agentctlPath()
	if err != nil {
		return nil, fmt.Errorf("locating the agentctl binary to run the egress proxy: %w", err)
	}
	return &startPlan{SSHPort: sshPort, ProxyPort: proxyPort, Paths: paths, Proxy: proxyCommand(agentctl, paths, proxyPort)}, nil
}

// pickPorts returns name's SSH-forward and egress-proxy ports: the ones
// recorded last time if they're still free, otherwise the first free ports
// scanning up (and wrapping) from a starting point derived from the
// instance name. That's deterministic for a given machine state, which is
// what lets PreviewStart show the ports Start will pick without recording
// anything. Ports recorded for other instances are never handed out, even
// while those instances are stopped.
func pickPorts(name string, s *stateFile, free func(int) bool, ownProxyUp bool) (sshPort, proxyPort int, err error) {
	reserved := map[int]bool{}
	for other, st := range s.Instances {
		if other == name {
			continue
		}
		reserved[st.SSHLocalPort] = true
		reserved[st.EgressProxyPort] = true
	}
	own := s.Instances[name]
	usable := func(port int) bool {
		if port < pinnedPortMin || port > pinnedPortMax || reserved[port] {
			return false
		}
		return free(port) || (ownProxyUp && port == own.EgressProxyPort)
	}
	if own.SSHLocalPort != own.EgressProxyPort && usable(own.SSHLocalPort) && usable(own.EgressProxyPort) {
		return own.SSHLocalPort, own.EgressProxyPort, nil
	}
	span := pinnedPortMax - pinnedPortMin + 1
	h := fnv.New32a()
	h.Write([]byte(name))
	start := int(h.Sum32() % uint32(span))
	var found []int
	for i := 0; i < span && len(found) < 2; i++ {
		if port := pinnedPortMin + (start+i)%span; usable(port) {
			found = append(found, port)
		}
	}
	if len(found) < 2 {
		return 0, 0, errors.New("no free loopback ports left to pin for the instance's SSH forward and egress proxy")
	}
	return found[0], found[1], nil
}

// loopbackPortFree reports whether port can currently be bound on the
// host's loopback interface.
func loopbackPortFree(port int) bool {
	ln, err := net.Listen("tcp", proxyListenAddr(port))
	if err != nil {
		return false
	}
	ln.Close()
	return true
}

// sandboxProfile is the Seatbelt profile `limactl start` — and with it the
// hostagent and everything it spawns — runs under: outbound connections
// are denied except to Unix sockets (Lima's own IPC, and the system DNS
// resolver the hostagent answers the guest's DNS queries through) and to
// exactly two host loopback ports — the pinned SSH forward the hostagent
// reaches its own guest through, and the instance's egress proxy, the
// only way out the guest has. Allowing just those two (rather than
// "localhost:*") also keeps the guest away from every other service on
// the host's loopback, including other instances' proxies.
//
// The last matching rule wins in Seatbelt's profile language, so the
// allows after the blanket deny carve out the exceptions; binds and
// inbound connections (port forwards) aren't restricted at all. Every
// construct here is one that sandbox-exec users like Bazel's darwin
// sandbox and Anthropic's sandbox-runtime rely on.
func sandboxProfile(sshPort, proxyPort int) string {
	return "(version 1) (allow default) (deny network-outbound)" +
		" (allow network-outbound (remote unix-socket))" +
		fmt.Sprintf(` (allow network-outbound (remote ip "localhost:%d"))`, sshPort) +
		fmt.Sprintf(` (allow network-outbound (remote ip "localhost:%d"))`, proxyPort)
}

// buildConfinedStartArgs returns sandbox-exec's arguments for starting
// name under sandboxProfile: the profile, then the ordinary `limactl
// start` invocation (buildStartArgs), unchanged.
func buildConfinedStartArgs(name string, sshPort, proxyPort int) []string {
	return append([]string{"-p", sandboxProfile(sshPort, proxyPort), binary}, buildStartArgs(name)...)
}

// guestProxyEnv is the proxy environment the guest gets (Lima writes the
// instance's env: into /etc/environment at boot). Both spellings are set
// explicitly since tools disagree on which one they read.
func guestProxyEnv(proxyPort int) [][2]string {
	url := fmt.Sprintf("http://%s:%d", slirpGateway, proxyPort)
	noProxy := "localhost,127.0.0.1,::1"
	return [][2]string{
		{"http_proxy", url}, {"https_proxy", url}, {"no_proxy", noProxy},
		{"HTTP_PROXY", url}, {"HTTPS_PROXY", url}, {"NO_PROXY", noProxy},
	}
}

// buildNetworkEditArgs returns the `limactl edit` invocation run before
// every confined start to (re-)assert the configuration confinement
// depends on:
//
//   - .networks = [] drops any additional NIC (vzNAT, socket_vmnet, ...),
//     whose traffic would leave through the VZ framework rather than the
//     hostagent, outside the sandbox.
//   - .ssh.localPort pins the SSH forward to the port sandboxProfile
//     allows.
//   - the guest's proxy environment points at this instance's egress
//     proxy, and propagateProxyEnv=false stops the host's own proxy
//     settings from overriding it.
//
// --tty=false and --start=false matter: an interactive edit could offer to
// start the instance itself, outside the sandbox. Re-running this with
// nothing to change is a no-op ("no changes made").
func buildNetworkEditArgs(name string, sshPort, proxyPort int) []string {
	args := []string{"edit", "--tty=false", "--start=false",
		"--set", ".networks = []",
		"--set", fmt.Sprintf(".ssh.localPort = %d", sshPort),
		"--set", ".propagateProxyEnv = false",
	}
	for _, kv := range guestProxyEnv(proxyPort) {
		args = append(args, "--set", fmt.Sprintf(".env.%s = %q", kv[0], kv[1]))
	}
	return append(args, name)
}

// checkConfinable verifies Lima's effective configuration for an instance
// (after its lima.yaml has been merged with ~/.lima/_config/default.yaml
// and override.yaml) matches what confinement relies on.
func checkConfinable(j limaInstanceJSON, plan *startPlan) error {
	name := j.Name
	if !strings.EqualFold(j.VMType, "vz") {
		return fmt.Errorf("Lima instance %q uses vmType %q; agentctl's network enforcement on Lima requires the vz VM type (the macOS default), whose guest networking runs inside the sandboxed hostagent", name, j.VMType)
	}
	if len(j.Networks) > 0 {
		return fmt.Errorf("Lima instance %q has additional networks configured (%s) — probably from ~/.lima/_config/default.yaml or override.yaml; their traffic would bypass agentctl's egress enforcement, so agentctl won't start it until they're removed", name, joinRaw(j.Networks))
	}
	if j.SSHLocalPort != plan.SSHPort {
		return fmt.Errorf("Lima instance %q has ssh.localPort %d, not the %d agentctl pinned — probably overridden by ~/.lima/_config/override.yaml; remove that override so agentctl can confine the instance", name, j.SSHLocalPort, plan.SSHPort)
	}
	if j.Config == nil {
		return fmt.Errorf("could not read Lima's effective configuration for %q to verify network confinement", name)
	}
	if j.Config.PropagateProxyEnv == nil || *j.Config.PropagateProxyEnv {
		return fmt.Errorf("Lima instance %q has propagateProxyEnv enabled — probably by ~/.lima/_config/override.yaml; it would override the guest's egress proxy settings", name)
	}
	for _, kv := range guestProxyEnv(plan.ProxyPort) {
		if got := j.Config.Env[kv[0]]; got != kv[1] {
			return fmt.Errorf("Lima instance %q has env %s=%q, not %q — probably overridden by ~/.lima/_config/override.yaml; the guest would not use its egress proxy", name, kv[0], got, kv[1])
		}
	}
	// The egress policy lives in agentctl's config directory, and the
	// proxy picks up changes to it. A guest that could write there could
	// rewrite its own allowlist — so no writable mount may overlap it.
	// (Lima's templates share the home directory read-only by default.)
	for _, m := range j.Config.Mounts {
		if m.Writable != nil && *m.Writable && pathsOverlap(m.Location, plan.Paths.ConfigDir) {
			return fmt.Errorf("Lima instance %q mounts %s writable, which overlaps agentctl's state directory %s — the guest could rewrite its own egress policy. Make that mount read-only (or narrower) and retry", name, m.Location, plan.Paths.ConfigDir)
		}
	}
	return nil
}

// pathsOverlap reports whether a and b are the same directory or one
// contains the other. It compares file identities rather than strings, so
// symlinks and case-insensitive filesystems (macOS's default) can't hide
// an overlap. Paths that don't exist can't overlap anything.
func pathsOverlap(a, b string) bool {
	return isAncestorOrSelf(a, b) || isAncestorOrSelf(b, a)
}

// isAncestorOrSelf reports whether dir is path itself or one of its
// ancestors.
func isAncestorOrSelf(dir, path string) bool {
	dirInfo, err := os.Stat(dir)
	if err != nil {
		return false
	}
	p, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	for {
		if info, err := os.Stat(p); err == nil && os.SameFile(dirInfo, info) {
			return true
		}
		parent := filepath.Dir(p)
		if parent == p {
			return false
		}
		p = parent
	}
}

func joinRaw(raws []json.RawMessage) string {
	parts := make([]string, len(raws))
	for i, r := range raws {
		parts[i] = string(r)
	}
	return strings.Join(parts, ", ")
}

// egressProbeTarget is a well-known public address the guest tries to
// reach directly — deliberately bypassing its proxy — after every
// confined start. Under the sandbox the hostagent's connect() is refused
// and the guest sees an immediate connection refusal; getting through
// means confinement isn't in effect.
const egressProbeTarget = "1.1.1.1"

// egressProbeScript runs inside the guest and prints exactly one
// AGENTCTL_EGRESS=open|blocked|unverified line, using whichever of curl,
// bash's /dev/tcp, or python3 the image has. It always exits 0.
const egressProbeScript = `t=` + egressProbeTarget + `
if command -v curl >/dev/null 2>&1; then
  curl --noproxy '*' -s -o /dev/null --connect-timeout 5 --max-time 10 "http://$t/"
  case $? in 7|28) echo AGENTCTL_EGRESS=blocked ;; *) echo AGENTCTL_EGRESS=open ;; esac
elif command -v bash >/dev/null 2>&1 && command -v timeout >/dev/null 2>&1; then
  if timeout 5 bash -c "exec 3<>/dev/tcp/$t/80" 2>/dev/null; then echo AGENTCTL_EGRESS=open; else echo AGENTCTL_EGRESS=blocked; fi
elif command -v python3 >/dev/null 2>&1; then
  if python3 -c "import socket; socket.create_connection(('$t', 80), 5)" 2>/dev/null; then echo AGENTCTL_EGRESS=open; else echo AGENTCTL_EGRESS=blocked; fi
else
  echo AGENTCTL_EGRESS=unverified
fi
exit 0
`

func buildEgressProbeArgs(name string) []string {
	return buildExecArgs(name, []string{"sh", "-c", egressProbeScript}, false)
}

// parseEgressProbe extracts the probe's verdict ("open", "blocked",
// "unverified"), or "" if the output has none. It takes the last verdict
// line: the probe prints its verdict last, while anything the guest's
// login-shell startup files print comes before it.
func parseEgressProbe(stdout string) string {
	verdict := ""
	for _, line := range strings.Split(stdout, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "AGENTCTL_EGRESS="); ok {
			verdict = v
		}
	}
	return verdict
}

// egressVerdict runs egressProbeScript in the guest and returns its
// verdict: "blocked", "open", or "unverified" (the image has none of curl,
// bash, or python3 to probe with — the sandbox is in place either way,
// there's just nothing in the guest to double-check it from).
func (p *Provider) egressVerdict(ctx context.Context, name string) (string, error) {
	stdout, _, err := p.run(ctx, buildEgressProbeArgs(name)...)
	if err != nil {
		return "", fmt.Errorf("verifying network confinement of %q: %w", name, err)
	}
	switch v := parseEgressProbe(string(stdout)); v {
	case "blocked", "open", "unverified":
		return v, nil
	default:
		return "", fmt.Errorf("verifying network confinement of %q: unexpected probe output %q", name, stdout)
	}
}

// autostartPlists are where Lima registers an instance with launchd
// (`limactl autostart enable`, formerly `start-at-login`): as the user's
// LaunchAgent, or system-wide as a LaunchDaemon. launchd starting the
// hostagent itself would put it outside agentctl's sandbox.
func autostartPlists(name string) []string {
	var out []string
	if home, err := os.UserHomeDir(); err == nil {
		out = append(out, filepath.Join(home, "Library", "LaunchAgents", "io.lima-vm.autostart."+name+".plist"))
	}
	return append(out, filepath.Join("/Library", "LaunchDaemons", "io.lima-vm.daemon."+name+".plist"))
}

// startConfined is Start on macOS: see the top of this file.
func (p *Provider) startConfined(ctx context.Context, name string) error {
	j, err := p.inspect(ctx, name)
	if err != nil {
		return err
	}
	for _, plist := range p.autostartPlists(name) {
		if _, err := os.Stat(plist); err == nil {
			return fmt.Errorf("Lima instance %q is registered with launchd to start automatically (%s); launchd would start it outside agentctl's network sandbox, with unrestricted egress. Unregister it (`limactl autostart disable %s`) and retry", name, plist, name)
		}
	}
	if toInstanceStatus(j.Status) == provider.StatusRunning {
		return p.resumeConfined(ctx, name, j)
	}

	plan, err := p.planStart(name, true)
	if err != nil {
		return err
	}
	if _, _, err := p.run(ctx, buildNetworkEditArgs(name, plan.SSHPort, plan.ProxyPort)...); err != nil {
		return fmt.Errorf("configuring %q for network confinement: %w", name, err)
	}
	if j, err = p.inspect(ctx, name); err != nil {
		return err
	}
	if err := checkConfinable(j, plan); err != nil {
		return err
	}
	// Restart rather than reuse a proxy left over from an earlier run, so
	// it's always the current agentctl binary on the current port.
	if err := p.proxy.Stop(ctx, plan.Paths); err != nil {
		return fmt.Errorf("stopping %q's previous egress proxy: %w", name, err)
	}
	if err := p.proxy.Start(ctx, plan.Proxy, plan.Paths, plan.ProxyPort); err != nil {
		return fmt.Errorf("starting %q's egress proxy: %w", name, err)
	}

	// From here on, any failure leaves the instance stopped and its proxy
	// down: a start either completes confined and verified, or not at all.
	// The cleanup runs even if ctx has been canceled.
	abort := func(err error) error {
		cleanupCtx := context.WithoutCancel(ctx)
		_, _, _ = p.run(cleanupCtx, buildStopArgs(name, provider.StopOptions{Force: true})...)
		_ = p.proxy.Stop(cleanupCtx, plan.Paths)
		return err
	}
	if _, _, err := p.runner.Run(ctx, sandboxExecBinary, buildConfinedStartArgs(name, plan.SSHPort, plan.ProxyPort)...); err != nil {
		return abort(fmt.Errorf("sandbox-exec limactl start %s: %w", name, err))
	}
	verdict, err := p.egressVerdict(ctx, name)
	if err != nil {
		return abort(err)
	}
	if verdict == "open" {
		return abort(fmt.Errorf("network confinement check failed for %q: the guest reached %s directly, bypassing its egress proxy, so agentctl stopped it. Lima's processes don't appear to be running under agentctl's macOS sandbox; please report this with your macOS and `limactl --version` versions", name, egressProbeTarget))
	}
	return p.recordConfinedHostAgent(ctx, name)
}

// recordConfinedHostAgent remembers the PID of the hostagent agentctl just
// started under its sandbox, so a later start can tell "running, and
// confined by agentctl" from "running, started some other way".
func (p *Provider) recordConfinedHostAgent(ctx context.Context, name string) error {
	j, err := p.inspect(ctx, name)
	if err != nil {
		return err
	}
	return updateInstanceState(name, func(st *instanceState) { st.ConfinedHostAgentPID = j.HostAgentPID })
}

// resumeConfined handles Start on an instance that's already running.
// That's only fine if agentctl started it under its sandbox — then this
// just makes sure its proxy is still up (it's an idempotent no-op
// otherwise, which keeps `agentctl start`'s retry of an unfinished
// `create --agent` install working). A running instance agentctl didn't
// start has unrestricted egress, and saying nothing would imply otherwise.
func (p *Provider) resumeConfined(ctx context.Context, name string, j limaInstanceJSON) error {
	s, err := loadState()
	if err != nil {
		return err
	}
	st := s.Instances[name]
	notConfined := fmt.Errorf("Lima instance %q is already running, but agentctl didn't start it under its network sandbox, so its egress is unrestricted. Stop it (`agentctl stop %s`) and start it with agentctl", name, name)
	if j.HostAgentPID == 0 || j.HostAgentPID != st.ConfinedHostAgentPID || j.AutoStartedIdentifier != "" {
		return notConfined
	}
	// A matching PID is strong evidence but not proof — one recorded
	// before a host reboot could be reused by a hostagent started some
	// other way — so check from inside the guest too before vouching for
	// it.
	verdict, err := p.egressVerdict(ctx, name)
	if err != nil {
		return err
	}
	if verdict == "open" {
		return notConfined
	}
	paths, err := egressPathsFor(name)
	if err != nil {
		return err
	}
	if up, err := p.proxy.Running(paths); err != nil || up {
		return err
	}
	// The guest's proxy settings and the sandbox profile both point at the
	// recorded port, so the proxy has to come back on exactly that one.
	agentctl, err := p.agentctlPath()
	if err != nil {
		return fmt.Errorf("locating the agentctl binary to run the egress proxy: %w", err)
	}
	if err := p.proxy.Start(ctx, proxyCommand(agentctl, paths, st.EgressProxyPort), paths, st.EgressProxyPort); err != nil {
		return fmt.Errorf("restarting %q's egress proxy: %w", name, err)
	}
	return nil
}

// stopEgress tears down an instance's proxy once the instance itself is
// stopped.
func (p *Provider) stopEgress(ctx context.Context, name string) error {
	paths, err := egressPathsFor(name)
	if err != nil {
		return err
	}
	if err := p.proxy.Stop(ctx, paths); err != nil {
		return fmt.Errorf("instance %q stopped, but stopping its egress proxy failed: %w", name, err)
	}
	return updateInstanceState(name, func(st *instanceState) { st.ConfinedHostAgentPID = 0 })
}
