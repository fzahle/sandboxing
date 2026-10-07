package lima

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/apomonosi/sandboxing/internal/egress"
	"github.com/apomonosi/sandboxing/internal/provider"
)

const testAgentctl = "/usr/local/bin/agentctl"

// newTestProvider builds a Provider around r with network confinement
// pinned on or off — rather than following the host OS, so tests behave
// the same on a developer's Mac as on Linux CI — and every host-side seam
// faked: no real proxy processes, port probes, or launchd lookups. It also
// points AGENTCTL_CONFIG at a fresh directory, since confined
// Create/Start/Stop/Delete keep per-instance state there.
func newTestProvider(t *testing.T, r provider.Runner, confine bool) (*Provider, *fakeProxy) {
	t.Helper()
	t.Setenv("AGENTCTL_CONFIG", filepath.Join(t.TempDir(), "config.yaml"))
	p := newProvider(r, confine)
	fp := &fakeProxy{}
	if fl, ok := r.(*fakeLima); ok {
		fp.log = &fl.calls // interleave proxy events with limactl calls
	}
	p.proxy = fp
	p.agentctlPath = func() (string, error) { return testAgentctl, nil }
	p.portFree = func(int) bool { return true }
	p.autostartPlists = func(string) []string { return nil }
	return p, fp
}

// fakeProxy records proxy lifecycle events, optionally into the same log
// as a fakeLima's limactl calls so tests can assert their relative order.
type fakeProxy struct {
	log      *[][]string
	running  bool
	starts   []proxyStart
	stops    int
	startErr error
}

type proxyStart struct {
	cmd   provider.Command
	paths egressPaths
	port  int
}

func (f *fakeProxy) record(ev ...string) {
	if f.log != nil {
		*f.log = append(*f.log, ev)
	}
}

func (f *fakeProxy) Running(egressPaths) (bool, error) { return f.running, nil }

func (f *fakeProxy) Start(_ context.Context, c provider.Command, paths egressPaths, port int) error {
	f.record("<proxy-start>", strconv.Itoa(port))
	if f.startErr != nil {
		return f.startErr
	}
	f.starts = append(f.starts, proxyStart{cmd: c, paths: paths, port: port})
	f.running = true
	return nil
}

func (f *fakeProxy) Stop(context.Context, egressPaths) error {
	f.record("<proxy-stop>")
	f.stops++
	f.running = false
	return nil
}

// fakeLima simulates limactl (and sandbox-exec) for a single instance
// closely enough to drive the confined start path: `edit --set` changes
// what `list --json` reports as the effective configuration, and the
// *Override fields stand in for ~/.lima/_config/override.yaml winning over
// the instance's own lima.yaml.
type fakeLima struct {
	calls [][]string

	name         string
	running      bool
	hostAgentPID int
	edits        map[string]string // yq path -> value, from `limactl edit --set`

	vmType            string // default "vz"
	extraNetworks     []string
	sshPortOverride   int
	propagateOverride *bool
	envOverride       map[string]string
	mounts            []limaMountJSON
	probeOutput       string // default: blocked
	failSandboxStart  bool
}

func newFakeLima() *fakeLima { return &fakeLima{name: "demo", edits: map[string]string{}} }

func (f *fakeLima) Run(_ context.Context, bin string, args ...string) ([]byte, []byte, error) {
	f.calls = append(f.calls, append([]string{bin}, args...))
	if bin == sandboxExecBinary {
		if f.failSandboxStart {
			return nil, []byte("boom"), errors.New("exit status 1")
		}
		f.running, f.hostAgentPID = true, 4242
		return nil, nil, nil
	}
	if len(args) == 0 {
		return nil, nil, nil
	}
	switch args[0] {
	case "list":
		return f.listJSON(), nil, nil
	case "edit":
		if f.running {
			return nil, []byte("cannot edit a running instance"), errors.New("exit status 1")
		}
		for i := 0; i+1 < len(args); i++ {
			if args[i] == "--set" {
				k, v, _ := strings.Cut(args[i+1], " = ")
				if uq, err := strconv.Unquote(v); err == nil {
					v = uq
				}
				f.edits[k] = v
			}
		}
	case "start":
		f.running, f.hostAgentPID = true, 4242
	case "stop":
		f.running, f.hostAgentPID = false, 0
	case "shell":
		if len(args) >= 5 && args[3] == "sh" && args[4] == "-c" {
			out := f.probeOutput
			if out == "" {
				out = "AGENTCTL_EGRESS=blocked\n"
			}
			return []byte(out), nil, nil
		}
	}
	return nil, nil, nil
}

func (f *fakeLima) RunStream(_ context.Context, bin string, args []string, _ io.Reader, _, _ io.Writer) (int, error) {
	f.calls = append(f.calls, append([]string{bin}, args...))
	return 0, nil
}

func (f *fakeLima) listJSON() []byte {
	vmType := f.vmType
	if vmType == "" {
		vmType = "vz"
	}
	sshPort, _ := strconv.Atoi(f.edits[".ssh.localPort"])
	if f.sshPortOverride != 0 {
		sshPort = f.sshPortOverride
	}
	propagate := f.edits[".propagateProxyEnv"] != "false" // Lima's default is true
	if f.propagateOverride != nil {
		propagate = *f.propagateOverride
	}
	env := map[string]string{}
	for k, v := range f.edits {
		if name, ok := strings.CutPrefix(k, ".env."); ok {
			env[name] = v
		}
	}
	for k, v := range f.envOverride {
		env[k] = v
	}
	networks := []json.RawMessage{}
	for _, n := range f.extraNetworks {
		networks = append(networks, json.RawMessage(n))
	}
	status := "Stopped"
	if f.running {
		status = "Running"
	}
	line, _ := json.Marshal(map[string]any{
		"name": f.name, "status": status, "vmType": vmType, "network": networks,
		"sshLocalPort": sshPort, "hostAgentPID": f.hostAgentPID,
		"config": map[string]any{"propagateProxyEnv": propagate, "env": env, "mounts": f.mounts},
	})
	return append(line, '\n')
}

// callsTo returns the recorded invocations of bin (with args after bin).
func (f *fakeLima) callsTo(bin string) [][]string {
	var out [][]string
	for _, c := range f.calls {
		if c[0] == bin {
			out = append(out, c[1:])
		}
	}
	return out
}

// verbs summarizes the call log as "limactl <subcommand>", "sandbox-exec",
// or proxy events, for asserting order.
func (f *fakeLima) verbs() []string {
	var out []string
	for _, c := range f.calls {
		switch {
		case c[0] == binary && len(c) > 1:
			out = append(out, "limactl "+c[1])
		case c[0] == sandboxExecBinary:
			out = append(out, "sandbox-exec")
		default:
			out = append(out, c[0])
		}
	}
	return out
}

func TestConfinedStart_RunsTheFullSequenceInOrder(t *testing.T) {
	fl := newFakeLima()
	p, fp := newTestProvider(t, fl, true)

	if err := p.Start(context.Background(), "demo"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	want := []string{
		"limactl list",  // status + autostart preconditions
		"limactl edit",  // re-assert networks/ssh port/proxy env
		"limactl list",  // verify Lima's effective config
		"<proxy-stop>",  // never reuse a leftover proxy
		"<proxy-start>", // this instance's egress proxy
		"sandbox-exec",  // limactl start, confined
		"limactl shell", // in-guest check that direct egress is blocked
		"limactl list",  // record the confined hostagent's PID
	}
	if got := fl.verbs(); !reflect.DeepEqual(got, want) {
		t.Fatalf("call sequence = %v, want %v", got, want)
	}

	st := mustState(t, "demo")
	if st.SSHLocalPort == 0 || st.EgressProxyPort == 0 || st.SSHLocalPort == st.EgressProxyPort {
		t.Fatalf("pinned ports = %d/%d, want two distinct ports recorded", st.SSHLocalPort, st.EgressProxyPort)
	}
	if st.ConfinedHostAgentPID != 4242 {
		t.Errorf("ConfinedHostAgentPID = %d, want the started hostagent's 4242", st.ConfinedHostAgentPID)
	}

	// The proxy listens on the pinned proxy port, enforcing this
	// instance's policy file...
	paths, _ := egressPathsFor("demo")
	wantProxy := proxyCommand(testAgentctl, paths, st.EgressProxyPort)
	if len(fp.starts) != 1 || !reflect.DeepEqual(fp.starts[0].cmd, wantProxy) || fp.starts[0].port != st.EgressProxyPort {
		t.Errorf("proxy starts = %+v, want one start of %v on port %d", fp.starts, wantProxy, st.EgressProxyPort)
	}
	// ...the guest is pointed at it and has its SSH port pinned...
	edit := fl.callsTo(binary)[1]
	for _, expr := range []string{
		".networks = []",
		".ssh.localPort = " + strconv.Itoa(st.SSHLocalPort),
		".propagateProxyEnv = false",
		`.env.https_proxy = "http://192.168.5.2:` + strconv.Itoa(st.EgressProxyPort) + `"`,
	} {
		if !contains(edit, expr) {
			t.Errorf("edit args %v missing %q", edit, expr)
		}
	}
	// ...and the sandbox allows exactly those two loopback ports.
	sb := fl.callsTo(sandboxExecBinary)[0]
	if !reflect.DeepEqual(sb, buildConfinedStartArgs("demo", st.SSHLocalPort, st.EgressProxyPort)) {
		t.Errorf("sandbox-exec args = %v", sb)
	}
}

// TestConfinedStart_MatchesPreview is the drift guard for the confined
// path: every command PreviewStart shows must be exactly what Start runs.
func TestConfinedStart_MatchesPreview(t *testing.T) {
	fl := newFakeLima()
	p, fp := newTestProvider(t, fl, true)

	preview := p.PreviewStart("demo")
	if len(preview) != 4 {
		t.Fatalf("PreviewStart returned %d commands, want 4: %v", len(preview), preview)
	}
	if err := p.Start(context.Background(), "demo"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	limactlCalls := fl.callsTo(binary)
	if got := (provider.Command{Binary: binary, Args: limactlCalls[1]}); !reflect.DeepEqual(got, preview[0]) {
		t.Errorf("edit: ran %v, previewed %v", got, preview[0])
	}
	if len(fp.starts) != 1 || !reflect.DeepEqual(fp.starts[0].cmd, preview[1]) {
		t.Errorf("proxy: ran %+v, previewed %v", fp.starts, preview[1])
	}
	if got := (provider.Command{Binary: sandboxExecBinary, Args: fl.callsTo(sandboxExecBinary)[0]}); !reflect.DeepEqual(got, preview[2]) {
		t.Errorf("start: ran %v, previewed %v", got, preview[2])
	}
	if got := (provider.Command{Binary: binary, Args: limactlCalls[3]}); !reflect.DeepEqual(got, preview[3]) {
		t.Errorf("probe: ran %v, previewed %v", got, preview[3])
	}
}

func TestPreviewStart_RecordsNothing(t *testing.T) {
	fl := newFakeLima()
	p, fp := newTestProvider(t, fl, true)
	_ = p.PreviewStart("demo")
	if len(fl.calls) != 0 || len(fp.starts) != 0 || fp.stops != 0 {
		t.Errorf("PreviewStart ran something: calls=%v starts=%v stops=%d", fl.calls, fp.starts, fp.stops)
	}
	if st := mustState(t, "demo"); st.SSHLocalPort != 0 || st.EgressProxyPort != 0 {
		t.Errorf("PreviewStart recorded ports %+v", st)
	}
}

func TestConfinedStart_ReusesPinnedPortsAcrossRestarts(t *testing.T) {
	fl := newFakeLima()
	p, _ := newTestProvider(t, fl, true)
	ctx := context.Background()

	if err := p.Start(ctx, "demo"); err != nil {
		t.Fatalf("first Start: %v", err)
	}
	first := mustState(t, "demo")
	if err := p.Stop(ctx, "demo", provider.StopOptions{}); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if err := p.Start(ctx, "demo"); err != nil {
		t.Fatalf("second Start: %v", err)
	}
	second := mustState(t, "demo")
	if first.SSHLocalPort != second.SSHLocalPort || first.EgressProxyPort != second.EgressProxyPort {
		t.Errorf("ports changed across restarts: %+v -> %+v", first, second)
	}
}

// TestConfinedStart_RefusesUnconfinableConfigs: anything that would give
// the guest a way out that doesn't pass through the sandboxed hostagent
// and its proxy must stop the start before the VM boots.
func TestConfinedStart_RefusesUnconfinableConfigs(t *testing.T) {
	no := false
	yes := true
	cases := map[string]struct {
		setup   func(*fakeLima)
		wantErr string
	}{
		"qemu vmType":              {func(f *fakeLima) { f.vmType = "qemu" }, "requires the vz VM type"},
		"extra NIC from override":  {func(f *fakeLima) { f.extraNetworks = []string{`{"vzNAT":true}`} }, "additional networks"},
		"ssh port overridden":      {func(f *fakeLima) { f.sshPortOverride = 22222 }, "ssh.localPort"},
		"propagateProxyEnv forced": {func(f *fakeLima) { f.propagateOverride = &yes }, "propagateProxyEnv"},
		"proxy env overridden":     {func(f *fakeLima) { f.envOverride = map[string]string{"https_proxy": "http://corp:3128"} }, "https_proxy"},
		"propagate explicitly off": {func(f *fakeLima) { f.propagateOverride = &no }, ""}, // control: fine
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			fl := newFakeLima()
			c.setup(fl)
			p, fp := newTestProvider(t, fl, true)
			err := p.Start(context.Background(), "demo")
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("Start: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("Start error = %v, want one mentioning %q", err, c.wantErr)
			}
			if len(fl.callsTo(sandboxExecBinary)) != 0 || len(fp.starts) != 0 {
				t.Errorf("the instance or its proxy was started despite the refusal: %v", fl.verbs())
			}
		})
	}
}

// TestConfinedStart_RefusesWritableMountOverAgentctlState: the proxy
// re-reads its policy file when it changes, so a guest with write access
// to agentctl's state directory could widen its own allowlist.
func TestConfinedStart_RefusesWritableMountOverAgentctlState(t *testing.T) {
	rw, ro := true, false
	cases := map[string]struct {
		mount   func(cfgDir string) limaMountJSON
		refused bool
	}{
		"writable parent of the state dir (e.g. ~)": {func(d string) limaMountJSON {
			return limaMountJSON{Location: filepath.Dir(d), Writable: &rw}
		}, true},
		"writable state dir itself": {func(d string) limaMountJSON {
			return limaMountJSON{Location: d, Writable: &rw}
		}, true},
		"writable dir inside the state dir": {func(d string) limaMountJSON {
			sub := filepath.Join(d, "lima")
			_ = os.MkdirAll(sub, 0o700)
			return limaMountJSON{Location: sub, Writable: &rw}
		}, true},
		"writable symlink to the parent": {func(d string) limaMountJSON {
			link := filepath.Join(t.TempDir(), "home-link")
			_ = os.Symlink(filepath.Dir(d), link)
			return limaMountJSON{Location: link, Writable: &rw}
		}, true},
		"read-only parent (Lima's default home mount)": {func(d string) limaMountJSON {
			return limaMountJSON{Location: filepath.Dir(d), Writable: &ro}
		}, false},
		"writable unrelated workspace": {func(string) limaMountJSON {
			return limaMountJSON{Location: t.TempDir(), Writable: &rw}
		}, false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			fl := newFakeLima()
			p, fp := newTestProvider(t, fl, true)
			paths, _ := egressPathsFor("demo")
			if err := os.MkdirAll(paths.ConfigDir, 0o700); err != nil {
				t.Fatal(err)
			}
			fl.mounts = []limaMountJSON{c.mount(paths.ConfigDir)}

			err := p.Start(context.Background(), "demo")
			if !c.refused {
				if err != nil {
					t.Fatalf("Start: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "could rewrite its own egress policy") {
				t.Fatalf("Start error = %v, want a refusal over the writable mount", err)
			}
			if len(fl.callsTo(sandboxExecBinary)) != 0 || len(fp.starts) != 0 {
				t.Errorf("started despite the writable mount: %v", fl.verbs())
			}
		})
	}
}

func TestPathsOverlap(t *testing.T) {
	root := t.TempDir()
	a := filepath.Join(root, "a")
	ab := filepath.Join(a, "b")
	c := filepath.Join(root, "c")
	for _, d := range []string{ab, c} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		x, y string
		want bool
	}{
		{a, a, true},
		{a, ab, true},       // ancestor
		{ab, a, true},       // descendant
		{a, c, false},       // siblings
		{a + "b", a, false}, // a string prefix isn't a parent
		{filepath.Join(root, "missing"), a, false},
	}
	for _, tc := range cases {
		if got := pathsOverlap(tc.x, tc.y); got != tc.want {
			t.Errorf("pathsOverlap(%q, %q) = %v, want %v", tc.x, tc.y, got, tc.want)
		}
	}
}

func TestConfinedStart_RefusesLaunchdRegisteredInstance(t *testing.T) {
	fl := newFakeLima()
	p, fp := newTestProvider(t, fl, true)
	plist := filepath.Join(t.TempDir(), "io.lima-vm.autostart.demo.plist")
	if err := os.WriteFile(plist, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	p.autostartPlists = func(string) []string { return []string{"/nonexistent/x.plist", plist} }

	err := p.Start(context.Background(), "demo")
	if err == nil || !strings.Contains(err.Error(), "limactl autostart disable demo") {
		t.Fatalf("Start error = %v, want a refusal pointing at `limactl autostart disable`", err)
	}
	if len(fl.callsTo(sandboxExecBinary)) != 0 || len(fp.starts) != 0 {
		t.Errorf("started despite launchd registration: %v", fl.verbs())
	}
}

// TestConfinedStart_ProbeOpen_StopsInstance: if the in-guest check gets a
// direct connection out, confinement isn't in effect — the instance must
// not be left running as if it were.
func TestConfinedStart_ProbeOpen_StopsInstance(t *testing.T) {
	fl := newFakeLima()
	fl.probeOutput = "AGENTCTL_EGRESS=open\n"
	p, fp := newTestProvider(t, fl, true)

	err := p.Start(context.Background(), "demo")
	if err == nil || !strings.Contains(err.Error(), "network confinement check failed") {
		t.Fatalf("Start error = %v, want a confinement-check failure", err)
	}
	if fl.running {
		t.Error("instance left running after a failed confinement check")
	}
	if last := fl.callsTo(binary); !reflect.DeepEqual(last[len(last)-1], buildStopArgs("demo", provider.StopOptions{Force: true})) {
		t.Errorf("last limactl call = %v, want a forced stop", last[len(last)-1])
	}
	if fp.running {
		t.Error("egress proxy left running after a failed start")
	}
	if st := mustState(t, "demo"); st.ConfinedHostAgentPID != 0 {
		t.Errorf("a failed start recorded hostagent PID %d as confined", st.ConfinedHostAgentPID)
	}
}

func TestConfinedStart_ProbeUnverified_Proceeds(t *testing.T) {
	fl := newFakeLima()
	fl.probeOutput = "AGENTCTL_EGRESS=unverified\n"
	p, _ := newTestProvider(t, fl, true)
	if err := p.Start(context.Background(), "demo"); err != nil {
		t.Fatalf("Start: %v (an image with nothing to probe with is still confined)", err)
	}
	if !fl.running {
		t.Error("instance not running")
	}
}

func TestConfinedStart_ProbeGarbage_Fails(t *testing.T) {
	fl := newFakeLima()
	fl.probeOutput = "hello\n"
	p, _ := newTestProvider(t, fl, true)
	if err := p.Start(context.Background(), "demo"); err == nil || fl.running {
		t.Fatalf("Start error = %v, running = %v; want an error and a stopped instance", err, fl.running)
	}
}

func TestConfinedStart_SandboxedStartFails_CleansUp(t *testing.T) {
	fl := newFakeLima()
	fl.failSandboxStart = true
	p, fp := newTestProvider(t, fl, true)

	if err := p.Start(context.Background(), "demo"); err == nil || !strings.Contains(err.Error(), "sandbox-exec limactl start demo") {
		t.Fatalf("Start error = %v, want the sandboxed start's failure", err)
	}
	if fp.running {
		t.Error("egress proxy left running after the instance failed to start")
	}
}

func TestConfinedStart_ProxyFailsToStart(t *testing.T) {
	fl := newFakeLima()
	p, fp := newTestProvider(t, fl, true)
	fp.startErr = errors.New("port in use")
	if err := p.Start(context.Background(), "demo"); err == nil || !strings.Contains(err.Error(), "egress proxy") {
		t.Fatalf("Start error = %v, want it to report the proxy failure", err)
	}
	if len(fl.callsTo(sandboxExecBinary)) != 0 {
		t.Error("instance started without its egress proxy")
	}
}

// TestConfinedStart_AlreadyRunningAndConfined_IsIdempotent keeps `agentctl
// start`'s retry of an unfinished `create --agent` install working on an
// instance agentctl already started: no reconfiguration or reboot, just
// making sure its proxy is up.
func TestConfinedStart_AlreadyRunningAndConfined_IsIdempotent(t *testing.T) {
	fl := newFakeLima()
	p, fp := newTestProvider(t, fl, true)
	ctx := context.Background()
	if err := p.Start(ctx, "demo"); err != nil {
		t.Fatalf("first Start: %v", err)
	}
	st := mustState(t, "demo")

	before := len(fl.calls)
	if err := p.Start(ctx, "demo"); err != nil {
		t.Fatalf("second Start (proxy up): %v", err)
	}
	if got := fl.verbs()[before:]; !reflect.DeepEqual(got, []string{"limactl list", "limactl shell"}) {
		t.Errorf("second Start ran %v, want only the status check and the egress probe", got)
	}

	fp.running = false // the proxy died
	if err := p.Start(ctx, "demo"); err != nil {
		t.Fatalf("third Start (proxy down): %v", err)
	}
	if n := len(fp.starts); n != 2 || fp.starts[1].port != st.EgressProxyPort {
		t.Errorf("proxy starts = %+v, want it restarted on the recorded port %d", fp.starts, st.EgressProxyPort)
	}
	if len(fl.callsTo(sandboxExecBinary)) != 1 {
		t.Error("the running instance was started again")
	}
}

func TestConfinedStart_AlreadyRunningButNotConfined_Refuses(t *testing.T) {
	fl := newFakeLima()
	fl.running, fl.hostAgentPID = true, 999 // e.g. a plain `limactl start demo`
	p, fp := newTestProvider(t, fl, true)

	err := p.Start(context.Background(), "demo")
	if err == nil || !strings.Contains(err.Error(), "didn't start it under its network sandbox") {
		t.Fatalf("Start error = %v, want a refusal to adopt an unconfined instance", err)
	}
	if len(fp.starts) != 0 {
		t.Error("started a proxy for an instance it can't vouch for")
	}
}

// TestConfinedStart_AlreadyRunning_PIDMatchButEgressOpen_Refuses covers a
// recorded hostagent PID reused, after a host reboot, by a hostagent
// started some other way: the in-guest probe finds direct egress open, so
// agentctl must not vouch for the instance (nor stop something it didn't
// start).
func TestConfinedStart_AlreadyRunning_PIDMatchButEgressOpen_Refuses(t *testing.T) {
	fl := newFakeLima()
	p, fp := newTestProvider(t, fl, true)
	if err := updateInstanceState("demo", func(st *instanceState) {
		st.ConfinedHostAgentPID, st.SSHLocalPort, st.EgressProxyPort = 4242, 50001, 50002
	}); err != nil {
		t.Fatal(err)
	}
	fl.running, fl.hostAgentPID = true, 4242
	fl.probeOutput = "AGENTCTL_EGRESS=open\n"

	err := p.Start(context.Background(), "demo")
	if err == nil || !strings.Contains(err.Error(), "didn't start it under its network sandbox") {
		t.Fatalf("Start error = %v, want a refusal", err)
	}
	if len(fp.starts) != 0 || !fl.running {
		t.Errorf("proxy starts = %v, running = %v; want no proxy and the instance left alone", fp.starts, fl.running)
	}
}

func TestConfinedStop_StopsProxyAndForgetsHostAgent(t *testing.T) {
	fl := newFakeLima()
	p, fp := newTestProvider(t, fl, true)
	ctx := context.Background()
	if err := p.Start(ctx, "demo"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := p.Stop(ctx, "demo", provider.StopOptions{}); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if fp.running {
		t.Error("egress proxy still running after Stop")
	}
	if got := fl.verbs(); got[len(got)-2] != "limactl stop" || got[len(got)-1] != "<proxy-stop>" {
		t.Errorf("Stop sequence = %v, want the instance stopped before its proxy", got)
	}
	if st := mustState(t, "demo"); st.ConfinedHostAgentPID != 0 {
		t.Errorf("ConfinedHostAgentPID = %d after Stop, want 0", st.ConfinedHostAgentPID)
	}
}

func TestConfinedCreateAndDelete_ManagePolicyAndState(t *testing.T) {
	fl := newFakeLima()
	p, fp := newTestProvider(t, fl, true)
	ctx := context.Background()

	spec := provider.InstanceSpec{Name: "demo", Image: "template://ubuntu-lts", Overrides: provider.NetworkPolicy{
		DenyLAN: true,
		Allow:   []provider.AllowRule{{Domain: "*.anthropic.com", Ports: []int{443}}},
	}}
	if _, err := p.Create(ctx, spec); err != nil {
		t.Fatalf("Create: %v", err)
	}
	paths, _ := egressPathsFor("demo")
	pol, err := egress.LoadPolicy(paths.Policy)
	if err != nil {
		t.Fatalf("Create didn't record a loadable policy: %v", err)
	}
	if !pol.DenyLAN || len(pol.Allow) != 1 || pol.Allow[0].Domain != "*.anthropic.com" || pol.Allow[0].Ports[0] != 443 {
		t.Errorf("recorded policy = %+v, want the spec's network policy", pol)
	}

	if err := p.Start(ctx, "demo"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := p.Delete(ctx, "demo", true); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if fp.running {
		t.Error("egress proxy still running after Delete")
	}
	if _, err := os.Stat(paths.Dir); !os.IsNotExist(err) {
		t.Errorf("per-instance egress directory still exists after Delete (stat err %v)", err)
	}
	s, _ := loadState()
	if _, ok := s.Instances["demo"]; ok {
		t.Error("state entry (pinned ports etc.) survived Delete")
	}
}

func TestApplyNetworkPolicy_ConfinedRewritesPolicy(t *testing.T) {
	p, _ := newTestProvider(t, newFakeLima(), true)
	ctx := context.Background()
	if err := p.ApplyNetworkPolicy(ctx, "demo", provider.NetworkPolicy{}); err != nil {
		t.Fatalf("ApplyNetworkPolicy: %v", err)
	}
	if err := p.ApplyNetworkPolicy(ctx, "demo", provider.NetworkPolicy{Allow: []provider.AllowRule{{Domain: "pypi.org"}}}); err != nil {
		t.Fatalf("ApplyNetworkPolicy: %v", err)
	}
	paths, _ := egressPathsFor("demo")
	pol, err := egress.LoadPolicy(paths.Policy)
	if err != nil || pol.DenyLAN || len(pol.Allow) != 1 {
		t.Errorf("policy = %+v, %v; want the second policy", pol, err)
	}
}

func TestApplyNetworkPolicy_UnconfinedIsNotAvailable(t *testing.T) {
	p, _ := newTestProvider(t, newFakeLima(), false)
	if err := p.ApplyNetworkPolicy(context.Background(), "demo", provider.NetworkPolicy{}); !errors.Is(err, provider.ErrNotAvailable) {
		t.Errorf("ApplyNetworkPolicy() = %v, want ErrNotAvailable off macOS", err)
	}
}

func TestEgressPathsFor_RejectsPathTricks(t *testing.T) {
	t.Setenv("AGENTCTL_CONFIG", filepath.Join(t.TempDir(), "config.yaml"))
	for _, name := range []string{"", ".", "..", "../x", "a/b", `a\b`} {
		if _, err := egressPathsFor(name); err == nil {
			t.Errorf("egressPathsFor(%q) succeeded, want an error", name)
		}
	}
}

func TestCapabilities_NetworkPolicyFollowsConfinement(t *testing.T) {
	on := buildCapabilities(true)
	off := buildCapabilities(false)
	for _, f := range []provider.Feature{provider.FeatureNetworkACL, provider.FeatureDenyLAN} {
		if s := on.Get(f).Status; s != provider.Supported {
			t.Errorf("confined %s = %v, want supported", f, s)
		}
		if s := off.Get(f).Status; s != provider.NotAvailable {
			t.Errorf("unconfined %s = %v, want not available", f, s)
		}
	}
	if s := on.Get(provider.FeatureLogsNetwork).Status; s != provider.UnderDevelopment {
		t.Errorf("confined logs.network = %v, want under development (the proxy log exists, `agentctl logs` isn't wired to it)", s)
	}
	for _, tbl := range []provider.Table{on, off} {
		for _, f := range provider.AllFeatures {
			if tbl.Get(f).Status == provider.ManualWorkaround {
				t.Errorf("%s is still a manual workaround", f)
			}
		}
	}
}

func TestPickPorts(t *testing.T) {
	allFree := func(int) bool { return true }
	empty := func() *stateFile { return &stateFile{Instances: map[string]instanceState{}} }

	t.Run("deterministic and distinct", func(t *testing.T) {
		a1, b1, err := pickPorts("demo", empty(), allFree, false)
		if err != nil {
			t.Fatal(err)
		}
		a2, b2, _ := pickPorts("demo", empty(), allFree, false)
		if a1 != a2 || b1 != b2 || a1 == b1 {
			t.Errorf("pickPorts = (%d,%d) then (%d,%d); want the same distinct pair", a1, b1, a2, b2)
		}
		for _, port := range []int{a1, b1} {
			if port < pinnedPortMin || port > pinnedPortMax {
				t.Errorf("port %d outside the dynamic range", port)
			}
		}
	})

	t.Run("reuses recorded ports while free", func(t *testing.T) {
		s := empty()
		s.Instances["demo"] = instanceState{SSHLocalPort: 50001, EgressProxyPort: 50002}
		if a, b, _ := pickPorts("demo", s, allFree, false); a != 50001 || b != 50002 {
			t.Errorf("pickPorts = (%d,%d), want the recorded (50001,50002)", a, b)
		}
	})

	t.Run("re-picks when a recorded port is taken", func(t *testing.T) {
		s := empty()
		s.Instances["demo"] = instanceState{SSHLocalPort: 50001, EgressProxyPort: 50002}
		busy := func(port int) bool { return port != 50002 }
		a, b, _ := pickPorts("demo", s, busy, false)
		if b == 50002 || a == 50002 {
			t.Errorf("pickPorts = (%d,%d), handed out the busy port 50002", a, b)
		}
	})

	t.Run("own running proxy's port counts as free", func(t *testing.T) {
		s := empty()
		s.Instances["demo"] = instanceState{SSHLocalPort: 50001, EgressProxyPort: 50002}
		busy := func(port int) bool { return port != 50002 } // held by demo's own proxy
		if a, b, _ := pickPorts("demo", s, busy, true); a != 50001 || b != 50002 {
			t.Errorf("pickPorts = (%d,%d), want the recorded pair kept", a, b)
		}
	})

	t.Run("never reuses another instance's ports", func(t *testing.T) {
		s := empty()
		a, b, _ := pickPorts("demo", s, allFree, false)
		s.Instances["other"] = instanceState{SSHLocalPort: a, EgressProxyPort: b}
		c, d, _ := pickPorts("demo", s, allFree, false)
		if c == a || c == b || d == a || d == b {
			t.Errorf("pickPorts handed out (%d,%d), which are recorded for another instance", c, d)
		}
	})

	t.Run("no free ports", func(t *testing.T) {
		if _, _, err := pickPorts("demo", empty(), func(int) bool { return false }, false); err == nil {
			t.Error("pickPorts succeeded with no free ports")
		}
	})
}

func TestSandboxProfile(t *testing.T) {
	got := sandboxProfile(50001, 50002)
	want := `(version 1) (allow default) (deny network-outbound)` +
		` (allow network-outbound (remote unix-socket))` +
		` (allow network-outbound (remote ip "localhost:50001"))` +
		` (allow network-outbound (remote ip "localhost:50002"))`
	if got != want {
		t.Errorf("sandboxProfile() =\n  %s\nwant\n  %s", got, want)
	}
}

func TestBuildConfinedStartArgs(t *testing.T) {
	got := buildConfinedStartArgs("demo", 50001, 50002)
	want := []string{"-p", sandboxProfile(50001, 50002), "limactl", "start", "demo"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("buildConfinedStartArgs() = %v, want %v", got, want)
	}
}

func TestBuildNetworkEditArgs(t *testing.T) {
	got := buildNetworkEditArgs("demo", 50001, 50002)
	want := []string{"edit", "--tty=false", "--start=false",
		"--set", ".networks = []",
		"--set", ".ssh.localPort = 50001",
		"--set", ".propagateProxyEnv = false",
		"--set", `.env.http_proxy = "http://192.168.5.2:50002"`,
		"--set", `.env.https_proxy = "http://192.168.5.2:50002"`,
		"--set", `.env.no_proxy = "localhost,127.0.0.1,::1"`,
		"--set", `.env.HTTP_PROXY = "http://192.168.5.2:50002"`,
		"--set", `.env.HTTPS_PROXY = "http://192.168.5.2:50002"`,
		"--set", `.env.NO_PROXY = "localhost,127.0.0.1,::1"`,
		"demo",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("buildNetworkEditArgs() =\n  %v\nwant\n  %v", got, want)
	}
}

func TestParseEgressProbe(t *testing.T) {
	cases := map[string]string{
		"AGENTCTL_EGRESS=blocked\n":          "blocked",
		"motd noise\nAGENTCTL_EGRESS=open\n": "open",
		"  AGENTCTL_EGRESS=unverified  \n":   "unverified",
		"no verdict here\n":                  "",
		// A guest's login files run before the probe; a fake verdict
		// they print must not mask the probe's own, printed last.
		"AGENTCTL_EGRESS=blocked\nAGENTCTL_EGRESS=open\n": "open",
	}
	for in, want := range cases {
		if got := parseEgressProbe(in); got != want {
			t.Errorf("parseEgressProbe(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestEgressProbeScript runs the real in-guest probe script under sh with
// a PATH holding only fake tools, checking it reads each tool's result
// correctly — most importantly that a refused or timed-out connection is
// "blocked" and anything that got through is "open".
func TestEgressProbeScript(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh on this host")
	}
	type tool struct{ name, script string }
	exitWith := func(name string, code int) tool {
		return tool{name, "#!/bin/sh\nexit " + strconv.Itoa(code) + "\n"}
	}
	cases := map[string]struct {
		tools []tool
		want  string
	}{
		"curl refused (exit 7)":   {[]tool{exitWith("curl", 7)}, "blocked"},
		"curl timed out (28)":     {[]tool{exitWith("curl", 28)}, "blocked"},
		"curl connected (0)":      {[]tool{exitWith("curl", 0)}, "open"},
		"curl recv failure (56)":  {[]tool{exitWith("curl", 56)}, "open"},
		"bash /dev/tcp refused":   {[]tool{exitWith("bash", 0), exitWith("timeout", 1)}, "blocked"},
		"bash /dev/tcp connected": {[]tool{exitWith("bash", 0), exitWith("timeout", 0)}, "open"},
		"python3 refused":         {[]tool{exitWith("python3", 1)}, "blocked"},
		"python3 connected":       {[]tool{exitWith("python3", 0)}, "open"},
		"nothing to probe with":   {nil, "unverified"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			for _, tl := range c.tools {
				if err := os.WriteFile(filepath.Join(dir, tl.name), []byte(tl.script), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command(sh, "-c", egressProbeScript)
			cmd.Env = []string{"PATH=" + dir}
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("probe script failed: %v (output %q)", err, out)
			}
			if got := parseEgressProbe(string(out)); got != c.want {
				t.Errorf("verdict = %q (output %q), want %q", got, out, c.want)
			}
		})
	}
}

func mustState(t *testing.T, name string) instanceState {
	t.Helper()
	s, err := loadState()
	if err != nil {
		t.Fatalf("loadState: %v", err)
	}
	return s.Instances[name]
}
