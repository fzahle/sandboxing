package lima

import (
	"bytes"
	"context"
	"errors"
	"io"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/apomonosi/sandboxing/internal/provider"
)

// fakeRunner records every command it's asked to run and returns canned,
// empty-but-successful results, so lima.go's real dispatch methods can be
// exercised without a real `limactl` binary. Mirrors
// internal/provider/incus/incus_test.go's fakeRunner.
type fakeRunner struct {
	calls           [][]string
	readyFailCount  int
	readyFailAlways bool
	listJSON        string // canned `list`/`list <name>` response; defaults to one running "demo" instance
}

func (f *fakeRunner) Run(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	if isReadyProbe(args) && (f.readyFailAlways || f.readyFailCount > 0) {
		if f.readyFailCount > 0 {
			f.readyFailCount--
		}
		return nil, []byte("guest not reachable"), errors.New("exit status 1")
	}
	if len(args) > 0 && args[0] == "list" {
		if f.listJSON != "" {
			return []byte(f.listJSON), nil, nil
		}
		return []byte(`[{"name":"demo","status":"Running"}]`), nil, nil
	}
	return []byte("[]"), nil, nil
}

func isReadyProbe(args []string) bool {
	return len(args) == 4 && args[0] == "shell" && args[2] == "--" && args[3] == "true"
}

func (f *fakeRunner) RunStream(ctx context.Context, name string, args []string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	return 0, nil
}

func assertLastCall(t *testing.T, fr *fakeRunner, want []string) {
	t.Helper()
	if len(fr.calls) == 0 {
		t.Fatal("expected at least one recorded call")
	}
	got := fr.calls[len(fr.calls)-1]
	if !reflect.DeepEqual(got, want) {
		t.Errorf("last call = %v, want %v", got, want)
	}
}

// TestRealDispatch_MatchesPreview is the guard against preview output
// drifting from what actually executes — same role as Incus's own test
// of the same name.
func TestRealDispatch_MatchesPreview(t *testing.T) {
	ctx := context.Background()

	t.Run("Create", func(t *testing.T) {
		fr := &fakeRunner{}
		p, _ := newTestProvider(t, fr, false)
		spec := provider.InstanceSpec{Name: "demo", Image: "template://ubuntu-lts"}
		if _, err := p.Create(ctx, spec); err != nil {
			t.Fatalf("Create: %v", err)
		}
		want := append([]string{binary}, p.PreviewCreate(spec)[0].Args...)
		if len(fr.calls) == 0 || !reflect.DeepEqual(fr.calls[0], want) {
			t.Errorf("first call = %v, want %v", fr.calls[0], want)
		}
	})

	t.Run("Start", func(t *testing.T) {
		fr := &fakeRunner{}
		p, _ := newTestProvider(t, fr, false)
		if err := p.Start(ctx, "demo"); err != nil {
			t.Fatalf("Start: %v", err)
		}
		want := append([]string{binary}, p.PreviewStart("demo")[0].Args...)
		assertLastCall(t, fr, want)
	})

	t.Run("Stop", func(t *testing.T) {
		fr := &fakeRunner{}
		p, _ := newTestProvider(t, fr, false)
		opts := provider.StopOptions{Force: true}
		if err := p.Stop(ctx, "demo", opts); err != nil {
			t.Fatalf("Stop: %v", err)
		}
		want := append([]string{binary}, p.PreviewStop("demo", opts)[0].Args...)
		assertLastCall(t, fr, want)
	})

	t.Run("Delete", func(t *testing.T) {
		t.Setenv("AGENTCTL_CONFIG", filepath.Join(t.TempDir(), "config.yaml"))
		fr := &fakeRunner{}
		p, _ := newTestProvider(t, fr, false)
		if err := p.Delete(ctx, "demo", true); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		want := append([]string{binary}, p.PreviewDelete("demo", true)[0].Args...)
		assertLastCall(t, fr, want)
	})

	t.Run("Exec", func(t *testing.T) {
		fr := &fakeRunner{}
		p, _ := newTestProvider(t, fr, false)
		opts := provider.ExecOptions{Command: []string{"echo", "hi"}}
		wantCmds, err := p.PreviewExec(ctx, "demo", opts)
		if err != nil {
			t.Fatalf("PreviewExec: %v", err)
		}
		if _, err := p.Exec(ctx, "demo", opts); err != nil {
			t.Fatalf("Exec: %v", err)
		}
		want := append([]string{binary}, wantCmds[0].Args...)
		assertLastCall(t, fr, want)
	})

	t.Run("Shell", func(t *testing.T) {
		fr := &fakeRunner{}
		p, _ := newTestProvider(t, fr, false)
		opts := provider.ShellOptions{}
		wantCmds, err := p.PreviewShell(ctx, "demo", opts)
		if err != nil {
			t.Fatalf("PreviewShell: %v", err)
		}
		if err := p.Shell(ctx, "demo", opts); err != nil {
			t.Fatalf("Shell: %v", err)
		}
		want := append([]string{binary}, wantCmds[0].Args...)
		assertLastCall(t, fr, want)
	})
}

// TestCreate_DoesNotStartOrStopInstance is a regression test for the
// simplification described in lima.go's Create doc comment: unlike
// Incus, Lima's Create() must never start or stop the instance, since the
// non-root user comes from cloud-init at first boot, not a bootstrap step
// Create() runs itself.
func TestCreate_DoesNotStartOrStopInstance(t *testing.T) {
	fr := &fakeRunner{}
	p, _ := newTestProvider(t, fr, false)

	if _, err := p.Create(context.Background(), provider.InstanceSpec{Name: "demo", Image: "template://ubuntu-lts"}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if len(fr.calls) != 2 {
		t.Fatalf("expected exactly 2 calls (create + status lookup), got %d: %v", len(fr.calls), fr.calls)
	}
	for _, c := range fr.calls {
		if contains(c, "start") || contains(c, "stop") {
			t.Errorf("Create must not start or stop the instance, got call: %v", c)
		}
	}
}

func contains(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

// shrinkReadyWait overrides the package-level readiness timing so tests
// exercising waitForReady don't have to wait out the real 30s default.
func shrinkReadyWait(t *testing.T) {
	t.Helper()
	origTimeout, origPoll := readyTimeout, readyPollInterval
	readyTimeout = 100 * time.Millisecond
	readyPollInterval = 5 * time.Millisecond
	t.Cleanup(func() {
		readyTimeout, readyPollInterval = origTimeout, origPoll
	})
}

func TestExec_WaitsForReadyBeforeRunning(t *testing.T) {
	shrinkReadyWait(t)
	fr := &fakeRunner{readyFailCount: 2}
	p, _ := newTestProvider(t, fr, false)
	var stderr bytes.Buffer
	opts := provider.ExecOptions{Command: []string{"echo", "hi"}, Stderr: &stderr}

	code, err := p.Exec(context.Background(), "demo", opts)
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if code != 0 {
		t.Errorf("code = %d, want 0", code)
	}
	if !strings.Contains(stderr.String(), "waiting for the Lima guest") {
		t.Errorf("stderr = %q, want a heads-up about waiting for the guest", stderr.String())
	}
	want := append([]string{binary}, buildExecArgs("demo", opts.Command, false)...)
	assertLastCall(t, fr, want)
}

func TestExec_ReadyNeverBeforeTimeout(t *testing.T) {
	shrinkReadyWait(t)
	fr := &fakeRunner{readyFailAlways: true}
	p, _ := newTestProvider(t, fr, false)

	_, err := p.Exec(context.Background(), "demo", provider.ExecOptions{Command: []string{"echo", "hi"}})
	if err == nil {
		t.Fatal("expected an error once the guest never becomes reachable")
	}
	if !strings.Contains(err.Error(), "did not become reachable") {
		t.Errorf("error = %q, want it to explain the guest timed out", err.Error())
	}
	realArgs := buildExecArgs("demo", []string{"echo", "hi"}, false)
	for _, c := range fr.calls {
		if reflect.DeepEqual(c[1:], realArgs) {
			t.Errorf("real exec command was run despite the guest never becoming reachable: %v", c)
		}
	}
}

// waitForReady deliberately does NOT fail fast on an unrelated probe
// error the way incus.go's waitForAgent does (see lima.go's doc comment
// on waitForReady) — there's no known substring to match against yet, so
// there's nothing to test a fail-fast path against. This comment
// documents that omission explicitly rather than silently leaving it out.

func TestExec_RootFlag_UsesSudoNonInteractive(t *testing.T) {
	fr := &fakeRunner{}
	p, _ := newTestProvider(t, fr, false)

	if _, err := p.Exec(context.Background(), "demo", provider.ExecOptions{Command: []string{"whoami"}, Root: true}); err != nil {
		t.Fatalf("Exec: %v", err)
	}
	want := append([]string{binary}, buildExecArgs("demo", []string{"whoami"}, true)...)
	assertLastCall(t, fr, want)
}

func TestShell_RootFlag_UsesSudoDashI(t *testing.T) {
	fr := &fakeRunner{}
	p, _ := newTestProvider(t, fr, false)

	if err := p.Shell(context.Background(), "demo", provider.ShellOptions{Root: true}); err != nil {
		t.Fatalf("Shell: %v", err)
	}
	want := append([]string{binary}, buildShellArgs("demo", true)...)
	assertLastCall(t, fr, want)
}

func TestList_ParsesInstances(t *testing.T) {
	fr := &fakeRunner{listJSON: `[{"name":"a","status":"Running"},{"name":"b","status":"Stopped"}]`}
	p, _ := newTestProvider(t, fr, false)

	got, err := p.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 2 || got[0].Name != "a" || got[1].Name != "b" {
		t.Errorf("List() = %+v, want two instances a/b", got)
	}
}

func TestStatus_NotFound(t *testing.T) {
	fr := &fakeRunner{listJSON: `[]`}
	p, _ := newTestProvider(t, fr, false)

	_, err := p.Status(context.Background(), "missing")
	if !errors.Is(err, provider.ErrNotFound) {
		t.Errorf("Status() error = %v, want ErrNotFound", err)
	}
}

func TestName(t *testing.T) {
	p, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if p.Name() != "lima" {
		t.Errorf("Name() = %q, want lima", p.Name())
	}
}

// TestStubbedMethods_ReturnCapabilityError guards that the still-stubbed
// methods (view/snapshot/image-pull/image-build/logs, plus network policy
// off macOS) return the sentinel error matching their capability entry,
// rather than silently no-opping or panicking if called directly
// (bypassing internal/cli's capability gate). The macOS side of network
// policy is covered in network_test.go.
func TestStubbedMethods_ReturnCapabilityError(t *testing.T) {
	fr := &fakeRunner{}
	p, _ := newTestProvider(t, fr, false)
	ctx := context.Background()

	if err := p.View(ctx, "demo", provider.ViewOptions{}); !errors.Is(err, provider.ErrUnderDevelopment) {
		t.Errorf("View() error = %v, want ErrUnderDevelopment", err)
	}
	if err := p.SnapshotCreate(ctx, "demo", "snap"); !errors.Is(err, provider.ErrNotAvailable) {
		t.Errorf("SnapshotCreate() error = %v, want ErrNotAvailable", err)
	}
	if err := p.ApplyNetworkPolicy(ctx, "demo", provider.NetworkPolicy{}); !errors.Is(err, provider.ErrNotAvailable) {
		t.Errorf("ApplyNetworkPolicy() error = %v, want ErrNotAvailable", err)
	}
	if err := p.ImagePull(ctx, "template://ubuntu-lts"); !errors.Is(err, provider.ErrNotAvailable) {
		t.Errorf("ImagePull() error = %v, want ErrNotAvailable", err)
	}
	if _, err := p.ImageBuild(ctx, provider.ImageBuildSpec{}); !errors.Is(err, provider.ErrUnderDevelopment) {
		t.Errorf("ImageBuild() error = %v, want ErrUnderDevelopment", err)
	}
	if _, err := p.Logs(ctx, "demo", provider.LogOptions{}); !errors.Is(err, provider.ErrNotAvailable) {
		t.Errorf("Logs() error = %v, want ErrNotAvailable", err)
	}
}
