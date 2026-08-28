package lima

import (
	"reflect"
	"testing"

	"github.com/apomonosi/sandboxing/internal/provider"
)

func TestBuildCreateArgs_Full(t *testing.T) {
	spec := provider.InstanceSpec{
		Name:        "demo",
		Image:       "template://ubuntu-lts",
		DefaultUser: "claude",
		Resources:   provider.ResourceLimits{CPUCores: 2, Memory: "4GiB", DiskSize: "20GiB"},
		Mounts:      []provider.Mount{{HostPath: "/host/ws", GuestPath: "/workspace", ReadOnly: true}},
		Overrides: provider.NetworkPolicy{
			Ports: []provider.PortPublish{{HostPort: 8080, GuestPort: 80, Protocol: "tcp"}},
		},
	}
	got := buildCreateArgs(spec)
	want := []string{
		"create", "--name=demo", "--tty=false",
		"--set", `.cpus = 2`,
		"--set", `.memory = "4GiB"`,
		"--set", `.disk = "20GiB"`,
		"--set", `.user.name = "claude"`,
		"--set", `.mounts += [{"location": "/host/ws", "mountPoint": "/workspace", "writable": false}]`,
		"--set", `.portForwards += [{"guestPort": 80, "hostPort": 8080, "proto": "tcp"}]`,
		"template://ubuntu-lts",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("buildCreateArgs() = %v, want %v", got, want)
	}
}

// TestBuildCreateArgs_DefaultUsername_FallsBackToAgent is a regression
// test for cross-provider consistency: --agent=claude sets DefaultUser on
// Incus too, but a bare spec (no --agent) must still get a fixed,
// predictable username on Lima rather than whatever the template's own
// cloud-init default happens to be (which would vary per developer
// machine).
func TestBuildCreateArgs_DefaultUsername_FallsBackToAgent(t *testing.T) {
	got := buildCreateArgs(provider.InstanceSpec{Name: "demo", Image: "template://ubuntu-lts"})
	var sawUsername bool
	for _, a := range got {
		if a == `.user.name = "agent"` {
			sawUsername = true
		}
	}
	if !sawUsername {
		t.Errorf("buildCreateArgs() = %v, want it to include .user.name = \"agent\"", got)
	}
}

func TestBuildSetExpressions_Mounts(t *testing.T) {
	spec := provider.InstanceSpec{
		Mounts: []provider.Mount{
			{HostPath: "/a", GuestPath: "/b", ReadOnly: false},
			{HostPath: "/c", GuestPath: "/d", ReadOnly: true},
		},
	}
	got := buildSetExpressions(spec)
	wantWritable := `.mounts += [{"location": "/a", "mountPoint": "/b", "writable": true}]`
	wantReadOnly := `.mounts += [{"location": "/c", "mountPoint": "/d", "writable": false}]`
	if !containsExpr(got, wantWritable) {
		t.Errorf("buildSetExpressions() = %v, want it to include %q", got, wantWritable)
	}
	if !containsExpr(got, wantReadOnly) {
		t.Errorf("buildSetExpressions() = %v, want it to include %q", got, wantReadOnly)
	}
}

// TestBuildSetExpressions_PortForwards_DefaultsProtoToTCP mirrors Incus's
// own buildPortProxyDeviceArgs default (see incus/translate.go).
func TestBuildSetExpressions_PortForwards_DefaultsProtoToTCP(t *testing.T) {
	spec := provider.InstanceSpec{
		Overrides: provider.NetworkPolicy{
			Ports: []provider.PortPublish{{HostPort: 2222, GuestPort: 22}},
		},
	}
	got := buildSetExpressions(spec)
	want := `.portForwards += [{"guestPort": 22, "hostPort": 2222, "proto": "tcp"}]`
	if !containsExpr(got, want) {
		t.Errorf("buildSetExpressions() = %v, want it to include %q", got, want)
	}
}

func containsExpr(exprs []string, want string) bool {
	for _, e := range exprs {
		if e == want {
			return true
		}
	}
	return false
}

func TestBuildEditArgs(t *testing.T) {
	got := buildEditArgs("demo", `.cpus = 2`)
	want := []string{"edit", "--set", ".cpus = 2", "demo"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("buildEditArgs() = %v, want %v", got, want)
	}
}

func TestBuildStartArgs(t *testing.T) {
	got := buildStartArgs("demo")
	want := []string{"start", "demo"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("buildStartArgs() = %v, want %v", got, want)
	}
}

func TestBuildStopArgs_Force(t *testing.T) {
	got := buildStopArgs("demo", provider.StopOptions{Force: true})
	want := []string{"stop", "demo", "--force"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("buildStopArgs(Force) = %v, want %v", got, want)
	}
	got = buildStopArgs("demo", provider.StopOptions{})
	want = []string{"stop", "demo"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("buildStopArgs() = %v, want %v", got, want)
	}
}

func TestBuildDeleteArgs_Force(t *testing.T) {
	got := buildDeleteArgs("demo", true)
	want := []string{"delete", "demo", "--force"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("buildDeleteArgs(true) = %v, want %v", got, want)
	}
	got = buildDeleteArgs("demo", false)
	want = []string{"delete", "demo"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("buildDeleteArgs(false) = %v, want %v", got, want)
	}
}

func TestBuildListArgs(t *testing.T) {
	got := buildListArgs()
	want := []string{"list", "--json"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("buildListArgs() = %v, want %v", got, want)
	}
	got = buildListOneArgs("demo")
	want = []string{"list", "demo", "--json"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("buildListOneArgs() = %v, want %v", got, want)
	}
}

func TestBuildExecArgs_Root(t *testing.T) {
	got := buildExecArgs("demo", []string{"whoami"}, true)
	want := []string{"shell", "demo", "--", "sudo", "-n", "whoami"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("buildExecArgs(root) = %v, want %v", got, want)
	}
}

func TestBuildExecArgs_NonRoot(t *testing.T) {
	got := buildExecArgs("demo", []string{"whoami"}, false)
	want := []string{"shell", "demo", "--", "whoami"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("buildExecArgs(non-root) = %v, want %v", got, want)
	}
}

func TestBuildShellArgs_Root(t *testing.T) {
	got := buildShellArgs("demo", true)
	want := []string{"shell", "demo", "--", "sudo", "-i"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("buildShellArgs(root) = %v, want %v", got, want)
	}
}

func TestBuildShellArgs_NonRoot(t *testing.T) {
	got := buildShellArgs("demo", false)
	want := []string{"shell", "demo"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("buildShellArgs(non-root) = %v, want %v", got, want)
	}
}
