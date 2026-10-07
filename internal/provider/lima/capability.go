package lima

import "github.com/apomonosi/sandboxing/internal/provider"

// buildCapabilities returns Lima's capability table.
//
// Two different kinds of gap show up here, and it matters which is which:
//
//   - UnderDevelopment: Lima itself supports this fine; agentctl just
//     hasn't wired the `limactl` integration up yet. It's our roadmap,
//     not a platform limit.
//   - NotAvailable: the platform genuinely lacks the primitive (no local
//     image store; no way to confine Lima's processes off macOS) or the
//     relevant upstream API is too unstable to build on yet (limactl
//     snapshot is explicitly experimental).
//
// create/start/stop/delete/list/status/exec/shell/network.port-publish
// are Supported as of this backend's real implementation (lima.go,
// translate.go). image.pull is NotAvailable, not just unwired: Lima has
// no local named image store to pull into ahead of `create` — a
// template's base image resolves lazily, per-instance, inside
// `create`/`start` itself, so there's no daemon-side store to wire up to.
//
// network.acl/network.deny-lan are Supported when confine is set (macOS):
// Lima has no ACL object, but agentctl enforces the same policy Incus's
// ACL does, host-side, by confining Lima's own processes (network.go).
// That enforcement is built on macOS's sandbox-exec, so anywhere else
// (Lima on a Linux host) both are NotAvailable — there's no comparable
// way to confine the hostagent there, and the Incus provider is the
// supported choice on Linux anyway.
func buildCapabilities(confine bool) provider.Table {
	t := make(provider.Table, len(provider.AllFeatures))

	supported := func(f provider.Feature) {
		t[f] = provider.Capability{Feature: f, Status: provider.Supported}
	}
	underDev := func(f provider.Feature, msg string) {
		t[f] = provider.Capability{
			Feature:     f,
			Status:      provider.UnderDevelopment,
			Message:     msg,
			TrackingURL: "https://github.com/apomonosi/sandboxing/issues", // placeholder until real issues exist
		}
	}

	supported(provider.FeatureCreate)
	supported(provider.FeatureStart)
	supported(provider.FeatureStop)
	supported(provider.FeatureDelete)
	supported(provider.FeatureList)
	supported(provider.FeatureStatus)
	supported(provider.FeatureExec)
	supported(provider.FeatureShell)
	supported(provider.FeaturePortPublish)

	underDev(provider.FeatureView, "Lima has no first-class GUI console; agentctl plans a dedicated VNC bridge against the VM's own display, not yet built.")
	underDev(provider.FeatureImageBuild, "agentctl hasn't wired a Lima cloud-init JIT build path up yet.")
	underDev(provider.FeatureLogsExec, "agentctl hasn't wired exec history collection up yet.")

	t[provider.FeatureImagePull] = notAvailable(provider.FeatureImagePull,
		"Lima has no local named image store to pull into ahead of create; a template's base image resolves lazily, per-instance, inside create/start itself.")

	t[provider.FeatureSnapshotCreate] = notAvailable(provider.FeatureSnapshotCreate,
		"limactl snapshot is explicitly experimental/unstable upstream; agentctl won't build on it until it stabilizes.")
	t[provider.FeatureSnapshotList] = notAvailable(provider.FeatureSnapshotList,
		"limactl snapshot is explicitly experimental/unstable upstream; agentctl won't build on it until it stabilizes.")
	t[provider.FeatureSnapshotRestore] = notAvailable(provider.FeatureSnapshotRestore,
		"limactl snapshot is explicitly experimental/unstable upstream; agentctl won't build on it until it stabilizes.")
	t[provider.FeatureSnapshotDelete] = notAvailable(provider.FeatureSnapshotDelete,
		"limactl snapshot is explicitly experimental/unstable upstream; agentctl won't build on it until it stabilizes.")

	if confine {
		supported(provider.FeatureNetworkACL)
		supported(provider.FeatureDenyLAN)
		underDev(provider.FeatureLogsNetwork, "Each Lima instance's egress proxy already records every allowed and denied connection (~/.config/agentctl/lima/<name>/egress-proxy.log), but `agentctl logs` isn't wired up to it yet.")
	} else {
		const why = "agentctl enforces Lima network policy by confining Lima's own processes with macOS's sandbox-exec, which doesn't exist on this host OS; on Linux, use the incus provider."
		t[provider.FeatureNetworkACL] = notAvailable(provider.FeatureNetworkACL, why)
		t[provider.FeatureDenyLAN] = notAvailable(provider.FeatureDenyLAN, why)
		t[provider.FeatureLogsNetwork] = notAvailable(provider.FeatureLogsNetwork,
			"No egress log source exists without network policy enforcement, which isn't available for Lima on this host OS.")
	}

	return t
}

func notAvailable(f provider.Feature, msg string) provider.Capability {
	return provider.Capability{Feature: f, Status: provider.NotAvailable, Message: msg}
}
