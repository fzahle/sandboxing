# Preview Mode (`--preview` / `--dry-run`)

Pass `--preview` (or its alias `--dry-run`) to any command that shells out to
the backend, and instead of running anything, `agentctl` prints the exact
command(s) it would have run:

```console
$ agentctl --preview create demo --image=images:ubuntu/24.04 --profile=default --port=8080:80
incus init images:ubuntu/24.04 demo --vm -c security.secureboot=false -p default -c limits.cpu=2 -c limits.memory=4GiB
incus config device override demo root size=20GiB
incus config device add demo mount0 disk source=~/agentctl/workspaces/{{.Name}} path=/workspace
incus config device add demo port0 proxy listen=tcp:0.0.0.0:8080 connect=tcp:127.0.0.1:80
incus network acl delete agentctl-demo
incus network acl create agentctl-demo
incus network acl rule add agentctl-demo egress action=reject destination=10.0.0.0/8
incus network acl rule add agentctl-demo egress action=reject destination=172.16.0.0/12
incus network acl rule add agentctl-demo egress action=reject destination=192.168.0.0/16
incus network acl rule add agentctl-demo egress action=reject destination=169.254.0.0/16
incus network acl rule add agentctl-demo egress action=allow destination=151.101.0.223 protocol=tcp destination_port=443
incus config device override demo eth0 security.acls=agentctl-demo
```

Nothing runs. No instance is created, no ACL is touched. The output is a
plain, copy-pasteable list of `incus` invocations — one per line, correctly
shell-quoted — so you can run them by hand, put them in a script, or just
read them to understand exactly what agentctl was about to do.

## Why this exists

Transparency is the point, on two levels:

1. **Confidence in the tool.** Rather than trusting that agentctl's network
   policy enforcement, resource limits, and mounts are what it claims, you
   can see the actual backend commands and verify them yourself — against
   Incus's own documentation, or by running them one at a time.
2. **You don't have to install agentctl to benefit from it.** If you'd
   rather not add another tool to your primary desktop, run `agentctl
   --preview` on a machine where it's already available, copy the resulting
   `incus`/`limactl`/PowerShell commands, and run them directly wherever you
   actually want the sandbox — no agentctl installation required there at
   all.

## Where it's supported

Every command that dispatches to a backend supports `--preview`: `create`,
`start`, `stop`, `delete`, `exec`, `shell`, `view`, and `image pull`.

It's a global flag, so it goes before the subcommand (`agentctl --preview
create ...`) — the same as `--provider` or `--output`.

`--preview` only ever shows commands for an operation the active provider
actually supports. If the operation itself is blocked by the
[capability gate](../admin/capability-matrix.md) (`under development`, `not
available`, or an unforced `manual workaround`), you'll see that message
instead — `--preview` never fabricates output for something agentctl can't
really do yet. In practice this means `--preview` is fully live on the Incus
and Lima backends today, and has nothing to show yet on Hyper-V, since that's
still a stub implementation. Once that backend grows a real implementation,
it gets `--preview` support the same way Incus and Lima did: by implementing
the same internal interface (see [Capability Model](../reference/capability-model.md)).

## Lima: `start` shows its network confinement

On the Lima backend (macOS), starting an instance is where its network
policy gets enforced (see
[Lima setup](../admin/providers/lima-setup.md#network-policy-enforcement)),
so `start --preview` shows more than a bare `limactl start` — the full
sandbox profile included:

```console
$ agentctl --preview start demo
limactl edit --tty=false --start=false --set '.networks = []' --set '.ssh.localPort = 62774' --set '.propagateProxyEnv = false' --set '.env.http_proxy = "http://192.168.5.2:62775"' ... demo
/opt/homebrew/bin/agentctl egress-proxy --listen 127.0.0.1:62775 --policy /Users/me/.config/agentctl/lima/demo/egress-policy.json --pid-file /Users/me/.config/agentctl/lima/demo/egress-proxy.pid
/usr/bin/sandbox-exec -p '(version 1) (allow default) (deny network-outbound) (allow network-outbound (remote unix-socket)) (allow network-outbound (remote ip "localhost:62774")) (allow network-outbound (remote ip "localhost:62775"))' limactl start demo
limactl shell demo -- sh -c '...'
```

(Shortened here; the real output lists every `--set`, and the last line is
the full in-guest check that a direct connection out is refused.) The ports
are the ones `start` would pin right now. One caveat to the "no agentctl
needed" point above: the second line is agentctl itself — its egress proxy
is what applies the allowlist — so replicating a Lima start by hand means
running that proxy (or another filtering proxy) too.

## What guarantees preview output matches reality

Preview output is built from the *exact same* argument-construction code the
real dispatch path uses — there's no separate, hand-maintained copy that
could quietly drift out of sync with what actually executes. See
[Capability Model](../reference/capability-model.md#preview-and-drift) for
how this is enforced.
