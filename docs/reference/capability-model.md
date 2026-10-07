# Capability Model (internals)

Source of truth: `internal/provider/capability.go`. This is the mechanism
behind the "not available / under development / manual workaround" messages
described in [Troubleshooting](../user/troubleshooting.md) and the
[Capability Matrix](../admin/capability-matrix.md).

## Types

```go
type Status int
const (
    Supported Status = iota
    NotAvailable
    UnderDevelopment
    ManualWorkaround
)

type Feature string // e.g. FeatureCreate, FeatureNetworkACL, FeaturePortPublish

type Capability struct {
    Feature     Feature
    Status      Status
    Message     string // always shown, one-liner
    Plan        string // populated only for ManualWorkaround: a concrete,
                        // copyable procedure
    TrackingURL string // populated for UnderDevelopment: a roadmap link
}

type Table map[Feature]Capability
func (t Table) Get(f Feature) Capability // missing entry -> NotAvailable, never panics
```

`AllFeatures` is the closed set every provider must cover; a table-
completeness test (`internal/provider/capability_completeness_test.go`) runs
against every provider package — including Hyper-V's stub table — and
fails if any `Feature` is missing an entry, so a newly added feature can't
silently degrade to "unknown feature: not available" without someone
noticing.

## The two kinds of gap

It matters which of these a `Capability` represents:

- **`UnderDevelopment`**: the backend supports this fine; `agentctl`'s own
  integration just isn't built yet. This is the overwhelming majority of the
  Hyper-V stub table today, and a handful of remaining cells on Lima and
  Incus (e.g. `view`, `logs.*`) — see the
  [capability matrix](../admin/capability-matrix.md) for exactly which cells
  these are.
- **`NotAvailable` / `ManualWorkaround`**: the backend's platform genuinely
  lacks the primitive (Lima has no local image store; Hyper-V has no
  port-publish primitive) or the relevant upstream API is too unstable to
  build on yet (`limactl snapshot`). `ManualWorkaround` additionally means a
  concrete procedure exists — the `Plan` field carries it.

A missing *native* primitive doesn't have to mean a gap, though: Lima has no
network ACL object either, but agentctl enforces the same policy on macOS
by other means (a sandboxed hostagent plus a per-instance egress proxy — see
[Lima setup](../admin/providers/lima-setup.md#network-policy-enforcement)),
so those cells are `Supported`. What matters is whether agentctl enforces
the feature automatically, not which mechanism it uses.

Conflating these would either overstate a genuine platform limitation as
"just not implemented yet" or understate real, working functionality as a
permanent gap — both are misleading to someone deciding whether to trust a
given backend for a given task.

## Dispatch flow

Every leaf command in `internal/cli`:

1. Resolves the active `Provider` (`--provider` flag, falling back to
   persisted config).
2. Looks up `provider.Capabilities().Get(feature)` for the feature(s) it's
   about to touch — some conditionally, based on which flags were actually
   passed (e.g. `create` only checks `FeatureNetworkACL` if `--allow` was
   given, but always checks `FeatureDenyLAN` since that's on by default).
3. Calls `CapabilityGate` (`internal/cli/capability_gate.go`), a pure
   function (`io.Writer` in, no globals) that prints the standard message
   for the status and returns whether to proceed, plus an exit-code hint.
4. Only on `Supported` (or `ManualWorkaround` + `--force-partial`) does the
   command actually call the `Provider` method.

`CapabilityGate` is the single place all four statuses' user-facing copy and
exit codes are defined, so every command's behavior is consistent and the
whole thing is testable without Cobra or a real provider — see
`internal/cli/capability_gate_test.go`.

## Preview and drift

`internal/provider/preview.go` defines an optional second interface:

```go
type Command struct {
    Binary string
    Args   []string
}
func (c Command) String() string // shell-quoted, copy-pasteable

type CommandPreviewer interface {
    PreviewCreate(spec InstanceSpec) []Command
    PreviewStart(name string) []Command
    PreviewStop(name string, opts StopOptions) []Command
    PreviewDelete(name string, force bool) []Command
    PreviewExec(name string, opts ExecOptions) []Command
    PreviewShell(name string) []Command
    PreviewView(name string, opts ViewOptions) []Command
    PreviewImagePull(ref string) []Command
}
```

A provider implements this only if it has real commands to show — Incus and
Lima both do now; Hyper-V doesn't yet, since it's still a stub, so it simply
doesn't implement it. Nothing special has to happen for that case:
`internal/cli`'s `tryPreview` helper is only ever reached *after* the
capability gate has already let the operation through, and on Hyper-V today
the gate itself blocks with `UnderDevelopment` first — so `--preview`
naturally has nothing to show there without any provider-specific handling.

**The one thing this design is built to guarantee: preview output cannot
drift from what actually executes.** `internal/provider/incus/translate.go`
holds one argument-construction function per operation (`buildStartArgs`,
`buildStopArgs`, `buildExecArgs`, ...); both the real `Provider` methods in
`incus.go` and the `Preview*` methods in `preview.go` call the *same*
function. There is no second, hand-maintained copy of "what the command
looks like" that the preview path could quietly fall out of sync with —
`internal/provider/incus/incus_test.go`'s
`TestRealDispatch_MatchesPreview` asserts exactly this, by running each
real method against a fake runner and checking the recorded invocation
against the corresponding `Preview*` output.

## Extending it

Adding a new provider is: implement the `Provider` interface, build a
complete `capability.Table` covering every `Feature` in `AllFeatures`
(honestly categorizing each gap per the two kinds above), and register a
`Factory` for it in `cmd/agentctl/main.go`. Nothing in `internal/cli` needs
to change. Also implement `CommandPreviewer` if the provider shells out to
real commands (as opposed to an SDK/API client) — it's optional, but it's
what gives users of that backend the transparency `--preview` promises, and
following the pattern above (one builder function per operation, called by
both the real method and its `Preview*` counterpart) is what keeps it
trustworthy.
