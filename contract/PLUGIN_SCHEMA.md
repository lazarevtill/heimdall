# PLUGIN_SCHEMA

The wire contract for running a *source* or *detector* as an isolated
subprocess instead of a harness edit. Go types + enforcement: `internal/plugin`.

## `plugin.json` manifest

`{plugin_api, id, kind, version, capabilities, budgets}`

- **plugin_api** (int) is the ABI **major** version. The host speaks exactly
  one: `plugin.PluginAPIVersion`. A mismatch is a **hard, named error**
  (`plugin_api %d does not match host ABI %d`) — never silently tolerated.
  `LoadManifest`/`Run` refuse the plugin outright; the caller (the source
  adapter) turns that refusal into `source.Signal{State: Unknown}`, which the
  engine turns into an alertable Unknown finding. A version mismatch is
  therefore **harness-refused, never silent**.
- **id** matches `^[a-z0-9]{2,16}$`.
- **kind** ∈ `source | detector`.
- **version** is non-empty and opaque to the host (a plugin's own semver, not
  interpreted).
- **capabilities** — see below.
- **budgets** — `{deadline_seconds, memory_mb, max_output_bytes}`;
  `deadline_seconds > 0` and `max_output_bytes > 0` are hard requirements;
  `memory_mb >= 0` is accepted but only **advisory** at N=1 (see Sandbox
  status).

## Capabilities — the plugin's DECLARED, capability-scoped access

`{credential?, endpoints?}`. The host grants **nothing** beyond
what is declared here.

- **SOURCE**: may declare **at most one** credential — `credential` names the
  env var the host injects the one secret value into — and an `endpoints`
  allow-list. `endpoints` is **advisory at N=1**: it is parsed and recorded,
  not enforced by this package (see Sandbox status). If present, every entry
  must be non-empty.
- **DETECTOR**: is structurally I/O-free. It **must** declare no credential
  and no endpoints; a detector asking for either is rejected by
  `Manifest.Validate` — a detector has no legitimate reason to hold a secret
  or reach a network endpoint.

**There is no sink kind, and no plugin-visible sink registry.** Notification
delivery is IN-PROCESS (`internal/notify.Sink`, with `internal/telegram`,
`internal/gotify` and `internal/synology` behind it). A `capabilities.egress_id`
field was once reserved here for a future sink plugin; it has been REMOVED,
along with the idea. The reasoning is worth keeping, because it is the same
test any future plugin kind has to pass:

> The entire value of this subprocess host is capability scoping — a scrubbed
> environment, one declared credential, a deadline, an output cap. A sink
> *inherently* needs the credential and the network egress that scoping exists
> to withhold, so a Gotify or Synology sink plugin would hold the same token
> and reach the same endpoint as ~100 lines of stdlib `net/http` we wrote
> ourselves. It would buy no isolation and cost a second ABI (delivery-result
> wire types, partial-batch semantics, per-sink binaries) — while Telegram
> must stay in-process regardless, because its inline-button → suppression
> path is stateful and long-polled. Two delivery paths forever, for nothing.

Subprocess isolation is for **untrusted or third-party** code. First-party
transports belong next to the core. A manifest still declaring `egress_id` is
now a hard parse error (`LoadManifest` rejects unknown fields), rather than a
field that is silently ignored while its author believes it is in force.

## Kinds

### SOURCE: `FetchPlan` → `SignalSet`

Reference shape for the S3-b adapter (field names finalized there):

```
FetchPlan  {plugin_api, queries: [{query_id, expr, timeout_seconds}], cursor_state?}
SignalSet  {plugin_api, signals: {query_id -> {state, samples: [{labels, value}], err}}, cursor_state?}
```

`FetchPlan` is written to the child's stdin; `SignalSet` is read from its
stdout. `state` mirrors `contract.State` (`unknown | ok | firing`); an
`err` on any one query signal does not fail the whole batch, but a Run-level
failure (bad exit, timeout, oversized output) discards the **entire**
`SignalSet` — there is no partial acceptance (see "Fail-closed execution
contract" below).

### DETECTOR: `PluginInput` → `PluginOutput` (reserved)

Detectors are I/O-free: no credential, no network capability, no file
writes — they consume the harness-provided input and return computed output
only. The detector wire types are **reserved for a later slice**; S3 ships
the source ABI only.

## Fail-closed execution contract

`Run` either accepts a plugin's output **whole**, or discards it **whole**
and returns a non-nil error. There is no partial acceptance. Every one of the
following is a fail-closed error, not a degraded success:

- the manifest fails to validate (including a `plugin_api` mismatch)
- the child fails to start (missing or non-executable binary)
- the child exits non-zero
- the deadline elapses (`min(ctx deadline, budgets.deadline_seconds)`) — the
  child **and its process group** are killed so a forking child cannot
  outlive the timeout
- the child's stdout exceeds `budgets.max_output_bytes` — the child is
  killed and the output is discarded, never truncated-and-returned

The child's environment is **scrubbed**: it inherits nothing from the host
process — no `PATH`, no `HOME`, no ambient secrets — plus, iff `kind` is
`source` and `capabilities.credential` is set, exactly one env var
`"<credential>=<secret>"` carrying the one declared credential's value.
Captured stderr (bounded to a small fixed cap) is folded into the error text
on a non-zero exit or a kill, for diagnostics only — it is never mixed into
the returned stdout.

`Run` validates none of the plugin's stdout **content** — it does not decode
JSON or check the payload's own `plugin_api` field. That is the separate
ABI-decode step (the typed `DecodeSignalSet` helper, S3-b) layered on top, so
the host stays kind-agnostic. `Run`'s contract is purely: "ran to a clean
exit within budget, here are the ≤cap bytes it wrote."

The caller turns **any** `Run` error into `source.Signal{State: Unknown}`;
the engine already treats Unknown as alertable. A broken plugin can never
look like a clean, calm run.

## Sandbox status

At N=1 this package isolates a plugin at the **process** level only:
a scrubbed environment (no inherited PATH/HOME/secrets beyond the one
declared credential), a hard wall-clock deadline, an output-size cap, and a
process-group kill so a forking child cannot outlive either. Nothing this
package does grants network reachability beyond whatever a source's own
declared credential + advisory `endpoints` imply is intended — but nothing
here *enforces* that intent at the kernel level either.

This package does **not** provide kernel-level network or filesystem
sandboxing. That is the responsibility of the **infra layer** — the
`systemd-run` transient-scope unit that launches `heimdall-detect` — via
`IPAddressDeny`, `MemoryMax`, `ProtectSystem`, and friends. That control is
gated on a named, unresolved operator pre-check (does `IPAddressDeny` behave
as expected in the target unprivileged LXC?) and is out of scope for this
package. `memory_mb` and `endpoints` are **declared and recorded** by this
package for that future infra layer to consume; they are not enforced here.
Do not read a stronger guarantee into this document than the process-level
hygiene described above.
