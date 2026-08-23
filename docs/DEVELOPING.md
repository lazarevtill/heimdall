# Developing Heimdall

For humans and for coding agents. [`../AGENTS.md`](../AGENTS.md) is the
**contract** — the trust invariants, the package map, the style budget. Read
it first and treat it as binding. This document is the *practical* layer: how
to set up, what the gates actually check, how to add each kind of thing, and
the traps that have already cost time.

---

## Before you change anything

Four rules that are not negotiable and are enforced in code, not just prose:

1. **Unknown is always alertable.** Never convert a failure into a calm
   result. If a source, plugin or read fails, the answer is `unknown`.
2. **The LLM can never page, resolve, or silence.** `NewFinding` refuses
   `class=hypothesis`; `make lint` fails if `internal/llm` becomes reachable
   from `heimdall-detect`'s or `heimdall-ui`'s dependency graph.
3. **Fail-closed redaction at every egress**, and redaction happens **once**,
   at enqueue. Do not add a second pass; do not widen an egress without
   routing it through the redactor.
4. **Suppression silences notification, never detection.** A muted finding
   keeps its series and stays in the digest.

The rest of this file assumes those.

---

## Setting up to develop

```bash
go version          # go.mod says 1.25.0; GOTOOLCHAIN=auto, newer is fine
make ci             # lint + -race tests + static build of five binaries + govulncheck
```

`make test` runs with `CGO_ENABLED=1` because the race detector needs cgo —
you need a working C compiler. The **release** build is `CGO_ENABLED=0`; that
asymmetry is deliberate and recorded in the Makefile.

No other tooling is required. There is no linter to install, no generator to
run, no vendored toolchain.

**Establish a green baseline before you edit.** A failure you inherited is
much cheaper to recognise at the start than to debug at the end.

---

## What the gates actually check

`make lint` is more than `gofmt` + `vet`. Each gate encodes a decision:

| Gate | Refuses | Because |
|---|---|---|
| `time.Now()` in `internal/` | any call, tests included | the clock is injected, so window boundaries and cooldowns are table-testable |
| `contract.Finding{}` literals outside `internal/contract` | composite literals | `NewFinding` is the only sanctioned constructor (ADR-G09) — its caps cannot be bypassed |
| `internal/llm` on the detector's dep graph | any path | Tier 3 must stay off the trusted path (G1) |
| `internal/llm` on the console's dep graph | any path | the console *displays* hypothesis text; it must never be able to call the model |
| real-infra strings | `192.168.`, the cluster domain, a datastore name | this repo is mirrored to a public GitHub |
| secret-shaped tokens | `glpat-…` outside defanged fixtures | same |
| `go mod verify` | tampered module cache | reproducibility |

`policy_test.go` separately enforces the **three-direct-dependency budget**:
`golang.org/x/sync`, `modernc.org/sqlite`, `github.com/google/go-cmp`. Adding
a fourth requires amending ADR-G02 **first**. This is why the OIDC relying
party in `cmd/heimdall-ui` is hand-rolled from stdlib rather than using
`go-oidc`.

---

## Testing style

- **TDD, table-driven**, assert with `go-cmp` — not testify.
- **Inject the clock.** Every test in `internal/` uses a fixed `now`.
- **Golden vectors** pin the wire format and the fingerprint algorithm.
  Regenerate deliberately, never blindly: changing them breaks dedup identity
  across every existing finding.
- **Never a live network.** Drive an `httptest.Server` or a fake. Live tests
  are env-gated and not committed.
- **Test against the real producer, not a fixture that resembles it.** The
  console's readers are tested by driving `emit.WriteSpool`, `digest.Write`
  and `bridge.UpsertIssue` and reading the result back. A hand-rolled fixture
  would have hidden the `contract.State` decode problem below entirely.

Write the failing test **before** the fix.

---

## Logging convention

One mechanism, set once per binary, never repeated at a call site.

```go
func configureLogging() {
	log.SetFlags(0)                      // journald already stamps every line
	log.SetPrefix("heimdall-<binary>: ") // set ONCE, here
}
```

Rules:

- **`log`, never `fmt.Fprintln(os.Stderr, ...)`.** Both write to stderr; having
  two mechanisms for one job is how the formats drifted apart originally.
- **No flags.** Every binary runs under systemd and journald timestamps each
  line. `LstdFlags` would put a second timestamp *inside* the message.
- **Never write the binary name into a message or an error string.**
  `log.SetPrefix` supplies it. An error built as
  `fmt.Errorf("heimdall-ui: ...")` and then logged prints the name twice.
  Package-level prefixes from `internal/` (`config:`, `outbox:`) are different
  and welcome — they say which component failed.
- **`WARNING: ` for a condition that is not fatal but that an operator must
  see** — a disabled auth mode, a tracker credential that failed at startup.
- **`internal/` does not log at all.** Libraries return errors; the `cmd/`
  caller decides what is worth a line. Two comments in `internal/` mention
  logging, and both are about handing something *to* the caller to log. Keep it
  that way: a library that logs cannot be used quietly.

## How to add things

### A new check (Tier 1)

Checks are **pure functions** `(now, expectation, signal) → []Finding`. No
I/O. Put the logic in `internal/detect`, mint findings only via
`contract.NewFinding`, and let the engine handle concurrency and the panic
boundary.

Then **prove the rule can fire**. A check that matches nothing looks exactly
like a healthy system. Run it against real data, then run it again with a
threshold the current data must cross.

### A new source

Implement `source.Source` in `internal/source`. The contract is tri-state and
fail-closed: any error, timeout or panic becomes `unknown`, never an empty
`ok`. Pin the CA if it speaks TLS — never `InsecureSkipVerify`.

### A new notification sink

Implement `notify.Sink` — `ID()` and `Send(ctx, outbox.Entry)`.

**The verbatim-body contract:** transmit `e.Body` byte-identical. You may add
only *static* per-sink configuration (a title, a priority, a chat id). Never
anything derived from message content, and **never a second redaction pass** —
that would create independently-configured redactors free to drift apart.

Put the transport in its own package next to `internal/telegram`, keep it pure
(no policy, no state, no clock), make it fail-closed, and have it scrub its
own credential out of any error it returns — `net/http` puts the request URL
in its error strings.

Register it in `internal/notify/sinkconfig.go` and add validation for its
required fields. Every validation rule should map to a way messages would
otherwise vanish quietly.

**There is no sink *plugin* kind, deliberately.** A sink inherently needs the
credential and network egress that the subprocess host's capability scoping
exists to withhold, so it would buy no isolation and cost a second ABI. See
`contract/PLUGIN_SCHEMA.md`, which records the reasoning as the test any
future plugin kind must pass.

### A new console page

1. A **reader** in `cmd/heimdall-ui` that is fail-soft and non-fabricating:
   every unusable state yields an explicit reason, never invented data, and
   "empty" must never look like "unreadable".
2. A **view model** free of `net/http` and of the wall clock, so the whole
   behaviour is table-testable.
3. A route, a template, a nav entry.
4. Tests: the reader against the real producer, and the route through the
   real handler including the auth matrix and HTML escaping.

Reads are `GET`; every write is `POST`. A mute or an action must never be
reachable by a link a browser can prefetch.

### A plugin

Subprocess, JSON over stdin/stdout, capability-scoped. The core never imports
plugin code. `contract/PLUGIN_SCHEMA.md` is the wire contract; note that the
manifest now rejects **unknown fields**, so a stale key fails loud rather than
being silently ignored.

---

## Traps this codebase has already hit

Each of these cost real time. They are listed because they are not obvious
from the types.

**`contract.Finding` does not round-trip.** `State` has `MarshalJSON` and no
`UnmarshalJSON`, so a spool doc cannot be decoded back into a `Finding` —
`json.Unmarshal` fails with *"cannot unmarshal string into Go struct field
Finding.state"*. Readers use a local DTO. `contract.Digest` **does** round-trip
(`DigestStatus` has both halves, and its unmarshal is fail-closed), so the real
type is reused there. Verify, do not assume, before reusing a wire type.

**A fingerprint is a filename.** The spool writes `<fingerprint>.json`, and
fingerprints arrive from untrusted places — a URL path segment, an
Alertmanager webhook label. Always `contract.ValidFingerprint` before joining
one to a path. A path-traversal via `labels["fingerprint"]` was live in the
bridge until it was closed.

**`hyp_fp` and finding fingerprints share a grammar.** Both are 16 lowercase
hex and both pass `ValidFingerprint`. They are different namespaces: give
hypotheses their own routes and labels.

**`OpenStore` writes.** `bridge.OpenStore`, `outbox.Open` and
`analyst.OpenStore` all run `CREATE TABLE IF NOT EXISTS` on open. A
"read-only" consumer of those files is not strictly read-only. Idempotent and
harmless, but do not claim otherwise in a doc comment.

**SQLite stores that share a file open their own handle** with the same WAL
config and **never touch `PRAGMA user_version`** — that counter belongs to
whichever migrator owns the file. New tables use `CREATE TABLE IF NOT EXISTS`
plus an idempotent backfill instead of a migration counter.

**The same file has two variable names.** The engine state.db is
`HEIMDALL_STATE_DB` to the detector and `HEIMDALL_ENGINE_STATE_DB` to
everything else. Splitting them produces no error, just silence.

**Map iteration leaks into output.** Anything rendered — a metric series, a
log line, a page — must be sorted first, or it reorders between runs for no
reason. Where timestamps tie (one detector run stamps every finding
identically), add a deterministic tiebreak.

**`go build ./cmd/<name>` writes a binary into your working directory.**
Without `-o` it does, and `git add -A` will then commit 16–20 MB of unstripped
debug binary into a public-mirrored repo. `make build` always passes
`-o bin/`; the repo-root names are now gitignored, but the habit to keep is
building through `make`.

**An absent series cannot alert.** When adding a gauge with labels, emit an
explicit zero for every expected label combination. A sink that has never had
a backlog must still have a series, or it is indistinguishable from a sink
that was removed.

---

## Process

- Branch → MR → merge. Never force-push shared history.
- Conventional commits: `feat:`, `fix:`, `docs:`, `refactor:`, `chore:`,
  with a scope where it helps (`feat(notify):`).
- Explain **why** in the commit body. The diff shows what changed; the message
  is where the reasoning lives, and this repo leans on that heavily.
- **Never commit real IPs, hostnames, Vault paths, or tokens.** `design/` is
  private-only. The lint gate catches the obvious cases; it is not a substitute
  for care.
- Update the docs in the **same** change as the code. A follow-up docs commit
  does not happen.

---

## See also

- [`../AGENTS.md`](../AGENTS.md) — the binding contract
- [`SETUP.md`](SETUP.md) — running it
- [`DEBUGGING.md`](DEBUGGING.md) — when it misbehaves
- [`../contract/`](../contract/) — wire schemas
- [`../design/`](../design/) — design records (private-only)
