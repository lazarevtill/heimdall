# AGENTS.md — working agreement for Heimdall

Canonical instructions for humans and coding agents in this repo. `CLAUDE.md` points here.

## What this is
A deterministic, IaC-managed log/metric observer. It catches **silent failures** (a backup
that ran broken with no threshold tripped) and slow **trends**, reasons over the residue with a
local LLM, and takes the right action per severity (notify vs ticket vs escalate). Design is in
`design/`; the canonical target is `design/2026-07-19-final-design.md`, the growth path is
`design/2026-07-19-heimdall-at-scale.md`, the language decision is `design/adr-0001-language-go.md`.

**Status:** all three tiers are **built** — five binaries, every connector, the plugin host, and
the llama.cpp analyst. Every surface with a reachable data source/credential is **live-verified**
against the real stack. The three-tier model and every trust invariant are enforced in code + CI.
What remains is deployment/IaC and operator-provisioned credentials.

## Practical guides

This file is the CONTRACT — what must stay true. The how-to layer lives beside it:
[`docs/SETUP.md`](docs/SETUP.md) (run it), [`docs/DEBUGGING.md`](docs/DEBUGGING.md) (symptom-first
triage), [`docs/DEVELOPING.md`](docs/DEVELOPING.md) (what the gates encode, how to add each kind
of thing, and the traps this codebase has already hit). When they disagree with this file, this
file wins and the guide is wrong.

## Binaries
- `cmd/heimdall-detect` — Tier-1 + Tier-2 oneshot (timer): manifest → sources → checks →
  ledger → redacted spool → atomic `.prom` + digest. The **only** `time.Now()` in the program.
- `cmd/heimdall-analyst` — Tier-3 oneshot: digest → health-gate LLM → analyze → verify/dedup/
  cap/redact → persist → POST `/hypothesis`.
- `cmd/heimdall-bridge` — HTTP daemon: `/am` (Alertmanager webhook → YouTrack), `/hypothesis`,
  `/healthz`; 15-min escalation sweep. `time.Now()` is allowed in `cmd/`.
- `cmd/heimdall-notifier` — daemon: Telegram getUpdates poll → button dispatch, outbox drain
  (fanned out to every routed sink), Alertmanager silence reconcile, weekly digest, own heartbeat.
- `cmd/heimdall-ui` — operator console (HTTP daemon). READS the finding ledger, the suppression
  authority, the outbox's per-sink backlog, the heartbeat textfiles, and the detector's redacted
  spool docs (its own read-only DTO: `contract.State` has no `UnmarshalJSON`, and decoding into a
  `contract.Finding` would mint one outside `NewFinding` — ADR-G09), and the Tier-2 digest (which
  DOES round-trip: `DigestStatus` has a fail-closed `UnmarshalJSON`, so the real type is reused),
  the Tier-3 analyst run files, and the bridge's issue ledger. Three things the hypotheses page
  must never imply, because the data invites all three: the run file holds only SURVIVORS (drops
  are counters in Prometheus, their text is retained nowhere); presence is not delivery (persist
  runs before any POST and survives a failed one); and confidence is metadata, never severity.
  `hyp_fp` shares the fingerprint grammar, so hypotheses get their own route — never `/finding/`.
  Access mode is explicit — `HEIMDALL_UI_AUTH` ∈ {oidc, token, none}; the OIDC relying party is
  stdlib-only (PKCE, RS256 pinned, iss/aud/exp/nonce checked) precisely because ADR-G02 fixes the
  direct-dependency budget at three. WRITES exactly one thing:
  a runtime mute via `suppress.AddMute`, so the 30-day cap, validation and the feedback ledger
  apply exactly as for a Telegram button. It cannot resolve, cannot delete a series, cannot mint
  a hypothesis, and cannot un-mute (no such operation exists — mutes expire). `time.Now()` is
  allowed in `cmd/`; the clock is injected into the server so every handler test is deterministic.

## Package map
- `internal/contract` — wire types (`Finding`/`Digest`/`HypothesisFinding`), `NewFinding`
  (refuses `hypothesis`, caps `trend`), `Fingerprint = sha256(check|target)[:16]`,
  `ValidFingerprint` (a fingerprint becomes a FILENAME — validate before joining it to a path,
  it arrives from webhook labels and URL segments),
  `HypFingerprint`, fail-closed `Redact`/`EvidenceOrWithheld`.
- `internal/manifest` — loads + validates the IaC-rendered expectation + Tier-2 manifest
  (rejects dup id AND dup `(check,target)` fingerprint; Tier-2 severity never `critical`).
- `internal/source` — `Source` interface + Prometheus, VictoriaLogs (LogsQL), and PBS
  (pinned-CA, never `InsecureSkipVerify`) clients; every failure → alertable `unknown`.
- `internal/detect` — pure checks (`DeadMan`, `Threshold`) + errgroup-bounded engine (panic
  boundary, never cancels siblings).
- `internal/baseline` — Tier-2 SQLite store (features/warmup/template_baseline/crossing) over the
  engine `state.db` (own handle, no `PRAGMA user_version`).
- `internal/tier2` — Tier-2 C6–C9 evaluation (robust-IQR zscore), graduation with hysteresis +
  7-day warm-up; unknown/warming never graduates.
- `internal/digest` — the Tier-2 digest producer (top-N cap, redact, 32 KB byte-cap, atomic
  `latest.json` + 14-day dated history).
- `internal/ledger` — SQLite finding ledger (`modernc.org/sqlite`, WAL, preserves `first_seen`).
- `internal/emit` — `.prom` render (frozen label set, no `state` label, no timestamps), atomic
  replace, redacted spool, analyst + notifier heartbeat renderers.
- `internal/config` — env + optional Vault-seeded cred file, fail-fast.
- `internal/suppress` — the **single suppression authority**: declarative (`suppressions.json`)
  ∪ runtime (SQLite mutes), five scopes, 30-day rolling cumulative cap, active-silence projection.
- `internal/plugin` — subprocess plugin host (manifest validate, `plugin_api` version gate,
  scrubbed-env/deadline/pgroup-kill/output-cap runner, capability-scoped credential injection) +
  the `source.Source` adapter that drives a source plugin as a data source.
- `internal/llm` — llama.cpp OpenAI-compatible client: strict `json_schema`, `temperature:0`,
  health gate, redact-before-send (registered egress).
- `internal/analyst` — the Tier-3 wrapper: health gate, row-id verification (drops hallucinated
  citations), wrapper-computed `hyp_fp`, 7-day dedup + per-run cap, persist-before-POST.
- `internal/tracker` — the tracker seam + YouTrack REST implementation + `[hb:<key>]` marker
  grammar (`<group>--<check>` / `t3-<hyp_fp>`) + configurable default assignee.
- `internal/outbox` — channel-typed, idempotent `notify_outbox` (bridge's own db).
- `internal/bridge` — AM webhook v4 parse, issue ledger, `Reconcile` (one issue per group,
  per-target checklist, close-on-group-resolved+`heimdall-auto`, mute-gated recurrence, storm
  fuse), `HandleHypothesis` (G1: structurally never pages), `EscalationSweep`.
- `internal/telegram` / `internal/gotify` / `internal/synology` — the three delivery transports.
  Pure transport, no policy, no clock. Each is fail-closed and scrubs its own credential out of
  any error text it returns (net/http embeds the request URL in errors; Synology's whole webhook
  URL is a secret, and Synology reports a REJECTED message inside an HTTP 200).
- `internal/silence` — Alertmanager v2 silence client.
- `internal/notify` — the `Sink` seam + routing (`sinks.json`), outbox drainer with per-sink
  fan-out, button-callback dispatcher (allow-listed → suppression writes), silence reconciler,
  weekly digest, notifier heartbeat.
- `plugins/source-reference` — a real, stdlib-only reference source plugin.
- `deploy/alerts/heimdall-meta.rules.yml` — the alerts that page when a component goes
  stale/absent/redaction-fails.

## Non-negotiable trust invariants (do not violate in any change)
1. **Unknown is always alertable.** A failed/timed-out/panicking source or plugin yields
   `unknown`, never a silent "nothing happened". A dead component **pages** (heartbeat staleness).
2. **The LLM can never page, resolve, or silence.** `class=hypothesis` is refused by `NewFinding`;
   the analyst's only egress is POST `/hypothesis`; the bridge's hypothesis handler only enqueues
   to the analyst channel or opens a `Task` ticket. A `make` gate walks
   `go list -deps ./cmd/heimdall-detect` and fails if `internal/llm` is reachable — keep it clean.
   `trend` is capped at `warning`; a CI gate bans `contract.Finding{}` literals outside the
   constructor.
3. **Fail-closed redaction at every egress.** Every place evidence leaves the process — spool,
   digest, the LLM prompt, the bridge `/hypothesis` re-redaction, the YouTrack issue body — runs
   through the redactor; a failure withholds content, is counted, and pages. Never widen an
   egress without routing it through the redaction library.
4. **A sink transmits the body VERBATIM.** Redaction happens once, at enqueue time
   (`outbox.Entry.Body` is post-redaction; the notifier never holds raw evidence). A new sink
   does not *widen* an egress — it multiplies transports of an already-sealed body. Adding a
   per-sink redaction pass would create three independently-configured redactors that drift
   apart; do not. A sink may add only STATIC per-sink fields (Gotify title/priority, a chat id).
5. **A dead sink must page.** A send failure is deliberately non-fatal — the entry stays pending
   and the cycle still succeeds — so the notifier heartbeat keeps advancing while a destination
   is dead. `heimdall_notifier_sink_oldest_pending_seconds{sink,channel}` is what closes that
   blind spot, and it emits an explicit 0 for every routed pair so the series always exists.
6. **Suppression silences notification, never detection.** A muted finding keeps its series and is
   annotated in the digest; the ledger is the authority, Alertmanager silences are a projection.
7. **The console may only ever widen what it READS.** `heimdall-ui` is a display over state the
   other binaries own. Its single write to a DECISION authority goes through `suppress.AddMute`,
   so adding any other such write means changing an authority rather than adding a handler.
   (It is not a read-only *process*: opening the stores runs their idempotent schema DDL, and
   `outbox.Open` runs its `notify_delivery` backfill insert — the same migrations its co-tenant
   daemons run. Stated because "read-only" is the kind of claim that gets relied on later.) Operator actions run a
   FIXED argv parsed from config at boot — nothing from a request reaches a command line, no
   shell is involved, and an unconfigured action answers 501 rather than being a hidden
   capability. A `make` gate keeps `internal/llm` off its dep graph too: the console displays
   hypothesis text, it must never be able to call the model.
8. **One emission path, one suppression authority, one resolve trigger** (`send_resolved`).
9. **Everything is IaC.** No hand-placed state; config is tofu-rendered. Real addresses/secrets
   live only in the infra repo + Vault — never commit them here (this repo is public-mirrored).

## Language & style
- **Go, stdlib-first.** One static binary per `cmd/`. The **direct-dependency budget is exactly
  three** — `golang.org/x/sync`, `modernc.org/sqlite` (pure-Go, keeps `CGO_ENABLED=0` static),
  `github.com/google/go-cmp` (tests only) — guarded by `policy_test.go`; adding one requires
  amending ADR-G02 first. `go 1.25.0`, `GOTOOLCHAIN=auto`.
- Business logic in `internal/`; keep packages small and single-purpose (see `design/repo-layout.md`).
- **No `time.Now()` under `internal/`** (including tests) — the clock is always injected as a
  `now time.Time`, so window boundaries and dedup cooldowns are table-testable. Only the `cmd/`
  mains call `time.Now()`.
- Checks are **pure functions** `(now, expectation, signal) → []Finding` — no I/O.
- SQLite stores that share the engine `state.db` open their **own** handle with the same WAL
  config and never touch `PRAGMA user_version` (the ledger's migrator owns it).
- Tests are **TDD + table-driven**, assert with `go-cmp` (not testify); wire-format and
  fingerprint invariants are locked by **golden vectors** — regenerate deliberately, never blindly.
  Live tests are env-gated and never committed; connectors are also proven against real services.
- Plugins are **subprocesses** (JSON over stdin/stdout), capability-scoped and sandboxed; the
  core never `import`s plugin code. There is **no sink plugin kind**: a sink inherently needs the
  credential and network egress that subprocess scoping exists to withhold, so it would buy no
  isolation and cost a second ABI. Subprocess isolation is for untrusted/third-party code;
  first-party transports live in `internal/`. See `contract/PLUGIN_SCHEMA.md`.

## Build / test
```
make build     # CGO_ENABLED=0 static, stripped → bin/{heimdall-detect,analyst,bridge,notifier,ui}
make test      # CGO_ENABLED=1 go test -race ./...   (cgo only for the race detector)
make lint      # gofmt, go vet, + policy gates: no time.Now() in internal/, no contract.Finding{}
               # literals outside the constructor, no internal/llm on the detector OR ui dep graph,
               # no real-infra strings in shipped code/deploy/CI, no secret-shaped tokens
make vuln      # govulncheck (pinned version, never @latest)
make ci        # lint + test + build + vuln   (this is what GitLab CI runs)
```

## Process
- Change → MR → `/apply` → merge (infra runbook). Never force-push shared history.
- **Do not commit real IPs, hostnames, Vault paths, or tokens.** This repo is mirrored to a
  public GitHub via a leak-scanning replay; keep it that way. `design/` is private-only.
