# Heimdall

A deterministic, three-tier log/metric observability system for a homelab. It evaluates metrics
and logs against an IaC-generated inventory of expected state, emits findings as Prometheus
textfile metrics, and delivers them through Alertmanager→Telegram and YouTrack. A local LLM tier
reasons over the results but is structurally barred from the alerting path.

## Architecture

```
 sources                detect                       emit / deliver
 ───────                ──────                       ──────────────
 Prometheus  ┐                                    ┌ .prom textfile → Alertmanager ┐
 VictoriaLogs├─▶ Tier 1: hard checks ─────────────┤                               ├─▶ Telegram
 PBS         │   Tier 2: soft signals ─┐          └ YouTrack issues (bridge)      │   (notifier)
 plugins     ┘                         └─▶ digest ─▶ Tier 3: llama.cpp analyst ───┘   + silences
```

Four independent binaries, each with its own liveness heartbeat:

| Binary | Type | Function |
|--------|------|----------|
| `heimdall-detect` | oneshot (timer) | Tier-1 hard checks + Tier-2 soft signals → SQLite ledger, redacted spool, atomic `.prom`, Tier-2 digest |
| `heimdall-analyst` | oneshot (scheduled) | Tier-3: reads the digest, calls a llama.cpp server under strict `json_schema`, emits vetted `hypothesis` docs |
| `heimdall-bridge` | HTTP daemon | `/am` Alertmanager webhook → YouTrack issues; `/hypothesis` ingress → routing; `/healthz`; escalation sweep |
| `heimdall-notifier` | daemon | Telegram getUpdates poller, outbox drain, button→suppression writes, Alertmanager silence reconciler, weekly digest |

## Tiers

**Tier 1 — hard checks.** Pure functions `(now, expectation, signal) → []Finding`. `DeadMan`
(dead-man switch over an IaC-derived inventory: pages on *absence* of an expected success) and
`Threshold` (signature/count). A source error, timeout, or panic degrades to an alertable
`unknown`, never a silent OK.

**Tier 2 — soft signals.** Continuous, deterministic, no LLM. Four signal families over a SQLite
feature baseline: quantile-creep, flap/`changes()`, slope, template-frequency surprise. Robust-IQR
z-scores; graduation to a finding requires hysteresis (separate graduate/clear thresholds + min-hold)
and a 7-day warm-up. Severity is capped at `warning` in code — Tier 2 can never page. Output feeds
a ≤200-row / ≤32 KB **digest** (redacted, atomic, 14-day dated history) carrying an `ok |
unknown | baseline_warming` status per row.

**Tier 3 — LLM analyst.** A scheduled process that reads only the Tier-2 digest and calls a local
llama.cpp server (OpenAI-compatible, `temperature:0`, strict `json_schema`). Its output is
`class=hypothesis`, which the finding constructor **refuses** — so it cannot become a pageable
finding. The wrapper verifies every cited `evidence_row` against the digest (drops hallucinations),
computes the `hyp_fp` itself, dedups on a 7-day cooldown, caps per-run volume, redacts, persists,
then POSTs to the bridge.

## Delivery

- **Bridge**: parses Alertmanager v4 webhooks, reconciles one YouTrack issue per `(group,check)`
  keyed by an `[hb:…]` marker, maintains a per-target checklist, closes only on group-resolved +
  its own tag, runs a storm fuse (N issues/hour) and a 15-min escalation sweep. `/hypothesis`
  re-redacts and routes to a low-urgency channel + optional ticket; it has no path to a page (G1).
- **Notifier**: drains a channel-typed outbox to Telegram with inline lifecycle buttons, turns
  allow-listed button presses into runtime suppressions, and reconciles the suppression authority's
  active silences into Alertmanager (create/list/delete), with a 30-day rolling cap.
- **Suppression** is a single authority (declarative `suppressions.json` ∪ runtime SQLite mutes,
  five scopes). It silences *notification*, never *detection*: a muted finding keeps its series and
  is annotated in the digest; Alertmanager silences are a downstream projection.

## Interfaces

- **In**: Prometheus (PromQL), VictoriaLogs (LogsQL), PBS (pinned-CA REST), and source **plugins**
  (subprocess, JSON stdin/stdout, capability-scoped, scrubbed-env). Manifest + suppressions are
  IaC-rendered JSON.
- **Out**: a Prometheus textfile-collector `.prom` (the emission path for everything that pages),
  redacted `findings/<fp>.json` spool docs, the digest, YouTrack issues, Telegram messages,
  Alertmanager silences. Meta-rules in `deploy/alerts/` page when any component goes stale/absent.

## Wire contract & trust properties (enforced in code + CI)

- **`.prom` label set** is frozen `{check,class,fingerprint,group,node,severity,source,target}` —
  no `state` label, no per-line timestamps, so a series keeps identity across `firing↔unknown`.
  `fingerprint = sha256(check|target)[:16]`, pinned by golden vectors.
- **Unknown is always alertable**; a failed run withholds its heartbeat (the `.prom`/digest write
  is strictly last), so staleness/absence meta-rules fire.
- **The LLM cannot reach the trusted path**: `class=hypothesis` is refused by `NewFinding`, `trend`
  is capped at `warning`, and a `make` gate walks `go list -deps ./cmd/heimdall-detect` to fail the
  build if `internal/llm` is reachable from it.
- **Fail-closed redaction at every egress** (spool, digest, LLM prompt, bridge `/hypothesis`,
  YouTrack body); a redactor failure withholds content, is counted, and pages via
  `heimdall_redaction_failures_total`.

## Stack

- **Go**, stdlib-first. Direct dependencies are exactly three (guarded by `policy_test.go`):
  `golang.org/x/sync`, `modernc.org/sqlite` (pure-Go → `CGO_ENABLED=0` static binaries),
  `github.com/google/go-cmp` (tests only). `go 1.25.0`.
- No `time.Now()` under `internal/` — the clock is injected, so window boundaries and dedup
  cooldowns are table-testable. Checks are pure; SQLite stores share the engine `state.db` via
  their own handles and never touch `PRAGMA user_version`.
- Plugins are language-agnostic subprocesses; the core never imports plugin code.

## Build

```
make build   # CGO_ENABLED=0 static binaries → bin/{heimdall-detect,analyst,bridge,notifier}
make test    # CGO_ENABLED=1 go test -race ./...
make lint    # gofmt, go vet, + policy gates (no time.Now() in internal/, no contract.Finding{}
             # literals outside the constructor, no internal/llm on the detector dep graph,
             # no real-infra strings, no secret-shaped tokens)
make vuln    # govulncheck (pinned)
make ci      # lint + test + build + vuln
```

## Layout

| Path | Responsibility |
|------|----------------|
| `cmd/heimdall-{detect,analyst,bridge,notifier}` | the four binaries; thin wiring over `internal/` |
| `internal/contract` | wire types, `NewFinding` (refuses `hypothesis`, caps `trend`), `Fingerprint`, fail-closed `Redact` |
| `internal/manifest` | loads + validates the expectation + Tier-2 manifest |
| `internal/source` | `Source` interface + Prometheus / VictoriaLogs / PBS clients (fail-closed tri-state) |
| `internal/detect` · `baseline` · `tier2` · `digest` | Tier-1 checks + engine; Tier-2 baseline, evaluation, digest producer |
| `internal/ledger` · `emit` · `config` | SQLite finding ledger; `.prom`/spool/heartbeat render + atomic write; env config |
| `internal/suppress` | the suppression authority (union, scopes, 30-day cap, silence projection) |
| `internal/plugin` · `llm` · `analyst` | plugin host + source adapter; llama.cpp client; Tier-3 wrapper |
| `internal/tracker` · `outbox` · `bridge` | YouTrack seam + markers; notify_outbox; webhook reconcile / hypothesis / escalation |
| `internal/telegram` · `silence` · `notify` | Telegram + Alertmanager clients; drainer / dispatcher / reconciler / digest |
| `plugins/source-reference` | reference source plugin (stdlib-only) |
| `contract/` · `deploy/alerts/` · `design/` | schema docs; meta-rules; design records (`design/2026-07-19-final-design.md`) |

See **[AGENTS.md](AGENTS.md)** for the full working agreement and **[IDEAS.md](IDEAS.md)** for the backlog.
