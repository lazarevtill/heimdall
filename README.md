# Heimdall

> *The watchman of the gods — sees and hears all, and sounds the Gjallarhorn to warn of danger.*

**A deterministic, IaC-managed log/metric observer for a homelab.** Every system already ships
its logs to one place (VictoriaLogs) and its metrics to another (Prometheus); Heimdall checks
those against an inventory of what *must* happen, catches real problems — especially the
**silent** ones that trip no threshold — reasons over the residue with a local LLM, and warns
through the existing Alertmanager→Telegram path and YouTrack before things break.

**Status:** ✅ **All three tiers built** — four binaries, every connector, and the LLM analyst.
Every surface that has a reachable data source or credential is **live-verified against the real
stack**. What remains is deployment/IaC and a handful of operator-provisioned credentials (see
[Deployment](#deployment-what-is-left)).

## Why

A backup ran broken for **five days** (a missing tmpdir left GitLab and a dozen containers
unbacked) and *nothing* alerted — the failure lived only in per-node task logs, and the backup
server's failure mails weren't being delivered either. Metric thresholds can't catch that class
of fault. Heimdall exists for exactly the silent failures and the slow trends.

## First principles

1. **TRUST above all.** Never cry wolf; never a false "all clear". A failed or timed-out query
   becomes an alertable **`unknown`**, never a silent OK. A dead detector **pages** itself.
2. **Deterministic code owns all detection.** The LLM tier is advisory-only and off the runtime
   path — it can never page, resolve, or silence anything (enforced in code *and* a CI gate).
3. **Everything is IaC.** The binaries are tofu-managed apps; the expectation manifest is
   **generated from the infrastructure repo**, so it can't drift when you add a guest.

## Three tiers

| Tier | What | Pages? | State |
|-----:|------|:------:|-------|
| **1** | Deterministic **hard** checks (dead-man, signature/threshold) → `.prom` textfile → Alertmanager | **yes** | ✅ built · live-verified |
| **2** | Deterministic **soft** signals (quantile-creep, flap, slope, template-surprise) over a SQLite baseline, graduation with hysteresis + 7-day warm-up, capped at `warning`; feeds a ≤200-row **digest** | yes (warn) | ✅ built · live-verified |
| **3** | Scheduled **llama.cpp** analyst — reasons over the Tier-2 digest, emits `hypothesis` docs only; structurally cannot mint a pageable finding | **never** | ✅ built · live-verified |

Delivery closes the loop: a **bridge** turns Alertmanager webhooks into YouTrack issues (one per
group, per-target checklist, storm fuse, escalation) and routes hypotheses to a separate
low-urgency channel; a **notifier** drains the outbox to Telegram with lifecycle buttons, turns
button presses into suppression writes, reconciles Alertmanager silences, and sends a weekly
digest — each with its own heartbeat so a dead component pages.

## The reframe: expectations, not anomalies

The silent-backup failure was a *missing success*, not an anomaly. Heimdall is built around a
**dead-man switch over an inventory derived from IaC** (backup VMID lists, timers, cert
renewals) — it pages on *absence*. That is near-zero false-positive and structurally cannot go
stale. Tier-2 adds the slow trends the dead-man can't see; Tier-3 explains the residue.

## Trust invariants (enforced in code + CI)

- **Unknown is always alertable** — a source/plugin error, timeout, or panic degrades to exactly
  one `unknown` finding and **never blanks a sibling** check. Proven live: with the metrics
  source made unreachable, every check — including the previously-OK ones — flipped to `unknown`.
- **The LLM can never touch the trusted path** — a hypothesis is `class=hypothesis`, which the
  finding constructor **refuses**; the analyst's only egress is a POST to the bridge; the bridge's
  hypothesis handler only ever enqueues to the low-urgency channel or opens a `Task` ticket. A
  `make` gate walks the detector's transitive dependency graph and fails if `internal/llm` is
  reachable from it.
- **Suppression silences *notification*, never *detection*** — a muted finding keeps its metric
  series (no false resolve), stays counted, and is annotated in the digest; the ledger is the
  authority, Alertmanager silences are a downstream projection with a 30-day rolling cap.
- **Fail-closed redaction at every egress** — spool, digest, the analyst prompt, the bridge's
  `/hypothesis` re-redaction, and the YouTrack issue body all run through the redactor; a failure
  withholds content, is counted, and **pages** via `heimdall_redaction_failures_total`.
- **A failed run withholds its heartbeat** — the `.prom`/digest write is strictly last; any
  earlier error leaves the previous artifact untouched and the staleness/absence meta-rules fire.
- **Stateless wire identity** — the `.prom` label set is frozen
  `{check,class,fingerprint,group,node,severity,source,target}` with **no `state` label** and no
  per-line timestamps. `fingerprint = sha256(check|target)[:16]`, pinned by golden vectors.

## Live-stack validation

Run against the real infrastructure (temporary tests, never committed), each completing a real
read/write cycle:

- **Tier-1 detector** vs the real **Prometheus** — dead-man fires on a genuinely overdue backup;
  an absent metric fires fail-closed; **Prometheus unreachable → every check `unknown`**.
- **Tier-2** produces a live digest row from real data (warm-up correctly suppresses graduation).
- **Plugin host** runs a real compiled reference plugin subprocess through the detect engine.
- **Tier-3 analyst** vs a real **llama.cpp** server — a planted-anomaly digest yields a hypothesis
  citing a real digest `row_id` (no hallucination); all wrapper gates hold.
- **Connectors** — **VictoriaLogs** (real LogsQL query) and **PBS** (real snapshot read, pinned-CA
  TLS, never insecure) both return live data.
- **Telegram** — the Bot API client authenticates and polls against the real API (non-intrusive).
- **Alertmanager silences** — the silence client creates → lists → deletes a real (harmless) silence.
- **YouTrack** — the tracker connector runs its full cycle live (verify → find → open → tag →
  comment → priority → transition), with a configurable default assignee.

## Quickstart

```
make build     # CGO_ENABLED=0 static, stripped binaries → bin/{heimdall-detect,analyst,bridge,notifier}
make test      # CGO_ENABLED=1 go test -race ./...        (cgo only for the race detector)
make lint      # gofmt, go vet, + policy gates (see Makefile)
make vuln      # govulncheck (pinned)
make ci        # lint + test + build + vuln               (this is what GitLab CI runs)
```

The four binaries (all config via env; the systemd units set these):

- **`heimdall-detect`** — Tier-1 + Tier-2 oneshot (systemd timer, ~5 min): manifest → sources →
  checks → ledger → redacted spool → atomic `.prom` + digest.
- **`heimdall-analyst`** — Tier-3 oneshot (scheduled): read digest → health-gate the LLM →
  analyze → verify/dedup/cap/redact → persist → POST `/hypothesis`.
- **`heimdall-bridge`** — HTTP daemon: `/am` (Alertmanager webhook → YouTrack), `/hypothesis`
  (analyst ingress → route), `/healthz`; 15-min escalation sweep.
- **`heimdall-notifier`** — daemon: Telegram getUpdates poll → button dispatch, outbox drain,
  Alertmanager silence reconcile, weekly digest, own heartbeat.

## Layout

| Path | Responsibility |
|------|----------------|
| `cmd/heimdall-detect` | Tier-1/2 oneshot; the **only** `time.Now()` in that program |
| `cmd/heimdall-analyst` | Tier-3 llama.cpp analyst oneshot |
| `cmd/heimdall-bridge` | Alertmanager→YouTrack bridge + hypothesis router (HTTP daemon) |
| `cmd/heimdall-notifier` | Telegram notifier + silence reconciler (daemon) |
| `internal/contract` | wire types (`Finding`/`Digest`/`Hypothesis`), `NewFinding` (refuses `hypothesis`, caps `trend`), `Fingerprint`, fail-closed `Redact` |
| `internal/manifest` | loads + validates the IaC-rendered expectation + Tier-2 manifest |
| `internal/source` | `Source` interface + Prometheus, VictoriaLogs, PBS clients (fail-closed tri-state) |
| `internal/detect` | pure Tier-1 checks (`DeadMan`, `Threshold`) + bounded-fan-out engine |
| `internal/baseline` | Tier-2 SQLite feature/warmup/template/crossing store |
| `internal/tier2` | Tier-2 C6–C9 signal evaluation + graduation (hysteresis, warm-up) |
| `internal/digest` | Tier-2 digest producer (cap, redact, atomic write + dated history) |
| `internal/ledger` | SQLite finding ledger (`modernc.org/sqlite`, preserves `first_seen`) |
| `internal/emit` | `.prom` render (frozen labels), atomic replace, redacted spool, analyst/notifier heartbeats |
| `internal/config` | env + optional Vault-seeded credential file, fail-fast |
| `internal/suppress` | the single suppression authority (declarative ∪ runtime, scopes, 30-day cap, silence projection) |
| `internal/plugin` | subprocess plugin host (manifest, version gate, scrubbed-env runner) + `source.Source` adapter |
| `internal/llm` | llama.cpp strict-`json_schema` client (health gate, redact-before-send) |
| `internal/analyst` | Tier-3 wrapper: row-id verify, `hyp_fp`, dedup/cap, persist-before-POST |
| `internal/tracker` | tracker seam + YouTrack implementation + `[hb:…]` marker grammar |
| `internal/outbox` | channel-typed, idempotent `notify_outbox` |
| `internal/bridge` | AM webhook parse, issue ledger, reconcile + checklist + storm fuse, hypothesis routing, escalation |
| `internal/telegram` | Telegram Bot API client |
| `internal/silence` | Alertmanager v2 silence client |
| `internal/notify` | outbox drainer, button-callback dispatcher (→ suppression writes), silence reconciler, weekly digest |
| `plugins/source-reference` | a real, stdlib-only reference source plugin |
| `contract/` | `FINDING_SCHEMA.md`, `DIGEST_SCHEMA.md`, `PLUGIN_SCHEMA.md` |
| `deploy/alerts` | the meta-rules that page when a component goes stale/absent |
| `design/` | design records; canonical is `design/2026-07-19-final-design.md` |

## Dependency budget

Stdlib-first. Direct dependencies are exactly three, guarded by `policy_test.go`:
`golang.org/x/sync`, `modernc.org/sqlite` (pure-Go, so `CGO_ENABLED=0` yields a static binary),
and `github.com/google/go-cmp` (tests only). Adding one requires amending ADR-G02 first.

## Deployment (what is left)

The code is complete; bringing it fully live is IaC + operator-provisioned credentials. The
current backlog lives as YouTrack issues in the `HEIM` project and covers: rotate the leaked
GitLab PAT, provision the VictoriaLogs reader token and PBS reader/cert, create a low-priv
YouTrack token, create the Telegram bot + chats, deploy the four binaries co-located with
Prometheus/Alertmanager, and wire the Alertmanager `source=heimdall` route. Each item names its
acceptance criteria.

## Contents

- **[design/2026-07-19-final-design.md](design/2026-07-19-final-design.md)** — canonical design.
- **[design/2026-07-19-heimdall-at-scale.md](design/2026-07-19-heimdall-at-scale.md)** — the growth path (plugins × shards).
- **[design/adr-0001-language-go.md](design/adr-0001-language-go.md)** — why Go.
- **[AGENTS.md](AGENTS.md)** — working agreement for humans and coding agents.
- **[IDEAS.md](IDEAS.md)** — backlog & adjacent fixes.
