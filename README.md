# Heimdall

> *The watchman of the gods — sees and hears all, and sounds the Gjallarhorn to warn of danger.*

**A deterministic, IaC-managed log/metric observer for a homelab.** Every system already ships
its logs to one place (VictoriaLogs) and its metrics to another (Prometheus); Heimdall checks
those against an inventory of what *must* happen, catches real problems — especially the
**silent** ones that trip no threshold — and warns through the existing Alertmanager→Telegram
path before things break.

**Status:** ✅ **Tier-1 detector built and live-tested** against the real stack · Tiers 2–3 designed, not yet built.

## Why

A backup ran broken for **five days** (a missing tmpdir left GitLab and a dozen containers
unbacked) and *nothing* alerted — the failure lived only in per-node task logs, and the backup
server's failure mails weren't being delivered either. Metric thresholds can't catch that class
of fault. Heimdall exists for exactly the silent failures and the slow trends.

## First principles

1. **TRUST above all.** Never cry wolf; never a false "all clear". A failed or timed-out query
   becomes an alertable **`unknown`**, never a silent OK. A dead detector **pages** itself.
2. **Deterministic code owns all detection.** The LLM tier is advisory-only and off the runtime
   path — it can never page, resolve, or silence anything.
3. **Everything is IaC.** The detector is a tofu-managed app; the expectation manifest is
   **generated from the infrastructure repo**, so it can't drift when you add a guest.

## The reframe: expectations, not anomalies

The silent-backup failure was a *missing success*, not an anomaly. Heimdall is built around a
**dead-man switch over an inventory derived from IaC** (backup VMID lists, timers, cert
renewals) — it pages on *absence*. That is near-zero false-positive and structurally cannot go
stale.

## Three tiers

| Tier | What | Pages? | State |
|-----:|------|:------:|-------|
| **1** | Deterministic **hard** checks (dead-man, signature/threshold) → `.prom` textfile → Alertmanager | **yes** | ✅ built |
| 2 | Deterministic **soft** signals (trends, correlation), capped at `warning` | yes (warn) | 📐 designed |
| 3 | Scheduled **llama.cpp** analyst — emits `hypothesis` docs only, structurally cannot mint a pageable finding | **never** | 📐 designed |

This repo currently contains **Tier 1**: `cmd/heimdall-detect`, a oneshot the systemd timer runs.
It loads the manifest, runs each expectation against its source (Prometheus today), upserts a
tiny SQLite ledger, writes a redacted JSON **spool** doc per finding, then **atomically** replaces
a Prometheus textfile-collector `.prom`. The meta-rules in `deploy/alerts/` watch the watcher.

## Trust invariants (enforced in code + CI)

- **Unknown is always alertable** — a source error/timeout/panic degrades to exactly one
  `unknown` finding and **never blanks a sibling** check.
- **Stateless wire identity** — the `.prom` label set is frozen
  `{check,class,fingerprint,group,node,severity,source,target}` with **no `state` label** and no
  per-line timestamps, so a series keeps its identity across firing↔unknown. `fingerprint =
  sha256(check|target)[:16]`, pinned by golden vectors.
- **Fail-closed redaction at every egress** — evidence is redacted before it reaches the spool or
  a `.prom` label; a redactor failure withholds content, is counted, and **pages** via
  `heimdall_redaction_failures_total`.
- **A failed run withholds its heartbeat** — the `.prom` write is strictly last; any earlier
  error leaves the previous file untouched and the staleness/absence meta-rules fire.
- **The `hypothesis` class can never page** — the finding constructor refuses it; `trend` is
  capped at `warning`. A CI gate bans `contract.Finding{}` literals outside the constructor.

## Live-stack validation

The static binary was run as the timer would, against the real Prometheus:

- a dead-man check with a tight grace window **fired** on a genuinely overdue backup; a wide
  grace stayed silently OK;
- an absent metric (empty result) **fired** "no success event recorded" (fail-closed);
- with **Prometheus made unreachable, all checks flipped to alertable `unknown`** — including the
  ones that had been OK — proving *never silent OK* against a real network failure.

## Quickstart

```
make build     # CGO_ENABLED=0 static, stripped binary → bin/heimdall-detect
make test      # CGO_ENABLED=1 go test -race ./...
make lint      # gofmt, go vet, + four policy gates (see Makefile)
make vuln      # govulncheck (pinned)
make ci        # lint + test + build + vuln
```

Run the detector (all paths via env; the systemd unit sets these):

```
HEIMDALL_MANIFEST=/etc/heimdall/manifest.json \
HEIMDALL_TEXTFILE_DIR=/var/lib/node_exporter/textfile \
HEIMDALL_SPOOL_DIR=/var/lib/heimdall/findings \
HEIMDALL_STATE_DB=/var/lib/heimdall/state.db \
HEIMDALL_PROM_URL=http://prometheus:9090 \
  bin/heimdall-detect
```

## Layout

| Path | Responsibility |
|------|----------------|
| `cmd/heimdall-detect` | the Tier-1 oneshot; the **only** `time.Now()` in the program |
| `internal/contract` | `Finding` types, `NewFinding` (refuses `hypothesis`, caps `trend`), `Fingerprint`, fail-closed `Redact` |
| `internal/manifest` | loads + validates the IaC-rendered expectation manifest |
| `internal/source` | `Source` interface + Prometheus client (jittered backoff, fail-closed) |
| `internal/detect` | pure check functions (`DeadMan`, `Threshold`) + the bounded-fan-out engine |
| `internal/ledger` | SQLite finding ledger (pure-Go `modernc.org/sqlite`, preserves `first_seen`) |
| `internal/emit` | `.prom` rendering, atomic file replace, redacted spool writer |
| `internal/config` | env + optional Vault-seeded credential file, fail-fast |
| `deploy/alerts` | the meta-rules that page when the detector goes stale/absent |
| `design/` | design records; canonical build target is `design/2026-07-19-final-design.md` |

## Dependency budget

Stdlib-first. Direct dependencies are exactly three, guarded by `policy_test.go`:
`golang.org/x/sync`, `modernc.org/sqlite` (pure-Go, so `CGO_ENABLED=0` yields a static binary),
and `github.com/google/go-cmp` (tests only). Adding one requires amending ADR-G02 first.

## Contents

- **[design/2026-07-19-final-design.md](design/2026-07-19-final-design.md)** — canonical design.
- **[design/adr-0001-language-go.md](design/adr-0001-language-go.md)** — why Go.
- **[docs/superpowers/plans/2026-07-19-heimdall-go-detector.md](docs/superpowers/plans/2026-07-19-heimdall-go-detector.md)** — the Go build plan (14 ADRs + tasks).
- **[AGENTS.md](AGENTS.md)** — working agreement for humans and coding agents.
- **[IDEAS.md](IDEAS.md)** — backlog & adjacent fixes.
