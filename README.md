# Heimdall

> **Canonical design is now [design/2026-07-19-final-design.md](design/2026-07-19-final-design.md)** — final Fable review wave, three tiers integrated, trust holds with guardrails.


> *The watchman of the gods — sees and hears all, and sounds the Gjallarhorn to warn of danger.*

**A deterministic, IaC-managed log/metric observer for the homelab.** All systems already
ship their logs to one place (VictoriaLogs); Heimdall watches that stream + metrics against
an inventory of what *must* happen, catches real problems — especially the **silent** ones
that trip no threshold — and warns you through the existing Alertmanager→Telegram path,
before things break.

**Status:** 💡 idea → 📐 designed (DRAFT, awaiting approval) → ⬜ not built yet.

Canonical design: **[design/2026-07-19-heimdall-design.md](design/2026-07-19-heimdall-design.md)**.
Implementation, once approved, lands in
[`lazarev-cloud/infrastructure`](https://<gitlab-host>/lazarev-cloud/infrastructure)
as `apps/log-anomaly` — **everything is IaC.**

## Why

A backup ran broken for **5 days** (missing tmpdir → GitLab + 12 CTs unbacked) and *nothing*
alerted — the failure lived only in per-node task logs, and PBS's failure mails weren't even
being delivered. Metric thresholds can't catch that class. Heimdall's job is exactly the
silent failures and the slow trends.

## First principles

1. **TRUST above all.** Never cry wolf; never a false "all clear" (a dead detector *pages*);
   the system executes nothing an LLM returns.
2. **Everything is IaC.** Detector is a tofu app; delivery reuses the IaC-managed
   Alertmanager; the **expectation manifest is generated from the IaC repo** so it can't
   drift.
3. **Deterministic code owns all detection.** The LLM is off the runtime path.

## The reframe: expectations, not anomalies

The silent-backup failure was a *missing success*, not an anomaly. Heimdall is built around
a **dead-man switch over an inventory derived from IaC** (backup VMID lists, timers, cert
renewals) — page on *absence*. That's near-zero false-positive and structurally can't go
stale when you add a guest in tofu.

## Shape (after MAGI deliberation + Fable review)

- Deterministic detection → **existing Alertmanager → Telegram** (no new sender/SPOF).
- **Suppression/feedback + cheap ±10 min correlation from day one** (not deferred).
- **LLM is offline & on-demand only** — rule authoring/review and an "explain this window"
  command *you* invoke; no always-on enrichment service. Endpoint-agnostic (survives the
  Ollama→llama.cpp move by config).
- **Cut** the noisy error-rate-delta baselining from Phase 1; **reject** ML log-clustering.

## Phases

| Phase | What | State |
|------|------|-------|
| 0 | Rotate leaked a leaked CI token + fix PBS mail (prereqs); redaction lib + LLM shim; prune noisy falco rules | ready |
| 1 | Expectation-based deterministic detection (IaC-derived) → Alertmanager, with suppression + heartbeat + correlation | ready to build |
| 2 | On-demand LLM tool ("explain this window", offline rule review) | design done |
| 3 | error-rate-delta w/ real baselines — *optional*, gated on Phase-1 track record | deferred |

## Contents

- **[design/2026-07-19-heimdall-design.md](design/2026-07-19-heimdall-design.md)** — canonical design.
- **[design/2026-07-19-magi-design.md](design/2026-07-19-magi-design.md)** — the MAGI 3-voice deliberation record (superseded).
- **[IDEAS.md](IDEAS.md)** — backlog & adjacent fixes.
