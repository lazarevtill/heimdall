# Ideas & backlog — Heimdall

> **Canonical design is now [design/2026-07-19-final-design.md](design/2026-07-19-final-design.md)** — final Fable review wave, three tiers integrated, trust holds with guardrails.


Running list. Designed items link to `design/`; open ones are fair game to pick up next.
Everything here is intended to ship as **IaC** (`apps/log-anomaly` in the infrastructure repo).

## Designed (canonical)

- **Expectation-based deterministic observer** — dead-man switches derived from IaC, into
  the existing Alertmanager. See
  [design/2026-07-19-heimdall-design.md](design/2026-07-19-heimdall-design.md) (principles) and
  [design/2026-07-19-magi-final-perpart-design.md](design/2026-07-19-magi-final-perpart-design.md)
  (MAGI-final per-part detail: ingestion, IaC-manifest, detection, delivery, action/YouTrack,
  suppression, LLM). DRAFT, overseer APPROVE.
- **Three-tier correction** — LLM restored to a proactive role: Tier 1 deterministic hard alerts /
  Tier 2 deterministic soft signals (usage creep, flaps, slope, template surprise) / Tier 3
  scheduled LLM analyst over the feature digest, HYPOTHESIS-only, separate low-urgency channel,
  llama.cpp only. See [design/2026-07-19-three-tier-correction.md](design/2026-07-19-three-tier-correction.md).
  A final Fable review wave is folding this in end-to-end.
- **Scale + plugin architecture** — new detection IDEAS ship as vendored plugins (detector/source/sink/analyzer) on a (shard×plugin) grid that is bit-identical to the single-CT design at N=1 and grows only when a trigger metric fires. See [design/2026-07-19-heimdall-at-scale.md](design/2026-07-19-heimdall-at-scale.md).

## Decided direction (from MAGI deliberation + Fable review)

- **Expectations, not anomalies** — generate the "must-happen" manifest FROM the IaC repo
  (backup VMID lists, timers) so it can't drift; page on absence.
- **Suppression + ±10 min correlation from day one**, not deferred to a later phase.
- **LLM off the runtime path** — offline rule authoring/review + on-demand "explain this
  window"; no always-on enrichment service.
- **Cut** error-rate-delta baselining from Phase 1 (noise engine); **reject** ML log-clustering.

## Open ideas (not yet designed)

- **"Ask Heimdall"** — natural-language question over the last N hours ("why did gitlab 500
  at 17:00?") → hypothesis + the queries behind it. This is the primary LLM surface now.
- **Predictive trend digest** — daily "what's trending toward a wall" (disks, cert expiries,
  retention) from metric slopes, before anything alerts.
- **Runbook suggestion** — on a recurring known incident, attach the prior fix (from memory /
  past MRs) as a suggested, human-executed action.
- **Novelty detection (maybe)** — cheap template-frequency surprise detection to surface
  *new* recurring lines, without full ML clustering. Only if IaC-derived expectations prove
  insufficient.

## Adjacent infra fixes — Phase 0 prerequisites (do before detector code)

- **Rotate + mask the leaking GitLab release-bot PAT** — `glpat-…` in cleartext in central
  logs via falco CI command lines (~47/24h). Move to a masked CI variable / credential store.
- **Fix PBS email notifications** — pbs postfix "Network is unreachable" to Cloudflare MX:25
  (~6948 deferred/24h); failure mails aren't delivered — part of why the 5-day silent outage
  stayed invisible.
- **Prune noisy falco rules** — falco+kernel = 63% of 3M lines/day; shrinking the source cuts
  retention, query time, and redaction blast-radius everywhere downstream.
