# CLAUDE.md

Instructions for Claude Code / coding agents in this repo live in **[AGENTS.md](AGENTS.md)** —
read it first. It defines the trust invariants, the full package map, the Go/stdlib-first style
and three-direct-dependency budget, the build commands, and the hard rule: **never commit real
IPs, hostnames, Vault paths, or tokens** — this repo is mirrored to a public GitHub.

**Status:** all three tiers are **built and live-verified** against the real stack.

Four binaries under `cmd/`:
- `heimdall-detect` — Tier-1 hard checks + Tier-2 soft signals + digest (oneshot/timer).
- `heimdall-analyst` — Tier-3 llama.cpp analyst over the digest (oneshot); emits `hypothesis`
  docs only, structurally off the pageable path.
- `heimdall-bridge` — Alertmanager `/am` webhook → YouTrack, `/hypothesis` router, `/healthz`,
  escalation sweep (HTTP daemon).
- `heimdall-notifier` — Telegram poller + button→suppression dispatch + Alertmanager silence
  reconciler + weekly digest (daemon).

Logic lives in `internal/` (contract, manifest, source, detect, baseline, tier2, digest, ledger,
emit, config, suppress, plugin, llm, analyst, tracker, outbox, bridge, telegram, silence,
notify); schema docs in `contract/`; a reference plugin in `plugins/`; design records in
`design/` (private-only, canonical: `design/2026-07-19-final-design.md`).

**Core invariants** (enforced in code + CI, do not break): unknown is always alertable; the LLM
can never page/resolve/silence (`class=hypothesis` refused, a `make` gate keeps `internal/llm`
off the detector's dep graph); fail-closed redaction at every egress; suppression silences
notification not detection; no `time.Now()` under `internal/` (inject the clock).

Quickstart: `make ci` (lint + `-race` tests + static build of all four binaries + govulncheck).
