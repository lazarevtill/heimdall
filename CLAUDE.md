# CLAUDE.md

Instructions for Claude Code / coding agents in this repo live in **[AGENTS.md](AGENTS.md)** —
read it first. It defines the trust invariants, the full package map, the Go/stdlib-first style
and three-direct-dependency budget, the build commands, and the hard rule: **never commit real
IPs, hostnames, Vault paths, or tokens** — this repo is mirrored to a public GitHub.

**Status:** all three tiers are **built and live-verified** against the real stack.

Five binaries under `cmd/`:
- `heimdall-detect` — Tier-1 hard checks + Tier-2 soft signals + digest (oneshot/timer).
- `heimdall-analyst` — Tier-3 llama.cpp analyst over the digest (oneshot); emits `hypothesis`
  docs only, structurally off the pageable path.
- `heimdall-bridge` — Alertmanager `/am` webhook → YouTrack, `/hypothesis` router, `/healthz`,
  escalation sweep (HTTP daemon).
- `heimdall-notifier` — Telegram poller + button→suppression dispatch + multi-sink delivery
  fan-out (Telegram/Gotify/Synology Chat) + Alertmanager silence reconciler + weekly digest
  (daemon).
- `heimdall-ui` — operator console (HTTP daemon): read-mostly views over the finding ledger,
  the Tier-2 digest, Tier-3 hypothesis runs, the bridge's ticket ledger, suppression authority,
  sink backlog, heartbeats and spool evidence. Access
  is `HEIMDALL_UI_AUTH` = `oidc` (stdlib RP: PKCE + RS256) | `token` | `none` (LAN, read-only
  by default) — no default, it must be chosen. Its ONLY write is a runtime mute through
  `suppress.AddMute`; operator actions run a fixed config-declared argv or 501.

Logic lives in `internal/` (contract, manifest, source, detect, baseline, tier2, digest, ledger,
emit, config, suppress, plugin, llm, analyst, tracker, outbox, bridge, telegram, gotify,
synology, silence, notify); schema docs in `contract/`; a reference plugin in `plugins/`; design records in
`design/` (private-only, canonical: `design/2026-07-19-final-design.md`).

**Core invariants** (enforced in code + CI, do not break): unknown is always alertable; the LLM
can never page/resolve/silence (`class=hypothesis` refused, a `make` gate keeps `internal/llm`
off the detector's dep graph); fail-closed redaction at every egress; suppression silences
notification not detection; no `time.Now()` under `internal/` (inject the clock); a sink
transmits the outbox body **verbatim** (redaction happens once, at enqueue).

Quickstart: `make ci` (lint + `-race` tests + static build of all five binaries + govulncheck).

**Practical guides** (AGENTS.md stays the binding contract; these are the how-to layer):
- [`docs/SETUP.md`](docs/SETUP.md) — running all five binaries, env per binary, verification chain.
  Note the trap it opens with: the engine state.db is `HEIMDALL_STATE_DB` to the detector and
  `HEIMDALL_ENGINE_STATE_DB` to everything else, and splitting them fails silently.
- [`docs/DEBUGGING.md`](docs/DEBUGGING.md) — symptom-first. Most surprises are the fail-closed
  design working as intended; it says which are which.
- [`docs/DEVELOPING.md`](docs/DEVELOPING.md) — what each `make lint` gate encodes, how to add a
  check / source / sink / console page / plugin, and the traps already paid for.
