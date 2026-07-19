# CLAUDE.md

Instructions for Claude Code / coding agents in this repo live in **[AGENTS.md](AGENTS.md)** —
read it first. It defines the trust invariants (unknown-always-alertable; the `hypothesis` class
can never page; fail-closed redaction at every egress; a failed run withholds its heartbeat), the
Go/stdlib-first style and three-direct-dependency budget, the package map, the build commands, and
the hard rule: **never commit real IPs, hostnames, Vault paths, or tokens** — this repo is mirrored
to a public GitHub.

**Status:** the **Tier-1 detector is built and live-tested** (`cmd/heimdall-detect`: manifest →
sources → ledger → spool → atomic `.prom`, plus the meta-rules in `deploy/alerts/`). Tiers 2–3
(soft signals; the llama.cpp analyst) are designed, not built.

Quickstart: `make ci` (lint + `-race` tests + static build + govulncheck). Design docs are in
`design/`; start at `design/repo-layout.md` and `design/2026-07-19-final-design.md`.
