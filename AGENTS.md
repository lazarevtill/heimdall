# AGENTS.md — working agreement for Heimdall

Canonical instructions for humans and coding agents in this repo. `CLAUDE.md` points here.

## What this is
A deterministic, IaC-managed log/metric observer. It catches **silent failures** (a backup
that ran broken with no threshold tripped) and slow **trends**, and takes the right action per
severity (notify vs ticket vs escalate). Design is in `design/`; the canonical build target is
`design/2026-07-19-final-design.md`, the growth path is `design/2026-07-19-heimdall-at-scale.md`,
the language decision is `design/adr-0001-language-go.md`.

**Status:** the **Tier-1 deterministic detector is built and live-tested** — `cmd/heimdall-detect`
(oneshot: manifest → sources → ledger → spool → atomic `.prom`) plus the meta-rules in
`deploy/alerts/`. Tier-2 (soft signals) and Tier-3 (llama.cpp analyst) are designed, not built.
The three-tier model and every trust invariant are enforced in code + CI.

## Package map (Tier-1)
- `cmd/heimdall-detect` — the oneshot; **thin** (env + wiring) and the only `time.Now()` in the program.
- `internal/contract` — `Finding`/`State`, `NewFinding` (refuses `hypothesis`, caps `trend`), `Fingerprint = sha256(check|target)[:16]`, fail-closed `Redact`/`EvidenceOrWithheld`.
- `internal/manifest` — loads + validates the IaC-rendered expectation manifest (rejects dup id AND dup `(check,target)` fingerprint).
- `internal/source` — `Source` interface + Prometheus client (jittered backoff, fail-closed failure matrix).
- `internal/detect` — pure checks (`DeadMan`, `Threshold`) + errgroup-bounded engine (panic boundary, never cancels siblings).
- `internal/ledger` — SQLite ledger (`modernc.org/sqlite`, WAL, preserves `first_seen`).
- `internal/emit` — `.prom` render (frozen label set, no `state` label, no timestamps), atomic replace, redacted spool.
- `internal/config` — env + optional Vault-seeded cred file, fail-fast.
- `deploy/alerts/heimdall-meta.rules.yml` — the alerts that page when the detector goes stale/absent/redaction-fails.

## Non-negotiable trust invariants (do not violate in any change)
1. **Unknown is always alertable.** A failed/timed-out query yields `unknown`, never a silent
   "nothing happened". A dead detector must **page** (heartbeat staleness).
2. **The `hypothesis` class can never page, resolve, or silence anything.** The Tier-3 LLM
   analyst (a local **llama.cpp** server, OpenAI-compatible, off the runtime path) emits
   `hypothesis` docs only; `internal/contract`'s `NewFinding` refuses that class and `trend` is
   capped at `warning` (enforced in code + a CI gate banning `contract.Finding{}` literals
   outside the constructor).
3. **Fail-closed redaction at every egress.** A redactor error withholds evidence but the
   finding still fires. Never widen an egress without routing it through the redaction library.
4. **One emission path, one suppression authority, one resolve trigger** (`send_resolved`).
5. **Everything is IaC.** No hand-placed state; config is tofu-rendered. Real addresses/secrets
   live only in the infra repo + Vault — never commit them here (this repo is public-mirrored).

## Language & style
- **Go, stdlib-first.** One static binary per `cmd/`. The **direct-dependency budget is exactly
  three** — `golang.org/x/sync`, `modernc.org/sqlite` (pure-Go, keeps `CGO_ENABLED=0` static),
  `github.com/google/go-cmp` (tests only) — guarded by `policy_test.go`; adding one requires
  amending ADR-G02 first. `go 1.25.0`.
- Business logic in `internal/`; keep packages small and single-purpose (see `design/repo-layout.md`).
- Checks are **pure functions** `(now, expectation, signal) → []Finding` — no I/O, no `time.Now()`
  (the clock is injected), so dead-man window boundaries are table-testable.
- Tests are **TDD + table-driven**, assert with `go-cmp` (not testify); wire-format and
  fingerprint invariants are locked by **golden vectors** — regenerate deliberately, never blindly.
- Plugins are **subprocesses** (JSON over stdin/stdout), capability-scoped and sandboxed; the
  core never `import`s plugin code.

## Build / test
```
make build     # CGO_ENABLED=0 static, stripped binary → bin/heimdall-detect
make test      # CGO_ENABLED=1 go test -race ./...   (cgo only for the race detector)
make lint      # gofmt, go vet, + four policy gates: no time.Now() in internal/,
               # no contract.Finding{} literals outside the constructor, no real-infra
               # strings in shipped code/deploy/CI, no secret-shaped tokens
make vuln      # govulncheck (pinned version, never @latest)
make ci        # lint + test + build + vuln   (this is what GitLab CI runs)
```

## Process
- Change → MR → `/apply` → merge (infra runbook). Never force-push shared history.
- **Do not commit real IPs, hostnames, Vault paths, or tokens.** This repo is mirrored to a
  public GitHub; keep it that way.
- Implementation is gated on design approval — stubs stay stubs until the owner says go.
