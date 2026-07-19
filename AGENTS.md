# AGENTS.md — working agreement for Heimdall

Canonical instructions for humans and coding agents in this repo. `CLAUDE.md` points here.

## What this is
A deterministic, IaC-managed log/metric observer. It catches **silent failures** (a backup
that ran broken with no threshold tripped) and slow **trends**, and takes the right action per
severity (notify vs ticket vs escalate). Design is in `design/`; the canonical build target is
`design/2026-07-19-final-design.md`, the growth path is `design/2026-07-19-heimdall-at-scale.md`,
the language decision is `design/adr-0001-language-go.md`.

## Non-negotiable trust invariants (do not violate in any change)
1. **Unknown is always alertable.** A failed/timed-out query yields `unknown`, never a silent
   "nothing happened". A dead detector must **page** (heartbeat staleness).
2. **The `hypothesis` class can never page, resolve, or silence anything.** Tier-3 LLM output is
   advisory only; `heimdall_lib` refuses it on any pageable path (enforced in code + CI).
3. **Fail-closed redaction at every egress.** A redactor error withholds evidence but the
   finding still fires. Never widen an egress without routing it through the redaction library.
4. **One emission path, one suppression authority, one resolve trigger** (`send_resolved`).
5. **Everything is IaC.** No hand-placed state; config is tofu-rendered. Real addresses/secrets
   live only in the infra repo + Vault — never commit them here (this repo is public-mirrored).

## Language & style
- **Go, stdlib-first.** One static binary per `cmd/`. Add a third-party dep only with a reason
  recorded in the PR (and prefer none). `CGO_ENABLED=0`.
- Business logic in `internal/`; keep packages small and single-purpose (see `design/repo-layout.md`).
- Checks are **pure functions** `(window, manifest, now) → []Finding` — deterministic, testable.
- Plugins are **subprocesses** (JSON over stdin/stdout), capability-scoped and sandboxed; the
  core never `import`s plugin code.

## Build / test
```
make build     # static binaries into bin/
make test      # go test ./...
make lint      # gofmt -l . && go vet ./...
```

## Process
- Change → MR → `/apply` → merge (infra runbook). Never force-push shared history.
- **Do not commit real IPs, hostnames, Vault paths, or tokens.** This repo is mirrored to a
  public GitHub; keep it that way.
- Implementation is gated on design approval — stubs stay stubs until the owner says go.
