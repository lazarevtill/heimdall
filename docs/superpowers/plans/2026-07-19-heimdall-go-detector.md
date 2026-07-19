# Heimdall Detector Slice — Go Design Decisions + TDD Build Plan

> Every line of Go below was **built and tested green** before this plan was written: `make ci` (gofmt, vet, four custom gates, `go test -race ./...` as root, `CGO_ENABLED=0` static build verified with `file(1)`, govulncheck v1.6.0 clean) passes on the exact tree this plan transcribes. All four lint/policy gates were negative-tested (a planted violation trips each one). The four fingerprint golden vectors were independently recomputed via `sha256sum`.

## Go design decisions

**ADR-G01 — Layout.** `cmd/heimdall-detect` (thin main: env, wire, one call into internal/) + `internal/{contract,manifest,source,detect,ledger,emit,config}` + a root-level `policy_test.go` for repo-policy tests. No `pkg/`, no `util`/`types`/`models` packages, ever. Grounded in go.dev/doc/modules/layout (cmd/ per binary; internal/ is compiler-enforced privacy) and go.dev/blog/package-names (name packages for capability, not contents). golang-standards/project-layout is explicitly NOT adopted — community, not official, over-structured for one binary.

**ADR-G02 — Dependency policy.** Stdlib-first with a recorded budget of exactly three direct modules: `golang.org/x/sync v0.22.0` (errgroup; golang.org/x is effectively first-party), `modernc.org/sqlite v1.54.0` (the one heavyweight, ADR-G03), `github.com/google/go-cmp v0.7.0` (test-only diffing). NO testify (the Go wiki advises against assertion DSLs; `if got != want` + `cmp.Diff` is idiomatic), no client_golang, no retry lib, no viper. Enforced in code by `TestDependencyBudget` (root `policy_test.go`, verified to catch a planted testify require). govulncheck is pinned (`@v1.6.0`) — `@latest` makes CI non-reproducible. "A little copying is better than a little dependency."

**ADR-G03 — SQLite driver: `modernc.org/sqlite`, NOT mattn/go-sqlite3.** mattn forces CGO_ENABLED=1, a per-target C toolchain, and breaks the static single-binary guarantee the delivery model rests on. Tradeoff accepted: modernc is ~60–75% of mattn on insert throughput and pulls `modernc.org/{libc,…}` transitive modules — irrelevant for a low-write dedup ledger at 5-min cadence (cvilsmeier/go-sqlite-bench); same SQLite engine, same WAL semantics. **Empirically pinned consequence: modernc v1.54.0 requires `go >= 1.25`, so the module declares `go 1.25.0` and CI uses `image: golang:1.25`** (verified: `go get` auto-bumped the directive; the suite runs green under the 1.25 toolchain). Mitigations in code: DSN pragmas `journal_mode(WAL)`, `synchronous(NORMAL)`, `busy_timeout(5000)` (in the DSN so every lazily-opened pool conn gets them) + `SetMaxOpenConns(1)` — verified: 10 concurrent upserts, zero `SQLITE_BUSY`. The dep-budget test doubles as the CI guard against mattn reappearing.

**ADR-G04 — Prometheus textfile: hand-written in `internal/emit`,** not client_golang — pulling in Registry/Gatherer machinery to serialize ~30 gauge lines is unjustified supply-chain weight. Load-bearing format rules, each CI-tested: (1) NEVER emit line-level timestamps — node_exporter discards the ENTIRE file on any client-side timestamp (collector/textfile.go), silently blinding every metric; freshness is a sample VALUE (`heimdall_last_run_timestamp_seconds`). (2) Trailing newline mandatory; HELP/TYPE constants defined once; deterministic sort; tested label escaper for `\ " \n`. (3) **Wire label set frozen WITHOUT `state`: `{check, class, fingerprint, group, node, severity, source, target}`.** State is doc-only (spool JSON) — a `state` label would change series identity on firing↔unknown transitions, go stale, and let `send_resolved` manufacture a false all-clear (the exact class the design forbids). (4) `heimdall_redaction_failures_total` counter is always present (see ADR-G13). Whole-file replacement is also what retires stale series — commented in code so nobody "optimizes" it into partial writes.

**ADR-G05 — Atomic emission + the alert that watches the watcher.** Whole-file replace: `os.CreateTemp` in the SAME directory (rename is atomic only within one filesystem; $TMPDIR may be another mount) → write → `f.Sync()` → chmod 0644 → close → `os.Rename` → best-effort parent-dir fsync (client_golang's WriteToTextfile omits both fsyncs; robustperception.io atomic-writes). A `committed` flag guards temp cleanup: failed runs leave no turds and NEVER touch the old `.prom`. A failed run withholds the heartbeat — and that is only an invariant if something alerts on it, so **the slice ships `deploy/alerts/heimdall-meta.rules.yml`** (staleness > 900s, `absent(...)` for the bootstrap/rejected-file case, redaction-failure > 0). Until that file is applied via the IaC alerts path, the detector is documented NOT crash-alertable.

**ADR-G06 — HTTP.** `net/http` only; shared `*http.Client{Timeout: 20s}` AND per-attempt `context.WithTimeout` (never `http.Get`/DefaultClient). Retry = hand-rolled exponential backoff with FULL jitter (AWS Builders' Library), max 3 attempts, ctx-aware sleep (no leaked timers), retrying ONLY transport errors, 5xx, 429; 4xx and malformed-200 fail fast. Safe only because the detector issues idempotent GETs — commented in code so a future write-capable source doesn't inherit blind retries. Exhausted retries → error → Unknown finding.

**ADR-G07 — Concurrency + panic containment.** Bounded fan-out via `errgroup.WithContext` + `g.SetLimit(8)` (configurable) over the ~30 expectation queries; serial rejected (30 sequential round-trips blows the 240s soft deadline). Two sharp edges, both regression-tested: (1) a per-source failure is captured as exactly one Unknown finding and the goroutine returns nil — returning the error to errgroup would cancel the shared ctx and blank every sibling (peng.fyi errgroup mishap); (2) `evalOne` carries a `recover()` boundary — a panicking check degrades to one Unknown finding for its own expectation instead of crashing the run and losing every other result.

**ADR-G08 — Errors.** Wrap with `fmt.Errorf("…: %w", err)`; package-owned sentinels (`manifest.ErrInvalid`, `contract.ErrHypothesisRefused`) matched via `errors.Is`. The engine boundary is the single place a query error becomes an Unknown finding at the expectation's own `severity_on_miss` — a failed fetch of a critical dead-man alerts at critical. Dedicated tests lock "a failed query is NEVER a silent ok" against refactors.

**ADR-G09 — Core types + the enforcement boundary.** All in `internal/contract`. Tri-state `State int` with `StateUnknown` as the ZERO VALUE — uninitialized state is fail-closed by construction. `Finding` is minted ONLY by `contract.NewFinding`, which refuses `Class=hypothesis` (ErrHypothesisRefused), caps `Class=trend` at warning, and validates Severity/Class/State enums. Because Go structs with exported fields can be literal-constructed, **the enforcement boundary is the constructor PLUS a `make lint` gate** that bans `contract.Finding{` composite literals outside internal/contract (slice-type `[]contract.Finding{` excepted; gate negative-tested). `Fingerprint(checkID, target) = hex(sha256(checkID+"|"+target))[:16]`, `|` banned in check IDs, frozen by golden vectors (independently recomputed): `("c1-deadman","backup:ds1/vm-100")→d86c07b5a41742c1`, `("c2-unit-failed","node-a")→34915542b733a584`, `("c1-deadman","target|with|pipes")→296c533b31dd957e`, `("c4-signature","node-b/ssh")→5aab268a9c139079`.

**ADR-G10 — Interfaces + purity.** `source.Source` is TWO methods (`ID()`, `Query(ctx, Query) (Signal, error)`) — "the bigger the interface, the weaker the abstraction" (Cheney); constructors return concrete types (`NewProm(...) *PromSource`). **Deliberate, documented deviation from the consumer-side-interface doctrine: the interface lives in the producer package `source`, because it IS the plugin-ABI seam** — shaped to mirror the at-scale subprocess FetchPlan/SignalSet contract and consumed by internal/detect and future transports alike; extraction later is a transport change, not a redesign. Checks are PURE: `type Check func(now time.Time, exp manifest.Expectation, sig source.Signal) []contract.Finding` — no I/O, no `time.Now()`. The only `time.Now()` in the program is in `cmd/heimdall-detect/main.go`; `make lint` greps internal/ for calls (comment mentions filtered; gate negative-tested).

**ADR-G11 — Testing.** Stdlib `testing` + go-cmp only; table-driven subtests (no `tt := tt` — Go ≥1.22 per-iteration loop vars); `httptest.NewServer` drives the real transport through the full failure matrix (200 / retried-500 / persistent-500 / 429 / 404 / garbage-JSON / prom-error-status / timeout), each row asserting the fail-closed mapping to Unknown; golden files in testdata/ with an `-update` flag CI never passes; injected `now` covers both sides of every dead-man boundary; `t.TempDir()` everywhere. **Root-proof failure injection: chmod-based tests are useless as root (CAP_DAC_OVERRIDE — verified), so atomic-write failure is injected via ENOTDIR (parent is a regular file) and rename-onto-directory, both of which fail even for root; the chmod old-file-intact variant runs only when `os.Geteuid() != 0`.** `go test -race ./...` always.

**ADR-G12 — Config.** `config.Load(getenv func(string) string)` — env-first (`HEIMDALL_MANIFEST`, `HEIMDALL_TEXTFILE_DIR`, `HEIMDALL_SPOOL_DIR`, `HEIMDALL_STATE_DB`, `HEIMDALL_PROM_URL`, `HEIMDALL_QUERY_LIMIT`) plus an optional Vault-seeded KEY=VALUE file (`HEIMDALL_CRED_FILE`, 0600) carrying the ONE least-privilege read-only credential; fail-fast validation; zero package-level state; `getenv` is a parameter so tests need no real environment. `Credentials` is parsed but deliberately unconsumed in this slice (first consumer: the VictoriaLogs source's vmauth token) — commented so nobody gold-plates it in.

**ADR-G13 — Redaction: content-fail-closed, signal-fail-open, and failure PAGES.** Lives in `internal/contract` (part of the wire contract); typed patterns (glpat-, PBSAPIToken=, hvs., bearer, **and URL userinfo `https?://user:pass@` — net/http error strings embed full request URLs**) → `[REDACTED:<kind>]`. Redaction happens once, at egress (`emit.WriteSpool` for Title+Evidence; every metric label value routes through `Redact` too). `EvidenceOrWithheld` returns `(string, failed bool)`: a panicking redactor yields `Withheld` AND `failed=true`; WriteSpool counts failures and RenderProm exports `heimdall_redaction_failures_total`, which the shipped meta-rule pages on — a broken redactor can withhold evidence but can never withhold it silently forever. CI routes the defanged `glpat-EXAMPLEexample12345678` through the real spool-write path and asserts masking.

**ADR-G14 — Build/CI: CGO scoped correctly.** `go test -race` REQUIRES cgo (verified: it errors under CGO_ENABLED=0), so **CGO_ENABLED=0 is a property of the RELEASE BUILD only**: `build: CGO_ENABLED=0 go build -trimpath -ldflags="-s -w"` (static, verified via `file(1)`: "statically linked"); `test: CGO_ENABLED=1 go test -race ./...`. modernc (pure Go) is exercised identically either way. CI gates = gofmt -l empty, `go vet`, race tests, `govulncheck@v1.6.0` (modernc's transitive modules are still CVE surface), `go mod verify`, plus four custom gates promoted into `make lint`: no `time.Now()` calls in internal/, no `contract.Finding{` literals outside contract, no real-infra strings (`192\.168\.|lazarev\.cloud|pbsHGST` — patterns chosen so the public module path `lazarevtill` can never false-positive), no secret-shaped `glpat-[A-Za-z0-9_-]{20,}` outside redact.go and test fixtures. CI image `golang:1.25`.

---

# Build Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the first testable Go slice of Heimdall — `cmd/heimdall-detect`: read a manifest, run deterministic tri-state checks against an HTTP source with bounded parallelism, record findings in a SQLite ledger, and atomically emit a node_exporter textfile + redacted finding docs, with the trust invariants (unknown is always alertable; atomic whole-file writes; trend≤warning; hypothesis refused; redaction failure pages; stable series identity) enforced in code and locked by tests.

**Architecture:** One static binary over seven `internal/` packages: `contract` (tri-state types, fingerprint, severity-cap constructor, fail-closed redaction), `manifest` (validated JSON loader), `source` (2-method Source ABI + Prometheus HTTP impl with retry/backoff), `detect` (pure Check funcs + errgroup engine with panic boundary; every failure → Unknown finding), `ledger` (pure-Go SQLite, write-only this slice), `emit` (hand-written .prom + atomic tmp+fsync+rename + redacted spool), `config` (env + Vault-seeded env-file). Checks are pure functions of `(now, expectation, signal)` — all I/O in sources, all time injected. Plus `deploy/alerts/heimdall-meta.rules.yml` (the alerts that watch the watcher) and a root `policy_test.go`.

**Tech Stack:** Go **1.25** (`go 1.25.0` in go.mod — forced by modernc v1.54.0; CI image `golang:1.25`). Direct deps exactly: `golang.org/x/sync v0.22.0`, `modernc.org/sqlite v1.54.0`, `github.com/google/go-cmp v0.7.0` (tests only).

## Global Constraints

- Module path: `github.com/lazarevtill/heimdall`; `go 1.25.0` in go.mod.
- Release build: `CGO_ENABLED=0 go build -trimpath -ldflags="-s -w"`. Tests: `CGO_ENABLED=1 go test -race ./...` (`-race` requires cgo — do NOT export CGO_ENABLED=0 globally in the Makefile).
- Direct deps limited to the three above — enforced by `TestDependencyBudget` (Task 11). `mattn/go-sqlite3` is banned.
- `time.Now()` calls only in `cmd/heimdall-detect/main.go`; `contract.Finding{...}` struct literals only inside `internal/contract` — both enforced by `make lint` greps (Task 11).
- Fingerprint contract, frozen: `hex(sha256(check_id + "|" + target))[:16]`; check IDs must not contain `|`; the four golden vectors in Task 1 may never change.
- Wire label set for `heimdall_finding`, frozen: `{check, class, fingerprint, group, node, severity, source, target}` — NO `state` label (state is spool-doc-only; series identity must survive firing↔unknown).
- Trust invariants every task preserves: a failed/unknown query, missing wiring, or panicking check ALWAYS yields exactly one alertable Unknown finding (never a silent ok, never a blanked sibling); `.prom` is replaced whole-file via temp-in-same-dir + fsync + rename, never with line timestamps; `class=trend` capped at warning in code; `class=hypothesis` refused by the constructor; redaction failures are counted and exported, never swallowed.
- No real IPs, hostnames, or secrets anywhere — placeholders only (`node-a`, `ds1`, `vm-100`, `127.0.0.1`, httptest URLs). The only token-shaped string allowed is the defanged `glpat-EXAMPLEexample12345678`. Enforced by `make lint`.
- Tests: stdlib `testing` + go-cmp, table-driven subtests; suite green under `-race` at the end of every task. Commit after every green cycle.

---

### Task 1: Module scaffold + contract core types + fingerprint golden vectors

**Files:**
- Create: `go.mod`, `.gitignore`
- Create: `internal/contract/contract.go`
- Test: `internal/contract/contract_test.go`

**Interfaces:**
- Consumes: nothing (first task).
- Produces (every later task imports these exact names):
  - `type State int` — `StateUnknown State = iota; StateOK; StateFiring`; `func (s State) String() string`; `func (s State) MarshalJSON() ([]byte, error)`
  - `type Severity string` (`SeverityInfo/SeverityWarning/SeverityCritical`), `type Class string` (`ClassHard/ClassTrend/ClassHypothesis`)
  - `type Finding struct` (JSON-tagged snake_case; see Step 4)
  - `type FindingSpec struct { Check, Group, Target, Node string; Severity Severity; Class Class; State State; Title, Evidence string }`
  - `func NewFinding(now time.Time, spec FindingSpec) (Finding, error)`
  - `func Fingerprint(checkID, target string) string`
  - `var ErrHypothesisRefused error`

- [ ] **Step 1: Initialize repo and module**

```bash
mkdir -p heimdall && cd heimdall && git init
go mod init github.com/lazarevtill/heimdall
go mod edit -go=1.25.0   # modernc v1.54.0 (Task 7) requires go >= 1.25
printf 'bin/\n*.db\n*.db-wal\n*.db-shm\n' > .gitignore
git add go.mod .gitignore && git commit -m "chore: init module github.com/lazarevtill/heimdall"
```

- [ ] **Step 2: Write the failing test** — `internal/contract/contract_test.go`:

```go
package contract_test

import (
	"testing"
	"time"

	"github.com/lazarevtill/heimdall/internal/contract"
)

func TestFingerprintGoldenVectors(t *testing.T) {
	// Frozen contract: hex(sha256(check_id+"|"+target))[:16].
	// These vectors may NEVER change; changing them breaks dedup identity.
	cases := []struct{ name, check, target, want string }{
		{"backup dead-man", "c1-deadman", "backup:ds1/vm-100", "d86c07b5a41742c1"},
		{"unit failed", "c2-unit-failed", "node-a", "34915542b733a584"},
		{"pipes legal in target", "c1-deadman", "target|with|pipes", "296c533b31dd957e"},
		{"signature", "c4-signature", "node-b/ssh", "5aab268a9c139079"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := contract.Fingerprint(tc.check, tc.target); got != tc.want {
				t.Errorf("Fingerprint(%q, %q) = %q, want %q", tc.check, tc.target, got, tc.want)
			}
		})
	}
}

func TestStateZeroValueIsUnknown(t *testing.T) {
	var s contract.State // fail-closed by construction
	if s != contract.StateUnknown {
		t.Fatalf("zero State = %v, want StateUnknown", s)
	}
	if got := s.String(); got != "unknown" {
		t.Errorf("String() = %q, want %q", got, "unknown")
	}
}

func newSpec() contract.FindingSpec {
	return contract.FindingSpec{
		Check: "c1-deadman", Group: "backup-ds1", Target: "backup:ds1/vm-100",
		Node: "node-a", Severity: contract.SeverityCritical, Class: contract.ClassHard,
		State: contract.StateFiring, Title: "backup missed", Evidence: "last success 26h ago",
	}
}

func TestNewFinding(t *testing.T) {
	now := time.Unix(1752900000, 0).UTC()

	t.Run("valid hard finding", func(t *testing.T) {
		f, err := contract.NewFinding(now, newSpec())
		if err != nil {
			t.Fatalf("NewFinding: %v", err)
		}
		if f.Fingerprint != "d86c07b5a41742c1" {
			t.Errorf("Fingerprint = %q, want d86c07b5a41742c1", f.Fingerprint)
		}
		if f.SchemaVersion != 1 || !f.ObservedAt.Equal(now) {
			t.Errorf("SchemaVersion/ObservedAt wrong: %+v", f)
		}
	})

	t.Run("hypothesis refused", func(t *testing.T) {
		spec := newSpec()
		spec.Class = contract.ClassHypothesis
		if _, err := contract.NewFinding(now, spec); err != contract.ErrHypothesisRefused {
			t.Fatalf("err = %v, want ErrHypothesisRefused", err)
		}
	})

	t.Run("trend capped at warning", func(t *testing.T) {
		spec := newSpec()
		spec.Class = contract.ClassTrend
		spec.Severity = contract.SeverityCritical
		f, err := contract.NewFinding(now, spec)
		if err != nil {
			t.Fatalf("NewFinding: %v", err)
		}
		if f.Severity != contract.SeverityWarning {
			t.Errorf("Severity = %q, want warning (class=trend can never page)", f.Severity)
		}
	})

	t.Run("pipe in check id rejected", func(t *testing.T) {
		spec := newSpec()
		spec.Check = "c1|deadman"
		if _, err := contract.NewFinding(now, spec); err == nil {
			t.Fatal("want error for '|' in check id, got nil")
		}
	})

	t.Run("invalid severity rejected", func(t *testing.T) {
		spec := newSpec()
		spec.Severity = "page-me-harder"
		if _, err := contract.NewFinding(now, spec); err == nil {
			t.Fatal("want error for invalid severity, got nil")
		}
	})

	t.Run("invalid state rejected", func(t *testing.T) {
		spec := newSpec()
		spec.State = contract.State(99)
		if _, err := contract.NewFinding(now, spec); err == nil {
			t.Fatal("want error for out-of-range state, got nil")
		}
	})
}
```

- [ ] **Step 3: Run test to verify it fails** — `go test ./internal/contract/` → FAIL: `no required module provides package .../internal/contract`.

- [ ] **Step 4: Write minimal implementation** — `internal/contract/contract.go`:

```go
// Package contract holds Heimdall's wire types: the tri-state Finding
// vocabulary, the frozen fingerprint algorithm, severity/class enums with the
// in-code class-cap table (trend<=warning, hypothesis refused), and the
// fail-closed redaction applied at every egress.
//
// Enforcement boundary (ADR-G09): NewFinding is the ONLY sanctioned way to
// mint a Finding; a `make lint` gate forbids contract.Finding composite
// literals outside this package, so the constructor's caps cannot be
// bypassed by literal construction.
package contract

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// State is tri-state. The zero value is StateUnknown so an uninitialized
// state is fail-closed: it can never read as ok.
type State int

const (
	StateUnknown State = iota
	StateOK
	StateFiring
)

func (s State) String() string {
	switch s {
	case StateOK:
		return "ok"
	case StateFiring:
		return "firing"
	default:
		return "unknown"
	}
}

func (s State) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

type Class string

const (
	ClassHard       Class = "hard"
	ClassTrend      Class = "trend"
	ClassHypothesis Class = "hypothesis"
)

// ErrHypothesisRefused: class=hypothesis can never become a Finding, so the
// LLM plane is structurally unable to reach Prometheus/Alertmanager (G1).
var ErrHypothesisRefused = errors.New("contract: class=hypothesis is refused; hypotheses never enter the finding path")

// Finding is the emitted result of one check over one target. State is
// carried in the finding doc only — it is deliberately NOT a metric label,
// so a firing<->unknown transition never changes series identity (a label
// change would go stale + resolve, manufacturing a false all-clear).
type Finding struct {
	SchemaVersion int       `json:"schema_version"`
	Fingerprint   string    `json:"fingerprint"`
	Check         string    `json:"check"`
	Group         string    `json:"group"`
	Target        string    `json:"target"`
	Node          string    `json:"node"`
	Severity      Severity  `json:"severity"`
	Class         Class     `json:"class"`
	State         State     `json:"state"`
	Title         string    `json:"title"`
	Evidence      string    `json:"evidence"`
	ObservedAt    time.Time `json:"observed_at"`
}

// FindingSpec is the input to NewFinding, the ONLY way to mint a Finding.
type FindingSpec struct {
	Check, Group, Target, Node string
	Severity                   Severity
	Class                      Class
	State                      State
	Title, Evidence            string
}

// Fingerprint returns hex(sha256(checkID+"|"+target))[:16]. Frozen by golden
// vectors; checkID must not contain "|" (NewFinding validates), so the
// concatenation is unambiguous even when target contains pipes.
func Fingerprint(checkID, target string) string {
	sum := sha256.Sum256([]byte(checkID + "|" + target))
	return hex.EncodeToString(sum[:])[:16]
}

// NewFinding validates and mints a Finding. It enforces the class-cap table
// in code: class=trend is capped at warning (Tier-2 can never page) and
// class=hypothesis is refused entirely.
func NewFinding(now time.Time, spec FindingSpec) (Finding, error) {
	if spec.Class == ClassHypothesis {
		return Finding{}, ErrHypothesisRefused
	}
	if strings.Contains(spec.Check, "|") {
		return Finding{}, fmt.Errorf("contract: check id %q contains reserved separator %q", spec.Check, "|")
	}
	switch spec.Severity {
	case SeverityInfo, SeverityWarning, SeverityCritical:
	default:
		return Finding{}, fmt.Errorf("contract: invalid severity %q", spec.Severity)
	}
	switch spec.Class {
	case ClassHard, ClassTrend:
	default:
		return Finding{}, fmt.Errorf("contract: invalid class %q", spec.Class)
	}
	switch spec.State {
	case StateUnknown, StateOK, StateFiring:
	default:
		return Finding{}, fmt.Errorf("contract: invalid state %d", spec.State)
	}
	sev := spec.Severity
	if spec.Class == ClassTrend && sev == SeverityCritical {
		sev = SeverityWarning // in-code cap: soft signals can never page (G2)
	}
	return Finding{
		SchemaVersion: 1,
		Fingerprint:   Fingerprint(spec.Check, spec.Target),
		Check:         spec.Check,
		Group:         spec.Group,
		Target:        spec.Target,
		Node:          spec.Node,
		Severity:      sev,
		Class:         spec.Class,
		State:         spec.State,
		Title:         spec.Title,
		Evidence:      spec.Evidence,
		ObservedAt:    now,
	}, nil
}
```

- [ ] **Step 5: Run tests** — `go test -race ./internal/contract/ -v` → PASS (all subtests).
- [ ] **Step 6: Commit** — `git add internal/contract/ && git commit -m "feat(contract): tri-state Finding types, frozen fingerprint, in-code class caps"`

---

### Task 2: Fail-closed redaction (reports its own failures)

**Files:**
- Create: `internal/contract/redact.go`
- Test: `internal/contract/redact_test.go`

**Interfaces:**
- Produces:
  - `func Redact(s string) string` — pure; replaces every secret-shaped substring with `[REDACTED:<kind>]`
  - `func EvidenceOrWithheld(s string) (out string, failed bool)` — fail-closed wrapper; on any redactor panic returns `(Withheld, true)`; truncates to 32KB. `failed` feeds `heimdall_redaction_failures_total` (Task 8) — a broken redactor pages, it never silently withholds forever.
  - `const Withheld = "[redaction failed — evidence withheld]"`

- [ ] **Step 1: Write the failing test** — `internal/contract/redact_test.go` (package `contract`, white-box, to test the panic path):

```go
package contract

import (
	"strings"
	"testing"
)

// defanged fixture: glpat-shaped but not a real token. This is the live
// falco leak class; the redactor must always mask it.
const defangedGlpat = "glpat-EXAMPLEexample12345678"

func TestRedact(t *testing.T) {
	cases := []struct{ name, in, wantContains, wantAbsent string }{
		{"gitlab pat", "token " + defangedGlpat + " leaked", "[REDACTED:gitlab-pat]", defangedGlpat},
		{"pbs api token", "Authorization: PBSAPIToken=monitor@pbs!x:aaaa-bbbb", "[REDACTED:pbs-token]", "aaaa-bbbb"},
		{"vault token", "using hvs.EXAMPLEexampleEXAMPLEexample", "[REDACTED:vault-token]", "hvs.EXAMPLE"},
		{"bearer", "hdr Bearer abcdefghijklmnop123456", "[REDACTED:bearer]", "abcdefghijklmnop123456"},
		{"url credentials", "GET http://svc:hunter2@127.0.0.1:9090/api failed", "[REDACTED:url-credentials]", "hunter2"},
		{"clean text unchanged", "backup vm-100 missed grace window", "backup vm-100 missed grace window", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Redact(tc.in)
			if !strings.Contains(got, tc.wantContains) {
				t.Errorf("Redact(%q) = %q, want it to contain %q", tc.in, got, tc.wantContains)
			}
			if tc.wantAbsent != "" && strings.Contains(got, tc.wantAbsent) {
				t.Errorf("Redact(%q) = %q, still contains secret %q", tc.in, got, tc.wantAbsent)
			}
		})
	}
}

func TestEvidenceOrWithheldFailsClosedAndReports(t *testing.T) {
	// Content-fail-closed / signal-fail-open: a panicking redactor withholds
	// the evidence, reports failed=true (feeds the paging counter), and must
	// not panic outward (the finding still fires).
	got, failed := evidenceOrWithheld("anything", func(string) string { panic("regex engine exploded") })
	if got != Withheld {
		t.Errorf("got %q, want %q", got, Withheld)
	}
	if !failed {
		t.Error("failed = false, want true (redaction failures must be countable)")
	}
}

func TestEvidenceOrWithheldTruncates(t *testing.T) {
	long := strings.Repeat("x", 40<<10)
	got, failed := EvidenceOrWithheld(long)
	if failed {
		t.Error("failed = true for healthy redaction")
	}
	if len(got) > 32<<10 {
		t.Errorf("evidence not truncated: %d bytes", len(got))
	}
}
```

- [ ] **Step 2: Run to verify it fails** — `go test ./internal/contract/ -run 'TestRedact|TestEvidence'` → FAIL: `undefined: Redact`, `undefined: evidenceOrWithheld`.

- [ ] **Step 3: Write minimal implementation** — `internal/contract/redact.go`:

```go
package contract

import "regexp"

// Withheld is the placeholder used when redaction itself fails. The finding
// still fires: content-fail-closed, signal-fail-open. Callers must count
// reported failures and surface them as heimdall_redaction_failures_total —
// a broken redactor is itself a paging condition, never a silent one.
const Withheld = "[redaction failed — evidence withheld]"

const maxEvidenceBytes = 32 << 10

var redactPatterns = []struct {
	kind string
	re   *regexp.Regexp
}{
	{"gitlab-pat", regexp.MustCompile(`glpat-[A-Za-z0-9_\-]{20,}`)},
	{"pbs-token", regexp.MustCompile(`PBSAPIToken=\S+`)},
	{"vault-token", regexp.MustCompile(`hvs\.[A-Za-z0-9_\-]{20,}`)},
	{"bearer", regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9._\-]{16,}`)},
	// net/http error strings embed full request URLs; a basic-auth PromURL
	// would otherwise leak into finding evidence via sig.Err.
	{"url-credentials", regexp.MustCompile(`https?://[^/\s@]+:[^/\s@]+@`)},
}

// Redact replaces every secret-shaped substring with a typed marker.
func Redact(s string) string {
	for _, p := range redactPatterns {
		s = p.re.ReplaceAllString(s, "[REDACTED:"+p.kind+"]")
	}
	return s
}

// EvidenceOrWithheld is the mandatory egress wrapper: truncate, then redact;
// if the redactor fails for any reason, withhold the content entirely and
// report the failure (failed=true) so the caller can count it into
// heimdall_redaction_failures_total.
func EvidenceOrWithheld(s string) (out string, failed bool) {
	return evidenceOrWithheld(s, Redact)
}

func evidenceOrWithheld(s string, redact func(string) string) (out string, failed bool) {
	defer func() {
		if recover() != nil {
			out, failed = Withheld, true
		}
	}()
	if len(s) > maxEvidenceBytes {
		s = s[:maxEvidenceBytes]
	}
	return redact(s), false
}
```

- [ ] **Step 4: Run tests** — `go test -race ./internal/contract/` → PASS.
- [ ] **Step 5: Commit** — `git add internal/contract/ && git commit -m "feat(contract): fail-closed redaction that reports failures for the paging counter"`

---

### Task 3: Manifest loader

**Files:**
- Create: `internal/manifest/manifest.go`, `internal/manifest/testdata/manifest.json`
- Test: `internal/manifest/manifest_test.go`

**Interfaces:**
- Consumes: `contract.Severity`.
- Produces:
  - `type Manifest struct { GeneratedAt time.Time; Expectations []Expectation }`
  - `type Expectation struct { ID, Check, Group, Target, Node string; GraceSeconds int64; SeverityOnMiss contract.Severity; Verify Verify }` (snake_case JSON tags)
  - `type Verify struct { Backend, Query string; MinCount float64 }`
  - `func (e Expectation) Grace() time.Duration`
  - `func Load(path string) (*Manifest, error)`; `var ErrInvalid error`

- [ ] **Step 1: Write the fixture** — `internal/manifest/testdata/manifest.json` (placeholder names only):

```json
{
  "generated_at": "2026-07-19T00:00:00Z",
  "expectations": [
    {
      "id": "backup-vm-100",
      "check": "c1-deadman",
      "group": "backup-ds1",
      "target": "backup:ds1/vm-100",
      "node": "node-a",
      "grace_seconds": 3600,
      "severity_on_miss": "critical",
      "verify": {
        "backend": "prometheus",
        "query": "max(backup_last_success_timestamp_seconds{backup_id=\"vm-100\"})"
      }
    },
    {
      "id": "unit-failures-node-a",
      "check": "c4-signature",
      "group": "node-a",
      "target": "node-a",
      "node": "node-a",
      "grace_seconds": 0,
      "severity_on_miss": "warning",
      "verify": {
        "backend": "prometheus",
        "query": "sum(node_systemd_units{state=\"failed\"})",
        "min_count": 1
      }
    }
  ]
}
```

- [ ] **Step 2: Write the failing test** — `internal/manifest/manifest_test.go`:

```go
package manifest_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lazarevtill/heimdall/internal/manifest"
)

func TestLoadValid(t *testing.T) {
	m, err := manifest.Load(filepath.Join("testdata", "manifest.json"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(m.Expectations) != 2 {
		t.Fatalf("len(Expectations) = %d, want 2", len(m.Expectations))
	}
	e := m.Expectations[0]
	if e.ID != "backup-vm-100" || e.Check != "c1-deadman" || e.Verify.Backend != "prometheus" {
		t.Errorf("unexpected first expectation: %+v", e)
	}
	if e.Grace() != time.Hour {
		t.Errorf("Grace() = %v, want 1h", e.Grace())
	}
}

func writeTemp(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "m.json")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadRejectsInvalid(t *testing.T) {
	cases := []struct{ name, body string }{
		{"duplicate id", `{"generated_at":"2026-07-19T00:00:00Z","expectations":[
			{"id":"a","check":"c4-signature","group":"g","target":"t","node":"n","severity_on_miss":"info","verify":{"backend":"prometheus","query":"up","min_count":1}},
			{"id":"a","check":"c4-signature","group":"g","target":"t2","node":"n","severity_on_miss":"info","verify":{"backend":"prometheus","query":"up","min_count":1}}]}`},
		{"bad severity", `{"generated_at":"2026-07-19T00:00:00Z","expectations":[
			{"id":"a","check":"c4-signature","group":"g","target":"t","node":"n","severity_on_miss":"panic","verify":{"backend":"prometheus","query":"up","min_count":1}}]}`},
		{"pipe in check id", `{"generated_at":"2026-07-19T00:00:00Z","expectations":[
			{"id":"a","check":"c1|deadman","group":"g","target":"t","node":"n","grace_seconds":60,"severity_on_miss":"info","verify":{"backend":"prometheus","query":"up"}}]}`},
		{"deadman without grace", `{"generated_at":"2026-07-19T00:00:00Z","expectations":[
			{"id":"a","check":"c1-deadman","group":"g","target":"t","node":"n","severity_on_miss":"info","verify":{"backend":"prometheus","query":"up"}}]}`},
		{"threshold without min_count", `{"generated_at":"2026-07-19T00:00:00Z","expectations":[
			{"id":"a","check":"c4-signature","group":"g","target":"t","node":"n","severity_on_miss":"info","verify":{"backend":"prometheus","query":"up"}}]}`},
		{"unknown backend", `{"generated_at":"2026-07-19T00:00:00Z","expectations":[
			{"id":"a","check":"c4-signature","group":"g","target":"t","node":"n","severity_on_miss":"info","verify":{"backend":"carrier-pigeon","query":"up","min_count":1}}]}`},
		{"garbage json", `{nope`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := manifest.Load(writeTemp(t, tc.body))
			if err == nil {
				t.Fatal("want error, got nil")
			}
			if tc.name != "garbage json" && !errors.Is(err, manifest.ErrInvalid) {
				t.Errorf("err = %v, want errors.Is(err, ErrInvalid)", err)
			}
		})
	}
}
```

- [ ] **Step 3: Run to verify it fails** — `go test ./internal/manifest/` → FAIL: package does not exist.

- [ ] **Step 4: Write minimal implementation** — `internal/manifest/manifest.go` (note: every `fmt.Errorf` verb has a matching argument — the `unknown verify.backend` line takes THREE args):

```go
// Package manifest loads the IaC-rendered expectation manifest
// (/etc/heimdall/manifest.json in production).
package manifest

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/lazarevtill/heimdall/internal/contract"
)

// ErrInvalid wraps every validation failure so callers can errors.Is it.
var ErrInvalid = errors.New("manifest: invalid")

type Manifest struct {
	GeneratedAt  time.Time     `json:"generated_at"`
	Expectations []Expectation `json:"expectations"`
}

type Expectation struct {
	ID             string            `json:"id"`
	Check          string            `json:"check"`
	Group          string            `json:"group"`
	Target         string            `json:"target"`
	Node           string            `json:"node"`
	GraceSeconds   int64             `json:"grace_seconds"`
	SeverityOnMiss contract.Severity `json:"severity_on_miss"`
	Verify         Verify            `json:"verify"`
}

type Verify struct {
	Backend  string  `json:"backend"` // prometheus | victorialogs | pbs
	Query    string  `json:"query"`
	MinCount float64 `json:"min_count"`
}

func (e Expectation) Grace() time.Duration {
	return time.Duration(e.GraceSeconds) * time.Second
}

var validBackends = map[string]bool{"prometheus": true, "victorialogs": true, "pbs": true}

func Load(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("manifest: read %s: %w", path, err)
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("manifest: parse %s: %w", path, err)
	}
	seen := make(map[string]bool, len(m.Expectations))
	for i, e := range m.Expectations {
		where := fmt.Sprintf("expectations[%d] (id %q)", i, e.ID)
		switch {
		case e.ID == "" || e.Check == "" || e.Target == "" || e.Group == "":
			return nil, fmt.Errorf("%w: %s: id, check, group, target are required", ErrInvalid, where)
		case seen[e.ID]:
			return nil, fmt.Errorf("%w: duplicate expectation id %q", ErrInvalid, e.ID)
		case strings.Contains(e.Check, "|"):
			return nil, fmt.Errorf("%w: %s: check id contains reserved '|'", ErrInvalid, where)
		case e.Check == "c1-deadman" && e.GraceSeconds <= 0:
			return nil, fmt.Errorf("%w: %s: c1-deadman requires grace_seconds > 0", ErrInvalid, where)
		case e.Check == "c4-signature" && e.Verify.MinCount < 1:
			// zero-value min_count would make Threshold fire on a 0-sum
			// signal (0 >= 0) — a manifest-rendering omission must be
			// rejected here, not flood warning findings.
			return nil, fmt.Errorf("%w: %s: c4-signature requires min_count >= 1", ErrInvalid, where)
		case !validBackends[e.Verify.Backend]:
			return nil, fmt.Errorf("%w: %s: unknown verify.backend %q", ErrInvalid, where, e.Verify.Backend)
		case e.Verify.Query == "":
			return nil, fmt.Errorf("%w: %s: verify.query is required", ErrInvalid, where)
		}
		switch e.SeverityOnMiss {
		case contract.SeverityInfo, contract.SeverityWarning, contract.SeverityCritical:
		default:
			return nil, fmt.Errorf("%w: %s: invalid severity_on_miss %q", ErrInvalid, where, e.SeverityOnMiss)
		}
		seen[e.ID] = true
	}
	return &m, nil
}
```

- [ ] **Step 5: Run tests** — `go test -race ./internal/manifest/` → PASS.
- [ ] **Step 6: Commit** — `git add internal/manifest/ && git commit -m "feat(manifest): validated loader for the IaC-rendered expectation manifest"`

---

### Task 4: Source ABI + retry/backoff + Prometheus source

**Files:**
- Create: `internal/source/source.go`, `internal/source/backoff.go`, `internal/source/prom.go`
- Test: `internal/source/backoff_test.go`, `internal/source/prom_test.go`

**Interfaces:**
- Consumes: `contract.State`.
- Produces:
  - `type Source interface { ID() string; Query(ctx context.Context, q Query) (Signal, error) }` (producer-side by design — this IS the plugin-ABI seam, ADR-G10)
  - `type Query struct { ID, Expr string }`; `type Signal struct { QueryID string; State contract.State; Samples []Sample; Attempts int; Err string }`; `type Sample struct { Labels map[string]string; Value float64 }`
  - `func NewProm(baseURL string, client *http.Client) *PromSource` (accept interfaces, return structs)

- [ ] **Step 1: Fetch the test dep and write the failing tests**

```bash
go get github.com/google/go-cmp@v0.7.0
```

`internal/source/backoff_test.go` (package `source`, white-box):

```go
package source

import (
	"testing"
	"time"
)

func TestRetryDelayCapAndJitter(t *testing.T) {
	one := func() float64 { return 1.0 }
	zero := func() float64 { return 0.0 }
	if d := retryDelay(0, 250*time.Millisecond, one); d != 250*time.Millisecond {
		t.Errorf("attempt 0 = %v, want 250ms", d)
	}
	if d := retryDelay(1, 250*time.Millisecond, one); d != 500*time.Millisecond {
		t.Errorf("attempt 1 = %v, want 500ms", d)
	}
	if d := retryDelay(10, 250*time.Millisecond, one); d != 8*time.Second {
		t.Errorf("attempt 10 = %v, want capped 8s", d)
	}
	if d := retryDelay(3, 250*time.Millisecond, zero); d != 0 {
		t.Errorf("full jitter with r=0 should give 0, got %v", d)
	}
}

func TestRetryableStatus(t *testing.T) {
	for status, want := range map[int]bool{500: true, 503: true, 429: true, 404: false, 400: false, 200: false} {
		if got := retryableStatus(status); got != want {
			t.Errorf("retryableStatus(%d) = %v, want %v", status, got, want)
		}
	}
}
```

`internal/source/prom_test.go` (package `source`, white-box so tests can zero the jitter/delay fields):

```go
package source

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/lazarevtill/heimdall/internal/contract"
)

const vectorBody = `{"status":"success","data":{"resultType":"vector","result":[
  {"metric":{"backup_id":"vm-100"},"value":[1752900000,"1752896400"]},
  {"metric":{"backup_id":"vm-101"},"value":[1752900000,"1752893000"]}]}}`

// newTestProm zeroes BOTH baseDelay and jitter: retryDelay treats d<=0 as
// the 8s ceiling before jitter, so zeroing only baseDelay would silently
// sleep 8s per retry.
func newTestProm(t *testing.T, h http.HandlerFunc) *PromSource {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	s := NewProm(srv.URL, srv.Client())
	s.baseDelay = 0
	s.jitter = func() float64 { return 0 }
	return s
}

func TestPromQueryOK(t *testing.T) {
	s := newTestProm(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/query" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Write([]byte(vectorBody))
	})
	sig, err := s.Query(context.Background(), Query{ID: "q1", Expr: "up"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	want := Signal{QueryID: "q1", State: contract.StateOK, Attempts: 1, Samples: []Sample{
		{Labels: map[string]string{"backup_id": "vm-100"}, Value: 1752896400},
		{Labels: map[string]string{"backup_id": "vm-101"}, Value: 1752893000},
	}}
	if diff := cmp.Diff(want, sig); diff != "" {
		t.Errorf("Signal mismatch (-want +got):\n%s", diff)
	}
}

func TestPromRetriesThenSucceeds(t *testing.T) {
	var calls atomic.Int64
	s := newTestProm(t, func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Write([]byte(vectorBody))
	})
	sig, err := s.Query(context.Background(), Query{ID: "q1", Expr: "up"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if sig.Attempts != 2 || calls.Load() != 2 {
		t.Errorf("attempts = %d, calls = %d, want 2/2", sig.Attempts, calls.Load())
	}
}

// The core trust invariant at the source layer: every failure mode returns
// State=Unknown and a non-nil error — never a silent ok.
func TestPromFailureMatrixIsNeverSilentOK(t *testing.T) {
	cases := []struct {
		name      string
		handler   http.HandlerFunc
		wantCalls int64
	}{
		{"persistent 500 retried 3x", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}, 3},
		{"429 retried 3x", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusTooManyRequests)
		}, 3},
		{"404 fails fast", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}, 1},
		{"garbage body fails fast", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("<html>not prometheus</html>"))
		}, 1},
		{"prometheus error status fails fast", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"error","error":"bad query"}`))
		}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int64
			s := newTestProm(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				tc.handler(w, r)
			})
			sig, err := s.Query(context.Background(), Query{ID: "q1", Expr: "up"})
			if err == nil {
				t.Fatal("want error, got nil")
			}
			if sig.State != contract.StateUnknown {
				t.Errorf("State = %v, want StateUnknown (never a silent ok)", sig.State)
			}
			if calls.Load() != tc.wantCalls {
				t.Errorf("calls = %d, want %d", calls.Load(), tc.wantCalls)
			}
		})
	}
}

func TestPromTimeoutIsUnknown(t *testing.T) {
	s := newTestProm(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.Write([]byte(vectorBody))
	})
	s.timeout = 20 * time.Millisecond
	sig, err := s.Query(context.Background(), Query{ID: "q1", Expr: "up"})
	if err == nil {
		t.Fatal("want timeout error, got nil")
	}
	if sig.State != contract.StateUnknown {
		t.Errorf("State = %v, want StateUnknown", sig.State)
	}
	if sig.Err == "" {
		t.Error("Signal.Err should describe the failure")
	}
}
```

- [ ] **Step 2: Run to verify they fail** — `go test ./internal/source/` → FAIL: `undefined: retryDelay`, `undefined: NewProm`.

- [ ] **Step 3: Write minimal implementation**

`internal/source/source.go`:

```go
// Package source defines the Source ABI: every backend query resolves to a
// tri-state Signal. A failed query is (Signal{State: Unknown}, err) — the
// engine converts that into an alertable Unknown finding, never a silent ok.
//
// The Source interface deliberately lives in the PRODUCER package, a
// documented deviation from the consumer-side doctrine: this interface IS
// the plugin-ABI seam (query-in, tri-state signal-out), shaped to mirror the
// at-scale subprocess FetchPlan/SignalSet contract so extraction later is a
// transport change, not a redesign. It is consumed by internal/detect and by
// future transports alike.
package source

import (
	"context"

	"github.com/lazarevtill/heimdall/internal/contract"
)

type Query struct {
	ID   string // expectation id, for error attribution
	Expr string // backend query text
}

type Sample struct {
	Labels map[string]string
	Value  float64
}

type Signal struct {
	QueryID  string
	State    contract.State
	Samples  []Sample
	Attempts int
	Err      string
}

// Source is consumed by the detect engine; implementations return concrete
// types from their constructors (accept interfaces, return structs).
type Source interface {
	ID() string
	Query(ctx context.Context, q Query) (Signal, error)
}
```

`internal/source/backoff.go`:

```go
package source

import (
	"context"
	"net/http"
	"time"
)

const maxAttempts = 3

// retryDelay: exponential backoff with FULL jitter, capped at 8s.
// delay = rand() * min(cap, base * 2^attempt). Note: base<=0 hits the
// ceiling BEFORE jitter — tests that want zero delay must zero the jitter
// func, not just baseDelay.
func retryDelay(attempt int, base time.Duration, jitter func() float64) time.Duration {
	d := base << attempt
	const ceiling = 8 * time.Second
	if d > ceiling || d <= 0 {
		d = ceiling
	}
	return time.Duration(jitter() * float64(d))
}

// retryableStatus: only transient classes are retried. Transport errors
// (status 0) are always retryable; 4xx and malformed 200s fail fast.
// Retrying is safe ONLY because the detector issues idempotent GETs — a
// future write-capable source must not inherit this policy blindly.
func retryableStatus(status int) bool {
	return status == 0 || status >= 500 || status == http.StatusTooManyRequests
}

// sleepCtx honors cancellation during backoff waits (no leaked timers).
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
```

`internal/source/prom.go`:

```go
package source

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/lazarevtill/heimdall/internal/contract"
)

// PromSource queries a Prometheus-compatible instant-query API.
type PromSource struct {
	base      string
	client    *http.Client
	timeout   time.Duration // per-attempt budget
	baseDelay time.Duration
	jitter    func() float64
}

func NewProm(baseURL string, client *http.Client) *PromSource {
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	return &PromSource{
		base:      strings.TrimRight(baseURL, "/"),
		client:    client,
		timeout:   15 * time.Second,
		baseDelay: 250 * time.Millisecond,
		jitter:    rand.Float64,
	}
}

func (s *PromSource) ID() string { return "prometheus" }

func (s *PromSource) Query(ctx context.Context, q Query) (Signal, error) {
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			if err := sleepCtx(ctx, retryDelay(attempt-1, s.baseDelay, s.jitter)); err != nil {
				lastErr = err
				break
			}
		}
		sig, status, err := s.once(ctx, q)
		if err == nil {
			sig.Attempts = attempt + 1
			return sig, nil
		}
		lastErr = err
		if !retryableStatus(status) {
			break
		}
	}
	wrapped := fmt.Errorf("prometheus query %q: %w", q.ID, lastErr)
	return Signal{QueryID: q.ID, State: contract.StateUnknown, Err: wrapped.Error()}, wrapped
}

type promResponse struct {
	Status string `json:"status"`
	Data   struct {
		Result []promResult `json:"result"`
	} `json:"data"`
}

type promResult struct {
	Metric map[string]string  `json:"metric"`
	Value  [2]json.RawMessage `json:"value"` // [unix_ts, "value-string"]
}

func (r promResult) value() (float64, error) {
	var s string
	if err := json.Unmarshal(r.Value[1], &s); err != nil {
		return 0, fmt.Errorf("sample value: %w", err)
	}
	return strconv.ParseFloat(s, 64)
}

// once returns status 0 for transport-level failures.
func (s *PromSource) once(ctx context.Context, q Query) (Signal, int, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	u := s.base + "/api/v1/query?query=" + url.QueryEscape(q.Expr)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return Signal{}, 0, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return Signal{}, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return Signal{}, resp.StatusCode, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	var pr promResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&pr); err != nil {
		return Signal{}, resp.StatusCode, fmt.Errorf("decode response: %w", err)
	}
	if pr.Status != "success" {
		return Signal{}, resp.StatusCode, fmt.Errorf("prometheus reported status %q", pr.Status)
	}
	sig := Signal{QueryID: q.ID, State: contract.StateOK}
	for _, r := range pr.Data.Result {
		v, err := r.value()
		if err != nil {
			return Signal{}, resp.StatusCode, err
		}
		sig.Samples = append(sig.Samples, Sample{Labels: r.Metric, Value: v})
	}
	return sig, http.StatusOK, nil
}
```

- [ ] **Step 4: Run tests** — `go test -race ./internal/source/` → PASS (all matrix rows; retry counts exact).
- [ ] **Step 5: Commit** — `git add go.mod go.sum internal/source/ && git commit -m "feat(source): Source ABI, jittered backoff, Prometheus source with fail-closed matrix"`

---

### Task 5: Pure checks — DeadMan + Threshold

**Files:**
- Create: `internal/detect/checks.go`
- Test: `internal/detect/checks_test.go`

**Interfaces:**
- Consumes: `contract.NewFinding/FindingSpec/State`, `manifest.Expectation`, `source.Signal/Sample`.
- Produces:
  - `type Check func(now time.Time, exp manifest.Expectation, sig source.Signal) []contract.Finding` — pure, no I/O, no time.Now(); OK → empty slice, Firing/Unknown → exactly one finding. Evidence is stored RAW (redaction happens once, at egress in Task 8).
  - `func DeadMan(...)`, `func Threshold(...)` matching `Check`

- [ ] **Step 1: Write the failing test** — `internal/detect/checks_test.go`:

```go
package detect_test

import (
	"testing"
	"time"

	"github.com/lazarevtill/heimdall/internal/contract"
	"github.com/lazarevtill/heimdall/internal/detect"
	"github.com/lazarevtill/heimdall/internal/manifest"
	"github.com/lazarevtill/heimdall/internal/source"
)

var now = time.Unix(1752900000, 0).UTC() // injected clock: checks never call time.Now()

func deadmanExp() manifest.Expectation {
	return manifest.Expectation{
		ID: "backup-vm-100", Check: "c1-deadman", Group: "backup-ds1",
		Target: "backup:ds1/vm-100", Node: "node-a", GraceSeconds: 3600,
		SeverityOnMiss: contract.SeverityCritical,
		Verify:         manifest.Verify{Backend: "prometheus", Query: "max(...)"},
	}
}

func okSignal(vals ...float64) source.Signal {
	s := source.Signal{QueryID: "q", State: contract.StateOK}
	for _, v := range vals {
		s.Samples = append(s.Samples, source.Sample{Value: v})
	}
	return s
}

func TestDeadMan(t *testing.T) {
	grace := int64(3600)
	cases := []struct {
		name      string
		sig       source.Signal
		wantCount int
		wantState contract.State
	}{
		// both sides of the grace boundary, deterministic via injected now
		{"inside grace ok", okSignal(float64(now.Unix() - grace + 1)), 0, 0},
		{"exactly at grace ok", okSignal(float64(now.Unix() - grace)), 0, 0},
		{"outside grace fires", okSignal(float64(now.Unix() - grace - 1)), 1, contract.StateFiring},
		{"newest of several samples wins", okSignal(float64(now.Unix()-7200), float64(now.Unix()-60)), 0, 0},
		{"no samples ever fires", okSignal(), 1, contract.StateFiring},
		{"unknown signal is alertable", source.Signal{State: contract.StateUnknown, Err: "boom"}, 1, contract.StateUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := detect.DeadMan(now, deadmanExp(), tc.sig)
			if len(fs) != tc.wantCount {
				t.Fatalf("len(findings) = %d, want %d", len(fs), tc.wantCount)
			}
			if tc.wantCount == 1 {
				f := fs[0]
				if f.State != tc.wantState {
					t.Errorf("State = %v, want %v", f.State, tc.wantState)
				}
				if f.Fingerprint != "d86c07b5a41742c1" {
					t.Errorf("Fingerprint = %q, want golden d86c07b5a41742c1", f.Fingerprint)
				}
				if f.Severity != contract.SeverityCritical {
					t.Errorf("Severity = %q, want critical (severity_on_miss)", f.Severity)
				}
			}
		})
	}
}

func TestThreshold(t *testing.T) {
	exp := manifest.Expectation{
		ID: "unit-failures-node-a", Check: "c4-signature", Group: "node-a",
		Target: "node-a", Node: "node-a", SeverityOnMiss: contract.SeverityWarning,
		Verify: manifest.Verify{Backend: "prometheus", Query: "sum(...)", MinCount: 2},
	}
	cases := []struct {
		name      string
		sig       source.Signal
		wantCount int
		wantState contract.State
	}{
		{"below threshold ok", okSignal(1), 0, 0},
		{"at threshold fires", okSignal(2), 1, contract.StateFiring},
		{"summed across samples", okSignal(1, 1), 1, contract.StateFiring},
		{"unknown signal is alertable", source.Signal{State: contract.StateUnknown, Err: "boom"}, 1, contract.StateUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := detect.Threshold(now, exp, tc.sig)
			if len(fs) != tc.wantCount {
				t.Fatalf("len(findings) = %d, want %d", len(fs), tc.wantCount)
			}
			if tc.wantCount == 1 && fs[0].State != tc.wantState {
				t.Errorf("State = %v, want %v", fs[0].State, tc.wantState)
			}
		})
	}
}
```

- [ ] **Step 2: Run to verify it fails** — `go test ./internal/detect/` → FAIL: package does not exist.

- [ ] **Step 3: Write minimal implementation** — `internal/detect/checks.go`:

```go
// Package detect holds the pure check functions and the engine that runs
// them. Checks do no I/O and never call time.Now(): the clock is injected,
// which is what makes dead-man window boundaries table-testable.
//
// Evidence strings are stored RAW in findings here; redaction happens once,
// at egress (internal/emit), which is the only boundary where content
// leaves the process.
package detect

import (
	"fmt"
	"time"

	"github.com/lazarevtill/heimdall/internal/contract"
	"github.com/lazarevtill/heimdall/internal/manifest"
	"github.com/lazarevtill/heimdall/internal/source"
)

// Check evaluates one expectation against its fetched Signal.
// Contract: OK evaluations return an empty slice; Firing and Unknown
// evaluations return exactly one Finding. An Unknown signal MUST surface
// as an Unknown finding — never a silent ok.
type Check func(now time.Time, exp manifest.Expectation, sig source.Signal) []contract.Finding

// DeadMan (C1): fires when the newest success timestamp is older than the
// expectation's grace window, or when no success has ever been recorded.
func DeadMan(now time.Time, exp manifest.Expectation, sig source.Signal) []contract.Finding {
	if sig.State == contract.StateUnknown {
		return one(now, exp, contract.StateUnknown, "dead-man evidence unavailable: "+sig.Err)
	}
	var newest float64
	found := false
	for _, s := range sig.Samples {
		if !found || s.Value > newest {
			newest, found = s.Value, true
		}
	}
	if !found {
		return one(now, exp, contract.StateFiring, "no success event recorded for target")
	}
	age := now.Sub(time.Unix(int64(newest), 0))
	if age > exp.Grace() {
		return one(now, exp, contract.StateFiring,
			fmt.Sprintf("last success %s ago exceeds grace %s", age.Round(time.Second), exp.Grace()))
	}
	return nil
}

// Threshold (C4-style): fires when the summed sample value reaches
// min_count (manifest validation guarantees min_count >= 1).
func Threshold(now time.Time, exp manifest.Expectation, sig source.Signal) []contract.Finding {
	if sig.State == contract.StateUnknown {
		return one(now, exp, contract.StateUnknown, "threshold evidence unavailable: "+sig.Err)
	}
	var total float64
	for _, s := range sig.Samples {
		total += s.Value
	}
	if total >= exp.Verify.MinCount {
		return one(now, exp, contract.StateFiring,
			fmt.Sprintf("count %.0f >= min_count %.0f", total, exp.Verify.MinCount))
	}
	return nil
}

// one mints the single finding for a non-ok evaluation. A malformed
// expectation must STILL be alertable, so constructor failure degrades to an
// internal unknown finding rather than dropping the signal.
func one(now time.Time, exp manifest.Expectation, state contract.State, evidence string) []contract.Finding {
	f, err := contract.NewFinding(now, contract.FindingSpec{
		Check: exp.Check, Group: exp.Group, Target: exp.Target, Node: exp.Node,
		Severity: exp.SeverityOnMiss, Class: contract.ClassHard, State: state,
		Title: exp.ID, Evidence: evidence,
	})
	if err != nil {
		// Fallback spec is statically valid, so this NewFinding cannot fail.
		fb, _ := contract.NewFinding(now, contract.FindingSpec{
			Check: "heimdall-internal", Group: "heimdall", Target: exp.ID, Node: exp.Node,
			Severity: contract.SeverityWarning, Class: contract.ClassHard,
			State: contract.StateUnknown, Title: "invalid expectation",
			Evidence: err.Error(),
		})
		return []contract.Finding{fb}
	}
	return []contract.Finding{f}
}
```

- [ ] **Step 4: Run tests** — `go test -race ./internal/detect/` → PASS.
- [ ] **Step 5: Commit** — `git add internal/detect/ && git commit -m "feat(detect): pure DeadMan and Threshold checks with injected clock"`

---

### Task 6: Detect engine — bounded parallel, unknown-on-error, panic boundary

**Files:**
- Create: `internal/detect/engine.go`
- Test: `internal/detect/engine_test.go`

**Interfaces:**
- Produces:
  - `func New(sources map[string]source.Source, checks map[string]Check, limit int) *Engine`
  - `func (e *Engine) Run(ctx context.Context, now time.Time, m *manifest.Manifest) []contract.Finding` — deterministic manifest order; never returns an error: failures AND panics become Unknown findings

- [ ] **Step 1: Fetch errgroup and write the failing test**

```bash
go get golang.org/x/sync@v0.22.0
```

`internal/detect/engine_test.go`:

```go
package detect_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lazarevtill/heimdall/internal/contract"
	"github.com/lazarevtill/heimdall/internal/detect"
	"github.com/lazarevtill/heimdall/internal/manifest"
	"github.com/lazarevtill/heimdall/internal/source"
)

type fakeSource struct {
	id string
	fn func(ctx context.Context, q source.Query) (source.Signal, error)
}

func (f *fakeSource) ID() string { return f.id }
func (f *fakeSource) Query(ctx context.Context, q source.Query) (source.Signal, error) {
	return f.fn(ctx, q)
}

func thresholdExp(id, target string) manifest.Expectation {
	return manifest.Expectation{
		ID: id, Check: "c4-signature", Group: "g", Target: target, Node: "node-a",
		SeverityOnMiss: contract.SeverityWarning,
		Verify:         manifest.Verify{Backend: "prometheus", Query: "q", MinCount: 1},
	}
}

func engineChecks() map[string]detect.Check {
	return map[string]detect.Check{"c1-deadman": detect.DeadMan, "c4-signature": detect.Threshold}
}

// THE load-bearing regression test: a failing source yields exactly one
// Unknown finding for ITS expectation, and does NOT cancel or blank the
// other sources' evaluations (no errgroup sibling-cancellation).
func TestRunSourceErrorIsUnknownAndDoesNotBlankSiblings(t *testing.T) {
	firing := &fakeSource{id: "prometheus", fn: func(_ context.Context, q source.Query) (source.Signal, error) {
		if q.ID == "exp-broken" {
			return source.Signal{QueryID: q.ID, State: contract.StateUnknown, Err: "conn refused"},
				errors.New("conn refused")
		}
		return source.Signal{QueryID: q.ID, State: contract.StateOK,
			Samples: []source.Sample{{Value: 5}}}, nil
	}}
	m := &manifest.Manifest{Expectations: []manifest.Expectation{
		thresholdExp("exp-a", "t-a"), thresholdExp("exp-broken", "t-b"), thresholdExp("exp-c", "t-c"),
	}}
	fs := detect.New(map[string]source.Source{"prometheus": firing}, engineChecks(), 4).
		Run(context.Background(), time.Unix(1752900000, 0), m)
	if len(fs) != 3 {
		t.Fatalf("len(findings) = %d, want 3 (2 firing + 1 unknown)", len(fs))
	}
	// manifest order is preserved
	if fs[0].Target != "t-a" || fs[1].Target != "t-b" || fs[2].Target != "t-c" {
		t.Errorf("order not deterministic: %v %v %v", fs[0].Target, fs[1].Target, fs[2].Target)
	}
	if fs[1].State != contract.StateUnknown {
		t.Errorf("broken source finding State = %v, want StateUnknown", fs[1].State)
	}
	if fs[0].State != contract.StateFiring || fs[2].State != contract.StateFiring {
		t.Error("sibling evaluations were blanked by the failing source")
	}
}

// A panicking check must degrade to one Unknown finding for its own
// expectation — never crash the run and lose every other result.
func TestRunCheckPanicIsUnknownAndDoesNotBlankSiblings(t *testing.T) {
	src := &fakeSource{id: "prometheus", fn: func(_ context.Context, q source.Query) (source.Signal, error) {
		return source.Signal{QueryID: q.ID, State: contract.StateOK,
			Samples: []source.Sample{{Value: 5}}}, nil
	}}
	checks := engineChecks()
	checks["c9-panics"] = func(time.Time, manifest.Expectation, source.Signal) []contract.Finding {
		panic("malformed sample blew up the check")
	}
	panicking := thresholdExp("exp-panics", "t-b")
	panicking.Check = "c9-panics"
	m := &manifest.Manifest{Expectations: []manifest.Expectation{
		thresholdExp("exp-a", "t-a"), panicking, thresholdExp("exp-c", "t-c"),
	}}
	fs := detect.New(map[string]source.Source{"prometheus": src}, checks, 4).
		Run(context.Background(), time.Unix(1752900000, 0), m)
	if len(fs) != 3 {
		t.Fatalf("len(findings) = %d, want 3 (2 firing + 1 unknown-from-panic)", len(fs))
	}
	if fs[1].State != contract.StateUnknown {
		t.Errorf("panicking check finding State = %v, want StateUnknown", fs[1].State)
	}
	if fs[0].State != contract.StateFiring || fs[2].State != contract.StateFiring {
		t.Error("sibling evaluations were blanked by the panicking check")
	}
}

func TestRunUnknownBackendAndCheckAreAlertable(t *testing.T) {
	src := &fakeSource{id: "prometheus", fn: func(_ context.Context, q source.Query) (source.Signal, error) {
		return source.Signal{State: contract.StateOK}, nil
	}}
	badBackend := thresholdExp("exp-nb", "t-nb")
	badBackend.Verify.Backend = "victorialogs" // valid in manifest, not wired in this engine
	badCheck := thresholdExp("exp-nc", "t-nc")
	badCheck.Check = "c99-not-implemented"
	m := &manifest.Manifest{Expectations: []manifest.Expectation{badBackend, badCheck}}
	fs := detect.New(map[string]source.Source{"prometheus": src}, engineChecks(), 4).
		Run(context.Background(), time.Unix(1752900000, 0), m)
	if len(fs) != 2 {
		t.Fatalf("len(findings) = %d, want 2 unknowns", len(fs))
	}
	for _, f := range fs {
		if f.State != contract.StateUnknown {
			t.Errorf("finding %q State = %v, want StateUnknown", f.Target, f.State)
		}
	}
}

func TestRunBoundedParallelism(t *testing.T) {
	var inFlight, peak atomic.Int64
	src := &fakeSource{id: "prometheus", fn: func(_ context.Context, q source.Query) (source.Signal, error) {
		cur := inFlight.Add(1)
		for {
			p := peak.Load()
			if cur <= p || peak.CompareAndSwap(p, cur) {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
		inFlight.Add(-1)
		return source.Signal{State: contract.StateOK, Samples: []source.Sample{{Value: 0}}}, nil
	}}
	var exps []manifest.Expectation
	for i := 0; i < 10; i++ {
		exps = append(exps, thresholdExp(string(rune('a'+i))+"-exp", string(rune('a'+i))))
	}
	detect.New(map[string]source.Source{"prometheus": src}, engineChecks(), 2).
		Run(context.Background(), time.Unix(1752900000, 0), &manifest.Manifest{Expectations: exps})
	if p := peak.Load(); p > 2 {
		t.Errorf("peak concurrency = %d, want <= 2 (SetLimit)", p)
	}
}
```

- [ ] **Step 2: Run to verify it fails** — `go test ./internal/detect/ -run TestRun` → FAIL: `undefined: detect.New`.

- [ ] **Step 3: Write minimal implementation** — `internal/detect/engine.go`:

```go
package detect

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/lazarevtill/heimdall/internal/contract"
	"github.com/lazarevtill/heimdall/internal/manifest"
	"github.com/lazarevtill/heimdall/internal/source"
)

// Engine fans expectations out over sources with bounded parallelism and
// folds every failure — query error, missing wiring, even a check panic —
// into an alertable Unknown finding.
type Engine struct {
	sources map[string]source.Source // keyed by verify.backend
	checks  map[string]Check         // keyed by expectation check family
	limit   int
}

func New(sources map[string]source.Source, checks map[string]Check, limit int) *Engine {
	if limit < 1 {
		limit = 8
	}
	return &Engine{sources: sources, checks: checks, limit: limit}
}

// Run evaluates every expectation. It never returns an error: a query or
// wiring failure becomes exactly one Unknown finding for that expectation.
// Goroutines always return nil to errgroup — returning an error would
// cancel the shared ctx and blank every sibling source (the silent-wipeout
// trap). Output order is manifest order (deterministic).
func (e *Engine) Run(ctx context.Context, now time.Time, m *manifest.Manifest) []contract.Finding {
	results := make([][]contract.Finding, len(m.Expectations))
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(e.limit)
	for i, exp := range m.Expectations {
		g.Go(func() error {
			results[i] = e.evalOne(ctx, now, exp)
			return nil
		})
	}
	_ = g.Wait() // goroutines never return errors; Wait is a join
	var out []contract.Finding
	for _, fs := range results {
		out = append(out, fs...)
	}
	return out
}

// evalOne contains the panic boundary: a panicking check or source degrades
// to one Unknown finding for THIS expectation instead of crashing the run
// and losing every other expectation's result.
func (e *Engine) evalOne(ctx context.Context, now time.Time, exp manifest.Expectation) (out []contract.Finding) {
	defer func() {
		if r := recover(); r != nil {
			out = one(now, exp, contract.StateUnknown, fmt.Sprintf("check panicked: %v", r))
		}
	}()
	src, ok := e.sources[exp.Verify.Backend]
	if !ok {
		return one(now, exp, contract.StateUnknown, "no source wired for backend "+exp.Verify.Backend)
	}
	chk, ok := e.checks[exp.Check]
	if !ok {
		return one(now, exp, contract.StateUnknown, "no check implemented for family "+exp.Check)
	}
	sig, err := src.Query(ctx, source.Query{ID: exp.ID, Expr: exp.Verify.Query})
	if err != nil {
		// Fail-closed: the check sees an explicit Unknown signal and must
		// surface it; err is already folded into sig.Err by the source.
		sig = source.Signal{QueryID: exp.ID, State: contract.StateUnknown, Err: err.Error()}
	}
	return chk(now, exp, sig)
}
```

- [ ] **Step 4: Run tests** — `go test -race ./internal/detect/` → PASS, including the race detector over the bounded fan-out.
- [ ] **Step 5: Commit** — `git add go.mod go.sum internal/detect/ && git commit -m "feat(detect): errgroup engine; failures and panics degrade to Unknown, never blank siblings"`

---

### Task 7: Ledger — pure-Go SQLite state (write-only this slice)

**Files:**
- Create: `internal/ledger/ledger.go`
- Test: `internal/ledger/ledger_test.go`

**Interfaces:**
- Produces:
  - `func Open(path string) (*Ledger, error)` — WAL/NORMAL/busy_timeout pragmas in the DSN, `SetMaxOpenConns(1)`, `PRAGMA user_version` migration
  - `func (l *Ledger) Upsert(now time.Time, fs []contract.Finding) error`
  - `type Entry struct { Fingerprint, Check, Target, State, Severity string; FirstSeen, LastSeen time.Time; Count int64 }`
  - `func (l *Ledger) Get(fp string) (Entry, bool, error)`; `func (l *Ledger) Close() error`
- Deliberately OUT of scope: state transitions, resolution, GC — bridge/notifier slice. Do not invent resolve semantics.

- [ ] **Step 1: Fetch the driver and write the failing test**

```bash
go get modernc.org/sqlite@v1.54.0   # bumps go directive to 1.25.0 — expected (ADR-G03)
```

`internal/ledger/ledger_test.go`:

```go
package ledger_test

import (
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/lazarevtill/heimdall/internal/contract"
	"github.com/lazarevtill/heimdall/internal/ledger"
)

func testFinding(t *testing.T) contract.Finding {
	t.Helper()
	f, err := contract.NewFinding(time.Unix(1752900000, 0).UTC(), contract.FindingSpec{
		Check: "c1-deadman", Group: "backup-ds1", Target: "backup:ds1/vm-100",
		Node: "node-a", Severity: contract.SeverityCritical, Class: contract.ClassHard,
		State: contract.StateFiring, Title: "backup missed", Evidence: "e",
	})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestUpsertLifecycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	l, err := ledger.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	f := testFinding(t)
	t0 := time.Unix(1752900000, 0).UTC()
	t1 := t0.Add(5 * time.Minute)

	if err := l.Upsert(t0, []contract.Finding{f}); err != nil {
		t.Fatalf("first Upsert: %v", err)
	}
	e, ok, err := l.Get(f.Fingerprint)
	if err != nil || !ok {
		t.Fatalf("Get: ok=%v err=%v", ok, err)
	}
	if e.Count != 1 || !e.FirstSeen.Equal(t0) || !e.LastSeen.Equal(t0) {
		t.Errorf("after first upsert: %+v", e)
	}

	if err := l.Upsert(t1, []contract.Finding{f}); err != nil {
		t.Fatalf("second Upsert: %v", err)
	}
	e, _, _ = l.Get(f.Fingerprint)
	if e.Count != 2 {
		t.Errorf("Count = %d, want 2", e.Count)
	}
	if !e.FirstSeen.Equal(t0) {
		t.Errorf("FirstSeen moved: %v, want %v (must be preserved)", e.FirstSeen, t0)
	}
	if !e.LastSeen.Equal(t1) {
		t.Errorf("LastSeen = %v, want %v", e.LastSeen, t1)
	}

	// persistence across reopen
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	l2, err := ledger.Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer l2.Close()
	e, ok, err = l2.Get(f.Fingerprint)
	if err != nil || !ok || e.Count != 2 {
		t.Errorf("after reopen: ok=%v err=%v entry=%+v", ok, err, e)
	}
}

func TestGetMissing(t *testing.T) {
	l, err := ledger.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	_, ok, err := l.Get("0000000000000000")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if ok {
		t.Error("ok = true for missing fingerprint")
	}
}

// MaxOpenConns(1) must serialize concurrent writers with no
// "database is locked" errors.
func TestConcurrentUpserts(t *testing.T) {
	l, err := ledger.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	f := testFinding(t)
	var wg sync.WaitGroup
	errs := make(chan error, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs <- l.Upsert(time.Unix(1752900000+int64(i), 0), []contract.Finding{f})
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("concurrent Upsert: %v", err)
		}
	}
	e, _, _ := l.Get(f.Fingerprint)
	if e.Count != 10 {
		t.Errorf("Count = %d, want 10", e.Count)
	}
}
```

- [ ] **Step 2: Run to verify it fails** — `go test ./internal/ledger/` → FAIL: package does not exist.

- [ ] **Step 3: Write minimal implementation** — `internal/ledger/ledger.go`:

```go
// Package ledger persists finding state in SQLite via modernc.org/sqlite
// (pure Go — keeps the release build CGO_ENABLED=0 and the static-binary
// guarantee; see ADR-G03). One writer connection; pragmas ride the DSN so
// every lazily opened connection is configured identically.
//
// Scope note: the ledger is WRITE-ONLY in this slice (insert/bump). State
// transitions, resolution, and findings GC arrive with the bridge/notifier
// slice — do not invent resolve semantics here.
package ledger

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite" // driver name "sqlite"

	"github.com/lazarevtill/heimdall/internal/contract"
)

const schemaVersion = 1

type Ledger struct{ db *sql.DB }

func Open(path string) (*Ledger, error) {
	dsn := "file:" + path +
		"?_pragma=journal_mode(WAL)" +
		"&_pragma=synchronous(NORMAL)" +
		"&_pragma=busy_timeout(5000)" +
		"&_pragma=foreign_keys(ON)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("ledger: open %s: %w", path, err)
	}
	// Single writer: eliminates SQLITE_BUSY under concurrency entirely.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	return &Ledger{db: db}, nil
}

func migrate(db *sql.DB) error {
	var v int
	if err := db.QueryRow("PRAGMA user_version").Scan(&v); err != nil {
		return fmt.Errorf("ledger: read user_version: %w", err)
	}
	if v >= schemaVersion {
		return nil
	}
	const schema = `
CREATE TABLE IF NOT EXISTS findings (
  fingerprint TEXT PRIMARY KEY,
  check_id    TEXT NOT NULL,
  target      TEXT NOT NULL,
  state       TEXT NOT NULL,
  severity    TEXT NOT NULL,
  first_seen  INTEGER NOT NULL,
  last_seen   INTEGER NOT NULL,
  count       INTEGER NOT NULL
);`
	if _, err := db.Exec(schema); err != nil {
		return fmt.Errorf("ledger: create schema: %w", err)
	}
	if _, err := db.Exec(fmt.Sprintf("PRAGMA user_version = %d", schemaVersion)); err != nil {
		return fmt.Errorf("ledger: set user_version: %w", err)
	}
	return nil
}

// Upsert records the run's findings: new fingerprints insert with count 1;
// recurring ones bump count and last_seen, preserving first_seen.
// Transactions stay short: diffing happens in Go, writes are one quick tx.
func (l *Ledger) Upsert(now time.Time, fs []contract.Finding) error {
	if len(fs) == 0 {
		return nil
	}
	tx, err := l.db.Begin()
	if err != nil {
		return fmt.Errorf("ledger: begin: %w", err)
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`
INSERT INTO findings (fingerprint, check_id, target, state, severity, first_seen, last_seen, count)
VALUES (?, ?, ?, ?, ?, ?, ?, 1)
ON CONFLICT(fingerprint) DO UPDATE SET
  state = excluded.state, severity = excluded.severity,
  last_seen = excluded.last_seen, count = count + 1`)
	if err != nil {
		return fmt.Errorf("ledger: prepare upsert: %w", err)
	}
	defer stmt.Close()
	ts := now.Unix()
	for _, f := range fs {
		if _, err := stmt.Exec(f.Fingerprint, f.Check, f.Target, f.State.String(), string(f.Severity), ts, ts); err != nil {
			return fmt.Errorf("ledger: upsert %s: %w", f.Fingerprint, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("ledger: commit: %w", err)
	}
	return nil
}

type Entry struct {
	Fingerprint, Check, Target, State, Severity string
	FirstSeen, LastSeen                         time.Time
	Count                                       int64
}

func (l *Ledger) Get(fp string) (Entry, bool, error) {
	var e Entry
	var first, last int64
	err := l.db.QueryRow(`SELECT fingerprint, check_id, target, state, severity, first_seen, last_seen, count
FROM findings WHERE fingerprint = ?`, fp).
		Scan(&e.Fingerprint, &e.Check, &e.Target, &e.State, &e.Severity, &first, &last, &e.Count)
	if err == sql.ErrNoRows {
		return Entry{}, false, nil
	}
	if err != nil {
		return Entry{}, false, fmt.Errorf("ledger: get %s: %w", fp, err)
	}
	e.FirstSeen = time.Unix(first, 0).UTC()
	e.LastSeen = time.Unix(last, 0).UTC()
	return e, true, nil
}

func (l *Ledger) Close() error { return l.db.Close() }
```

- [ ] **Step 4: Run tests** — `go test -race ./internal/ledger/` → PASS, including 10 concurrent upserts with zero lock errors (verified empirically).
- [ ] **Step 5: Commit** — `git add go.mod go.sum internal/ledger/ && git commit -m "feat(ledger): pure-Go SQLite state (WAL, single writer conn, user_version migration)"`

---

### Task 8: Emit — hand-written .prom (no state label), atomic write, redacted spool

**Files:**
- Create: `internal/emit/prom.go`, `internal/emit/atomic.go`, `internal/emit/spool.go`, `internal/emit/testdata/heimdall.prom.golden`
- Test: `internal/emit/prom_test.go`, `internal/emit/atomic_test.go`, `internal/emit/spool_test.go`

**Interfaces:**
- Produces:
  - `func RenderProm(now time.Time, fs []contract.Finding, redactionFailures int) []byte` — deterministic, no line timestamps, no `state` label, trailing newline; always emits `heimdall_redaction_failures_total` and the heartbeat
  - `func WriteFileAtomic(path string, data []byte) error` — temp-in-same-dir + fsync + rename + dir fsync
  - `func WriteSpool(dir string, fs []contract.Finding) (redactionFailures int, err error)` — one redacted `<fingerprint>.json` per finding, each written atomically

- [ ] **Step 1: Write the golden file** — `internal/emit/testdata/heimdall.prom.golden` (exact bytes, trailing newline; verified byte-identical to RenderProm output):

```
# HELP heimdall_finding Active Heimdall finding; 1 while firing or unknown.
# TYPE heimdall_finding gauge
heimdall_finding{check="c1-deadman",class="hard",fingerprint="d86c07b5a41742c1",group="backup-ds1",node="node-a",severity="critical",source="heimdall",target="backup:ds1/vm-100"} 1
heimdall_finding{check="c2-unit-failed",class="hard",fingerprint="34915542b733a584",group="node-a",node="node-a",severity="warning",source="heimdall",target="node-a"} 1
# HELP heimdall_redaction_failures_total Redaction failures during the last run; any nonzero value pages.
# TYPE heimdall_redaction_failures_total counter
heimdall_redaction_failures_total 0
# HELP heimdall_last_run_timestamp_seconds Unix time of the last completed detector run.
# TYPE heimdall_last_run_timestamp_seconds gauge
heimdall_last_run_timestamp_seconds{plane="tier1"} 1752900000
```

- [ ] **Step 2: Write the failing tests**

`internal/emit/prom_test.go`:

```go
package emit_test

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/lazarevtill/heimdall/internal/contract"
	"github.com/lazarevtill/heimdall/internal/emit"
)

var update = flag.Bool("update", false, "rewrite golden files (NEVER pass in CI)")

func mkFinding(t *testing.T, check, group, target, node string, sev contract.Severity, st contract.State) contract.Finding {
	t.Helper()
	f, err := contract.NewFinding(time.Unix(1752900000, 0).UTC(), contract.FindingSpec{
		Check: check, Group: group, Target: target, Node: node,
		Severity: sev, Class: contract.ClassHard, State: st, Title: "t", Evidence: "e",
	})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func fixture(t *testing.T) []contract.Finding {
	// deliberately out of sorted order: RenderProm must sort
	return []contract.Finding{
		mkFinding(t, "c2-unit-failed", "node-a", "node-a", "node-a", contract.SeverityWarning, contract.StateUnknown),
		mkFinding(t, "c1-deadman", "backup-ds1", "backup:ds1/vm-100", "node-a", contract.SeverityCritical, contract.StateFiring),
	}
}

func TestRenderPromGolden(t *testing.T) {
	got := emit.RenderProm(time.Unix(1752900000, 0).UTC(), fixture(t), 0)
	golden := filepath.Join("testdata", "heimdall.prom.golden")
	if *update {
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(string(want), string(got)); diff != "" {
		t.Errorf("rendered .prom differs from golden (-want +got):\n%s", diff)
	}
}

// Series identity must not change on firing<->unknown transitions: the
// finding sample line has NO state label (state lives in the spool doc).
func TestRenderPromHasNoStateLabel(t *testing.T) {
	out := string(emit.RenderProm(time.Unix(1752900000, 0).UTC(), fixture(t), 0))
	if strings.Contains(out, "state=") {
		t.Errorf("state label leaked into wire label set (breaks sticky series identity):\n%s", out)
	}
}

// A nonzero redaction-failure count must surface in the rendered body —
// a broken redactor pages, it never silently withholds forever.
func TestRenderPromRedactionFailureCounter(t *testing.T) {
	out := string(emit.RenderProm(time.Unix(1752900000, 0).UTC(), nil, 3))
	if !strings.Contains(out, "heimdall_redaction_failures_total 3\n") {
		t.Errorf("redaction failure counter missing or wrong:\n%s", out)
	}
}

// A single stray line-level timestamp makes node_exporter discard the
// ENTIRE file. Every sample line must be `name{labels} value` or
// `name value` — nothing after the value.
func TestRenderPromNeverEmitsLineTimestamps(t *testing.T) {
	out := string(emit.RenderProm(time.Unix(1752900000, 0).UTC(), fixture(t), 0))
	for _, line := range strings.Split(out, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		rest := line
		if i := strings.Index(line, "{"); i >= 0 {
			j := strings.LastIndex(line, "}")
			if j < i {
				t.Errorf("malformed sample line: %q", line)
				continue
			}
			rest = line[:i] + line[j+1:]
		}
		if fields := strings.Fields(rest); len(fields) != 2 {
			t.Errorf("sample line is not exactly `name value` after label strip (timestamp?): %q", line)
		}
	}
}

func TestRenderPromTrailingNewline(t *testing.T) {
	out := emit.RenderProm(time.Unix(1752900000, 0).UTC(), fixture(t), 0)
	if !bytes.HasSuffix(out, []byte("\n")) {
		t.Error("output must end with a newline (parsers reject files without it)")
	}
	if bytes.HasSuffix(out, []byte("\n\n")) {
		t.Error("output must not end with a blank line")
	}
}

func TestRenderPromEscapesLabelValues(t *testing.T) {
	f := mkFinding(t, "c1-deadman", "g", `a\b"c`+"\n"+`d`, "n", contract.SeverityInfo, contract.StateFiring)
	out := string(emit.RenderProm(time.Unix(1752900000, 0).UTC(), []contract.Finding{f}, 0))
	if !strings.Contains(out, `target="a\\b\"c\nd"`) {
		t.Errorf("label value not escaped per exposition format:\n%s", out)
	}
}
```

`internal/emit/atomic_test.go` (root-proof failure injection — chmod does NOT block root):

```go
package emit_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/lazarevtill/heimdall/internal/emit"
)

func TestWriteFileAtomicRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "heimdall.prom")
	if err := emit.WriteFileAtomic(path, []byte("v1\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := emit.WriteFileAtomic(path, []byte("v2\n")); err != nil {
		t.Fatalf("overwrite: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "v2\n" {
		t.Errorf("content = %q err=%v, want v2", got, err)
	}
	// no temp turds left behind
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("dir has %d entries, want 1 (no orphaned temp files)", len(entries))
	}
}

// Root-proof failure injection #1: the temp-create step fails when the
// parent "directory" is a regular file (ENOTDIR ignores CAP_DAC_OVERRIDE).
func TestWriteFileAtomicCreateFailure(t *testing.T) {
	dir := t.TempDir()
	notdir := filepath.Join(dir, "plainfile")
	if err := os.WriteFile(notdir, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := emit.WriteFileAtomic(filepath.Join(notdir, "heimdall.prom"), []byte("v\n")); err == nil {
		t.Fatal("want error when parent is not a directory, got nil")
	}
}

// Root-proof failure injection #2: rename over an existing DIRECTORY fails
// even as root; the destination must be untouched and the temp cleaned up.
func TestWriteFileAtomicRenameFailureLeavesDestinationAndNoTurds(t *testing.T) {
	dir := t.TempDir()
	occupied := filepath.Join(dir, "occupied")
	if err := os.Mkdir(occupied, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := emit.WriteFileAtomic(occupied, []byte("v\n")); err == nil {
		t.Fatal("want rename error when destination is a directory, got nil")
	}
	fi, err := os.Stat(occupied)
	if err != nil || !fi.IsDir() {
		t.Errorf("destination was disturbed: fi=%v err=%v", fi, err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("dir has %d entries, want 1 (temp file must be removed on failure)", len(entries))
	}
}

// Old-file-intact under a mid-write failure. chmod-based injection does not
// work as root (CAP_DAC_OVERRIDE), so this variant is skipped there; the
// two root-proof variants above still exercise the failure path in CI.
func TestWriteFileAtomicFailureLeavesOldFileIntact(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions (CAP_DAC_OVERRIDE)")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "heimdall.prom")
	if err := emit.WriteFileAtomic(path, []byte("old\n")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o755) })
	if err := emit.WriteFileAtomic(path, []byte("new\n")); err == nil {
		t.Fatal("want error on read-only dir, got nil")
	}
	os.Chmod(dir, 0o755)
	got, _ := os.ReadFile(path)
	if string(got) != "old\n" {
		t.Errorf("old file clobbered: %q", got)
	}
}
```

`internal/emit/spool_test.go`:

```go
package emit_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lazarevtill/heimdall/internal/contract"
	"github.com/lazarevtill/heimdall/internal/emit"
)

// The egress boundary: the spool write must be redacted. The defanged
// glpat-shaped token must never reach disk.
func TestWriteSpoolRedactsSecrets(t *testing.T) {
	dir := t.TempDir()
	f, err := contract.NewFinding(time.Unix(1752900000, 0).UTC(), contract.FindingSpec{
		Check: "c4-signature", Group: "node-a", Target: "node-a", Node: "node-a",
		Severity: contract.SeverityWarning, Class: contract.ClassHard,
		State: contract.StateFiring, Title: "token in journal",
		Evidence: "found glpat-EXAMPLEexample12345678 in unit log",
	})
	if err != nil {
		t.Fatal(err)
	}
	failures, err := emit.WriteSpool(dir, []contract.Finding{f})
	if err != nil {
		t.Fatalf("WriteSpool: %v", err)
	}
	if failures != 0 {
		t.Errorf("redactionFailures = %d for healthy redaction, want 0", failures)
	}
	doc, err := os.ReadFile(filepath.Join(dir, f.Fingerprint+".json"))
	if err != nil {
		t.Fatalf("read spool doc: %v", err)
	}
	if strings.Contains(string(doc), "glpat-EXAMPLEexample12345678") {
		t.Error("defanged token leaked into spool doc")
	}
	if !strings.Contains(string(doc), "[REDACTED:gitlab-pat]") {
		t.Error("redaction marker missing from spool doc")
	}
	if !strings.Contains(string(doc), `"fingerprint": "`+f.Fingerprint+`"`) {
		t.Error("spool doc missing fingerprint field")
	}
	// state was removed from the wire label set; it MUST live in the doc
	if !strings.Contains(string(doc), `"state": "firing"`) {
		t.Error("spool doc missing state field (state is doc-only, not a metric label)")
	}
}
```

- [ ] **Step 3: Run to verify they fail** — `go test ./internal/emit/` → FAIL: package does not exist.

- [ ] **Step 4: Write minimal implementation**

`internal/emit/prom.go`:

```go
// Package emit writes Heimdall's outputs: the node_exporter textfile
// (hand-written exposition format — see ADR-G04) and the redacted finding
// spool. All writes are atomic whole-file replacements.
//
// Whole-file replacement is load-bearing beyond atomicity: it is what
// retires stale series when a finding disappears between runs. An
// append/partial writer would leave dead series serving forever — do not
// "optimize" this into partial writes.
package emit

import (
	"bytes"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lazarevtill/heimdall/internal/contract"
)

// HELP text must be defined in exactly one place and stay byte-identical:
// inconsistent HELP across .prom files poisons node_exporter's scrape.
const (
	helpFinding = "# HELP heimdall_finding Active Heimdall finding; 1 while firing or unknown.\n" +
		"# TYPE heimdall_finding gauge\n"
	helpRedaction = "# HELP heimdall_redaction_failures_total Redaction failures during the last run; any nonzero value pages.\n" +
		"# TYPE heimdall_redaction_failures_total counter\n"
	helpLastRun = "# HELP heimdall_last_run_timestamp_seconds Unix time of the last completed detector run.\n" +
		"# TYPE heimdall_last_run_timestamp_seconds gauge\n"
)

// Exposition format escapes for label values: backslash, quote, newline.
var labelEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)

// lv routes every label value through the redactor (uniform every-egress
// redaction), then escapes it per the exposition format.
func lv(s string) string { return labelEscaper.Replace(contract.Redact(s)) }

// RenderProm renders the full textfile body. Deterministic: findings sorted
// by (check, target), labels in fixed alphabetical order. NEVER emits
// line-level timestamps (node_exporter discards the whole file); freshness
// is the heimdall_last_run_timestamp_seconds sample VALUE.
//
// State is deliberately NOT a label: the wire label set is frozen as
// {check, class, fingerprint, group, node, severity, source, target} so a
// firing<->unknown transition keeps series identity (no stale-series
// resolve, no manufactured all-clear). State lives in the spool doc.
func RenderProm(now time.Time, fs []contract.Finding, redactionFailures int) []byte {
	sorted := make([]contract.Finding, len(fs))
	copy(sorted, fs)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Check != sorted[j].Check {
			return sorted[i].Check < sorted[j].Check
		}
		return sorted[i].Target < sorted[j].Target
	})
	var b bytes.Buffer
	b.WriteString(helpFinding)
	for _, f := range sorted {
		b.WriteString(`heimdall_finding{check="` + lv(f.Check) +
			`",class="` + lv(string(f.Class)) +
			`",fingerprint="` + lv(f.Fingerprint) +
			`",group="` + lv(f.Group) +
			`",node="` + lv(f.Node) +
			`",severity="` + lv(string(f.Severity)) +
			`",source="heimdall",target="` + lv(f.Target) + `"} 1` + "\n")
	}
	b.WriteString(helpRedaction)
	b.WriteString("heimdall_redaction_failures_total " + strconv.Itoa(redactionFailures) + "\n")
	b.WriteString(helpLastRun)
	b.WriteString(`heimdall_last_run_timestamp_seconds{plane="tier1"} ` +
		strconv.FormatInt(now.Unix(), 10) + "\n")
	return b.Bytes()
}
```

`internal/emit/atomic.go`:

```go
package emit

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteFileAtomic replaces path with data atomically: temp file in the SAME
// directory (rename is atomic only within one filesystem), write, fsync,
// chmod 0644, close, rename, then best-effort fsync of the parent directory
// so the rename survives a crash. On any failure the previous file is
// untouched and the temp file is removed.
func WriteFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("emit: create temp in %s: %w", dir, err)
	}
	tmp := f.Name()
	committed := false
	defer func() {
		if !committed {
			f.Close()
			os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("emit: write %s: %w", tmp, err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("emit: fsync %s: %w", tmp, err)
	}
	if err := f.Chmod(0o644); err != nil {
		return fmt.Errorf("emit: chmod %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("emit: close %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("emit: rename %s over %s: %w", tmp, path, err)
	}
	committed = true
	if d, err := os.Open(dir); err == nil { // durability of the rename itself
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
```

`internal/emit/spool.go`:

```go
package emit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/lazarevtill/heimdall/internal/contract"
)

// WriteSpool writes one redacted <fingerprint>.json per finding. This is
// the mandatory egress boundary: Title and Evidence pass through the
// fail-closed redactor before touching disk. The returned count is the
// number of redaction FAILURES (content withheld); the caller must surface
// it as heimdall_redaction_failures_total so a broken redactor pages
// instead of silently withholding evidence forever.
func WriteSpool(dir string, fs []contract.Finding) (redactionFailures int, err error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return redactionFailures, fmt.Errorf("emit: spool dir %s: %w", dir, err)
	}
	for _, f := range fs {
		var failed bool
		f.Title, failed = contract.EvidenceOrWithheld(f.Title)
		if failed {
			redactionFailures++
		}
		f.Evidence, failed = contract.EvidenceOrWithheld(f.Evidence)
		if failed {
			redactionFailures++
		}
		doc, err := json.MarshalIndent(f, "", "  ")
		if err != nil {
			return redactionFailures, fmt.Errorf("emit: marshal finding %s: %w", f.Fingerprint, err)
		}
		path := filepath.Join(dir, f.Fingerprint+".json")
		if err := WriteFileAtomic(path, append(doc, '\n')); err != nil {
			return redactionFailures, err
		}
	}
	return redactionFailures, nil
}
```

- [ ] **Step 5: Run tests** — `go test -race ./internal/emit/` → PASS; golden byte-identical (verified). If a legitimate format change is ever needed, inspect the diff by eye, run once with `-update`, re-verify — CI never passes `-update`.
- [ ] **Step 6: Commit** — `git add internal/emit/ && git commit -m "feat(emit): stateless-label textfile exposition, atomic tmp+fsync+rename, redacted spool with failure counting"`

---

### Task 9: Config

**Files:**
- Create: `internal/config/config.go`
- Test: `internal/config/config_test.go`

**Interfaces:**
- Produces:
  - `type Config struct { ManifestPath, TextfileDir, SpoolDir, StateDBPath, PromURL string; QueryLimit int; Credentials map[string]string }`
  - `func Load(getenv func(string) string) (Config, error)`
- `Credentials` is parsed but unconsumed in this slice (first consumer: VictoriaLogs source, next slice) — keep it that way.

- [ ] **Step 1: Write the failing test** — `internal/config/config_test.go`:

```go
package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/lazarevtill/heimdall/internal/config"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func fullEnv() map[string]string {
	return map[string]string{
		"HEIMDALL_MANIFEST":     "/etc/heimdall/manifest.json",
		"HEIMDALL_TEXTFILE_DIR": "/var/lib/textfile",
		"HEIMDALL_SPOOL_DIR":    "/var/lib/heimdall/findings",
		"HEIMDALL_STATE_DB":     "/var/lib/heimdall/state.db",
		"HEIMDALL_PROM_URL":     "http://127.0.0.1:9090",
	}
}

func TestLoadValid(t *testing.T) {
	c, err := config.Load(env(fullEnv()))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.QueryLimit != 8 {
		t.Errorf("QueryLimit default = %d, want 8", c.QueryLimit)
	}
	if c.PromURL != "http://127.0.0.1:9090" {
		t.Errorf("PromURL = %q", c.PromURL)
	}
}

func TestLoadFailsFastOnMissing(t *testing.T) {
	for _, missing := range []string{"HEIMDALL_MANIFEST", "HEIMDALL_TEXTFILE_DIR",
		"HEIMDALL_SPOOL_DIR", "HEIMDALL_STATE_DB", "HEIMDALL_PROM_URL"} {
		t.Run(missing, func(t *testing.T) {
			m := fullEnv()
			delete(m, missing)
			if _, err := config.Load(env(m)); err == nil {
				t.Fatalf("want error when %s missing, got nil", missing)
			}
		})
	}
}

func TestLoadRejectsBadLimit(t *testing.T) {
	m := fullEnv()
	m["HEIMDALL_QUERY_LIMIT"] = "zero"
	if _, err := config.Load(env(m)); err == nil {
		t.Fatal("want error for non-integer limit")
	}
}

func TestLoadCredFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "creds.env")
	if err := os.WriteFile(p, []byte("# vault-seeded, one least-privilege credential\nVL_TOKEN=defanged-not-a-real-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := fullEnv()
	m["HEIMDALL_CRED_FILE"] = p
	c, err := config.Load(env(m))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Credentials["VL_TOKEN"] != "defanged-not-a-real-token" {
		t.Errorf("Credentials = %v", c.Credentials)
	}
	m["HEIMDALL_CRED_FILE"] = filepath.Join(t.TempDir(), "missing.env")
	if _, err := config.Load(env(m)); err == nil {
		t.Fatal("want error for unreadable cred file (fail fast)")
	}
}
```

- [ ] **Step 2: Run to verify it fails** — `go test ./internal/config/` → FAIL: package does not exist.

- [ ] **Step 3: Write minimal implementation** — `internal/config/config.go`:

```go
// Package config loads detector configuration: environment variables first,
// plus an optional Vault-seeded KEY=VALUE credential file holding the one
// least-privilege token. Fail fast, no package-level state.
//
// Scope note: Credentials is parsed and validated here but has no consumer
// in this slice — its first consumer is the VictoriaLogs source (vmauth
// token) in the next slice. Do not wire it anywhere else prematurely.
package config

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	ManifestPath string
	TextfileDir  string
	SpoolDir     string
	StateDBPath  string
	PromURL      string
	QueryLimit   int
	Credentials  map[string]string
}

// Load reads config through the supplied getenv (os.Getenv in main;
// a map lookup in tests).
func Load(getenv func(string) string) (Config, error) {
	c := Config{
		ManifestPath: getenv("HEIMDALL_MANIFEST"),
		TextfileDir:  getenv("HEIMDALL_TEXTFILE_DIR"),
		SpoolDir:     getenv("HEIMDALL_SPOOL_DIR"),
		StateDBPath:  getenv("HEIMDALL_STATE_DB"),
		PromURL:      getenv("HEIMDALL_PROM_URL"),
		QueryLimit:   8,
	}
	required := []struct{ name, val string }{
		{"HEIMDALL_MANIFEST", c.ManifestPath},
		{"HEIMDALL_TEXTFILE_DIR", c.TextfileDir},
		{"HEIMDALL_SPOOL_DIR", c.SpoolDir},
		{"HEIMDALL_STATE_DB", c.StateDBPath},
		{"HEIMDALL_PROM_URL", c.PromURL},
	}
	for _, r := range required {
		if r.val == "" {
			return Config{}, fmt.Errorf("config: %s is required", r.name)
		}
	}
	if v := getenv("HEIMDALL_QUERY_LIMIT"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return Config{}, fmt.Errorf("config: HEIMDALL_QUERY_LIMIT %q must be a positive integer", v)
		}
		c.QueryLimit = n
	}
	if path := getenv("HEIMDALL_CRED_FILE"); path != "" {
		creds, err := loadEnvFile(path)
		if err != nil {
			return Config{}, fmt.Errorf("config: credential file: %w", err)
		}
		c.Credentials = creds
	}
	return c, nil
}

func loadEnvFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := make(map[string]string)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("malformed line %q in %s", line, path)
		}
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return out, sc.Err()
}
```

- [ ] **Step 4: Run tests** — `go test -race ./internal/config/` → PASS.
- [ ] **Step 5: Commit** — `git add internal/config/ && git commit -m "feat(config): env + vault-seeded cred file, fail-fast validation"`

---

### Task 10: cmd/heimdall-detect wiring + end-to-end test + meta alert rules

**Files:**
- Create: `cmd/heimdall-detect/main.go`, `deploy/alerts/heimdall-meta.rules.yml`
- Test: `cmd/heimdall-detect/main_test.go`

**Interfaces:**
- Produces: binary `bin/heimdall-detect`; `func run() error` (tested end-to-end); the alerts-that-watch-the-watcher rules file.

- [ ] **Step 1: Write the failing end-to-end test** — `cmd/heimdall-detect/main_test.go`:

```go
package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// End-to-end: manifest -> engine -> ledger -> spool -> atomic .prom,
// against an httptest Prometheus stand-in. The dead-man target has no
// fresh success, so the run must produce a firing finding.
func TestRunEndToEnd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// stale success timestamp -> dead-man fires; threshold query returns 0
		if strings.Contains(r.URL.RawQuery, "backup_last_success") {
			w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[1752900000,"1752800000"]}]}}`))
			return
		}
		w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[1752900000,"0"]}]}}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(manifestPath, []byte(`{
	  "generated_at": "2026-07-19T00:00:00Z",
	  "expectations": [
	    {"id":"backup-vm-100","check":"c1-deadman","group":"backup-ds1","target":"backup:ds1/vm-100","node":"node-a",
	     "grace_seconds":3600,"severity_on_miss":"critical",
	     "verify":{"backend":"prometheus","query":"max(backup_last_success_timestamp_seconds)"}},
	    {"id":"unit-failures-node-a","check":"c4-signature","group":"node-a","target":"node-a","node":"node-a",
	     "severity_on_miss":"warning",
	     "verify":{"backend":"prometheus","query":"sum(node_systemd_units)","min_count":1}}
	  ]}`), 0o644); err != nil {
		t.Fatal(err)
	}

	textfileDir := filepath.Join(dir, "textfile")
	if err := os.MkdirAll(textfileDir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HEIMDALL_MANIFEST", manifestPath)
	t.Setenv("HEIMDALL_TEXTFILE_DIR", textfileDir)
	t.Setenv("HEIMDALL_SPOOL_DIR", filepath.Join(dir, "findings"))
	t.Setenv("HEIMDALL_STATE_DB", filepath.Join(dir, "state.db"))
	t.Setenv("HEIMDALL_PROM_URL", srv.URL)

	if err := run(); err != nil {
		t.Fatalf("run: %v", err)
	}

	prom, err := os.ReadFile(filepath.Join(textfileDir, "heimdall.prom"))
	if err != nil {
		t.Fatalf("no heimdall.prom written: %v", err)
	}
	if !strings.Contains(string(prom), `check="c1-deadman"`) ||
		!strings.Contains(string(prom), `fingerprint="d86c07b5a41742c1"`) {
		t.Errorf("dead-man finding missing from .prom:\n%s", prom)
	}
	if strings.Contains(string(prom), "state=") {
		t.Errorf("state label leaked into wire label set:\n%s", prom)
	}
	if !strings.Contains(string(prom), "heimdall_last_run_timestamp_seconds") {
		t.Error("heartbeat sample missing")
	}
	if !strings.Contains(string(prom), "heimdall_redaction_failures_total 0") {
		t.Error("redaction failure counter missing")
	}
	// spool doc exists for the firing fingerprint and carries the state
	doc, err := os.ReadFile(filepath.Join(dir, "findings", "d86c07b5a41742c1.json"))
	if err != nil {
		t.Fatalf("spool doc missing: %v", err)
	}
	if !strings.Contains(string(doc), `"state": "firing"`) {
		t.Errorf("spool doc missing firing state:\n%s", doc)
	}
}
```

- [ ] **Step 2: Run to verify it fails** — `go test ./cmd/heimdall-detect/` → FAIL: `undefined: run`.

- [ ] **Step 3: Implement main** — `cmd/heimdall-detect/main.go`:

```go
// Command heimdall-detect is the Tier-1 detector oneshot: load config and
// manifest, run checks against sources, upsert the ledger, write the
// redacted spool, then atomically replace heimdall.prom. Intended to be
// invoked by a systemd timer (RuntimeMaxSec backstop in the unit).
//
// main is thin by design: flags/env, wiring, one call into internal/.
// This file contains the ONLY time.Now() in the program.
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/lazarevtill/heimdall/internal/config"
	"github.com/lazarevtill/heimdall/internal/detect"
	"github.com/lazarevtill/heimdall/internal/emit"
	"github.com/lazarevtill/heimdall/internal/ledger"
	"github.com/lazarevtill/heimdall/internal/manifest"
	"github.com/lazarevtill/heimdall/internal/source"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "heimdall-detect:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}
	m, err := manifest.Load(cfg.ManifestPath)
	if err != nil {
		return err
	}
	led, err := ledger.Open(cfg.StateDBPath)
	if err != nil {
		return err
	}
	defer led.Close()

	sources := map[string]source.Source{
		"prometheus": source.NewProm(cfg.PromURL, nil),
	}
	checks := map[string]detect.Check{
		"c1-deadman":   detect.DeadMan,
		"c4-signature": detect.Threshold,
	}
	eng := detect.New(sources, checks, cfg.QueryLimit)

	// 240s in-process soft deadline; the systemd unit's RuntimeMaxSec=300
	// is the backstop. In-flight queries past the deadline degrade to
	// Unknown findings via the source error path.
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()

	now := time.Now().UTC() // the only time.Now() in the program
	findings := eng.Run(ctx, now, m)

	if err := led.Upsert(now, findings); err != nil {
		return err
	}
	// Spool docs first, then the atomic .prom (docs must exist before the
	// series that references them can fire). If anything above failed we
	// exited non-zero WITHOUT touching the old .prom: the heartbeat stays
	// withheld and the staleness meta-rule (deploy/alerts/) reports us —
	// a failed run can never look like a clean one.
	redactionFailures, err := emit.WriteSpool(cfg.SpoolDir, findings)
	if err != nil {
		return err
	}
	return emit.WriteFileAtomic(
		filepath.Join(cfg.TextfileDir, "heimdall.prom"),
		emit.RenderProm(now, findings, redactionFailures),
	)
}
```

- [ ] **Step 4: Run tests** — `go test -race ./cmd/...` → PASS.

- [ ] **Step 5: Ship the alerts that watch the watcher** — `deploy/alerts/heimdall-meta.rules.yml`:

```yaml
# Heimdall meta-rules: the alerts that watch the watcher. Until these are
# applied to Prometheus via the IaC alerts path, a crashed detector is NOT
# alertable — deploying this file is part of the detector slice, not
# optional polish.
groups:
  - name: heimdall-meta
    rules:
      - alert: HeimdallDetectorStale
        expr: time() - heimdall_last_run_timestamp_seconds{plane="tier1"} > 900
        labels:
          severity: critical
          source: heimdall-meta
        annotations:
          summary: "Heimdall detector has not completed a run in 15m"
          description: "The heartbeat gauge stopped advancing: the detector is crashing, hanging, or failing before its atomic .prom write (which deliberately withholds the heartbeat on failure)."
      - alert: HeimdallDetectorAbsent
        expr: absent(heimdall_last_run_timestamp_seconds{plane="tier1"})
        labels:
          severity: critical
          source: heimdall-meta
        annotations:
          summary: "Heimdall heartbeat series is absent"
          description: "Bootstrap gap, deleted textfile, or node_exporter rejected the .prom file (e.g. stray line timestamp). Absence is never treated as ok."
      - alert: HeimdallRedactionFailure
        expr: heimdall_redaction_failures_total > 0
        labels:
          severity: critical
          source: heimdall-meta
        annotations:
          summary: "Heimdall redaction failed during the last run"
          description: "Evidence was withheld (content-fail-closed). A broken redactor must page — it can never silently withhold forever."
```

Applying this file through the existing IaC alerts path is a deploy step of this slice; until it is applied, record in the MR description that the detector is not yet crash-alertable.

- [ ] **Step 6: Commit** — `git add cmd/ deploy/ && git commit -m "feat(detect-cmd): wire manifest->engine->ledger->spool->atomic prom; ship meta alert rules"`

---

### Task 11: Policy test + Makefile gates + CI

**Files:**
- Create: `policy_test.go` (module root), `Makefile`, `.gitlab-ci.yml`

- [ ] **Step 1: Write the dependency-budget test** — `policy_test.go` (module root — it guards go.mod, not any one package):

```go
// Repo-policy tests live at the module root — they guard go.mod, not any
// one package.
package heimdall

import (
	"os"
	"strings"
	"testing"
)

// The recorded dependency budget (ADR-G02). Adding a direct dependency
// requires amending the ADR first, then this list. This test doubles as the
// CI guard against mattn/go-sqlite3 (cgo) ever reappearing.
var allowedDirect = map[string]bool{
	"golang.org/x/sync":        true,
	"modernc.org/sqlite":       true,
	"github.com/google/go-cmp": true, // tests only
}

func TestDependencyBudget(t *testing.T) {
	data, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	inBlock := false
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case line == "require (":
			inBlock = true
			continue
		case inBlock && line == ")":
			inBlock = false
			continue
		}
		var entry string
		if inBlock {
			entry = line
		} else if strings.HasPrefix(line, "require ") {
			entry = strings.TrimPrefix(line, "require ")
		} else {
			continue
		}
		if strings.Contains(entry, "// indirect") {
			continue
		}
		fields := strings.Fields(entry)
		if len(fields) < 2 {
			continue
		}
		if !allowedDirect[fields[0]] {
			t.Errorf("direct dependency %q is outside the recorded budget; amend ADR-G02 before go.mod", fields[0])
		}
	}
}
```

Verify it guards: temporarily append `require github.com/stretchr/testify v1.9.0` to go.mod → `go test -run TestDependencyBudget ./` must FAIL; revert.

- [ ] **Step 2: Makefile** (verified: every gate catches a planted violation; the time.Now grep filters comment mentions; the Finding-literal grep excepts `[]contract.Finding{` slice types; the leak greps are chosen so the public module path `lazarevtill` can never false-positive):

```make
GO ?= go

.PHONY: build test lint vuln ci

# CGO_ENABLED=0 is a property of the RELEASE BUILD (static binary); tests
# run with cgo enabled because `go test -race` requires it (ADR-G14).
build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="-s -w" -o bin/heimdall-detect ./cmd/heimdall-detect

test:
	CGO_ENABLED=1 $(GO) test -race ./...

lint:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed on:"; echo "$$out"; exit 1; fi
	$(GO) vet ./...
	@if grep -rn --include='*.go' 'time\.Now()' internal/ | grep -v '//.*time\.Now()'; then \
		echo "time.Now() in internal/ is banned: inject now (ADR-G10)"; exit 1; fi
	@if grep -rn --include='*.go' 'contract\.Finding{' cmd/ internal/ | grep -v '^internal/contract/' \
		| sed 's/\[\]contract\.Finding{//g' | grep 'contract\.Finding{'; then \
		echo "contract.Finding literals outside internal/contract are banned: use NewFinding (ADR-G09)"; exit 1; fi
	@if git grep -nE '192\.168\.|lazarev\.cloud|pbsHGST' -- ':!Makefile'; then \
		echo "real-infrastructure string leaked into the public repo"; exit 1; fi
	@if git grep -nE 'glpat-[A-Za-z0-9_-]{20,}' -- ':!Makefile' ':!internal/contract/redact.go' ':!*_test.go'; then \
		echo "secret-shaped token outside the defanged test fixtures"; exit 1; fi
	$(GO) mod verify

# pinned: bump deliberately, never @latest (reproducible CI)
vuln:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...

ci: lint test build vuln
```

- [ ] **Step 3: CI** — `.gitlab-ci.yml` (image matches the go 1.25 directive; a mismatched older image would silently download a different toolchain every run):

```yaml
stages: [check]

go-checks:
  stage: check
  image: golang:1.25
  script:
    - make ci
```

- [ ] **Step 4: Run the full gate** — `make ci` → gofmt clean, vet clean, four custom gates silent, all tests PASS under `-race`, static binary at `bin/heimdall-detect` (verify: `file bin/heimdall-detect` → `statically linked`), `govulncheck@v1.6.0` → `No vulnerabilities found` (all verified on the reference tree).

- [ ] **Step 5: Negative-test the gates** (each verified to catch its violation):
  - plant `var sneaky = time.Now()` in an internal file → `make lint` fails; remove.
  - plant `var sneaky = contract.Finding{}` in cmd/ → `make lint` fails; remove.
  - plant `// lazarev.cloud` in a tracked file → `make lint` fails; remove.
  - plant a testify require in go.mod → `go test -run TestDependencyBudget ./` fails; revert.

- [ ] **Step 6: Commit** — `git add policy_test.go Makefile .gitlab-ci.yml && git commit -m "chore(ci): release-build CGO_ENABLED=0, race tests, four policy gates, pinned govulncheck"`

---

## Self-Review Checklist (run after Task 11)

- [ ] `make ci` green end to end; `file bin/heimdall-detect` reports `statically linked`.
- [ ] Trust-invariant regression locks present and passing: `TestPromFailureMatrixIsNeverSilentOK`, `TestRunSourceErrorIsUnknownAndDoesNotBlankSiblings`, `TestRunCheckPanicIsUnknownAndDoesNotBlankSiblings`, `TestRenderPromNeverEmitsLineTimestamps`, `TestRenderPromHasNoStateLabel`, `TestRenderPromRedactionFailureCounter`, `TestWriteFileAtomicRenameFailureLeavesDestinationAndNoTurds`, `TestNewFinding/hypothesis_refused`, `TestNewFinding/trend_capped_at_warning`, `TestEvidenceOrWithheldFailsClosedAndReports`, `TestWriteSpoolRedactsSecrets`.
- [ ] Golden vectors unchanged: `d86c07b5a41742c1`, `34915542b733a584`, `296c533b31dd957e`, `5aab268a9c139079`.
- [ ] `deploy/alerts/heimdall-meta.rules.yml` committed AND an MR/step exists to apply it via the IaC alerts path (until applied: detector is documented not crash-alertable).
- [ ] `make lint`'s leak greps pass on the clean tree (they are pattern-safe against the module path) — do not weaken them; they run on every CI, not just at review time.

---

## Next Go slices (handoff — not planned here)

1. **Bridge/notifier:** consumes the ledger + spool; state transitions (sticky-on-unknown, resolve semantics), findings GC (30d), Alertmanager/webhook delivery. This is where `send_resolved` policy and the ledger's read path get built.
2. **VictoriaLogs + PBS sources:** second and third `source.Source` implementations; first consumer of `config.Credentials` (vmauth token). Add `heimdall_check_last_success_timestamp_seconds{check}` per-family gauges here.
3. **Analyst (LLM plane):** reads spool docs only; structurally cannot mint findings (`ErrHypothesisRefused` + literal-ban gate already guarantee it).
4. **Plugin host:** extract `source.Source` over the subprocess FetchPlan/SignalSet ABI — the interface shape was chosen so this is a transport change.
5. **Repo hygiene for the public mirror:** README + LICENSE, promtool/expfmt advisory round-trip check in CI, systemd unit + IaC delivery of the binary, manifest, and alert rules.
