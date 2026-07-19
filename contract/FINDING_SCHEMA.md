# FINDING_SCHEMA

The wire contract for everything that can page, plus the explicitly separate
advisory HYPOTHESIS surface. Go types + enforcement: `internal/contract`.

## Finding
`NewFinding` is the ONLY sanctioned constructor (a `make lint` gate bans
`contract.Finding{}` literals elsewhere), so the class‑cap table cannot be bypassed.

`{schema_version, fingerprint, check, group, target, node, severity, class, state, title, evidence, observed_at}`

- **severity** ∈ `info | warning | critical` (single enum).
- **class** ∈ `hard | trend | hypothesis`. `trend` is **capped at `warning` in code**
  (Tier‑2 can never page); `hypothesis` is **refused by `NewFinding`** entirely
  (`ErrHypothesisRefused`) — the LLM plane structurally cannot reach the finding path (G1).
- **state** ∈ `unknown | ok | firing`, zero value `unknown` (fail‑closed). State lives in
  the doc only — **never a metric label** — so `firing ↔ unknown` never changes series identity.
- **fingerprint** = `hex(sha256(check + "|" + target))[:16]`; `check` may not contain `|`.

## Wire labels (`.prom`)
Frozen: `{source="heimdall", check, class, fingerprint, group, node, severity, target}` — value `1`,
no `state` label, no per‑line timestamps.

## Marker grammar
`[hb:<key>]`, key `^[a-z0-9-]{1,64}$` (colons banned). Issue key = `<group>--<check>`;
hypothesis key = `t3-<hyp_fp>`.

## Metric naming
`heimdall_last_run_timestamp_seconds{plane}`, `heimdall_digest_generated_timestamp_seconds`,
`heimdall_analyst_last_success_timestamp_seconds`, `heimdall_check_last_success_timestamp_seconds{check}`,
plus counters incl. `heimdall_digest_rows_truncated_total` and `heimdall_redaction_failures_total`
(nonzero **pages**).

## HYPOTHESIS section (Tier‑3 advisory — never pages)
The analyst emits `AnalystOutput` (strict `json_schema` from llama.cpp); the wrapper turns it
into an `AnalystRun` and POSTs to the bridge `/hypothesis` seam — the ONLY hypothesis transport.

`HypothesisFinding` = `{kind, targets[], hypothesis(≤500), confidence, evidence_rows[], suggested_queries[], suggested_check?, fingerprint}`
- **kind** ∈ `trend | anomaly | correlation | degradation`; **confidence** ∈ `low | medium | high`
  (out‑of‑vocabulary values are dropped, never coerced).
- **evidence_rows** are digest `row_id`s — the only machine‑stable handle. A finding citing a
  `row_id` absent from the digest is a checkable hallucination: **dropped + counted**.
- **suggested_check** is MR fodder only and is **never applied**.
- **fingerprint** (`hyp_fp`) = `hex(sha256("t3|" + join(sorted(unique(evidence_rows)), ",")))[:16]`,
  computed by the **wrapper, never the model**, so wording/order drift cannot defeat the 7‑day
  dedup cooldown. Golden vectors pinned in `hypothesis_test.go`.

Trust: an empty analyst run posts **nothing** (no LLM all‑clear); the bridge executes nothing
based on any field (all DATA); every hypothesis egress is redacted fail‑closed.
