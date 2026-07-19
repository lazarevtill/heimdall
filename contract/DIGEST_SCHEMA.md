# DIGEST_SCHEMA

The Tier‑2 → Tier‑3 interface. The engine writes `digest/latest.json` (plus a
14‑day dated history) after the `.prom`, redacted at write (4th mandatory egress).
It is the analyst's **entire** input — never raw logs. Go types: `internal/contract`
(`Digest`, `DigestRow`, `DigestStatus`, `OpenTier1Finding`).

## Bounds
- **≤ 200 rows** (`contract.MaxDigestRows`), top‑N by `|zscore|`, dropped count in
  `rows_truncated` → `heimdall_digest_rows_truncated_total`. `CapRows` enforces it,
  retaining non‑`ok` rows preferentially so a blind spot is never truncated for a calm row.
- **≤ 32 KB post‑redaction** (byte cap applied at the emit egress).

## `Digest`
| field | type | notes |
|-------|------|-------|
| `schema_version` | int | additive‑only |
| `generated_at` | RFC3339 | so the analyst can flag its own staleness |
| `manifest_generated_at` | RFC3339 | manifest freshness echo |
| `rows` | `[]DigestRow` | the feature table |
| `unknown_markers` | `[]string` | top‑level echo of every unmeasurable feature |
| `new_templates` | `[]string` | C9 template‑surprise surface |
| `flaps` | `[]string` | C7 flap surface |
| `open_tier1_findings` | `[]OpenTier1Finding` | for cross‑linking a hypothesis to a firing hard finding |
| `suppressed` | `[]string` | muted targets stay IN the digest, annotated — suppression never blinds |
| `rows_truncated` | int | rows dropped by the 200 cap |

## `DigestRow`
`{row_id, entity(host|ct|vm|unit|app|fs), target, feature, value, baseline_7d, zscore, unit, status}`.
`row_id` is the analyst's only evidence handle: a hypothesis citing a `row_id` absent
from the digest is a checkable hallucination and is dropped + counted.

## `status` is load‑bearing
`ok | unknown | baseline_warming`. The **zero value is `unknown`** (fail‑closed): a
feature whose fetch failed appears as an explicit `unknown` row, and a cold baseline as
`baseline_warming` — the analyst can never present a blind spot or a warming baseline as calm
(the no‑false‑all‑clear invariant extended into the feature plane). An unrecognized status
string decodes to `unknown`, never `ok`.
