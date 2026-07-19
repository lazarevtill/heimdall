package contract

import (
	"encoding/json"
	"sort"
	"time"
)

// DigestStatus marks whether a feature row is trustworthy. The zero value is
// StatusUnknown so an uninitialized status is fail-closed — a blind spot can
// never be serialized as "ok" and presented to the analyst as calm (the
// no-false-all-clear invariant extended into the feature plane).
type DigestStatus int

const (
	StatusUnknown DigestStatus = iota // fetch failed / unmeasurable — always surfaced
	StatusOK
	StatusBaselineWarming // baseline not yet trustworthy (7d warm-up / post-restore)
)

func (s DigestStatus) String() string {
	switch s {
	case StatusOK:
		return "ok"
	case StatusBaselineWarming:
		return "baseline_warming"
	default:
		return "unknown"
	}
}

func (s DigestStatus) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

func (s *DigestStatus) UnmarshalJSON(b []byte) error {
	var str string
	if err := json.Unmarshal(b, &str); err != nil {
		return err
	}
	switch str {
	case "ok":
		*s = StatusOK
	case "baseline_warming":
		*s = StatusBaselineWarming
	default:
		*s = StatusUnknown // any unrecognized value is fail-closed
	}
	return nil
}

// DigestRow is one measured feature: Tier 2's output to Tier 3. row_id is the
// analyst's only handle on evidence — a hypothesis citing a row_id absent from
// the digest is a checkable hallucination (dropped by the wrapper).
type DigestRow struct {
	RowID      string       `json:"row_id"`
	Entity     string       `json:"entity"` // host|ct|vm|unit|app|fs
	Target     string       `json:"target"`
	Feature    string       `json:"feature"`
	Value      float64      `json:"value"`
	Baseline7d float64      `json:"baseline_7d"`
	ZScore     float64      `json:"zscore"`
	Unit       string       `json:"unit"`
	Status     DigestStatus `json:"status"`
}

// OpenTier1Finding is the minimal reference the analyst needs to cross-link a
// hypothesis to an already-firing hard finding on the same target.
type OpenTier1Finding struct {
	Fingerprint string `json:"fingerprint"`
	Check       string `json:"check"`
	Target      string `json:"target"`
}

// Digest is Tier 3's ENTIRE input: /var/lib/heimdall/digest/latest.json.
// Hard cap <=200 rows / <=32KB post-redaction (row cap here, byte cap + redaction
// at the emit egress). unknown_markers is a top-level echo of every unmeasurable
// feature so the analyst is always told what it could not see.
type Digest struct {
	SchemaVersion       int                `json:"schema_version"`
	GeneratedAt         time.Time          `json:"generated_at"`
	ManifestGeneratedAt time.Time          `json:"manifest_generated_at"`
	Rows                []DigestRow        `json:"rows"`
	UnknownMarkers      []string           `json:"unknown_markers"`
	NewTemplates        []string           `json:"new_templates"`
	Flaps               []string           `json:"flaps"`
	OpenTier1Findings   []OpenTier1Finding `json:"open_tier1_findings"`
	Suppressed          []string           `json:"suppressed"`
	RowsTruncated       int                `json:"rows_truncated"`
}

// MaxDigestRows is the pinned launch bound (G4). Persistent truncation is
// visible via RowsTruncated / heimdall_digest_rows_truncated_total, raised by MR.
const MaxDigestRows = 200

// CapRows enforces the row bound: keep the top-max rows by |zscore| (the most
// anomalous), returning how many were dropped. Ordering is deterministic —
// ties break by row_id — so the same digest input always yields the same bytes.
// Rows whose status is not ok are retained preferentially: a blind spot must
// never be truncated away in favor of a calm row.
func CapRows(rows []DigestRow, max int) (kept []DigestRow, truncated int) {
	if max < 0 {
		max = 0
	}
	sorted := make([]DigestRow, len(rows))
	copy(sorted, rows)
	sort.SliceStable(sorted, func(i, j int) bool {
		// non-ok (unknown/warming) sort ahead of ok so they survive the cap
		ni, nj := sorted[i].Status != StatusOK, sorted[j].Status != StatusOK
		if ni != nj {
			return ni
		}
		ai, aj := absf(sorted[i].ZScore), absf(sorted[j].ZScore)
		if ai != aj {
			return ai > aj
		}
		return sorted[i].RowID < sorted[j].RowID
	})
	if len(sorted) <= max {
		return sorted, 0
	}
	return sorted[:max], len(sorted) - max
}

func absf(f float64) float64 {
	if f < 0 {
		return -f
	}
	return f
}
