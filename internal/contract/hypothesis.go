package contract

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// HypKind is the analyst's classification of a hypothesis. It is DATA — the
// bridge executes nothing based on it.
type HypKind string

const (
	HypTrend       HypKind = "trend"
	HypAnomaly     HypKind = "anomaly"
	HypCorrelation HypKind = "correlation"
	HypDegradation HypKind = "degradation"
)

// Confidence is the LLM's self-reported confidence. Advisory only; it never
// gates whether a hypothesis can page (it structurally cannot) — at most it
// selects a ticket policy.
type Confidence string

const (
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)

// HypMaxText / HypMaxBody bound the free-text fields (design: hypothesis<=500,
// body<=2KB). The wrapper truncates rather than trusting the model.
const (
	HypMaxText = 500
	HypMaxBody = 2048
)

// HypothesisFinding is one analyst finding. evidence_rows are digest row_ids —
// the ONLY machine-stable identity handle, and the field the wrapper verifies
// against the digest (nonexistent row_id => hallucination => dropped+counted).
// suggested_check is MR fodder only and is NEVER applied.
type HypothesisFinding struct {
	Kind           HypKind    `json:"kind"`
	Targets        []string   `json:"targets"`
	Hypothesis     string     `json:"hypothesis"`
	Confidence     Confidence `json:"confidence"`
	EvidenceRows   []string   `json:"evidence_rows"`
	SuggestedQuery []string   `json:"suggested_queries"`
	SuggestedCheck string     `json:"suggested_check,omitempty"`
	Fingerprint    string     `json:"fingerprint,omitempty"` // hyp_fp, wrapper-computed
}

// AnalystOutput is the strict-json_schema response from the llama.cpp analyst.
// nothing_notable true with an empty Findings list is the ONLY sanctioned
// all-clear shape, and it still posts nothing — Tier 3 silence is meaningless.
type AnalystOutput struct {
	SchemaVersion  int                 `json:"schema_version"`
	Findings       []HypothesisFinding `json:"findings"`
	NothingNotable bool                `json:"nothing_notable"`
}

// AnalystRun is the full persisted run (/var/lib/heimdall/analyst/<run_id>.json),
// written before any /hypothesis POST so nothing is lost if the bridge is down.
type AnalystRun struct {
	SchemaVersion  int                 `json:"schema_version"`
	RunID          string              `json:"run_id"`
	GeneratedAt    string              `json:"generated_at"`
	Findings       []HypothesisFinding `json:"findings"`
	NothingNotable bool                `json:"nothing_notable"`
}

// HypFingerprint returns the pinned hypothesis identity:
// sha256("t3|" + strings.Join(sorted(evidenceRows), ",")) [:16].
// The WRAPPER computes this, never the model, so wording drift cannot defeat
// the 7-day dedup cooldown. Row ids are de-duplicated and sorted first, so the
// identity is invariant to the model's ordering or repetition.
func HypFingerprint(evidenceRows []string) string {
	seen := make(map[string]struct{}, len(evidenceRows))
	uniq := make([]string, 0, len(evidenceRows))
	for _, r := range evidenceRows {
		if _, ok := seen[r]; ok {
			continue
		}
		seen[r] = struct{}{}
		uniq = append(uniq, r)
	}
	sort.Strings(uniq)
	sum := sha256.Sum256([]byte("t3|" + strings.Join(uniq, ",")))
	return hex.EncodeToString(sum[:])[:16]
}

// ValidKind / ValidConfidence report whether the model returned an in-vocabulary
// value; the wrapper drops findings that fail these (never coerces silently).
func ValidKind(k HypKind) bool {
	switch k {
	case HypTrend, HypAnomaly, HypCorrelation, HypDegradation:
		return true
	}
	return false
}

func ValidConfidence(c Confidence) bool {
	switch c {
	case ConfidenceLow, ConfidenceMedium, ConfidenceHigh:
		return true
	}
	return false
}
