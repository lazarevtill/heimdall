package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/lazarevtill/heimdall/internal/contract"
)

func writeRun(t *testing.T, dir string, run contract.AnalystRun) {
	t.Helper()
	data, err := json.MarshalIndent(run, "", "  ")
	if err != nil {
		t.Fatalf("marshal run: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, run.RunID+".json"), data, 0o600); err != nil {
		t.Fatalf("write run: %v", err)
	}
}

func sampleRun(id string, at time.Time, findings ...contract.HypothesisFinding) contract.AnalystRun {
	return contract.AnalystRun{
		SchemaVersion: 1,
		RunID:         id,
		GeneratedAt:   at.Format(time.RFC3339),
		Findings:      findings,
	}
}

func TestReadRunsListsNewestFirst(t *testing.T) {
	dir := t.TempDir()
	writeRun(t, dir, sampleRun("20260821T050000Z", fixedNow.Add(-48*time.Hour)))
	writeRun(t, dir, sampleRun("20260823T050000Z", fixedNow.Add(-7*time.Hour)))
	writeRun(t, dir, sampleRun("20260822T050000Z", fixedNow.Add(-24*time.Hour)))

	got := ReadRuns(dir, fixedNow, nil)
	if !got.Present {
		t.Fatalf("want Present, got %q", got.Reason)
	}
	var ids []string
	for _, r := range got.Runs {
		ids = append(ids, r.RunID)
	}
	// Run ids are fixed-width UTC, so lexical order IS chronological order.
	want := []string{"20260823T050000Z", "20260822T050000Z", "20260821T050000Z"}
	if diff := cmp.Diff(want, ids); diff != "" {
		t.Errorf("ordering mismatch (-want +got):\n%s", diff)
	}
}

func TestReadRunsRendersAHypothesis(t *testing.T) {
	dir := t.TempDir()
	writeRun(t, dir, sampleRun("20260823T050000Z", fixedNow.Add(-time.Hour),
		contract.HypothesisFinding{
			Kind:           contract.HypCorrelation,
			Targets:        []string{"datastore-02", "ct-app-01"},
			Hypothesis:     "Both signals begin in the same window.",
			Confidence:     contract.ConfidenceMedium,
			EvidenceRows:   []string{"r-14", "r-27"},
			SuggestedQuery: []string{"rate(x[5m])"},
			SuggestedCheck: "alert: Something",
			Fingerprint:    "91c4aaaabbbbcccc",
		}))

	got := ReadRuns(dir, fixedNow, nil)
	if got.Total != 1 {
		t.Fatalf("Total = %d, want 1", got.Total)
	}
	h := got.Runs[0].Findings[0]
	if h.Kind != "correlation" || h.Confidence != "medium" {
		t.Errorf("kind/confidence = %q/%q", h.Kind, h.Confidence)
	}
	if len(h.EvidenceRows) != 2 || h.SuggestedCheck == "" {
		t.Errorf("fields not carried: %+v", h)
	}
	if h.TextTruncated || h.RowsTruncated {
		t.Error("nothing here is at a cap")
	}
}

// The wrapper truncates silently, so a value sitting exactly at its cap must
// be flagged — otherwise the page implies the model said exactly this much.
func TestReadRunsFlagsSilentTruncation(t *testing.T) {
	dir := t.TempDir()
	rows := make([]string, hypBoundedItems)
	for i := range rows {
		rows[i] = "r-" + strings.Repeat("x", i+1)
	}
	writeRun(t, dir, sampleRun("20260823T050000Z", fixedNow,
		contract.HypothesisFinding{
			Hypothesis:   strings.Repeat("a", contract.HypMaxText),
			EvidenceRows: rows,
			Fingerprint:  "aaaabbbbccccdddd",
		}))

	h := ReadRuns(dir, fixedNow, nil).Runs[0].Findings[0]
	if !h.TextTruncated {
		t.Error("text at the 500-rune cap must be flagged as possibly truncated")
	}
	if !h.RowsTruncated {
		t.Error("an evidence list at the 16-item cap must be flagged")
	}
}

// A hypothesis an operator already dismissed must be marked, not presented
// again as new.
func TestReadRunsMarksDismissedHypotheses(t *testing.T) {
	dir := t.TempDir()
	writeRun(t, dir, sampleRun("20260823T050000Z", fixedNow,
		contract.HypothesisFinding{Hypothesis: "h", Fingerprint: "deadbeefdeadbeef"}))

	got := ReadRuns(dir, fixedNow, map[string]contract2Suppression{
		"deadbeefdeadbeef": {Reason: "not useful"},
	})
	h := got.Runs[0].Findings[0]
	if !h.Muted {
		t.Fatal("want Muted=true")
	}
	if h.MuteReason != "not useful" {
		t.Errorf("MuteReason = %q", h.MuteReason)
	}
}

func TestReadRunsFailSoft(t *testing.T) {
	dir := t.TempDir()
	// One corrupt file must not blank the page.
	if err := os.WriteFile(filepath.Join(dir, "20260823T050000Z.json"), []byte("not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	writeRun(t, dir, sampleRun("20260823T060000Z", fixedNow,
		contract.HypothesisFinding{Hypothesis: "ok", Fingerprint: "aaaabbbbccccdddd"}))

	got := ReadRuns(dir, fixedNow, nil)
	if got.Total != 1 {
		t.Errorf("Total = %d, want the good run still read", got.Total)
	}

	for _, tc := range []struct{ name, dir, want string }{
		{"unconfigured", "", "No analyst run directory is configured"},
		{"absent", filepath.Join(t.TempDir(), "nope"), "does not exist"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := ReadRuns(tc.dir, fixedNow, nil)
			if v.Present {
				t.Error("want Present=false")
			}
			if !strings.Contains(v.Reason, tc.want) {
				t.Errorf("Reason = %q, want %q", v.Reason, tc.want)
			}
		})
	}

	// An empty directory is readable and empty — distinct from unreadable.
	empty := ReadRuns(t.TempDir(), fixedNow, nil)
	if !empty.Present {
		t.Error("an empty run directory is present, just empty")
	}
}

func TestReadRunsCapsHowManyRunsAreShown(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < maxRunsShown+5; i++ {
		writeRun(t, dir, sampleRun(fixedNow.Add(time.Duration(i)*time.Hour).Format("20060102T150405Z"), fixedNow))
	}
	got := ReadRuns(dir, fixedNow, nil)
	if len(got.Runs) != maxRunsShown {
		t.Errorf("shown = %d, want the cap %d", len(got.Runs), maxRunsShown)
	}
	if !got.Truncated {
		t.Error("want Truncated=true so the page says older runs exist")
	}
}

// Confidence is metadata, never severity. The wording must not borrow
// severity vocabulary.
func TestDescribeConfidenceNeverReadsAsSeverity(t *testing.T) {
	for _, c := range []string{"low", "medium", "high", "weird"} {
		got := describeConfidence(c)
		if !strings.HasPrefix(got, "model-reported confidence") {
			t.Errorf("describeConfidence(%q) = %q", c, got)
		}
		for _, banned := range []string{"critical", "severity", "urgent", "warning"} {
			if strings.Contains(strings.ToLower(got), banned) {
				t.Errorf("describeConfidence(%q) borrows severity vocabulary: %q", c, got)
			}
		}
	}
}

// The standing caveat must actually say the two things the data requires:
// that this is not everything, and that presence is not delivery.
func TestHypothesisNoteStatesBothCaveats(t *testing.T) {
	lower := strings.ToLower(hypothesisNote)
	if !strings.Contains(lower, "not everything") {
		t.Error("the note must say the run file is not everything the model produced")
	}
	if !strings.Contains(lower, "delivered") {
		t.Error("the note must say appearing here is not delivery")
	}
}
