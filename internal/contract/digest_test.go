package contract_test

import (
	"encoding/json"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/lazarevtill/heimdall/internal/contract"
)

func TestDigestStatusZeroIsUnknown(t *testing.T) {
	var s contract.DigestStatus // zero value
	if s != contract.StatusUnknown || s.String() != "unknown" {
		t.Fatalf("zero DigestStatus = %v (%q), want StatusUnknown/unknown", s, s.String())
	}
}

func TestDigestStatusJSONRoundTrip(t *testing.T) {
	for _, s := range []contract.DigestStatus{contract.StatusUnknown, contract.StatusOK, contract.StatusBaselineWarming} {
		b, err := json.Marshal(s)
		if err != nil {
			t.Fatalf("marshal %v: %v", s, err)
		}
		var back contract.DigestStatus
		if err := json.Unmarshal(b, &back); err != nil {
			t.Fatalf("unmarshal %s: %v", b, err)
		}
		if back != s {
			t.Errorf("round trip %v -> %s -> %v", s, b, back)
		}
	}
}

// An unrecognized status string must decode to unknown, never ok — a corrupted
// or forward-version digest row is fail-closed, not silently calm.
func TestDigestStatusUnknownOnBadInput(t *testing.T) {
	var s contract.DigestStatus = contract.StatusOK
	if err := json.Unmarshal([]byte(`"calm"`), &s); err != nil {
		t.Fatal(err)
	}
	if s != contract.StatusUnknown {
		t.Errorf("unrecognized status decoded to %v, want unknown", s)
	}
}

func TestCapRowsKeepsTopByAbsZScore(t *testing.T) {
	rows := []contract.DigestRow{
		{RowID: "a", ZScore: 0.5, Status: contract.StatusOK},
		{RowID: "b", ZScore: -9.0, Status: contract.StatusOK},
		{RowID: "c", ZScore: 3.0, Status: contract.StatusOK},
		{RowID: "d", ZScore: 0.1, Status: contract.StatusOK},
	}
	kept, truncated := contract.CapRows(rows, 2)
	if truncated != 2 {
		t.Fatalf("truncated = %d, want 2", truncated)
	}
	gotIDs := []string{kept[0].RowID, kept[1].RowID}
	if diff := cmp.Diff([]string{"b", "c"}, gotIDs); diff != "" {
		t.Errorf("kept rows (-want +got):\n%s", diff)
	}
}

// A blind spot must never be truncated away in favor of a calm row: non-ok
// status rows are retained preferentially over higher-|zscore| ok rows.
func TestCapRowsRetainsUnknownOverCalm(t *testing.T) {
	rows := []contract.DigestRow{
		{RowID: "calm-big", ZScore: 100, Status: contract.StatusOK},
		{RowID: "blind", ZScore: 0, Status: contract.StatusUnknown},
	}
	kept, truncated := contract.CapRows(rows, 1)
	if truncated != 1 || len(kept) != 1 || kept[0].RowID != "blind" {
		t.Fatalf("kept=%+v truncated=%d, want the unknown row retained", kept, truncated)
	}
}

func TestCapRowsNoTruncationUnderLimit(t *testing.T) {
	rows := []contract.DigestRow{{RowID: "a", Status: contract.StatusOK}}
	kept, truncated := contract.CapRows(rows, contract.MaxDigestRows)
	if truncated != 0 || len(kept) != 1 {
		t.Errorf("kept=%d truncated=%d, want 1/0", len(kept), truncated)
	}
}

// Deterministic ordering: equal |zscore| breaks by row_id so the same digest
// input always serializes to identical bytes (atomic .prom-style stability).
func TestCapRowsDeterministicTieBreak(t *testing.T) {
	rows := []contract.DigestRow{
		{RowID: "z", ZScore: 2, Status: contract.StatusOK},
		{RowID: "a", ZScore: 2, Status: contract.StatusOK},
		{RowID: "m", ZScore: 2, Status: contract.StatusOK},
	}
	kept, _ := contract.CapRows(rows, 3)
	got := []string{kept[0].RowID, kept[1].RowID, kept[2].RowID}
	if diff := cmp.Diff([]string{"a", "m", "z"}, got); diff != "" {
		t.Errorf("tie-break order (-want +got):\n%s", diff)
	}
}
