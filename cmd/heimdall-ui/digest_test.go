package main

import (
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/lazarevtill/heimdall/internal/contract"
	"github.com/lazarevtill/heimdall/internal/digest"
)

// Fidelity: the console must read what internal/digest actually WRITES.
// This drives the real writer and reads the result back, so a change to the
// on-disk layout or the redaction pass breaks here rather than in production.
func TestReadDigestReadsWhatDigestWrites(t *testing.T) {
	dir := t.TempDir()
	now := fixedNow
	dg := contract.Digest{
		SchemaVersion: 1,
		GeneratedAt:   now.Add(-2 * time.Minute),
		Rows: []contract.DigestRow{
			{RowID: "r-ok", Entity: "ct", Target: "ct-app-01", Feature: "root_disk_pct",
				Value: 71.5, Baseline7d: 62.0, ZScore: 2.4, Unit: "pct", Status: contract.StatusOK},
			{RowID: "r-unknown", Entity: "host", Target: "node-a", Feature: "cpu",
				Status: contract.StatusUnknown},
			{RowID: "r-warming", Entity: "vm", Target: "vm-1", Feature: "net",
				ZScore: 9.9, Status: contract.StatusBaselineWarming},
		},
		UnknownMarkers: []string{"pbs unreachable"},
		Flaps:          []string{"svc-b"},
		RowsTruncated:  4,
	}
	if _, err := digest.Write(dir, dg, now); err != nil {
		t.Fatalf("digest.Write: %v", err)
	}

	got := ReadDigest(dir, now)
	if !got.Present {
		t.Fatalf("want the digest read, got %q", got.Reason)
	}
	if got.Counts.Total != 3 || got.Counts.OK != 1 || got.Counts.Unknown != 1 || got.Counts.Warming != 1 {
		t.Errorf("counts = %+v", got.Counts)
	}
	if got.RowsTruncated != 4 {
		t.Errorf("RowsTruncated = %d, want 4", got.RowsTruncated)
	}
	if len(got.UnknownMarkers) != 1 {
		t.Errorf("UnknownMarkers = %v", got.UnknownMarkers)
	}
	if got.Stale {
		t.Error("a two-minute-old digest is not stale")
	}
}

// Ordering mirrors contract.CapRows: a blind spot must never sort below a
// calm row, or the cap and the console would disagree about what matters.
func TestDigestRowsPutUnmeasurableFirstThenMostAnomalous(t *testing.T) {
	v := buildDigestView(fixedNow, contract.Digest{
		GeneratedAt: fixedNow,
		Rows: []contract.DigestRow{
			{RowID: "calm", ZScore: 0.2, Status: contract.StatusOK},
			{RowID: "hot", ZScore: 4.1, Status: contract.StatusOK},
			{RowID: "warming", ZScore: 8.0, Status: contract.StatusBaselineWarming},
			{RowID: "blind", ZScore: 0, Status: contract.StatusUnknown},
			{RowID: "cold", ZScore: -5.5, Status: contract.StatusOK},
		},
	})
	var order []string
	for _, r := range v.Rows {
		order = append(order, r.RowID)
	}
	// unknown, then warming, then ok by |z| descending.
	want := []string{"blind", "warming", "cold", "hot", "calm"}
	if diff := cmp.Diff(want, order); diff != "" {
		t.Errorf("ordering mismatch (-want +got):\n%s", diff)
	}
}

func TestDigestOrderingIsDeterministic(t *testing.T) {
	dg := contract.Digest{GeneratedAt: fixedNow, Rows: []contract.DigestRow{
		{RowID: "b", ZScore: 1, Status: contract.StatusOK},
		{RowID: "a", ZScore: 1, Status: contract.StatusOK},
		{RowID: "c", ZScore: 1, Status: contract.StatusOK},
	}}
	first := buildDigestView(fixedNow, dg)
	for i := 0; i < 5; i++ {
		if diff := cmp.Diff(first, buildDigestView(fixedNow, dg)); diff != "" {
			t.Fatalf("run %d differs (-first +again):\n%s", i, diff)
		}
	}
}

// A stale digest describes an earlier window. Rendering it as current would
// have an operator act on data the detector has already superseded.
func TestDigestStalenessMatchesTheDetectorWindow(t *testing.T) {
	fresh := buildDigestView(fixedNow, contract.Digest{GeneratedAt: fixedNow.Add(-time.Minute)})
	if fresh.Stale {
		t.Error("a one-minute-old digest is current")
	}
	old := buildDigestView(fixedNow, contract.Digest{GeneratedAt: fixedNow.Add(-digestStaleAfter - time.Second)})
	if !old.Stale {
		t.Error("past the detector staleness window the digest must read as stale")
	}
	// A digest with no timestamp cannot be shown to be current, so it is not.
	none := buildDigestView(fixedNow, contract.Digest{})
	if !none.Stale {
		t.Error("a digest with no generated_at must not read as current")
	}
}

// Fail-soft and non-fabricating, exactly like the spool reader.
func TestReadDigestRefusesUnusableFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "latest.json"), []byte("not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	tests := []struct {
		name, dir, want string
	}{
		{"no dir configured", "", "No digest directory"},
		{"missing", t.TempDir(), "No digest has been written yet"},
		{"undecodable", dir, "could not be decoded"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ReadDigest(tc.dir, fixedNow)
			if got.Present {
				t.Fatal("want Present=false")
			}
			if len(got.Rows) != 0 {
				t.Error("an unusable digest must yield no rows")
			}
			if !strings.Contains(got.Reason, tc.want) {
				t.Errorf("Reason = %q, want it to contain %q", got.Reason, tc.want)
			}
		})
	}
}

// An unrecognised status decodes to unknown, never to ok — the fail-closed
// property contract.DigestStatus.UnmarshalJSON provides, relied on here.
func TestUnrecognisedStatusReadsAsUnknownNotOK(t *testing.T) {
	dir := t.TempDir()
	body := `{"schema_version":1,"generated_at":"` + fixedNow.Format(time.RFC3339) + `",
	          "rows":[{"row_id":"r1","target":"t","feature":"f","status":"something-new"}]}`
	if err := os.WriteFile(filepath.Join(dir, "latest.json"), []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := ReadDigest(dir, fixedNow)
	if !got.Present {
		t.Fatalf("want the digest read, got %q", got.Reason)
	}
	if got.Counts.Unknown != 1 || got.Counts.OK != 0 {
		t.Errorf("counts = %+v, want the unrecognised status to read as unknown", got.Counts)
	}
}

func TestDescribeDriftIsCoarseAndOnlyForMeasuredRows(t *testing.T) {
	// An unmeasured row gets no reading at all — a phrase would imply a
	// measurement that does not exist.
	if got := describeDrift(contract.DigestRow{ZScore: 9, Status: contract.StatusUnknown}); got != "" {
		t.Errorf("unknown row drift = %q, want empty", got)
	}
	for _, tc := range []struct {
		z    float64
		want string
	}{
		{0.3, "in line with its baseline"},
		{1.4, "drifting above baseline"},
		{-1.4, "drifting below baseline"},
		{2.5, "clearly above baseline"},
		{7.0, "far above baseline"},
		{-7.0, "far below baseline"},
	} {
		got := describeDrift(contract.DigestRow{ZScore: tc.z, Status: contract.StatusOK})
		if got != tc.want {
			t.Errorf("describeDrift(z=%v) = %q, want %q", tc.z, got, tc.want)
		}
	}
}

func TestFormatFloatHandlesNonFinite(t *testing.T) {
	for _, s := range []string{formatFloat(math.NaN()), formatFloat(math.Inf(1)), formatFloat(math.Inf(-1))} {
		if s != "—" {
			t.Errorf("non-finite rendered as %q, want an em dash", s)
		}
	}
	if got := formatFloat(71.5); got != "71.5" {
		t.Errorf("formatFloat(71.5) = %q", got)
	}
}
