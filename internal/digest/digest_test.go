package digest_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/lazarevtill/heimdall/internal/contract"
	"github.com/lazarevtill/heimdall/internal/digest"
	"github.com/lazarevtill/heimdall/internal/tier2"
)

var fixedNow = time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
var fixedManifestGeneratedAt = time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC)

func row(id string, z float64, status contract.DigestStatus) *contract.DigestRow {
	return &contract.DigestRow{RowID: id, Entity: "host", Target: "node-a", Feature: "cpu", ZScore: z, Status: status}
}

func TestBuildAssemblesRows(t *testing.T) {
	results := []tier2.Result{
		{Row: row("a", 1, contract.StatusOK)},
		{Row: row("b", 2, contract.StatusOK)},
		{}, // no row (spec.Digest==false, status==OK) — must not be added
	}
	dg := digest.Build(fixedNow, fixedManifestGeneratedAt, results, nil, nil)
	if len(dg.Rows) != 2 {
		t.Fatalf("Rows = %d, want 2", len(dg.Rows))
	}
}

func TestBuildCollectsMarkersDedupedSorted(t *testing.T) {
	results := []tier2.Result{
		{UnknownMarker: "b/feat"},
		{UnknownMarker: "a/feat"},
		{UnknownMarker: "a/feat"}, // dup
		{Flap: "z: 5 changes"},
		{Flap: "y: 3 changes"},
		{NewTemplate: "node-b/tmpl"},
		{NewTemplate: "node-a/tmpl"},
	}
	dg := digest.Build(fixedNow, fixedManifestGeneratedAt, results, nil, nil)
	if diff := cmp.Diff([]string{"a/feat", "b/feat"}, dg.UnknownMarkers); diff != "" {
		t.Errorf("UnknownMarkers (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]string{"y: 3 changes", "z: 5 changes"}, dg.Flaps); diff != "" {
		t.Errorf("Flaps (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]string{"node-a/tmpl", "node-b/tmpl"}, dg.NewTemplates); diff != "" {
		t.Errorf("NewTemplates (-want +got):\n%s", diff)
	}
}

// 205 total rows -> 200 kept, 5 truncated; the two non-ok rows must survive
// the cap over the calm ok rows (mirrors contract.CapRows' retention rule).
func TestBuildRowsTruncatedOver200(t *testing.T) {
	var results []tier2.Result
	for i := 0; i < 203; i++ {
		results = append(results, tier2.Result{Row: row(fmt.Sprintf("r%03d", i), float64(i), contract.StatusOK)})
	}
	results = append(results,
		tier2.Result{Row: row("blind1", 0, contract.StatusUnknown)},
		tier2.Result{Row: row("blind2", 0, contract.StatusBaselineWarming)},
	)
	dg := digest.Build(fixedNow, fixedManifestGeneratedAt, results, nil, nil)
	if dg.RowsTruncated != 5 {
		t.Fatalf("RowsTruncated = %d, want 5", dg.RowsTruncated)
	}
	if len(dg.Rows) != 200 {
		t.Fatalf("len(Rows) = %d, want 200", len(dg.Rows))
	}
	var foundBlind1, foundBlind2 bool
	for _, r := range dg.Rows {
		switch r.RowID {
		case "blind1":
			foundBlind1 = true
		case "blind2":
			foundBlind2 = true
		}
	}
	if !foundBlind1 || !foundBlind2 {
		t.Error("non-ok rows must be retained over calm rows under the 200-row cap")
	}
}

func TestBuildPassesThroughMeta(t *testing.T) {
	openTier1 := []contract.OpenTier1Finding{{Fingerprint: "fp", Check: "c1-deadman", Target: "node-a"}}
	suppressed := []string{"suppressed-thing"}
	dg := digest.Build(fixedNow, fixedManifestGeneratedAt, nil, openTier1, suppressed)
	if dg.SchemaVersion != digest.SchemaVersion {
		t.Errorf("SchemaVersion = %d, want %d", dg.SchemaVersion, digest.SchemaVersion)
	}
	if !dg.GeneratedAt.Equal(fixedNow) {
		t.Errorf("GeneratedAt = %v, want %v", dg.GeneratedAt, fixedNow)
	}
	if !dg.ManifestGeneratedAt.Equal(fixedManifestGeneratedAt) {
		t.Errorf("ManifestGeneratedAt = %v, want %v", dg.ManifestGeneratedAt, fixedManifestGeneratedAt)
	}
	if diff := cmp.Diff(openTier1, dg.OpenTier1Findings); diff != "" {
		t.Errorf("OpenTier1Findings (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(suppressed, dg.Suppressed); diff != "" {
		t.Errorf("Suppressed (-want +got):\n%s", diff)
	}
}

// Identical input must yield byte-identical JSON: Rows come out in CapRows
// order (deterministic tie-break), echo arrays are sorted.
func TestBuildDeterministicJSON(t *testing.T) {
	results := []tier2.Result{
		{Row: row("a", 1, contract.StatusOK)},
		{Row: row("b", -3, contract.StatusOK)},
		{UnknownMarker: "x/y"},
	}
	dg1 := digest.Build(fixedNow, fixedManifestGeneratedAt, results, nil, nil)
	dg2 := digest.Build(fixedNow, fixedManifestGeneratedAt, results, nil, nil)
	b1, err := json.Marshal(dg1)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := json.Marshal(dg2)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(string(b1), string(b2)); diff != "" {
		t.Errorf("non-deterministic JSON (-want +got):\n%s", diff)
	}
}

func TestWriteLatestAndHistory(t *testing.T) {
	dir := t.TempDir()
	dg := digest.Build(fixedNow, fixedManifestGeneratedAt,
		[]tier2.Result{{Row: row("a", 1, contract.StatusOK)}}, nil, nil)

	failures, err := digest.Write(dir, dg, fixedNow)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if failures != 0 {
		t.Errorf("redactionFailures = %d, want 0 on normal (non-secret-shaped) input", failures)
	}

	latestData, err := os.ReadFile(filepath.Join(dir, "latest.json"))
	if err != nil {
		t.Fatalf("latest.json missing: %v", err)
	}
	var got contract.Digest
	if err := json.Unmarshal(latestData, &got); err != nil {
		t.Fatalf("parse latest.json: %v", err)
	}
	if len(got.Rows) != 1 || got.Rows[0].RowID != "a" {
		t.Errorf("latest.json Rows = %+v, want one row 'a'", got.Rows)
	}
	if !got.GeneratedAt.Equal(fixedNow) {
		t.Errorf("GeneratedAt round-trip = %v, want %v", got.GeneratedAt, fixedNow)
	}

	histPath := filepath.Join(dir, "history", fixedNow.UTC().Format("20060102T150405Z")+".json")
	if _, err := os.Stat(histPath); err != nil {
		t.Errorf("history file missing: %v", err)
	}
}

func TestWriteGCsOldHistoryKeepsRecent(t *testing.T) {
	dir := t.TempDir()
	histDir := filepath.Join(dir, "history")
	if err := os.MkdirAll(histDir, 0o755); err != nil {
		t.Fatal(err)
	}
	oldName := fixedNow.Add(-15*24*time.Hour).UTC().Format("20060102T150405Z") + ".json"
	recentName := fixedNow.Add(-1*24*time.Hour).UTC().Format("20060102T150405Z") + ".json"
	if err := os.WriteFile(filepath.Join(histDir, oldName), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(histDir, recentName), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	dg := digest.Build(fixedNow, fixedManifestGeneratedAt, nil, nil, nil)
	if _, err := digest.Write(dir, dg, fixedNow); err != nil {
		t.Fatalf("Write: %v", err)
	}

	if _, err := os.Stat(filepath.Join(histDir, oldName)); !os.IsNotExist(err) {
		t.Errorf("old (>14d) history file not GC'd, stat err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(histDir, recentName)); err != nil {
		t.Errorf("recent history file should be kept: %v", err)
	}
}

// A digest whose redacted JSON exceeds the 32KB cap must be trimmed row by
// row (lowest-priority first) until it fits; RowsTruncated grows to record
// the additional drop beyond the 200-row cap.
func TestWriteEnforcesByteCap(t *testing.T) {
	dir := t.TempDir()
	longTarget := strings.Repeat("x", 500) // long but not secret-shaped
	var results []tier2.Result
	for i := 0; i < 200; i++ {
		results = append(results, tier2.Result{Row: &contract.DigestRow{
			RowID: fmt.Sprintf("r%03d", i), Entity: "host", Target: longTarget, Feature: "cpu",
			ZScore: float64(200 - i), Status: contract.StatusOK,
		}})
	}
	dg := digest.Build(fixedNow, fixedManifestGeneratedAt, results, nil, nil)
	if dg.RowsTruncated != 0 {
		t.Fatalf("precondition: Build should not truncate exactly 200 rows, got RowsTruncated=%d", dg.RowsTruncated)
	}

	if _, err := digest.Write(dir, dg, fixedNow); err != nil {
		t.Fatalf("Write: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "latest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(data) > 32<<10 {
		t.Errorf("written digest = %d bytes, want <= 32KB", len(data))
	}
	var got contract.Digest
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.RowsTruncated == 0 {
		t.Error("RowsTruncated should grow when the byte cap forces additional row drops beyond the 200-row cap")
	}
	if len(got.Rows) >= 200 {
		t.Errorf("len(Rows) = %d, want fewer than 200 after byte-cap trimming", len(got.Rows))
	}
}
