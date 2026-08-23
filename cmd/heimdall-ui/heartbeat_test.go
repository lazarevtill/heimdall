package main

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func writeProm(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

// THE load-bearing case for this parser: the detector's heartbeat carries a
// plane="tier1" label while the notifier's carries none. A parser that only
// matched bare metric names would silently miss the single most important
// row on the liveness strip.
func TestParsePromSampleHandlesLabelledAndBareSamples(t *testing.T) {
	tests := []struct {
		name      string
		line      string
		wantName  string
		wantValue string
		wantOK    bool
	}{
		{"labelled", `heimdall_last_run_timestamp_seconds{plane="tier1"} 1756000000`, "heimdall_last_run_timestamp_seconds", "1756000000", true},
		{"bare", `heimdall_notifier_last_success_timestamp_seconds 1756000001`, "heimdall_notifier_last_success_timestamp_seconds", "1756000001", true},
		{"multi-label", `x{a="1",b="2"} 5`, "x", "5", true},
		{"float value", `x 1756000000.5`, "x", "1756000000.5", true},
		{"no value", `x`, "", "", false},
		{"empty", ``, "", "", false},
		{"value only", ` 5`, "", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			name, value, ok := parsePromSample(tc.line)
			if ok != tc.wantOK || name != tc.wantName || value != tc.wantValue {
				t.Errorf("parsePromSample(%q) = (%q,%q,%v), want (%q,%q,%v)",
					tc.line, name, value, ok, tc.wantName, tc.wantValue, tc.wantOK)
			}
		})
	}
}

func TestReadHeartbeatsAcrossFiles(t *testing.T) {
	dir := t.TempDir()
	detect := time.Date(2026, 8, 23, 11, 59, 0, 0, time.UTC)
	notifier := time.Date(2026, 8, 23, 11, 58, 0, 0, time.UTC)
	analyst := time.Date(2026, 8, 23, 9, 0, 0, 0, time.UTC)

	writeProm(t, dir, "heimdall.prom",
		"# HELP heimdall_last_run_timestamp_seconds x\n"+
			"# TYPE heimdall_last_run_timestamp_seconds gauge\n"+
			`heimdall_last_run_timestamp_seconds{plane="tier1"} `+strconv.FormatInt(detect.Unix(), 10)+"\n")
	writeProm(t, dir, "heimdall-notifier.prom",
		"heimdall_notifier_last_success_timestamp_seconds "+strconv.FormatInt(notifier.Unix(), 10)+"\n")
	writeProm(t, dir, "heimdall-analyst.prom",
		"heimdall_analyst_last_success_timestamp_seconds "+strconv.FormatInt(analyst.Unix(), 10)+"\n")
	// Not a .prom, must be ignored entirely.
	writeProm(t, dir, "notes.txt", "heimdall_last_run_timestamp_seconds 1\n")

	got, err := ReadHeartbeats(dir)
	if err != nil {
		t.Fatalf("ReadHeartbeats: %v", err)
	}

	for name, want := range map[string]time.Time{
		"detect": detect, "notifier": notifier, "analyst": analyst,
	} {
		if !got[name].Equal(want) {
			t.Errorf("%s = %v, want %v", name, got[name], want)
		}
	}
	// The bridge writes no textfile at all — it must NOT appear here, so
	// BuildComponents renders it as absent rather than healthy.
	if _, ok := got["bridge"]; ok {
		t.Error("bridge must not be sourced from a textfile — it renders no heartbeat")
	}
}

func TestReadHeartbeatsKeepsNewestWhenDuplicated(t *testing.T) {
	dir := t.TempDir()
	older := time.Date(2026, 8, 23, 10, 0, 0, 0, time.UTC)
	newer := time.Date(2026, 8, 23, 11, 0, 0, 0, time.UTC)
	writeProm(t, dir, "a.prom", "heimdall_notifier_last_success_timestamp_seconds "+strconv.FormatInt(older.Unix(), 10)+"\n")
	writeProm(t, dir, "b.prom", "heimdall_notifier_last_success_timestamp_seconds "+strconv.FormatInt(newer.Unix(), 10)+"\n")

	got, err := ReadHeartbeats(dir)
	if err != nil {
		t.Fatalf("ReadHeartbeats: %v", err)
	}
	if !got["notifier"].Equal(newer) {
		t.Errorf("notifier = %v, want the newest sample %v", got["notifier"], newer)
	}
}

// Fail-soft: a garbage file must not blind the whole strip, and must never
// produce a fabricated timestamp.
func TestReadHeartbeatsToleratesJunkWithoutInventingLiveness(t *testing.T) {
	dir := t.TempDir()
	ts := time.Date(2026, 8, 23, 11, 0, 0, 0, time.UTC)
	writeProm(t, dir, "junk.prom", "this is not\nprometheus text\n{{{\n")
	writeProm(t, dir, "good.prom", "heimdall_notifier_last_success_timestamp_seconds "+strconv.FormatInt(ts.Unix(), 10)+"\n")
	writeProm(t, dir, "unparseable-value.prom", "heimdall_last_run_timestamp_seconds{plane=\"tier1\"} not-a-number\n")

	got, err := ReadHeartbeats(dir)
	if err != nil {
		t.Fatalf("ReadHeartbeats: %v", err)
	}
	if !got["notifier"].Equal(ts) {
		t.Errorf("the good file must still be read, got %v", got["notifier"])
	}
	if _, ok := got["detect"]; ok {
		t.Error("an unparseable value must yield NO timestamp, never a fabricated one")
	}
}

func TestReadHeartbeatsMissingDirIsAnErrorNotAPanic(t *testing.T) {
	got, err := ReadHeartbeats(filepath.Join(t.TempDir(), "does-not-exist"))
	if err == nil {
		t.Fatal("want an error for a missing directory")
	}
	if len(got) != 0 {
		t.Errorf("want an empty map alongside the error, got %v", got)
	}
	// The caller renders this as four absent components, which is correct.
	if views := BuildComponents(fixedNow, got); len(views) != 4 {
		t.Errorf("want four absent components, got %d", len(views))
	}
}
