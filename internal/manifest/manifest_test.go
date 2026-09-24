package manifest_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lazarevtill/heimdall/internal/contract"
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

func TestLoadValidTier2(t *testing.T) {
	m, err := manifest.Load(filepath.Join("testdata", "manifest_tier2.json"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(m.Tier2) != 1 {
		t.Fatalf("len(Tier2) = %d, want 1", len(m.Tier2))
	}
	ts := m.Tier2[0]
	if ts.ID != "node-a-cpu-creep" || ts.Signal != "quantile" || ts.Check != "c6-quantile-creep" ||
		ts.Group != "node" || ts.Entity != "host" || ts.Target != "node-a" || ts.Node != "node-a" ||
		ts.Feature != "cpu_p95" || ts.Unit != "ratio" || ts.Backend != "prometheus" ||
		ts.Query != "quantile(0.95, node_cpu_seconds_total)" ||
		ts.GraduateThreshold != 2.5 || ts.ClearThreshold != 1.5 || ts.Digest != false ||
		ts.Severity != contract.SeverityWarning {
		t.Errorf("unexpected tier2 spec: %+v", ts)
	}
	if ts.Window() != time.Hour {
		t.Errorf("Window() = %v, want 1h", ts.Window())
	}
	if ts.BaselineWindow() != 7*24*time.Hour {
		t.Errorf("BaselineWindow() = %v, want 168h", ts.BaselineWindow())
	}
	if ts.MinHoldSeconds != 1800 {
		t.Errorf("MinHoldSeconds = %d, want 1800", ts.MinHoldSeconds)
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
	// v is the tail every otherwise-valid tier2 fixture carries, so each case
	// below is rejected for ITS defect and not for a missing baseline window
	// or threshold pair (want pins which rule fired).
	const v = `"baseline_window_seconds":604800,"graduate_threshold":2,"clear_threshold":1`
	cases := []struct{ name, body, want string }{
		{"duplicate id", `{"generated_at":"2026-07-19T00:00:00Z","expectations":[
			{"id":"a","check":"c4-signature","group":"g","target":"t","node":"n","severity_on_miss":"info","verify":{"backend":"prometheus","query":"up","min_count":1}},
			{"id":"a","check":"c4-signature","group":"g","target":"t2","node":"n","severity_on_miss":"info","verify":{"backend":"prometheus","query":"up","min_count":1}}]}`, "duplicate expectation id"},
		{"duplicate (check,target) fingerprint", `{"generated_at":"2026-07-19T00:00:00Z","expectations":[
			{"id":"backup-primary","check":"c1-deadman","group":"g","target":"backup:ds1/vm-100","node":"n","grace_seconds":60,"severity_on_miss":"critical","verify":{"backend":"prometheus","query":"up"}},
			{"id":"backup-secondary","check":"c1-deadman","group":"g","target":"backup:ds1/vm-100","node":"n","grace_seconds":60,"severity_on_miss":"critical","verify":{"backend":"prometheus","query":"up"}}]}`, "collides"},
		{"bad severity", `{"generated_at":"2026-07-19T00:00:00Z","expectations":[
			{"id":"a","check":"c4-signature","group":"g","target":"t","node":"n","severity_on_miss":"panic","verify":{"backend":"prometheus","query":"up","min_count":1}}]}`, "severity_on_miss"},
		{"pipe in check id", `{"generated_at":"2026-07-19T00:00:00Z","expectations":[
			{"id":"a","check":"c1|deadman","group":"g","target":"t","node":"n","grace_seconds":60,"severity_on_miss":"info","verify":{"backend":"prometheus","query":"up"}}]}`, "reserved"},
		{"deadman without grace", `{"generated_at":"2026-07-19T00:00:00Z","expectations":[
			{"id":"a","check":"c1-deadman","group":"g","target":"t","node":"n","severity_on_miss":"info","verify":{"backend":"prometheus","query":"up"}}]}`, "grace_seconds"},
		{"threshold without min_count", `{"generated_at":"2026-07-19T00:00:00Z","expectations":[
			{"id":"a","check":"c4-signature","group":"g","target":"t","node":"n","severity_on_miss":"info","verify":{"backend":"prometheus","query":"up"}}]}`, "min_count"},
		{"unknown backend", `{"generated_at":"2026-07-19T00:00:00Z","expectations":[
			{"id":"a","check":"c4-signature","group":"g","target":"t","node":"n","severity_on_miss":"info","verify":{"backend":"carrier-pigeon","query":"up","min_count":1}}]}`, "verify.backend"},
		{"garbage json", `{nope`, "parse"},
		{"tier2 missing id", `{"generated_at":"2026-07-19T00:00:00Z","tier2":[
			{"signal":"quantile","check":"c6-quantile-creep","group":"node","target":"t","backend":"prometheus","query":"up",` + v + `}]}`, "required"},
		{"tier2 missing check", `{"generated_at":"2026-07-19T00:00:00Z","tier2":[
			{"id":"a","signal":"quantile","group":"node","target":"t","backend":"prometheus","query":"up",` + v + `}]}`, "required"},
		{"tier2 missing target", `{"generated_at":"2026-07-19T00:00:00Z","tier2":[
			{"id":"a","signal":"quantile","check":"c6-quantile-creep","group":"node","backend":"prometheus","query":"up",` + v + `}]}`, "required"},
		{"tier2 missing group", `{"generated_at":"2026-07-19T00:00:00Z","tier2":[
			{"id":"a","signal":"quantile","check":"c6-quantile-creep","target":"t","backend":"prometheus","query":"up",` + v + `}]}`, "required"},
		{"tier2 pipe in check id", `{"generated_at":"2026-07-19T00:00:00Z","tier2":[
			{"id":"a","signal":"quantile","check":"c6|creep","group":"node","target":"t","backend":"prometheus","query":"up",` + v + `}]}`, "reserved"},
		{"tier2 unknown signal", `{"generated_at":"2026-07-19T00:00:00Z","tier2":[
			{"id":"a","signal":"vibes","check":"c6-quantile-creep","group":"node","target":"t","backend":"prometheus","query":"up",` + v + `}]}`, "unknown signal"},
		{"tier2 unknown backend", `{"generated_at":"2026-07-19T00:00:00Z","tier2":[
			{"id":"a","signal":"quantile","check":"c6-quantile-creep","group":"node","target":"t","backend":"pbs","query":"up",` + v + `}]}`, "tier2 backend"},
		{"tier2 missing query", `{"generated_at":"2026-07-19T00:00:00Z","tier2":[
			{"id":"a","signal":"quantile","check":"c6-quantile-creep","group":"node","target":"t","backend":"prometheus",` + v + `}]}`, "query is required"},
		{"tier2 negative min_hold_seconds", `{"generated_at":"2026-07-19T00:00:00Z","tier2":[
			{"id":"a","signal":"quantile","check":"c6-quantile-creep","group":"node","target":"t","backend":"prometheus","query":"up","min_hold_seconds":-1,` + v + `}]}`, "min_hold_seconds"},
		{"tier2 bad severity", `{"generated_at":"2026-07-19T00:00:00Z","tier2":[
			{"id":"a","signal":"quantile","check":"c6-quantile-creep","group":"node","target":"t","backend":"prometheus","query":"up","severity":"panic",` + v + `}]}`, "invalid severity"},
		{"tier2 critical severity rejected", `{"generated_at":"2026-07-19T00:00:00Z","tier2":[
			{"id":"a","signal":"quantile","check":"c6-quantile-creep","group":"node","target":"t","backend":"prometheus","query":"up","severity":"critical",` + v + `}]}`, "critical"},
		{"tier2 duplicate (check,target) fingerprint", `{"generated_at":"2026-07-19T00:00:00Z","tier2":[
			{"id":"a","signal":"quantile","check":"c6-quantile-creep","group":"node","target":"t","feature":"f1","backend":"prometheus","query":"up",` + v + `},
			{"id":"b","signal":"quantile","check":"c6-quantile-creep","group":"node","target":"t","feature":"f2","backend":"prometheus","query":"up",` + v + `}]}`, "collides"},
		{"tier2 collides with expectation fingerprint", `{"generated_at":"2026-07-19T00:00:00Z","expectations":[
			{"id":"backup-primary","check":"c1-deadman","group":"g","target":"backup:ds1/vm-100","node":"n","grace_seconds":60,"severity_on_miss":"critical","verify":{"backend":"prometheus","query":"up"}}],
			"tier2":[
			{"id":"a","signal":"quantile","check":"c1-deadman","group":"node","target":"backup:ds1/vm-100","backend":"prometheus","query":"up",` + v + `}]}`, "collides"},
		// The baseline store keys feature history by (target, feature) only,
		// so two specs sharing that pair would read each other's values as
		// their own baseline (one spec's 0.1 history showed baseline_7d=100).
		{"tier2 duplicate (target,feature)", `{"generated_at":"2026-07-19T00:00:00Z","tier2":[
			{"id":"a","signal":"quantile","check":"c6-quantile-creep","group":"node","target":"t","feature":"disk","backend":"prometheus","query":"up",` + v + `},
			{"id":"b","signal":"flap","check":"c7-flap","group":"node","target":"t","feature":"disk","backend":"prometheus","query":"up",` + v + `}]}`, "(target,feature)"},
		// A zero baseline window holds only the current sample, so every row
		// reads zscore 0 / status ok forever: a permanent false calm.
		{"tier2 missing baseline_window_seconds", `{"generated_at":"2026-07-19T00:00:00Z","tier2":[
			{"id":"a","signal":"quantile","check":"c6-quantile-creep","group":"node","target":"t","backend":"prometheus","query":"up","graduate_threshold":2,"clear_threshold":1}]}`, "baseline_window_seconds"},
		{"tier2 negative baseline_window_seconds", `{"generated_at":"2026-07-19T00:00:00Z","tier2":[
			{"id":"a","signal":"quantile","check":"c6-quantile-creep","group":"node","target":"t","backend":"prometheus","query":"up","baseline_window_seconds":-60,"graduate_threshold":2,"clear_threshold":1}]}`, "baseline_window_seconds"},
		// Omitted thresholds are 0/0: no hysteresis band, and a higher-is-worse
		// spec "graduates" on every non-negative value once warm.
		{"tier2 thresholds omitted", `{"generated_at":"2026-07-19T00:00:00Z","tier2":[
			{"id":"a","signal":"quantile","check":"c6-quantile-creep","group":"node","target":"t","backend":"prometheus","query":"up","baseline_window_seconds":604800}]}`, "clear_threshold"},
		{"tier2 higher-is-worse thresholds inverted", `{"generated_at":"2026-07-19T00:00:00Z","tier2":[
			{"id":"a","signal":"quantile","check":"c6-quantile-creep","group":"node","target":"t","backend":"prometheus","query":"up","baseline_window_seconds":604800,"graduate_threshold":1,"clear_threshold":2}]}`, "clear_threshold"},
		{"tier2 slope thresholds inverted", `{"generated_at":"2026-07-19T00:00:00Z","tier2":[
			{"id":"a","signal":"slope","check":"c8-exhaustion-slope","group":"node","target":"t","backend":"prometheus","query":"up","baseline_window_seconds":604800,"graduate_threshold":14,"clear_threshold":7}]}`, "clear_threshold"},
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
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to name %q (rejected for the wrong reason?)", err, tc.want)
			}
		})
	}
}

// Threshold ordering follows the signal's direction: a slope (lower-is-worse)
// spec graduates at or BELOW graduate_threshold, so its clear threshold sits
// above it. Both directions must load.
func TestLoadAcceptsThresholdOrderPerDirection(t *testing.T) {
	body := `{"generated_at":"2026-07-19T00:00:00Z","tier2":[
		{"id":"a","signal":"quantile","check":"c6-quantile-creep","group":"node","target":"t","feature":"cpu","backend":"prometheus","query":"up","baseline_window_seconds":604800,"graduate_threshold":0.9,"clear_threshold":0.7},
		{"id":"b","signal":"slope","check":"c8-exhaustion-slope","group":"node","target":"t","feature":"disk_days","backend":"prometheus","query":"up","baseline_window_seconds":604800,"graduate_threshold":7,"clear_threshold":14}]}`
	if _, err := manifest.Load(writeTemp(t, body)); err != nil {
		t.Fatalf("Load: %v", err)
	}
}
