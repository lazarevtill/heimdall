package manifest_test

import (
	"errors"
	"os"
	"path/filepath"
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
	cases := []struct{ name, body string }{
		{"duplicate id", `{"generated_at":"2026-07-19T00:00:00Z","expectations":[
			{"id":"a","check":"c4-signature","group":"g","target":"t","node":"n","severity_on_miss":"info","verify":{"backend":"prometheus","query":"up","min_count":1}},
			{"id":"a","check":"c4-signature","group":"g","target":"t2","node":"n","severity_on_miss":"info","verify":{"backend":"prometheus","query":"up","min_count":1}}]}`},
		{"duplicate (check,target) fingerprint", `{"generated_at":"2026-07-19T00:00:00Z","expectations":[
			{"id":"backup-primary","check":"c1-deadman","group":"g","target":"backup:ds1/vm-100","node":"n","grace_seconds":60,"severity_on_miss":"critical","verify":{"backend":"prometheus","query":"up"}},
			{"id":"backup-secondary","check":"c1-deadman","group":"g","target":"backup:ds1/vm-100","node":"n","grace_seconds":60,"severity_on_miss":"critical","verify":{"backend":"prometheus","query":"up"}}]}`},
		{"bad severity", `{"generated_at":"2026-07-19T00:00:00Z","expectations":[
			{"id":"a","check":"c4-signature","group":"g","target":"t","node":"n","severity_on_miss":"panic","verify":{"backend":"prometheus","query":"up","min_count":1}}]}`},
		{"pipe in check id", `{"generated_at":"2026-07-19T00:00:00Z","expectations":[
			{"id":"a","check":"c1|deadman","group":"g","target":"t","node":"n","grace_seconds":60,"severity_on_miss":"info","verify":{"backend":"prometheus","query":"up"}}]}`},
		{"deadman without grace", `{"generated_at":"2026-07-19T00:00:00Z","expectations":[
			{"id":"a","check":"c1-deadman","group":"g","target":"t","node":"n","severity_on_miss":"info","verify":{"backend":"prometheus","query":"up"}}]}`},
		{"threshold without min_count", `{"generated_at":"2026-07-19T00:00:00Z","expectations":[
			{"id":"a","check":"c4-signature","group":"g","target":"t","node":"n","severity_on_miss":"info","verify":{"backend":"prometheus","query":"up"}}]}`},
		{"unknown backend", `{"generated_at":"2026-07-19T00:00:00Z","expectations":[
			{"id":"a","check":"c4-signature","group":"g","target":"t","node":"n","severity_on_miss":"info","verify":{"backend":"carrier-pigeon","query":"up","min_count":1}}]}`},
		{"garbage json", `{nope`},
		{"tier2 missing id", `{"generated_at":"2026-07-19T00:00:00Z","tier2":[
			{"signal":"quantile","check":"c6-quantile-creep","group":"node","target":"t","backend":"prometheus","query":"up"}]}`},
		{"tier2 missing check", `{"generated_at":"2026-07-19T00:00:00Z","tier2":[
			{"id":"a","signal":"quantile","group":"node","target":"t","backend":"prometheus","query":"up"}]}`},
		{"tier2 missing target", `{"generated_at":"2026-07-19T00:00:00Z","tier2":[
			{"id":"a","signal":"quantile","check":"c6-quantile-creep","group":"node","backend":"prometheus","query":"up"}]}`},
		{"tier2 missing group", `{"generated_at":"2026-07-19T00:00:00Z","tier2":[
			{"id":"a","signal":"quantile","check":"c6-quantile-creep","target":"t","backend":"prometheus","query":"up"}]}`},
		{"tier2 pipe in check id", `{"generated_at":"2026-07-19T00:00:00Z","tier2":[
			{"id":"a","signal":"quantile","check":"c6|creep","group":"node","target":"t","backend":"prometheus","query":"up"}]}`},
		{"tier2 unknown signal", `{"generated_at":"2026-07-19T00:00:00Z","tier2":[
			{"id":"a","signal":"vibes","check":"c6-quantile-creep","group":"node","target":"t","backend":"prometheus","query":"up"}]}`},
		{"tier2 unknown backend", `{"generated_at":"2026-07-19T00:00:00Z","tier2":[
			{"id":"a","signal":"quantile","check":"c6-quantile-creep","group":"node","target":"t","backend":"pbs","query":"up"}]}`},
		{"tier2 missing query", `{"generated_at":"2026-07-19T00:00:00Z","tier2":[
			{"id":"a","signal":"quantile","check":"c6-quantile-creep","group":"node","target":"t","backend":"prometheus"}]}`},
		{"tier2 negative min_hold_seconds", `{"generated_at":"2026-07-19T00:00:00Z","tier2":[
			{"id":"a","signal":"quantile","check":"c6-quantile-creep","group":"node","target":"t","backend":"prometheus","query":"up","min_hold_seconds":-1}]}`},
		{"tier2 bad severity", `{"generated_at":"2026-07-19T00:00:00Z","tier2":[
			{"id":"a","signal":"quantile","check":"c6-quantile-creep","group":"node","target":"t","backend":"prometheus","query":"up","severity":"panic"}]}`},
		{"tier2 critical severity rejected", `{"generated_at":"2026-07-19T00:00:00Z","tier2":[
			{"id":"a","signal":"quantile","check":"c6-quantile-creep","group":"node","target":"t","backend":"prometheus","query":"up","severity":"critical"}]}`},
		{"tier2 duplicate (check,target) fingerprint", `{"generated_at":"2026-07-19T00:00:00Z","tier2":[
			{"id":"a","signal":"quantile","check":"c6-quantile-creep","group":"node","target":"t","backend":"prometheus","query":"up"},
			{"id":"b","signal":"quantile","check":"c6-quantile-creep","group":"node","target":"t","backend":"prometheus","query":"up"}]}`},
		{"tier2 collides with expectation fingerprint", `{"generated_at":"2026-07-19T00:00:00Z","expectations":[
			{"id":"backup-primary","check":"c1-deadman","group":"g","target":"backup:ds1/vm-100","node":"n","grace_seconds":60,"severity_on_miss":"critical","verify":{"backend":"prometheus","query":"up"}}],
			"tier2":[
			{"id":"a","signal":"quantile","check":"c1-deadman","group":"node","target":"backup:ds1/vm-100","backend":"prometheus","query":"up"}]}`},
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
		})
	}
}
