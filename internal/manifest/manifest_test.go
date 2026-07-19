package manifest_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

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
