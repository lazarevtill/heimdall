package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lazarevtill/heimdall/internal/contract"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func fullEnv(dir string) map[string]string {
	return map[string]string{
		"HEIMDALL_DIGEST_DIR":            filepath.Join(dir, "digest"),
		"HEIMDALL_LLM_URL":               "http://127.0.0.1:1",
		"HEIMDALL_BRIDGE_HYPOTHESIS_URL": "http://127.0.0.1:1/hypothesis",
		"HEIMDALL_ANALYST_STATE_DB":      filepath.Join(dir, "analyst-state.db"),
		"HEIMDALL_ANALYST_RUN_DIR":       filepath.Join(dir, "runs"),
		"HEIMDALL_TEXTFILE_DIR":          filepath.Join(dir, "textfile"),
	}
}

func TestLoadConfigValid(t *testing.T) {
	dir := t.TempDir()
	c, err := loadConfig(env(fullEnv(dir)))
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if c.DryRun {
		t.Error("DryRun default = true, want false when unset")
	}
	if c.LLMURL != "http://127.0.0.1:1" {
		t.Errorf("LLMURL = %q", c.LLMURL)
	}
}

func TestLoadConfigFailsFastOnMissing(t *testing.T) {
	dir := t.TempDir()
	for _, missing := range []string{
		"HEIMDALL_DIGEST_DIR", "HEIMDALL_LLM_URL", "HEIMDALL_BRIDGE_HYPOTHESIS_URL",
		"HEIMDALL_ANALYST_STATE_DB", "HEIMDALL_ANALYST_RUN_DIR", "HEIMDALL_TEXTFILE_DIR",
	} {
		t.Run(missing, func(t *testing.T) {
			m := fullEnv(dir)
			delete(m, missing)
			if _, err := loadConfig(env(m)); err == nil {
				t.Fatalf("want error when %s missing, got nil", missing)
			}
		})
	}
}

func TestLoadConfigDryRunParsing(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]bool{"": false, "0": false, "false": false, "1": true, "true": true, "TRUE": true}
	for raw, want := range cases {
		m := fullEnv(dir)
		m["HEIMDALL_ANALYST_DRY_RUN"] = raw
		c, err := loadConfig(env(m))
		if err != nil {
			t.Fatalf("loadConfig(%q): %v", raw, err)
		}
		if c.DryRun != want {
			t.Errorf("HEIMDALL_ANALYST_DRY_RUN=%q => DryRun = %v, want %v", raw, c.DryRun, want)
		}
	}
}

// TestRunEndToEnd wires run() against httptest stand-ins for both the LLM
// and the bridge, plus a real digest on disk: manifest-free, but otherwise
// the same "wire it up, assert the files on disk" shape as
// cmd/heimdall-detect's end-to-end test. It proves the full production path
// (analyst.DefaultSystemPrompt / analyst.AnalystSchema / analyst.Run /
// emit.RenderAnalystProm) survives being wired together, not just each
// piece in isolation.
func TestRunEndToEnd(t *testing.T) {
	llmSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.Write([]byte(`{"status":"ok"}`))
		case "/v1/chat/completions":
			out := contract.AnalystOutput{
				SchemaVersion: 1,
				Findings: []contract.HypothesisFinding{{
					Kind:           contract.HypAnomaly,
					Targets:        []string{"node-a"},
					Hypothesis:     "cpu_p95 on node-a is far outside its 7d baseline",
					Confidence:     contract.ConfidenceHigh,
					EvidenceRows:   []string{"row-1"},
					SuggestedQuery: []string{"cpu_p95"},
					SuggestedCheck: "check for a runaway process",
				}},
			}
			content, err := json.Marshal(out)
			if err != nil {
				t.Fatal(err)
			}
			resp := map[string]any{
				"choices": []map[string]any{{"message": map[string]string{"content": string(content)}}},
				"usage":   map[string]int{"prompt_tokens": 5, "completion_tokens": 7},
			}
			data, err := json.Marshal(resp)
			if err != nil {
				t.Fatal(err)
			}
			w.Write(data)
		default:
			http.NotFound(w, r)
		}
	}))
	defer llmSrv.Close()

	var bridgeHits int
	bridgeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bridgeHits++
		w.WriteHeader(http.StatusAccepted)
	}))
	defer bridgeSrv.Close()

	dir := t.TempDir()
	digestDir := filepath.Join(dir, "digest")
	if err := os.MkdirAll(digestDir, 0o755); err != nil {
		t.Fatal(err)
	}
	dg := contract.Digest{
		SchemaVersion: 1,
		Rows: []contract.DigestRow{
			{RowID: "row-1", Entity: "host", Target: "node-a", Feature: "cpu_p95", Value: 0.97, Baseline7d: 0.4, ZScore: 6.2, Status: contract.StatusOK},
		},
	}
	digestData, err := json.Marshal(dg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(digestDir, "latest.json"), digestData, 0o644); err != nil {
		t.Fatal(err)
	}

	m := fullEnv(dir)
	m["HEIMDALL_LLM_URL"] = llmSrv.URL
	m["HEIMDALL_BRIDGE_HYPOTHESIS_URL"] = bridgeSrv.URL + "/hypothesis"
	for k, v := range m {
		t.Setenv(k, v)
	}

	if err := run(); err != nil {
		t.Fatalf("run: %v", err)
	}

	if bridgeHits != 1 {
		t.Errorf("bridge received %d hits, want 1", bridgeHits)
	}

	promData, err := os.ReadFile(filepath.Join(dir, "textfile", "heimdall-analyst.prom"))
	if err != nil {
		t.Fatalf("heimdall-analyst.prom not written: %v", err)
	}
	prom := string(promData)
	if !strings.Contains(prom, "heimdall_analyst_hypotheses_posted_total 1\n") {
		t.Errorf("posted counter missing/wrong:\n%s", prom)
	}
	if !strings.Contains(prom, "heimdall_analyst_last_success_timestamp_seconds") {
		t.Errorf("heartbeat missing:\n%s", prom)
	}
	if !strings.Contains(prom, `heimdall_redaction_failures_total{plane="tier3"} 0`) {
		t.Errorf("plane-scoped redaction counter missing/wrong:\n%s", prom)
	}

	runFiles, err := os.ReadDir(filepath.Join(dir, "runs"))
	if err != nil || len(runFiles) != 1 {
		t.Fatalf("run dir: %v, entries=%v", err, runFiles)
	}
	runData, err := os.ReadFile(filepath.Join(dir, "runs", runFiles[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	var persisted contract.AnalystRun
	if err := json.Unmarshal(runData, &persisted); err != nil {
		t.Fatalf("parse persisted run: %v", err)
	}
	if len(persisted.Findings) != 1 || persisted.Findings[0].EvidenceRows[0] != "row-1" {
		t.Errorf("persisted run findings = %+v", persisted.Findings)
	}
}

// TestRunFailsClosedOnDeadLLM proves invariant 8 end-to-end: a health-gate
// failure must leave no heartbeat file behind at all (so staleness fires).
func TestRunFailsClosedOnDeadLLM(t *testing.T) {
	dir := t.TempDir()
	digestDir := filepath.Join(dir, "digest")
	if err := os.MkdirAll(digestDir, 0o755); err != nil {
		t.Fatal(err)
	}
	dg := contract.Digest{SchemaVersion: 1}
	digestData, err := json.Marshal(dg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(digestDir, "latest.json"), digestData, 0o644); err != nil {
		t.Fatal(err)
	}

	m := fullEnv(dir)
	m["HEIMDALL_LLM_URL"] = "http://127.0.0.1:1" // nothing listening: health fails
	for k, v := range m {
		t.Setenv(k, v)
	}

	if err := run(); err == nil {
		t.Fatal("run: want an error when the LLM health gate fails")
	}
	if _, err := os.Stat(filepath.Join(dir, "textfile", "heimdall-analyst.prom")); !os.IsNotExist(err) {
		t.Errorf("heartbeat must not be written on a hard failure, stat err = %v", err)
	}
}
