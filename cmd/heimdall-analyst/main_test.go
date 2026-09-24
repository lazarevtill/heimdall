package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
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
	if c.BridgeToken != "" {
		t.Errorf("BridgeToken = %q, want empty when HEIMDALL_BRIDGE_TOKEN is unset (it is optional)", c.BridgeToken)
	}
	m := fullEnv(dir)
	m["HEIMDALL_BRIDGE_TOKEN"] = "bridge-token"
	c, err = loadConfig(env(m))
	if err != nil {
		t.Fatalf("loadConfig with token: %v", err)
	}
	if c.BridgeToken != "bridge-token" {
		t.Errorf("BridgeToken = %q, want it read from HEIMDALL_BRIDGE_TOKEN", c.BridgeToken)
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
// llmStub is a llama.cpp stand-in that passes the health gate and answers
// every completion with one well-formed hypothesis citing row-1.
func llmStub(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	t.Cleanup(srv.Close)
	return srv
}

// bridgeEnqueued is the bridge's /hypothesis reply for a new enqueue
// (cmd/heimdall-bridge hypResponse).
const bridgeEnqueued = `{"enqueued":true,"deduped":false,"ticketed":false}`

// setupRun writes a one-row digest into a fresh temp tree and points every
// env var run() reads at it, the LLM stub and bridgeURL. It returns the
// tree's root.
func setupRun(t *testing.T, llmURL, bridgeURL string, extra map[string]string) string {
	t.Helper()
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
	m["HEIMDALL_LLM_URL"] = llmURL
	m["HEIMDALL_BRIDGE_HYPOTHESIS_URL"] = bridgeURL
	for k, v := range extra {
		m[k] = v
	}
	for k, v := range m {
		t.Setenv(k, v)
	}
	return dir
}

func TestRunEndToEnd(t *testing.T) {
	llmSrv := llmStub(t)

	var bridgeHits int
	bridgeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bridgeHits++
		io.WriteString(w, bridgeEnqueued)
	}))
	defer bridgeSrv.Close()

	dir := setupRun(t, llmSrv.URL, bridgeSrv.URL+"/hypothesis", nil)

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
	if !strings.Contains(prom, "heimdall_analyst_hypotheses_post_failed_total 0\n") {
		t.Errorf("post_failed counter missing/wrong:\n%s", prom)
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

// The bridge authenticates /hypothesis with a bearer token. run() sends
// HEIMDALL_BRIDGE_TOKEN as one when it is set, sends no Authorization
// header when it is not, and never writes the token to the log.
func TestRunSendsTheBridgeToken(t *testing.T) {
	const token = "t0k3n-for-the-bridge-only"
	tests := []struct {
		name       string
		env        map[string]string
		wantHeader string
	}{
		{"token set", map[string]string{"HEIMDALL_BRIDGE_TOKEN": token}, "Bearer " + token},
		{"token unset", nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotHeader string
			bridgeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotHeader = r.Header.Get("Authorization")
				io.WriteString(w, bridgeEnqueued)
			}))
			defer bridgeSrv.Close()
			setupRun(t, llmStub(t).URL, bridgeSrv.URL+"/hypothesis", tt.env)

			var logBuf bytes.Buffer
			log.SetOutput(&logBuf)
			t.Cleanup(func() { log.SetOutput(os.Stderr) })

			if err := run(); err != nil {
				t.Fatalf("run: %v", err)
			}
			if gotHeader != tt.wantHeader {
				t.Errorf("Authorization = %q, want %q", gotHeader, tt.wantHeader)
			}
			if strings.Contains(logBuf.String(), token) {
				t.Errorf("the bridge token reached the log:\n%s", logBuf.String())
			}
		})
	}
}

// A bridge that refuses the POST (here: a 401, as for a wrong token) is not
// a hard failure — the run is persisted and the heartbeat advances — but it
// is COUNTED, so it can alert, and it is logged as a WARNING.
func TestRunCountsARefusedPost(t *testing.T) {
	bridgeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer bridgeSrv.Close()
	dir := setupRun(t, llmStub(t).URL, bridgeSrv.URL+"/hypothesis", nil)

	var logBuf bytes.Buffer
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	if err := run(); err != nil {
		t.Fatalf("run: a refused POST must not fail the run, got %v", err)
	}
	promData, err := os.ReadFile(filepath.Join(dir, "textfile", "heimdall-analyst.prom"))
	if err != nil {
		t.Fatalf("heimdall-analyst.prom not written: %v", err)
	}
	prom := string(promData)
	for _, want := range []string{
		"heimdall_analyst_hypotheses_posted_total 0\n",
		"heimdall_analyst_hypotheses_post_failed_total 1\n",
	} {
		if !strings.Contains(prom, want) {
			t.Errorf("prom missing %q:\n%s", want, prom)
		}
	}
	if !strings.Contains(logBuf.String(), "WARNING: analyst: post ") {
		t.Errorf("the refused POST was not logged as a WARNING:\n%s", logBuf.String())
	}
}
