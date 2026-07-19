package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// End-to-end: manifest -> engine -> ledger -> spool -> atomic .prom,
// against an httptest Prometheus stand-in. The dead-man target has no
// fresh success, so the run must produce a firing finding.
func TestRunEndToEnd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// stale success timestamp -> dead-man fires; threshold query returns 0
		if strings.Contains(r.URL.RawQuery, "backup_last_success") {
			w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[1752900000,"1752800000"]}]}}`))
			return
		}
		w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[1752900000,"0"]}]}}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(manifestPath, []byte(`{
	  "generated_at": "2026-07-19T00:00:00Z",
	  "expectations": [
	    {"id":"backup-vm-100","check":"c1-deadman","group":"backup-ds1","target":"backup:ds1/vm-100","node":"node-a",
	     "grace_seconds":3600,"severity_on_miss":"critical",
	     "verify":{"backend":"prometheus","query":"max(backup_last_success_timestamp_seconds)"}},
	    {"id":"unit-failures-node-a","check":"c4-signature","group":"node-a","target":"node-a","node":"node-a",
	     "severity_on_miss":"warning",
	     "verify":{"backend":"prometheus","query":"sum(node_systemd_units)","min_count":1}}
	  ]}`), 0o644); err != nil {
		t.Fatal(err)
	}

	textfileDir := filepath.Join(dir, "textfile")
	if err := os.MkdirAll(textfileDir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HEIMDALL_MANIFEST", manifestPath)
	t.Setenv("HEIMDALL_TEXTFILE_DIR", textfileDir)
	t.Setenv("HEIMDALL_SPOOL_DIR", filepath.Join(dir, "findings"))
	t.Setenv("HEIMDALL_STATE_DB", filepath.Join(dir, "state.db"))
	t.Setenv("HEIMDALL_PROM_URL", srv.URL)

	if err := run(); err != nil {
		t.Fatalf("run: %v", err)
	}

	prom, err := os.ReadFile(filepath.Join(textfileDir, "heimdall.prom"))
	if err != nil {
		t.Fatalf("no heimdall.prom written: %v", err)
	}
	if !strings.Contains(string(prom), `check="c1-deadman"`) ||
		!strings.Contains(string(prom), `fingerprint="d86c07b5a41742c1"`) {
		t.Errorf("dead-man finding missing from .prom:\n%s", prom)
	}
	if strings.Contains(string(prom), "state=") {
		t.Errorf("state label leaked into wire label set:\n%s", prom)
	}
	if !strings.Contains(string(prom), "heimdall_last_run_timestamp_seconds") {
		t.Error("heartbeat sample missing")
	}
	if !strings.Contains(string(prom), "heimdall_redaction_failures_total 0") {
		t.Error("redaction failure counter missing")
	}
	// spool doc exists for the firing fingerprint and carries the state
	doc, err := os.ReadFile(filepath.Join(dir, "findings", "d86c07b5a41742c1.json"))
	if err != nil {
		t.Fatalf("spool doc missing: %v", err)
	}
	if !strings.Contains(string(doc), `"state": "firing"`) {
		t.Errorf("spool doc missing firing state:\n%s", doc)
	}
}
