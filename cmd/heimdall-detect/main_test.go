package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lazarevtill/heimdall/internal/config"
	"github.com/lazarevtill/heimdall/internal/contract"
	"github.com/lazarevtill/heimdall/internal/ledger"
	"github.com/lazarevtill/heimdall/internal/source"
	"github.com/lazarevtill/heimdall/internal/suppress"
)

// End-to-end: manifest -> engine -> ledger -> spool -> atomic .prom,
// against an httptest Prometheus stand-in. The dead-man target has no
// fresh success, so the run must produce a firing finding. The manifest
// also carries one Tier-2 quantile spec (backend prometheus, same stub) so
// the Tier-2 phase, the digest producer, and the digest-freshness metric
// are all exercised end to end.
func TestRunEndToEnd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		// stale success timestamp -> dead-man fires
		case strings.Contains(r.URL.RawQuery, "backup_last_success"):
			w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[1752900000,"1752800000"]}]}}`))
		// Tier-2 quantile query: a real measured sample, well past the
		// spec's graduate_threshold, so the ONLY thing that can be
		// suppressing graduation on a fresh DB is the warm-up gate.
		case strings.Contains(r.URL.RawQuery, "quantile_over_time"):
			w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[1752900000,"0.95"]}]}}`))
		default: // threshold query returns 0
			w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[1752900000,"0"]}]}}`))
		}
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
	  ],
	  "tier2": [
	    {"id":"c6-quantile-creep-node-a","signal":"quantile","check":"c6-quantile-creep","group":"node",
	     "entity":"host","target":"node-a","node":"node-a","feature":"cpu_p95_creep","unit":"ratio",
	     "backend":"prometheus","query":"quantile_over_time(...)",
	     "window_seconds":300,"baseline_window_seconds":604800,
	     "graduate_threshold":0.9,"clear_threshold":0.7,"min_hold_seconds":3600,
	     "digest":true,"severity":"info"}
	  ]}`), 0o644); err != nil {
		t.Fatal(err)
	}

	textfileDir := filepath.Join(dir, "textfile")
	if err := os.MkdirAll(textfileDir, 0o755); err != nil {
		t.Fatal(err)
	}
	digestDir := filepath.Join(dir, "digest")
	t.Setenv("HEIMDALL_MANIFEST", manifestPath)
	t.Setenv("HEIMDALL_TEXTFILE_DIR", textfileDir)
	t.Setenv("HEIMDALL_SPOOL_DIR", filepath.Join(dir, "findings"))
	t.Setenv("HEIMDALL_STATE_DB", filepath.Join(dir, "state.db"))
	t.Setenv("HEIMDALL_PROM_URL", srv.URL)
	t.Setenv("HEIMDALL_DIGEST_DIR", digestDir)

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
	// Pin the FULL series, not just the metric name: both meta-rules
	// (HeimdallDetectorStale/Absent) select on {plane="tier1"}, so the
	// emitted label must match that literal at the integration layer too.
	if !strings.Contains(string(prom), `heimdall_last_run_timestamp_seconds{plane="tier1"}`) {
		t.Errorf("heartbeat series heimdall_last_run_timestamp_seconds{plane=\"tier1\"} missing:\n%s", prom)
	}
	if !strings.Contains(string(prom), "heimdall_redaction_failures_total 0") {
		t.Error("redaction failure counter missing")
	}
	// (a) the digest-freshness gauge must be present now that Tier-2 ran.
	if !strings.Contains(string(prom), "heimdall_digest_generated_timestamp_seconds") {
		t.Errorf("digest freshness metric missing from .prom:\n%s", prom)
	}
	// ...and the truncation series contract/DIGEST_SCHEMA.md promises,
	// explicitly 0: an absent series cannot alert.
	if !strings.Contains(string(prom), "heimdall_digest_rows_truncated_total 0\n") {
		t.Errorf("heimdall_digest_rows_truncated_total 0 missing from .prom:\n%s", prom)
	}
	// A fresh state.db means the warm-up gate holds: no trend finding, even
	// though the Tier-2 sample (0.95) is well past graduate_threshold (0.9).
	if strings.Contains(string(prom), `check="c6-quantile-creep"`) {
		t.Errorf("Tier-2 graduated on a fresh (warming) DB, want warm-up gate to hold:\n%s", prom)
	}
	// spool doc exists for the firing fingerprint and carries the state
	doc, err := os.ReadFile(filepath.Join(dir, "findings", "d86c07b5a41742c1.json"))
	if err != nil {
		t.Fatalf("spool doc missing: %v", err)
	}
	if !strings.Contains(string(doc), `"state": "firing"`) {
		t.Errorf("spool doc missing firing state:\n%s", doc)
	}

	// (b) DigestDir/latest.json exists and parses to a Digest whose Tier-2
	// row reflects warm-up (a brand-new baseline has no 7d history yet).
	digestData, err := os.ReadFile(filepath.Join(digestDir, "latest.json"))
	if err != nil {
		t.Fatalf("digest latest.json missing: %v", err)
	}
	var dg contract.Digest
	if err := json.Unmarshal(digestData, &dg); err != nil {
		t.Fatalf("parse digest latest.json: %v", err)
	}
	if len(dg.Rows) != 1 {
		t.Fatalf("digest Rows = %d, want 1", len(dg.Rows))
	}
	row := dg.Rows[0]
	if row.Status != contract.StatusBaselineWarming {
		t.Errorf("digest row Status = %v, want StatusBaselineWarming (fresh DB, warm-up gate)", row.Status)
	}
	if row.RowID != contract.Fingerprint("c6-quantile-creep", "node-a") {
		t.Errorf("digest row RowID = %q, want fingerprint(c6-quantile-creep,node-a)", row.RowID)
	}
	if row.Target != "node-a" || row.Feature != "cpu_p95_creep" {
		t.Errorf("digest row Target/Feature = %q/%q, want node-a/cpu_p95_creep", row.Target, row.Feature)
	}
	// (c) no graduation on a fresh warming DB: the digest carries no
	// unknown/new-template/flap markers for this spec either (it WAS
	// measured, just warming).
	if len(dg.UnknownMarkers) != 0 {
		t.Errorf("UnknownMarkers = %v, want none (Tier-2 signal was measured)", dg.UnknownMarkers)
	}
}

// suppressionTestEnv stands up the same minimal httptest Prometheus stub +
// single-expectation manifest, returning the dirs the caller needs to set
// HEIMDALL_STATE_DB / HEIMDALL_DIGEST_DIR / HEIMDALL_SUPPRESSIONS_FILE
// around, so each suppression-focused test controls only what it's testing.
func suppressionTestEnv(t *testing.T) (dir, digestDir string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[1752900000,"0"]}]}}`))
	}))
	t.Cleanup(srv.Close)

	dir = t.TempDir()
	manifestPath := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(manifestPath, []byte(`{
	  "generated_at": "2026-07-19T00:00:00Z",
	  "expectations": [
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
	digestDir = filepath.Join(dir, "digest")
	t.Setenv("HEIMDALL_MANIFEST", manifestPath)
	t.Setenv("HEIMDALL_TEXTFILE_DIR", textfileDir)
	t.Setenv("HEIMDALL_SPOOL_DIR", filepath.Join(dir, "findings"))
	t.Setenv("HEIMDALL_STATE_DB", filepath.Join(dir, "state.db"))
	t.Setenv("HEIMDALL_PROM_URL", srv.URL)
	t.Setenv("HEIMDALL_DIGEST_DIR", digestDir)
	return dir, digestDir
}

func readDigest(t *testing.T, digestDir string) contract.Digest {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(digestDir, "latest.json"))
	if err != nil {
		t.Fatalf("digest latest.json missing: %v", err)
	}
	var dg contract.Digest
	if err := json.Unmarshal(data, &dg); err != nil {
		t.Fatalf("parse digest latest.json: %v", err)
	}
	return dg
}

// TestRunFeedsDeclarativeSuppressionAnnotation proves a configured
// HEIMDALL_SUPPRESSIONS_FILE's active record reaches the digest's
// Suppressed[] (the S5-b wiring under test).
func TestRunFeedsDeclarativeSuppressionAnnotation(t *testing.T) {
	dir, digestDir := suppressionTestEnv(t)

	suppressionsPath := filepath.Join(dir, "suppressions.json")
	if err := os.WriteFile(suppressionsPath, []byte(`[
	  {"key":"target:node-a-maint","scope":"target","matcher":{"target":"node-a"},
	   "until":"2099-01-01T00:00:00Z","cumulative_days":0,
	   "reason":"docs test fixture","actor":"docs-tester","source":"declarative"}
	]`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HEIMDALL_SUPPRESSIONS_FILE", suppressionsPath)

	if err := run(); err != nil {
		t.Fatalf("run: %v", err)
	}

	dg := readDigest(t, digestDir)
	if len(dg.Suppressed) == 0 {
		t.Fatal("digest Suppressed is empty, want the declarative record's annotation")
	}
	want := "target:node-a suppressed until 2099-01-01T00:00:00Z by docs-tester: docs test fixture"
	found := false
	for _, a := range dg.Suppressed {
		if a == want {
			found = true
		}
	}
	if !found {
		t.Errorf("digest Suppressed = %v, want to contain %q", dg.Suppressed, want)
	}
}

// TestRunNoSuppressionsFileMeansEmptySuppressed proves the old (pre-S5-b)
// behavior is preserved when HEIMDALL_SUPPRESSIONS_FILE is unset: an empty
// declarative authority is valid (a fresh lab has no mutes), and with no
// runtime mutes either, the digest's Suppressed[] stays empty/null.
func TestRunNoSuppressionsFileMeansEmptySuppressed(t *testing.T) {
	_, digestDir := suppressionTestEnv(t)
	// HEIMDALL_SUPPRESSIONS_FILE deliberately left unset.

	if err := run(); err != nil {
		t.Fatalf("run: %v", err)
	}

	dg := readDigest(t, digestDir)
	if len(dg.Suppressed) != 0 {
		t.Errorf("digest Suppressed = %v, want empty when HEIMDALL_SUPPRESSIONS_FILE is unset", dg.Suppressed)
	}
}

// TestRunFeedsRuntimeMuteAnnotation is the belt-and-suspenders case: a
// runtime mute pre-seeded into the engine state.db (the same file the
// ledger/baseline use) via suppress.OpenStore/AddMute must reach the digest
// too, unioned with the (here, absent) declarative side.
func TestRunFeedsRuntimeMuteAnnotation(t *testing.T) {
	_, digestDir := suppressionTestEnv(t)
	stateDBPath := os.Getenv("HEIMDALL_STATE_DB")

	sstore, err := suppress.OpenStore(stateDBPath)
	if err != nil {
		t.Fatalf("suppress.OpenStore: %v", err)
	}
	// AddMute's until is computed as now+addDays; use the real current time
	// (not a fixed docs date) so the mute is guaranteed still active whenever
	// this test actually runs, independent of the detector's own
	// time.Now()-derived now moments later in run().
	if _, err := sstore.AddMute(time.Now().UTC(), "group_check:node-a/c4-signature",
		suppress.ScopeGroupCheck, suppress.Matcher{Group: "node-a", Check: "c4-signature"},
		7, "", "", "docs test runtime mute", "docs-tester"); err != nil {
		t.Fatalf("AddMute: %v", err)
	}
	if err := sstore.Close(); err != nil {
		t.Fatalf("close pre-seed store: %v", err)
	}

	if err := run(); err != nil {
		t.Fatalf("run: %v", err)
	}

	dg := readDigest(t, digestDir)
	found := false
	for _, a := range dg.Suppressed {
		if strings.Contains(a, "group_check:node-a/c4-signature") {
			found = true
		}
	}
	if !found {
		t.Errorf("digest Suppressed = %v, want to contain the runtime mute's annotation", dg.Suppressed)
	}
}

// One sources map serves both tiers. A Tier-1 expectation on victorialogs
// used to be a permanent "no source wired" Unknown (the VictoriaLogs client
// was wired for Tier 2 only); it now evaluates for real. A backend that is
// still unwired (pbs) stays an explicit, alertable Unknown — never dropped.
func TestRunTier1ExpectationOnVictoriaLogs(t *testing.T) {
	prom := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[]}}`))
	}))
	defer prom.Close()
	vl := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/select/logsql/query" {
			t.Errorf("VL path = %q", r.URL.Path)
		}
		w.Write([]byte(`{"_hv":"3","hostname":"node-a"}` + "\n"))
	}))
	defer vl.Close()

	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(manifestPath, []byte(`{
	  "generated_at": "2026-07-19T00:00:00Z",
	  "expectations": [
	    {"id":"oom-kills-node-a","check":"c4-signature","group":"node-a","target":"node-a","node":"node-a",
	     "severity_on_miss":"warning",
	     "verify":{"backend":"victorialogs","query":"_time:1h oom-kill | stats count() as _hv","min_count":1}},
	    {"id":"backup-vm-100","check":"c1-deadman","group":"backup-ds1","target":"backup:ds1/vm-100","node":"node-a",
	     "grace_seconds":3600,"severity_on_miss":"critical",
	     "verify":{"backend":"pbs","query":"datastore=ds1;id=100"}}
	  ]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	textfileDir := filepath.Join(dir, "textfile")
	t.Setenv("HEIMDALL_MANIFEST", manifestPath)
	t.Setenv("HEIMDALL_TEXTFILE_DIR", textfileDir)
	t.Setenv("HEIMDALL_SPOOL_DIR", filepath.Join(dir, "findings"))
	t.Setenv("HEIMDALL_STATE_DB", filepath.Join(dir, "state.db"))
	t.Setenv("HEIMDALL_PROM_URL", prom.URL)
	t.Setenv("HEIMDALL_VL_URL", vl.URL)
	t.Setenv("HEIMDALL_DIGEST_DIR", filepath.Join(dir, "digest"))

	if err := run(); err != nil {
		t.Fatalf("run: %v", err)
	}
	states := map[string]string{}
	for _, fp := range []string{contract.Fingerprint("c4-signature", "node-a"), contract.Fingerprint("c1-deadman", "backup:ds1/vm-100")} {
		data, err := os.ReadFile(filepath.Join(dir, "findings", fp+".json"))
		if err != nil {
			t.Fatalf("spool doc %s missing: %v", fp, err)
		}
		var doc struct {
			Check, State, Evidence string
		}
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatal(err)
		}
		states[doc.Check] = doc.State + ": " + doc.Evidence
	}
	if got := states["c4-signature"]; !strings.HasPrefix(got, "firing: count 3") {
		t.Errorf("victorialogs Tier-1 finding = %q, want it evaluated (firing: count 3 ...)", got)
	}
	if got := states["c1-deadman"]; !strings.HasPrefix(got, "unknown: ") || !strings.Contains(got, "no source wired for backend pbs") {
		t.Errorf("pbs Tier-1 finding = %q, want an explicit Unknown (no source wired)", got)
	}
}

// buildSources wires every CONFIGURED backend. An unusable PBS fails the
// start; a broken PLUGIN install does not stop the other checks — its
// backend answers Unknown with the reason instead.
func TestBuildSources(t *testing.T) {
	base := config.Config{PromURL: "http://127.0.0.1:9090"}

	got, err := buildSources(base)
	if err != nil {
		t.Fatalf("buildSources(minimal): %v", err)
	}
	if _, ok := got["prometheus"]; !ok || len(got) != 1 {
		t.Errorf("minimal config wired %v, want prometheus only", keys(got))
	}

	withVL := base
	withVL.VLURL = "http://127.0.0.1:9428"
	if got, err := buildSources(withVL); err != nil || got["victorialogs"] == nil {
		t.Errorf("VL configured: sources %v, err %v; want victorialogs wired", keys(got), err)
	}

	badPBS := base
	badPBS.PBSURL, badPBS.PBSCA = "https://pbs.example.invalid:8007", []byte("not a certificate")
	if _, err := buildSources(badPBS); err == nil {
		t.Error("PBS with an unusable CA: want a startup error")
	}

	broken := t.TempDir()
	if err := os.MkdirAll(filepath.Join(broken, "refsrc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(broken, "refsrc", "plugin.json"), []byte(`{"plugin_api":2}`), 0o644); err != nil {
		t.Fatal(err)
	}
	withPlugins := base
	withPlugins.PluginDir = broken
	got, err = buildSources(withPlugins)
	if err != nil {
		t.Fatalf("a broken plugin must not fail the start: %v", err)
	}
	if got["prometheus"] == nil {
		t.Error("prometheus lost to a broken plugin")
	}
	src := got["plugin:refsrc"]
	if src == nil {
		t.Fatal("broken plugin not registered: its expectations would read 'no source wired' instead of the reason")
	}
	if sig, _ := src.Query(context.Background(), source.Query{ID: "q"}); sig.State != contract.StateUnknown {
		t.Errorf("broken plugin answered %v, want Unknown", sig.State)
	}
}

func keys(m map[string]source.Source) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// A finding resolves in the ledger only once a run that no longer produces
// it has written its .prom. A run that fails before then keeps the old
// .prom, whose series still say firing, so the ledger must not claim a
// recovery either.
func TestRunResolvesARecoveredFindingOnlyAfterItsPromIsWritten(t *testing.T) {
	var fresh atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		last := int64(1752800000) // long past the grace: the dead-man fires
		if fresh.Load() {
			last = time.Now().Unix()
		}
		fmt.Fprintf(w, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[%d,"%d"]}]}}`, last, last)
	}))
	defer srv.Close()

	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(manifestPath, []byte(`{"generated_at":"2026-07-19T00:00:00Z","expectations":[
	  {"id":"backup-vm-100","check":"c1-deadman","group":"backup-ds1","target":"backup:ds1/vm-100","node":"node-a",
	   "grace_seconds":3600,"severity_on_miss":"critical",
	   "verify":{"backend":"prometheus","query":"max(backup_last_success_timestamp_seconds)"}}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	textfileDir := filepath.Join(dir, "textfile")
	if err := os.MkdirAll(textfileDir, 0o755); err != nil {
		t.Fatal(err)
	}
	stateDB := filepath.Join(dir, "state.db")
	t.Setenv("HEIMDALL_MANIFEST", manifestPath)
	t.Setenv("HEIMDALL_TEXTFILE_DIR", textfileDir)
	t.Setenv("HEIMDALL_SPOOL_DIR", filepath.Join(dir, "findings"))
	t.Setenv("HEIMDALL_STATE_DB", stateDB)
	t.Setenv("HEIMDALL_PROM_URL", srv.URL)
	t.Setenv("HEIMDALL_DIGEST_DIR", filepath.Join(dir, "digest"))

	state := func() string {
		t.Helper()
		led, err := ledger.Open(stateDB)
		if err != nil {
			t.Fatal(err)
		}
		defer led.Close()
		entries, err := led.List()
		if err != nil || len(entries) != 1 {
			t.Fatalf("ledger = %+v, %v; want one entry", entries, err)
		}
		return entries[0].State
	}

	if err := run(); err != nil {
		t.Fatalf("firing run: %v", err)
	}
	if got := state(); got != "firing" {
		t.Fatalf("after the firing run: state = %q, want firing", got)
	}

	// The backup recovers, but this run cannot write its .prom: a directory
	// squats on the path, so the atomic rename fails.
	fresh.Store(true)
	promPath := filepath.Join(textfileDir, "heimdall.prom")
	if err := os.Remove(promPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(promPath, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := run(); err == nil {
		t.Fatal("run with an unwritable .prom succeeded, want an error")
	}
	if got := state(); got != "firing" {
		t.Errorf("after a run that failed its .prom write: state = %q, want still firing", got)
	}

	if err := os.Remove(promPath); err != nil {
		t.Fatal(err)
	}
	if err := run(); err != nil {
		t.Fatalf("recovered run: %v", err)
	}
	if got := state(); got != "ok" {
		t.Errorf("after a clean run without the finding: state = %q, want ok", got)
	}
}
