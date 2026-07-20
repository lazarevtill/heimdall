package analyst_test

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lazarevtill/heimdall/internal/analyst"
	"github.com/lazarevtill/heimdall/internal/contract"
	"github.com/lazarevtill/heimdall/internal/llm"
)

// fixedNow stands in for every Params.Now / Store now in this file — no
// time.Now() anywhere under internal/ (ADR-G10).
var fixedNow = time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)

const testCooldown = 7 * 24 * time.Hour

// fakeAnalyzer is the hermetic Analyzer seam: it never talks to a real LLM.
type fakeAnalyzer struct {
	healthErr  error
	result     llm.Result
	analyzeErr error
	analyzed   bool
}

func (f *fakeAnalyzer) Health(ctx context.Context) error { return f.healthErr }
func (f *fakeAnalyzer) Analyze(ctx context.Context, req llm.Request) (llm.Result, error) {
	f.analyzed = true
	return f.result, f.analyzeErr
}

// fakePoster records every hypothesis it is asked to deliver; err, if set,
// makes every Post fail (without recording anything).
type fakePoster struct {
	posted []contract.HypothesisFinding
	runIDs []string
	err    error
}

func (p *fakePoster) Post(ctx context.Context, runID string, h contract.HypothesisFinding) error {
	if p.err != nil {
		return p.err
	}
	p.posted = append(p.posted, h)
	p.runIDs = append(p.runIDs, runID)
	return nil
}

func mustAnalyzeResult(t *testing.T, out contract.AnalystOutput) llm.Result {
	t.Helper()
	data, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal fixture AnalystOutput: %v", err)
	}
	return llm.Result{Content: data, PromptTokens: 10, CompletionTokens: 20}
}

// testDigest is a small, fixed digest with two real row_ids — the ONLY
// values a hypothesis's evidence_rows may legitimately cite.
func testDigest() contract.Digest {
	return contract.Digest{
		SchemaVersion: 1,
		Rows: []contract.DigestRow{
			{RowID: "row-1", Entity: "host", Target: "node-a", Feature: "cpu_p95", Value: 0.97, Baseline7d: 0.4, ZScore: 6.2, Unit: "ratio", Status: contract.StatusOK},
			{RowID: "row-2", Entity: "host", Target: "node-b", Feature: "mem_p95", Value: 0.5, Baseline7d: 0.45, ZScore: 0.3, Unit: "ratio", Status: contract.StatusOK},
		},
	}
}

func openTestStore(t *testing.T) *analyst.Store {
	t.Helper()
	store, err := analyst.OpenStore(filepath.Join(t.TempDir(), "analyst-state.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

// capturePersist returns a persist func that records the AnalystRun it was
// given and reports whether it was ever called.
func capturePersist(dst *contract.AnalystRun, called *bool) func(contract.AnalystRun) error {
	return func(ar contract.AnalystRun) error {
		if called != nil {
			*called = true
		}
		*dst = ar
		return nil
	}
}

func baseParams(now time.Time, digest contract.Digest) analyst.Params {
	return analyst.Params{
		Now:          now,
		RunID:        "run-1",
		Digest:       digest,
		SystemPrompt: "system",
		SchemaName:   "schema",
		Schema:       json.RawMessage(`{}`),
		MaxTokens:    100,
		Cooldown:     testCooldown,
		MaxPerRun:    3,
	}
}

// validFinding returns a well-formed hypothesis citing a real row_id — the
// baseline "everything should survive" fixture the other tests mutate.
func validFinding(evidenceRows ...string) contract.HypothesisFinding {
	return contract.HypothesisFinding{
		Kind:           contract.HypAnomaly,
		Targets:        []string{"node-a"},
		Hypothesis:     "cpu_p95 on node-a is far outside its 7d baseline",
		Confidence:     contract.ConfidenceHigh,
		EvidenceRows:   evidenceRows,
		SuggestedQuery: []string{"cpu_p95{target=\"node-a\"}"},
		SuggestedCheck: "check for a runaway process on node-a",
	}
}

// --- G10 planted-anomaly / correct citation ------------------------------

func TestRunPlantedAnomalySurvivesAndPosts(t *testing.T) {
	a := &fakeAnalyzer{result: mustAnalyzeResult(t, contract.AnalystOutput{
		SchemaVersion: 1,
		Findings:      []contract.HypothesisFinding{validFinding("row-1")},
	})}
	store := openTestStore(t)
	poster := &fakePoster{}
	var persisted contract.AnalystRun
	var persistCalled bool

	out, err := analyst.Run(context.Background(), a, store, poster,
		capturePersist(&persisted, &persistCalled), baseParams(fixedNow, testDigest()))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !persistCalled {
		t.Fatal("persist was never called")
	}
	if out.Posted != 1 {
		t.Errorf("Posted = %d, want 1", out.Posted)
	}
	if out.Hallucinated != 0 || out.InvalidDropped != 0 || out.Deduped != 0 || out.CapDropped != 0 {
		t.Errorf("unexpected drops: %+v", out)
	}
	if len(persisted.Findings) != 1 {
		t.Fatalf("persisted Findings = %d, want 1", len(persisted.Findings))
	}
	wantFP := contract.HypFingerprint([]string{"row-1"})
	if persisted.Findings[0].Fingerprint != wantFP {
		t.Errorf("persisted fingerprint = %q, want %q", persisted.Findings[0].Fingerprint, wantFP)
	}
	if len(poster.posted) != 1 || poster.posted[0].Fingerprint != wantFP {
		t.Errorf("poster.posted = %+v, want one finding with fingerprint %q", poster.posted, wantFP)
	}
	if poster.runIDs[0] != "run-1" {
		t.Errorf("poster runID = %q, want run-1", poster.runIDs[0])
	}
	if out.PromptTokens != 10 || out.CompletionTokens != 20 {
		t.Errorf("token counts not threaded through: %+v", out)
	}
}

// --- Hallucinated row-id rejection ---------------------------------------

func TestRunHallucinatedRowIDDropped(t *testing.T) {
	f := validFinding("row-999") // does not exist in testDigest()
	a := &fakeAnalyzer{result: mustAnalyzeResult(t, contract.AnalystOutput{Findings: []contract.HypothesisFinding{f}})}
	store := openTestStore(t)
	poster := &fakePoster{}
	var persisted contract.AnalystRun

	out, err := analyst.Run(context.Background(), a, store, poster,
		capturePersist(&persisted, nil), baseParams(fixedNow, testDigest()))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out.Hallucinated != 1 {
		t.Errorf("Hallucinated = %d, want 1", out.Hallucinated)
	}
	if out.Posted != 0 {
		t.Errorf("Posted = %d, want 0", out.Posted)
	}
	if len(persisted.Findings) != 0 {
		t.Errorf("persisted Findings = %d, want 0", len(persisted.Findings))
	}
	if !persisted.NothingNotable {
		t.Error("persisted run should be NothingNotable when every finding is dropped")
	}
}

// --- Empty-evidence rejection ---------------------------------------------

func TestRunEmptyEvidenceRejected(t *testing.T) {
	f := validFinding() // no evidence_rows at all
	a := &fakeAnalyzer{result: mustAnalyzeResult(t, contract.AnalystOutput{Findings: []contract.HypothesisFinding{f}})}
	store := openTestStore(t)
	poster := &fakePoster{}
	var persisted contract.AnalystRun

	out, err := analyst.Run(context.Background(), a, store, poster,
		capturePersist(&persisted, nil), baseParams(fixedNow, testDigest()))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out.Hallucinated != 1 {
		t.Errorf("Hallucinated = %d, want 1 (empty evidence_rows has no verifiable basis)", out.Hallucinated)
	}
	if out.Posted != 0 || len(persisted.Findings) != 0 {
		t.Errorf("expected zero survivors, got Posted=%d Findings=%d", out.Posted, len(persisted.Findings))
	}
}

// --- Invalid kind/confidence -----------------------------------------------

func TestRunInvalidKindOrConfidenceDropped(t *testing.T) {
	cases := []struct {
		name string
		f    contract.HypothesisFinding
	}{
		{"bad kind", func() contract.HypothesisFinding { f := validFinding("row-1"); f.Kind = "splunk-search"; return f }()},
		{"bad confidence", func() contract.HypothesisFinding { f := validFinding("row-1"); f.Confidence = "certain"; return f }()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := &fakeAnalyzer{result: mustAnalyzeResult(t, contract.AnalystOutput{Findings: []contract.HypothesisFinding{tc.f}})}
			store := openTestStore(t)
			poster := &fakePoster{}
			var persisted contract.AnalystRun

			out, err := analyst.Run(context.Background(), a, store, poster,
				capturePersist(&persisted, nil), baseParams(fixedNow, testDigest()))
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if out.InvalidDropped != 1 {
				t.Errorf("InvalidDropped = %d, want 1", out.InvalidDropped)
			}
			if out.Posted != 0 || len(persisted.Findings) != 0 {
				t.Errorf("expected zero survivors, got Posted=%d Findings=%d", out.Posted, len(persisted.Findings))
			}
		})
	}
}

// --- nothing_notable / all-dropped => zero POSTs, still a persisted run ---

func TestRunNothingNotableOrAllDroppedPostsNothingButPersists(t *testing.T) {
	cases := []struct {
		name string
		out  contract.AnalystOutput
	}{
		{"nothing_notable true, empty findings", contract.AnalystOutput{NothingNotable: true}},
		{"nothing_notable true with a finding present", contract.AnalystOutput{
			NothingNotable: true,
			Findings:       []contract.HypothesisFinding{validFinding("row-1")},
		}},
		{"every finding gated away", contract.AnalystOutput{
			Findings: []contract.HypothesisFinding{func() contract.HypothesisFinding {
				f := validFinding("row-1")
				f.Kind = "bogus"
				return f
			}()},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := &fakeAnalyzer{result: mustAnalyzeResult(t, tc.out)}
			store := openTestStore(t)
			poster := &fakePoster{}
			var persisted contract.AnalystRun
			var persistCalled bool

			outcome, err := analyst.Run(context.Background(), a, store, poster,
				capturePersist(&persisted, &persistCalled), baseParams(fixedNow, testDigest()))
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if !persistCalled {
				t.Fatal("an empty run must still be persisted (invariant 4)")
			}
			if outcome.Posted != 0 || len(poster.posted) != 0 {
				t.Errorf("Posted = %d, poster.posted = %+v, want zero POSTs", outcome.Posted, poster.posted)
			}
			if !persisted.NothingNotable {
				t.Error("persisted run must be NothingNotable when there are no survivors")
			}
			if len(persisted.Findings) != 0 {
				t.Errorf("persisted Findings = %d, want 0", len(persisted.Findings))
			}
		})
	}
}

// --- Dedup cooldown ---------------------------------------------------------

func TestRunDedupCooldown(t *testing.T) {
	f := validFinding("row-1")
	newAnalyzer := func() *fakeAnalyzer {
		return &fakeAnalyzer{result: mustAnalyzeResult(t, contract.AnalystOutput{Findings: []contract.HypothesisFinding{f}})}
	}
	store := openTestStore(t)

	// First run: nothing recorded yet, so it posts.
	poster1 := &fakePoster{}
	var run1 contract.AnalystRun
	out1, err := analyst.Run(context.Background(), newAnalyzer(), store, poster1,
		capturePersist(&run1, nil), baseParams(fixedNow, testDigest()))
	if err != nil {
		t.Fatalf("run 1: %v", err)
	}
	if out1.Posted != 1 {
		t.Fatalf("run 1 Posted = %d, want 1", out1.Posted)
	}

	// Second run, same instant (well within cooldown): must dedup, not repost.
	poster2 := &fakePoster{}
	var run2 contract.AnalystRun
	out2, err := analyst.Run(context.Background(), newAnalyzer(), store, poster2,
		capturePersist(&run2, nil), baseParams(fixedNow, testDigest()))
	if err != nil {
		t.Fatalf("run 2: %v", err)
	}
	if out2.Deduped != 1 {
		t.Errorf("run 2 Deduped = %d, want 1", out2.Deduped)
	}
	if out2.Posted != 0 || len(poster2.posted) != 0 {
		t.Errorf("run 2 Posted = %d, poster.posted = %+v, want zero", out2.Posted, poster2.posted)
	}

	// Third run, outside the cooldown window: posts again.
	poster3 := &fakePoster{}
	var run3 contract.AnalystRun
	later := fixedNow.Add(testCooldown + time.Hour)
	out3, err := analyst.Run(context.Background(), newAnalyzer(), store, poster3,
		capturePersist(&run3, nil), baseParams(later, testDigest()))
	if err != nil {
		t.Fatalf("run 3: %v", err)
	}
	if out3.Deduped != 0 {
		t.Errorf("run 3 Deduped = %d, want 0 (outside cooldown)", out3.Deduped)
	}
	if out3.Posted != 1 || len(poster3.posted) != 1 {
		t.Errorf("run 3 Posted = %d, poster.posted = %+v, want one repost", out3.Posted, poster3.posted)
	}
}

// --- MaxPerRun cap -----------------------------------------------------------

func TestRunMaxPerRunCap(t *testing.T) {
	var findings []contract.HypothesisFinding
	for i := 1; i <= 5; i++ {
		f := validFinding("row-" + string(rune('0'+i)))
		f.Confidence = contract.ConfidenceHigh // tie -> ordered by fingerprint
		findings = append(findings, f)
	}
	digest := contract.Digest{Rows: []contract.DigestRow{
		{RowID: "row-1"}, {RowID: "row-2"}, {RowID: "row-3"}, {RowID: "row-4"}, {RowID: "row-5"},
	}}
	a := &fakeAnalyzer{result: mustAnalyzeResult(t, contract.AnalystOutput{Findings: findings})}
	store := openTestStore(t)
	poster := &fakePoster{}
	var persisted contract.AnalystRun

	p := baseParams(fixedNow, digest)
	p.MaxPerRun = 3
	out, err := analyst.Run(context.Background(), a, store, poster, capturePersist(&persisted, nil), p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out.Posted != 3 {
		t.Errorf("Posted = %d, want 3", out.Posted)
	}
	if out.CapDropped != 2 {
		t.Errorf("CapDropped = %d, want 2", out.CapDropped)
	}
	if len(persisted.Findings) != 3 {
		t.Errorf("persisted Findings = %d, want 3", len(persisted.Findings))
	}
}

// --- hyp_fp is wrapper-computed --------------------------------------------

func TestRunFingerprintIsWrapperComputedNotModelSupplied(t *testing.T) {
	f := validFinding("row-1")
	f.Fingerprint = "totally-bogus-model-supplied-value"
	a := &fakeAnalyzer{result: mustAnalyzeResult(t, contract.AnalystOutput{Findings: []contract.HypothesisFinding{f}})}
	store := openTestStore(t)
	poster := &fakePoster{}
	var persisted contract.AnalystRun

	_, err := analyst.Run(context.Background(), a, store, poster, capturePersist(&persisted, nil), baseParams(fixedNow, testDigest()))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	want := contract.HypFingerprint([]string{"row-1"})
	if len(persisted.Findings) != 1 {
		t.Fatalf("persisted Findings = %d, want 1", len(persisted.Findings))
	}
	if persisted.Findings[0].Fingerprint != want {
		t.Errorf("persisted fingerprint = %q, want wrapper-computed %q", persisted.Findings[0].Fingerprint, want)
	}
	if len(poster.posted) != 1 || poster.posted[0].Fingerprint != want {
		t.Errorf("posted fingerprint = %+v, want wrapper-computed %q", poster.posted, want)
	}
}

// --- Persist-before-POST ordering -------------------------------------------

func TestRunPersistFailureBlocksAllPosting(t *testing.T) {
	f := validFinding("row-1")
	a := &fakeAnalyzer{result: mustAnalyzeResult(t, contract.AnalystOutput{Findings: []contract.HypothesisFinding{f}})}
	store := openTestStore(t)
	poster := &fakePoster{}
	persistErr := errors.New("disk full")
	failingPersist := func(contract.AnalystRun) error { return persistErr }

	_, err := analyst.Run(context.Background(), a, store, poster, failingPersist, baseParams(fixedNow, testDigest()))
	if !errors.Is(err, persistErr) {
		t.Fatalf("Run error = %v, want it to wrap %v", err, persistErr)
	}
	if len(poster.posted) != 0 {
		t.Errorf("poster.posted = %+v, want zero POSTs when persist fails", poster.posted)
	}
}

// --- DryRun ------------------------------------------------------------------

func TestRunDryRun(t *testing.T) {
	f := validFinding("row-1")
	a := &fakeAnalyzer{result: mustAnalyzeResult(t, contract.AnalystOutput{Findings: []contract.HypothesisFinding{f}})}
	store := openTestStore(t)
	poster := &fakePoster{}
	var persisted contract.AnalystRun
	var persistCalled bool

	p := baseParams(fixedNow, testDigest())
	p.DryRun = true
	out, err := analyst.Run(context.Background(), a, store, poster, capturePersist(&persisted, &persistCalled), p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !persistCalled {
		t.Error("DryRun must still persist the computed run")
	}
	if len(persisted.Findings) != 1 {
		t.Errorf("persisted Findings = %d, want 1 (DryRun still computes everything)", len(persisted.Findings))
	}
	if out.Posted != 0 || len(poster.posted) != 0 {
		t.Errorf("DryRun Posted = %d, poster.posted = %+v, want zero", out.Posted, poster.posted)
	}
	fp := persisted.Findings[0].Fingerprint
	recent, err := store.RecentlyPosted(fixedNow, fp, testCooldown)
	if err != nil {
		t.Fatalf("RecentlyPosted: %v", err)
	}
	if recent {
		t.Error("DryRun must not RecordPosted anything")
	}
}

// --- Redaction at egress -----------------------------------------------------

func TestRunRedactsSecretShapedTextAtEgress(t *testing.T) {
	// Fake token, assembled from split literals so no contiguous
	// "glpat-<20+chars>" string appears anywhere in this file's source (the
	// public GitHub mirror's leak scanner is stricter than the Makefile
	// gate and does not exempt _test.go). The runtime VALUE is still a
	// glpat- shape, so the redactor matches and strips it.
	fakeToken := "glp" + "at-" + "yyyyyyyyyyyyyyyyyyyyyyyy" // runtime: glpat- + 24 'y'

	f := validFinding("row-1")
	f.Hypothesis = "found a leaked token " + fakeToken + " in the log line"
	a := &fakeAnalyzer{result: mustAnalyzeResult(t, contract.AnalystOutput{Findings: []contract.HypothesisFinding{f}})}
	store := openTestStore(t)
	poster := &fakePoster{}
	var persisted contract.AnalystRun

	_, err := analyst.Run(context.Background(), a, store, poster, capturePersist(&persisted, nil), baseParams(fixedNow, testDigest()))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(persisted.Findings) != 1 {
		t.Fatalf("persisted Findings = %d, want 1", len(persisted.Findings))
	}
	got := persisted.Findings[0].Hypothesis
	if want := "[REDACTED:gitlab-pat]"; !strings.Contains(got, want) {
		t.Errorf("persisted hypothesis = %q, want it to contain %q", got, want)
	}
	if strings.Contains(got, fakeToken) {
		t.Errorf("persisted hypothesis leaked the raw token: %q", got)
	}
	if len(poster.posted) != 1 || strings.Contains(poster.posted[0].Hypothesis, fakeToken) {
		t.Errorf("posted hypothesis leaked the raw token: %+v", poster.posted)
	}
}

// --- Health-gate failure -----------------------------------------------------

func TestRunHealthGateFailureIsHardAndPostsNothing(t *testing.T) {
	healthErr := errors.New("llm unreachable")
	a := &fakeAnalyzer{healthErr: healthErr}
	store := openTestStore(t)
	poster := &fakePoster{}
	var persistCalled bool
	failIfCalled := func(contract.AnalystRun) error { persistCalled = true; return nil }

	_, err := analyst.Run(context.Background(), a, store, poster, failIfCalled, baseParams(fixedNow, testDigest()))
	if !errors.Is(err, healthErr) {
		t.Fatalf("Run error = %v, want it to wrap %v", err, healthErr)
	}
	if a.analyzed {
		t.Error("Analyze must not be called when the health gate fails")
	}
	if persistCalled {
		t.Error("persist must not be called when the health gate fails")
	}
	if len(poster.posted) != 0 {
		t.Error("poster must not be called when the health gate fails")
	}
}

// --- LLM call / decode hard-failure sanity ----------------------------------

func TestRunAnalyzeErrorIsHard(t *testing.T) {
	analyzeErr := errors.New("transport error")
	a := &fakeAnalyzer{analyzeErr: analyzeErr}
	store := openTestStore(t)
	poster := &fakePoster{}
	var persistCalled bool
	persist := func(contract.AnalystRun) error { persistCalled = true; return nil }

	_, err := analyst.Run(context.Background(), a, store, poster, persist, baseParams(fixedNow, testDigest()))
	if !errors.Is(err, analyzeErr) {
		t.Fatalf("Run error = %v, want it to wrap %v", err, analyzeErr)
	}
	if persistCalled {
		t.Error("persist must not be called when Analyze fails")
	}
}

func TestRunDecodeFailureIsHard(t *testing.T) {
	a := &fakeAnalyzer{result: llm.Result{Content: []byte("not json")}}
	store := openTestStore(t)
	poster := &fakePoster{}
	persist := func(contract.AnalystRun) error { t.Fatal("persist must not be called on decode failure"); return nil }

	if _, err := analyst.Run(context.Background(), a, store, poster, persist, baseParams(fixedNow, testDigest())); err == nil {
		t.Fatal("Run: want a decode error, got nil")
	}
}
