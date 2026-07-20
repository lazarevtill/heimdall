package analyst_test

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lazarevtill/heimdall/internal/analyst"
	"github.com/lazarevtill/heimdall/internal/contract"
	"github.com/lazarevtill/heimdall/internal/llm"
)

// TestLiveAnalystRun is the REAL Ornith proof for the FULL production path:
// the exported analyst.DefaultSystemPrompt + analyst.AnalystSchema +
// analyst.DefaultSchemaName (the exact values cmd/heimdall-analyst wires up)
// driven through analyst.Run against a real llama.cpp server, with a
// recording fake Poster (no bridge required) so DryRun stays false and
// Posted counts are still assertable.
//
// It is compiled (not build-tagged) so it never rots, but SKIPs unless
// HEIMDALL_LLM_LIVE_URL is set — this keeps `make ci` fully hermetic (no
// real infra string is ever hardcoded here). The controller runs this
// against the real endpoint after review.
func TestLiveAnalystRun(t *testing.T) {
	url := os.Getenv("HEIMDALL_LLM_LIVE_URL")
	if url == "" {
		t.Skip("set HEIMDALL_LLM_LIVE_URL to run the live analyst test")
	}

	client := llm.NewClient(url, &http.Client{})
	store, err := analyst.OpenStore(filepath.Join(t.TempDir(), "analyst-state.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.Close()
	poster := &recordingPoster{}

	// A planted anomaly: row-cpu-spike has an obviously high zscore, well
	// past what any sane baseline would call normal; row-mem-calm is
	// deliberately unremarkable. The real model is free to call this
	// nothing_notable or not — the proof isn't "the model must flag it," it
	// is "whatever the model returns, every surviving finding cites only
	// real row_ids and the run completes without a hard error."
	digest := contract.Digest{
		SchemaVersion: 1,
		GeneratedAt:   time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC),
		Rows: []contract.DigestRow{
			{
				RowID: "row-cpu-spike", Entity: "host", Target: "node-a",
				Feature: "cpu_p95_creep", Value: 0.98, Baseline7d: 0.32, ZScore: 7.4,
				Unit: "ratio", Status: contract.StatusOK,
			},
			{
				RowID: "row-mem-calm", Entity: "host", Target: "node-b",
				Feature: "mem_p95_creep", Value: 0.41, Baseline7d: 0.40, ZScore: 0.1,
				Unit: "ratio", Status: contract.StatusOK,
			},
		},
	}
	realRowIDs := map[string]bool{"row-cpu-spike": true, "row-mem-calm": true}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	var persisted contract.AnalystRun
	persist := func(ar contract.AnalystRun) error { persisted = ar; return nil }

	outcome, err := analyst.Run(ctx, client, store, poster, persist, analyst.Params{
		Now:          now,
		RunID:        "live-test-run",
		Digest:       digest,
		SystemPrompt: analyst.DefaultSystemPrompt,
		SchemaName:   analyst.DefaultSchemaName,
		Schema:       analyst.AnalystSchema,
		MaxTokens:    1500,
		Cooldown:     7 * 24 * time.Hour,
		MaxPerRun:    3,
		DryRun:       false,
	})
	if err != nil {
		t.Fatalf("Run against live Ornith: %v", err)
	}

	// The proof: the real model's output flowed through every gate without
	// a hard error, and the row-id gate held — every SURVIVING finding
	// (which is exactly what got persisted and posted) cites only real
	// row_ids. It is fine if the model returned nothing_notable.
	for _, f := range persisted.Findings {
		for _, rid := range f.EvidenceRows {
			if !realRowIDs[rid] {
				t.Errorf("persisted finding cited a non-real row_id %q: the row-id gate failed against a real model", rid)
			}
		}
		if len(f.EvidenceRows) == 0 {
			t.Error("a persisted finding has no evidence_rows: the empty-evidence gate failed against a real model")
		}
		if !contract.ValidKind(f.Kind) {
			t.Errorf("persisted finding has invalid kind %q: the kind gate failed against a real model", f.Kind)
		}
		if !contract.ValidConfidence(f.Confidence) {
			t.Errorf("persisted finding has invalid confidence %q: the confidence gate failed against a real model", f.Confidence)
		}
	}
	if outcome.Posted != len(poster.posted) {
		t.Errorf("outcome.Posted = %d, recording poster saw %d posts", outcome.Posted, len(poster.posted))
	}
	if outcome.Posted != len(persisted.Findings) {
		t.Errorf("outcome.Posted = %d, persisted Findings = %d, want equal (non-dry-run posts every survivor)", outcome.Posted, len(persisted.Findings))
	}
	t.Logf("live analyst run: nothing_notable=%v findings=%d posted=%d hallucinated=%d invalid=%d prompt_tokens=%d completion_tokens=%d",
		persisted.NothingNotable, len(persisted.Findings), outcome.Posted, outcome.Hallucinated, outcome.InvalidDropped, outcome.PromptTokens, outcome.CompletionTokens)
}

// recordingPoster is a Poster that always succeeds and records what it was
// asked to deliver, so the live test can assert Posted matches survivors
// without needing a real bridge.
type recordingPoster struct {
	posted []contract.HypothesisFinding
}

func (p *recordingPoster) Post(ctx context.Context, runID string, h contract.HypothesisFinding) error {
	p.posted = append(p.posted, h)
	return nil
}
