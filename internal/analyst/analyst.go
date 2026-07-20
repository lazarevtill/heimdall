package analyst

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/lazarevtill/heimdall/internal/contract"
	"github.com/lazarevtill/heimdall/internal/llm"
)

// Analyzer is the LLM seam. *llm.Client satisfies it; tests inject a fake so
// the wrapper's gates can be exercised hermetically without a real model.
type Analyzer interface {
	Health(ctx context.Context) error
	Analyze(ctx context.Context, req llm.Request) (llm.Result, error)
}

// Poster delivers ONE vetted, wrapper-fingerprinted hypothesis to the
// bridge. HTTPPoster (poster.go) is the real implementation; tests inject a
// fake. DryRun does not need a distinct no-op implementation: Run itself
// short-circuits posting entirely when Params.DryRun is true (step 10), so
// main can always construct the real HTTPPoster and let DryRun govern
// whether it is ever called.
type Poster interface {
	Post(ctx context.Context, runID string, h contract.HypothesisFinding) error
}

// maxBoundedItems caps Targets/SuggestedQuery/EvidenceRows slice lengths
// after the row-id gate has already run: the model does not get to hand the
// wrapper unbounded data just because every cited row happened to be real.
const maxBoundedItems = 16

// Params configures one analyst Run.
type Params struct {
	Now          time.Time
	RunID        string          // caller-supplied, stable per run (e.g. UTC timestamp)
	Digest       contract.Digest // parsed latest.json
	SystemPrompt string          // static instructions incl. prompt-injection defense
	SchemaName   string          // response_format json_schema name
	Schema       json.RawMessage // the AnalystOutput strict json_schema
	MaxTokens    int             // llm completion cap (e.g. 1500); 0 = server default
	Cooldown     time.Duration   // 7*24h per-hyp_fp dedup window
	MaxPerRun    int             // 3
	DryRun       bool            // true => persist + compute everything but POST nothing / record nothing
}

// Outcome reports what one Run did, for the heartbeat counters.
type Outcome struct {
	Run               contract.AnalystRun // what was persisted
	Posted            int
	Hallucinated      int // dropped: cited a nonexistent (or zero) evidence row_id
	InvalidDropped    int // dropped: bad kind/confidence
	Deduped           int // dropped: within cooldown
	CapDropped        int // dropped: over MaxPerRun
	RedactionFailures int // llm-call + egress redaction failures summed
	PromptTokens      int
	CompletionTokens  int
}

// confidenceRank orders survivors high->medium->low for the deterministic
// MaxPerRun cap (step 8). Anything else is unreachable here (ValidConfidence
// already gated every survivor in step 6a) but sorts last defensively rather
// than panicking.
func confidenceRank(c contract.Confidence) int {
	switch c {
	case contract.ConfidenceHigh:
		return 0
	case contract.ConfidenceMedium:
		return 1
	case contract.ConfidenceLow:
		return 2
	default:
		return 3
	}
}

func truncateRunes(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max])
}

func boundSlice(ss []string, max int) []string {
	if len(ss) <= max {
		return ss
	}
	out := make([]string, max)
	copy(out, ss[:max])
	return out
}

// Run executes one analyst cycle: health-gate the LLM, ask it for
// hypotheses over the digest, then verify/fingerprint/dedup/cap/redact in Go
// before persisting and (unless DryRun) posting. persist is called with the
// finished AnalystRun BEFORE any Post (invariant 7): it MUST succeed or Run
// returns its error before posting anything.
//
// Run returns a non-nil error ONLY for hard failures: the health gate, the
// LLM call, decoding the model's output, marshaling the digest, or persist.
// Per-finding drops are counted in Outcome, never returned as errors. A
// failure in the analyst's OWN dedup store (RecentlyPosted) is also treated
// as a hard failure and returned BEFORE persist — nothing has been posted or
// persisted yet at that point, so failing closed here costs nothing beyond
// a retry next cycle, and it avoids silently disabling the dedup gate on a
// database hiccup. See the package report for the POST-error / RecordPosted
// handling choice, which is deliberately NOT a hard failure (documented
// below at the call site).
//
// On any hard error the caller must NOT advance last_success (invariant 8):
// a dead/unhealthy LLM, or any of the failures above, must be visible.
func Run(ctx context.Context, a Analyzer, store *Store, poster Poster,
	persist func(contract.AnalystRun) error, p Params) (Outcome, error) {

	var out Outcome

	// 1. Health gate (invariant 8): a dead/unhealthy LLM must be VISIBLE,
	// never silently skipped.
	if err := a.Health(ctx); err != nil {
		return Outcome{}, fmt.Errorf("analyst: health gate: %w", err)
	}

	// 2. Marshal the digest and ask the model for hypotheses.
	digestJSON, err := json.Marshal(p.Digest)
	if err != nil {
		return Outcome{}, fmt.Errorf("analyst: marshal digest: %w", err)
	}
	res, err := a.Analyze(ctx, llm.Request{
		System:     p.SystemPrompt,
		User:       string(digestJSON),
		SchemaName: p.SchemaName,
		Schema:     p.Schema,
		MaxTokens:  p.MaxTokens,
	})
	if err != nil {
		return Outcome{}, fmt.Errorf("analyst: llm analyze: %w", err)
	}
	out.RedactionFailures = res.RedactionFailures
	out.PromptTokens = res.PromptTokens
	out.CompletionTokens = res.CompletionTokens

	// 3. Decode the strict-schema response. The schema is supposed to
	// guarantee valid JSON; a decode failure here is a real, visible
	// failure, not a per-finding drop.
	var aout contract.AnalystOutput
	if err := json.Unmarshal(res.Content, &aout); err != nil {
		return Outcome{}, fmt.Errorf("analyst: decode analyst output: %w", err)
	}

	// 4. row_id set for the anti-hallucination gate (invariant 2).
	rowIDs := make(map[string]struct{}, len(p.Digest.Rows))
	for _, r := range p.Digest.Rows {
		rowIDs[r.RowID] = struct{}{}
	}

	// 5/6. Gate every finding in the model's original order, UNLESS the
	// model already declared nothing_notable or returned no findings — in
	// which case there is nothing to gate and we fall straight through to
	// an empty persisted run (invariant 4: empty run posts nothing).
	var vetted []contract.HypothesisFinding
	if !aout.NothingNotable && len(aout.Findings) > 0 {
		for _, f := range aout.Findings {
			// 6a. kind/confidence must be in vocabulary — dropped, never
			// coerced to a default (invariant 9).
			if !contract.ValidKind(f.Kind) || !contract.ValidConfidence(f.Confidence) {
				out.InvalidDropped++
				continue
			}
			// 6b. row-id verification: empty evidence, or ANY cited row_id
			// absent from the digest, is a hallucination (invariant 2).
			if len(f.EvidenceRows) == 0 {
				out.Hallucinated++
				continue
			}
			allReal := true
			for _, rid := range f.EvidenceRows {
				if _, ok := rowIDs[rid]; !ok {
					allReal = false
					break
				}
			}
			if !allReal {
				out.Hallucinated++
				continue
			}

			// 6c. bound free text and slice lengths. The model does not get
			// to hand the wrapper unbounded data just because its evidence
			// checked out. suggested_check stays opaque text: it is never
			// parsed or executed anywhere (invariant 10).
			f.Hypothesis = truncateRunes(f.Hypothesis, contract.HypMaxText)
			f.SuggestedCheck = truncateRunes(f.SuggestedCheck, contract.HypMaxText)
			f.EvidenceRows = boundSlice(f.EvidenceRows, maxBoundedItems)
			f.Targets = boundSlice(f.Targets, maxBoundedItems)
			f.SuggestedQuery = boundSlice(f.SuggestedQuery, maxBoundedItems)

			// 6d. hyp_fp is WRAPPER-computed: overwrite whatever the model
			// supplied (invariant 3), computed AFTER the evidence_rows bound
			// above so the fingerprint matches what is actually persisted.
			f.Fingerprint = contract.HypFingerprint(f.EvidenceRows)

			// 6e. fail-closed redaction at the egress, every free-text
			// field (invariant 6). A redaction failure withholds that one
			// field's text but the hypothesis still flows (content-fail
			// closed / signal-fail-open) — each failure is counted into the
			// same total the heartbeat surfaces.
			var failed bool
			f.Hypothesis, failed = contract.EvidenceOrWithheld(f.Hypothesis)
			if failed {
				out.RedactionFailures++
			}
			f.SuggestedCheck, failed = contract.EvidenceOrWithheld(f.SuggestedCheck)
			if failed {
				out.RedactionFailures++
			}
			for i, tgt := range f.Targets {
				f.Targets[i], failed = contract.EvidenceOrWithheld(tgt)
				if failed {
					out.RedactionFailures++
				}
			}
			for i, q := range f.SuggestedQuery {
				f.SuggestedQuery[i], failed = contract.EvidenceOrWithheld(q)
				if failed {
					out.RedactionFailures++
				}
			}

			vetted = append(vetted, f)
		}
	}

	// 7. Dedup: drop anything posted within the cooldown window. In DryRun
	// this still queries the store (so Deduped stays an honest count) but
	// nothing is ever recorded (step 10 short-circuits before RecordPosted).
	//
	// A store error here is treated as a hard failure: nothing has been
	// persisted or posted yet, so returning now costs nothing beyond a
	// retry next cycle, and it is safer than silently treating a broken
	// dedup query as "not recent" (which would defeat the cooldown) or as
	// "recent" (which would silently drop a real hypothesis with no visible
	// cause).
	var deduped []contract.HypothesisFinding
	for _, f := range vetted {
		recent, err := store.RecentlyPosted(p.Now, f.Fingerprint, p.Cooldown)
		if err != nil {
			return Outcome{}, fmt.Errorf("analyst: dedup check %s: %w", f.Fingerprint, err)
		}
		if recent {
			out.Deduped++
			continue
		}
		deduped = append(deduped, f)
	}

	// 8. Deterministic cap ordering: confidence high->medium->low, then
	// fingerprint ascending, so the same set of survivors always yields the
	// same MaxPerRun cut regardless of the model's or the store's ordering.
	sort.SliceStable(deduped, func(i, j int) bool {
		ri, rj := confidenceRank(deduped[i].Confidence), confidenceRank(deduped[j].Confidence)
		if ri != rj {
			return ri < rj
		}
		return deduped[i].Fingerprint < deduped[j].Fingerprint
	})
	maxPerRun := p.MaxPerRun
	if maxPerRun < 0 {
		maxPerRun = 0
	}
	survivors := deduped
	if len(deduped) > maxPerRun {
		survivors = deduped[:maxPerRun]
		out.CapDropped = len(deduped) - maxPerRun
	}

	// 9. Persist the full run BEFORE any POST (invariant 7): a bridge
	// outage loses nothing, and a crash mid-POST is recoverable from the
	// file. nothing_notable is true whenever the model said so OR every
	// finding was gated away — either way there is nothing left to post.
	run := contract.AnalystRun{
		SchemaVersion:  1,
		RunID:          p.RunID,
		GeneratedAt:    p.Now.UTC().Format(time.RFC3339),
		Findings:       survivors,
		NothingNotable: aout.NothingNotable || len(survivors) == 0,
	}
	if err := persist(run); err != nil {
		return Outcome{}, fmt.Errorf("analyst: persist run: %w", err)
	}
	out.Run = run

	// 10. DryRun computes and persists everything above but posts nothing
	// and records nothing (invariant 4/5 still hold; Posted stays 0).
	if p.DryRun {
		return out, nil
	}
	for _, f := range survivors {
		if err := poster.Post(ctx, p.RunID, f); err != nil {
			// Log-and-continue: the run is already persisted (invariant 7),
			// so a single bridge/network failure loses nothing — the
			// persisted file is itself the retry path (an operator or a
			// future run can replay it), and one POST failing must not
			// abort delivery of the other, unrelated survivors in the same
			// run. Do NOT RecordPosted for a failed Post, so it is eligible
			// to post again next cycle instead of silently vanishing behind
			// a phantom cooldown.
			fmt.Fprintf(os.Stderr, "analyst: post %s: %v\n", f.Fingerprint, err)
			continue
		}
		out.Posted++
		if err := store.RecordPosted(p.Now, f.Fingerprint); err != nil {
			// The POST already succeeded — the bridge has the hypothesis.
			// Failing the whole Run here would misreport a successful
			// delivery as a hard failure (and would suppress the
			// heartbeat's last_success even though real work completed).
			// The only cost of losing this bookkeeping write is one
			// possible duplicate POST next cycle, which is bounded by the
			// same gates and MaxPerRun cap — strictly preferable to a false
			// failure. Log and continue, same as a Post error above.
			fmt.Fprintf(os.Stderr, "analyst: record posted %s: %v\n", f.Fingerprint, err)
		}
	}
	return out, nil
}
