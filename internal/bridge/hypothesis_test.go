package bridge_test

import (
	"context"
	"strings"
	"testing"

	"github.com/lazarevtill/heimdall/internal/bridge"
	"github.com/lazarevtill/heimdall/internal/contract"
	"github.com/lazarevtill/heimdall/internal/outbox"
)

// validHypothesis returns a structurally-valid contract.HypothesisFinding
// fixture. Callers mutate a copy for the specific case under test. Fixture
// values are all fake (192.0.2.x targets, made-up row ids).
func validHypothesis() contract.HypothesisFinding {
	return contract.HypothesisFinding{
		Kind:           contract.HypTrend,
		Targets:        []string{"192.0.2.10"},
		Hypothesis:     "disk latency on 192.0.2.10 has trended up over the last 6 digest windows",
		Confidence:     contract.ConfidenceMedium,
		EvidenceRows:   []string{"row-1", "row-2"},
		SuggestedQuery: []string{"select p99 from disk_latency where target='192.0.2.10'"},
		SuggestedCheck: "disk-latency-p99",
		Fingerprint:    "deadbeefcafef00d",
	}
}

func hypPost(h contract.HypothesisFinding) bridge.HypothesisPost {
	return bridge.HypothesisPost{
		SchemaVersion: 1,
		RunID:         "run-0001",
		Hypothesis:    h,
	}
}

func TestHandleHypothesisHappyPathTelegramOnly(t *testing.T) {
	deps, ft := testDeps(t, 10, nil)
	post := hypPost(validHypothesis())

	result, err := bridge.HandleHypothesis(context.Background(), fixedNow, deps, post, bridge.PolicyTelegramOnly)
	if err != nil {
		t.Fatalf("HandleHypothesis: %v", err)
	}
	if !result.Enqueued || result.Deduped || result.Ticketed {
		t.Errorf("result = %+v, want Enqueued only", result)
	}
	if result.RedactionFailures != 0 {
		t.Errorf("RedactionFailures = %d, want 0", result.RedactionFailures)
	}
	if len(ft.opens) != 0 {
		t.Errorf("tracker Open called %d times, want 0 (PolicyTelegramOnly)", len(ft.opens))
	}

	pending, err := deps.Outbox.Pending(0)
	if err != nil {
		t.Fatalf("Outbox.Pending: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("outbox pending = %d, want 1", len(pending))
	}
	entry := pending[0]
	if entry.Channel != outbox.ChannelAnalyst {
		t.Errorf("channel = %q, want analyst", entry.Channel)
	}
	if entry.IdemKey != "t3-deadbeefcafef00d" {
		t.Errorf("idem key = %q, want t3-deadbeefcafef00d", entry.IdemKey)
	}
	if !strings.Contains(entry.Body, "🔬 HYPOTHESIS (unverified)") {
		t.Errorf("body = %q, want the hypothesis prefix", entry.Body)
	}
	if !strings.Contains(entry.Body, "disk latency on 192.0.2.10") {
		t.Errorf("body = %q, want the hypothesis text", entry.Body)
	}
	if !strings.Contains(entry.Body, "row-1") || !strings.Contains(entry.Body, "row-2") {
		t.Errorf("body = %q, want the evidence row ids", entry.Body)
	}
	if !strings.Contains(entry.Body, "192.0.2.10") {
		t.Errorf("body = %q, want the target", entry.Body)
	}
	for _, sevWord := range []string{"critical", "warning", "info", "Critical", "Warning", "Info"} {
		if strings.Contains(entry.Body, sevWord) {
			t.Errorf("body = %q, must contain NO severity vocabulary (found %q)", entry.Body, sevWord)
		}
	}
	if strings.Contains(entry.Body, "@") {
		t.Errorf("body = %q, must contain NO @-mentions", entry.Body)
	}
}

func TestHandleHypothesisDedup(t *testing.T) {
	deps, _ := testDeps(t, 10, nil)
	post := hypPost(validHypothesis())

	first, err := bridge.HandleHypothesis(context.Background(), fixedNow, deps, post, bridge.PolicyTelegramOnly)
	if err != nil {
		t.Fatalf("HandleHypothesis #1: %v", err)
	}
	if !first.Enqueued || first.Deduped {
		t.Errorf("first = %+v, want Enqueued=true Deduped=false", first)
	}

	second, err := bridge.HandleHypothesis(context.Background(), fixedNow, deps, post, bridge.PolicyTelegramOnly)
	if err != nil {
		t.Fatalf("HandleHypothesis #2: %v", err)
	}
	if second.Enqueued || !second.Deduped {
		t.Errorf("second = %+v, want Enqueued=false Deduped=true", second)
	}

	pending, err := deps.Outbox.Pending(0)
	if err != nil {
		t.Fatalf("Outbox.Pending: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("outbox pending = %d, want 1 (dedup must not duplicate)", len(pending))
	}
}

func TestHandleHypothesisReRedaction(t *testing.T) {
	// Split-literal glpat-shaped token: no contiguous "glpat-<20+chars>"
	// string appears anywhere in this file's source (public-mirror scanner
	// requirement). It is still exactly the glpat- shape at runtime, so the
	// redactor matches and strips it.
	fakeToken := "glp" + "at-" + "zzzzzzzzzzzzzzzzzzzzzzzz" // runtime: glpat- + 24 'z'

	h := validHypothesis()
	h.Hypothesis = "found a leaked token " + fakeToken + " in the log digest"
	post := hypPost(h)

	deps, _ := testDeps(t, 10, nil)
	result, err := bridge.HandleHypothesis(context.Background(), fixedNow, deps, post, bridge.PolicyTelegramOnly)
	if err != nil {
		t.Fatalf("HandleHypothesis: %v", err)
	}
	// The redactor pattern-matches successfully here, so this is not a
	// redaction FAILURE (Withheld) — it's a successful strip.
	if result.RedactionFailures != 0 {
		t.Errorf("RedactionFailures = %d, want 0 (redaction succeeded, just stripped the token)", result.RedactionFailures)
	}

	pending, err := deps.Outbox.Pending(0)
	if err != nil {
		t.Fatalf("Outbox.Pending: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("outbox pending = %d, want 1", len(pending))
	}
	if strings.Contains(pending[0].Body, fakeToken) {
		t.Errorf("enqueued body leaked the raw token: %q", pending[0].Body)
	}
	if !strings.Contains(pending[0].Body, "REDACTED") {
		t.Errorf("enqueued body = %q, want a [REDACTED:...] marker", pending[0].Body)
	}
}

func TestHandleHypothesisInvalidPost(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(p *bridge.HypothesisPost)
	}{
		{"bad schema_version", func(p *bridge.HypothesisPost) { p.SchemaVersion = 2 }},
		{"empty run_id", func(p *bridge.HypothesisPost) { p.RunID = "" }},
		{"empty fingerprint", func(p *bridge.HypothesisPost) { p.Hypothesis.Fingerprint = "" }},
		{"empty evidence_rows", func(p *bridge.HypothesisPost) { p.Hypothesis.EvidenceRows = nil }},
		{"invalid kind", func(p *bridge.HypothesisPost) { p.Hypothesis.Kind = "not-a-kind" }},
		{"invalid confidence", func(p *bridge.HypothesisPost) { p.Hypothesis.Confidence = "not-a-confidence" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			deps, _ := testDeps(t, 10, nil)
			post := hypPost(validHypothesis())
			tc.mutate(&post)

			result, err := bridge.HandleHypothesis(context.Background(), fixedNow, deps, post, bridge.PolicyTelegramOnly)
			if err == nil {
				t.Fatal("HandleHypothesis: want error, got nil")
			}
			if result != (bridge.HypResult{}) {
				t.Errorf("result = %+v, want zero value on rejection", result)
			}
			pending, perr := deps.Outbox.Pending(0)
			if perr != nil {
				t.Fatalf("Outbox.Pending: %v", perr)
			}
			if len(pending) != 0 {
				t.Errorf("outbox pending = %d, want 0 (nothing enqueued on rejection)", len(pending))
			}
		})
	}
}

func TestHandleHypothesisTicketPolicyAlwaysOpensTicket(t *testing.T) {
	deps, ft := testDeps(t, 10, nil)
	post := hypPost(validHypothesis())

	result, err := bridge.HandleHypothesis(context.Background(), fixedNow, deps, post, bridge.PolicyAlways)
	if err != nil {
		t.Fatalf("HandleHypothesis: %v", err)
	}
	if !result.Ticketed {
		t.Error("Ticketed = false, want true (PolicyAlways)")
	}
	if len(ft.opens) != 1 {
		t.Fatalf("tracker Open called %d times, want 1", len(ft.opens))
	}
	req := ft.opens[0]
	if req.Marker != "[hb:t3-deadbeefcafef00d]" {
		t.Errorf("marker = %q, want [hb:t3-deadbeefcafef00d]", req.Marker)
	}
	if req.Priority != "Minor" {
		t.Errorf("priority = %q, want Minor", req.Priority)
	}
	if req.Type != "Task" {
		t.Errorf("type = %q, want Task", req.Type)
	}
	wantTags := map[string]bool{"heimdall": false, "heimdall-hypothesis": false}
	for _, tag := range req.Tags {
		if _, ok := wantTags[tag]; ok {
			wantTags[tag] = true
		}
	}
	for tag, seen := range wantTags {
		if !seen {
			t.Errorf("tags = %v, want %q present", req.Tags, tag)
		}
	}
	if !strings.HasPrefix(req.Summary, "HYPOTHESIS: ") {
		t.Errorf("summary = %q, want HYPOTHESIS: prefix", req.Summary)
	}
	if !strings.Contains(req.Description, "LLM HYPOTHESIS") {
		t.Errorf("description = %q, want the LLM HYPOTHESIS preamble", req.Description)
	}
}

func TestHandleHypothesisTicketPolicyHighConfidenceGatesOnConfidence(t *testing.T) {
	deps, ft := testDeps(t, 10, nil)

	low := validHypothesis()
	low.Confidence = contract.ConfidenceMedium
	low.Fingerprint = "fp-medium-conf"
	resLow, err := bridge.HandleHypothesis(context.Background(), fixedNow, deps, hypPost(low), bridge.PolicyHighConfidence)
	if err != nil {
		t.Fatalf("HandleHypothesis (medium): %v", err)
	}
	if resLow.Ticketed {
		t.Error("Ticketed = true for medium confidence, want false")
	}

	high := validHypothesis()
	high.Confidence = contract.ConfidenceHigh
	high.Fingerprint = "fp-high-conf"
	resHigh, err := bridge.HandleHypothesis(context.Background(), fixedNow, deps, hypPost(high), bridge.PolicyHighConfidence)
	if err != nil {
		t.Fatalf("HandleHypothesis (high): %v", err)
	}
	if !resHigh.Ticketed {
		t.Error("Ticketed = false for high confidence, want true")
	}
	if len(ft.opens) != 1 {
		t.Errorf("tracker Open called %d times, want 1 (only the high-confidence hypothesis)", len(ft.opens))
	}
}

func TestHandleHypothesisExistingMarkerSkipsDuplicateTicket(t *testing.T) {
	deps, ft := testDeps(t, 10, nil)
	post := hypPost(validHypothesis())

	first, err := bridge.HandleHypothesis(context.Background(), fixedNow, deps, post, bridge.PolicyAlways)
	if err != nil {
		t.Fatalf("HandleHypothesis #1: %v", err)
	}
	if !first.Ticketed {
		t.Fatal("first: Ticketed = false, want true")
	}

	second, err := bridge.HandleHypothesis(context.Background(), fixedNow, deps, post, bridge.PolicyAlways)
	if err != nil {
		t.Fatalf("HandleHypothesis #2: %v", err)
	}
	if second.Ticketed {
		t.Error("second: Ticketed = true, want false (existing marker, no duplicate)")
	}
	if len(ft.opens) != 1 {
		t.Errorf("tracker Open called %d times across two identical hypotheses, want 1", len(ft.opens))
	}
}

// TestHandleHypothesisG1NeverPages is the G1 proof: whatever the policy,
// HandleHypothesis's only outbox channel is analyst, and it never calls
// Transition or Priority (both of which stay reserved for Reconcile's
// auto-close path and EscalationSweep, never the hypothesis path).
func TestHandleHypothesisG1NeverPages(t *testing.T) {
	for _, policy := range []bridge.TicketPolicy{bridge.PolicyTelegramOnly, bridge.PolicyHighConfidence, bridge.PolicyAlways} {
		deps, ft := testDeps(t, 10, nil)
		h := validHypothesis()
		h.Confidence = contract.ConfidenceHigh
		post := hypPost(h)

		if _, err := bridge.HandleHypothesis(context.Background(), fixedNow, deps, post, policy); err != nil {
			t.Fatalf("HandleHypothesis (%s): %v", policy, err)
		}

		pending, err := deps.Outbox.Pending(0)
		if err != nil {
			t.Fatalf("Outbox.Pending (%s): %v", policy, err)
		}
		for _, e := range pending {
			if e.Channel != outbox.ChannelAnalyst {
				t.Errorf("policy %s: outbox entry channel = %q, want analyst only (G1: a hypothesis can never page)", policy, e.Channel)
			}
		}
		if len(ft.transitions) != 0 {
			t.Errorf("policy %s: tracker Transition called %d times, want 0", policy, len(ft.transitions))
		}
		if len(ft.priorities) != 0 {
			t.Errorf("policy %s: tracker Priority called %d times, want 0 (G1: only EscalationSweep may raise priority)", policy, len(ft.priorities))
		}
	}
}
