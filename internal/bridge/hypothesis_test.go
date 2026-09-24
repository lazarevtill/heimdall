package bridge_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/google/go-cmp/cmp"
	"github.com/lazarevtill/heimdall/internal/bridge"
	"github.com/lazarevtill/heimdall/internal/contract"
	"github.com/lazarevtill/heimdall/internal/outbox"
	"github.com/lazarevtill/heimdall/internal/suppress"
)

// Fixture row ids: digest row ids ARE finding fingerprints (16 lowercase
// hex), which the bridge now validates. Made-up values.
const (
	row1 = "00000000000000a1"
	row2 = "00000000000000a2"
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
		EvidenceRows:   []string{row1, row2},
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
	if !strings.Contains(entry.Body, row1) || !strings.Contains(entry.Body, row2) {
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
		{"fingerprint not hex", func(p *bridge.HypothesisPost) { p.Hypothesis.Fingerprint = "fp-medium-conf!!" }},
		{"fingerprint shaped like a finding key", func(p *bridge.HypothesisPost) { p.Hypothesis.Fingerprint = "node--c1-deadman" }},
		{"evidence row carrying free text", func(p *bridge.HypothesisPost) {
			p.Hypothesis.EvidenceRows = []string{row1, "Bearer " + strings.Repeat("x", 20)}
		}},
		{"hypothesis over HypMaxText runes", func(p *bridge.HypothesisPost) {
			p.Hypothesis.Hypothesis = strings.Repeat("ж", contract.HypMaxText+1)
		}},
		{"suggested_check over HypMaxText runes", func(p *bridge.HypothesisPost) {
			p.Hypothesis.SuggestedCheck = strings.Repeat("x", contract.HypMaxText+1)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			deps, _ := testDeps(t, 10, nil)
			post := hypPost(validHypothesis())
			tc.mutate(&post)

			result, err := bridge.HandleHypothesis(context.Background(), fixedNow, deps, post, bridge.PolicyTelegramOnly)
			if !errors.Is(err, bridge.ErrInvalidHypothesis) {
				t.Fatalf("HandleHypothesis: err = %v, want one wrapping ErrInvalidHypothesis", err)
			}
			if verr := bridge.ValidateHypothesisPost(post); !errors.Is(verr, bridge.ErrInvalidHypothesis) {
				t.Errorf("ValidateHypothesisPost: err = %v, want one wrapping ErrInvalidHypothesis", verr)
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

// Every field of a well-formed post is individually bounded, but together
// they can render past contract.HypMaxBody. That is the bridge's own
// rendering, so it fits the message itself — targets first, then the
// hypothesis text, evidence rows last — rather than 400ing a post the analyst would
// re-send, and be refused for, on every run.
func TestHandleHypothesisFitsAnOverCapBodyInsteadOfRefusingIt(t *testing.T) {
	many := func(n int, item string) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = item
		}
		return out
	}
	tests := []struct {
		name         string
		mutate       func(h *contract.HypothesisFinding)
		wantInBody   []string
		wantNotTexts bool // the hypothesis text itself had to be cut
	}{
		{"long targets list is summarised", func(h *contract.HypothesisFinding) {
			h.Targets = many(40, strings.Repeat("t", 60))
		}, []string{"(+", "more)", row1, row2, "disk latency"}, false},
		{"max-length multi-byte hypothesis is cut on a rune boundary", func(h *contract.HypothesisFinding) {
			h.Hypothesis = strings.Repeat("😀", contract.HypMaxText) // 4 bytes each: 2000 bytes alone
			h.Targets = many(8, strings.Repeat("t", 40))
		}, []string{row1, row2, "…"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deps, _ := testDeps(t, 10, nil)
			h := validHypothesis()
			tt.mutate(&h)

			result, err := bridge.HandleHypothesis(context.Background(), fixedNow, deps, hypPost(h), bridge.PolicyTelegramOnly)
			if err != nil {
				t.Fatalf("HandleHypothesis: %v (a well-formed post must be accepted)", err)
			}
			if !result.Enqueued {
				t.Fatalf("result = %+v, want Enqueued", result)
			}
			pending, err := deps.Outbox.Pending(0)
			if err != nil || len(pending) != 1 {
				t.Fatalf("Outbox.Pending = %d entries, err %v; want 1", len(pending), err)
			}
			body := pending[0].Body
			if len(body) > contract.HypMaxBody {
				t.Errorf("body is %d bytes, want <= %d", len(body), contract.HypMaxBody)
			}
			if !utf8.ValidString(body) {
				t.Error("body is not valid UTF-8: a rune was split")
			}
			for _, want := range tt.wantInBody {
				if !strings.Contains(body, want) {
					t.Errorf("body lacks %q:\n%s", want, body)
				}
			}
			if cut := !strings.Contains(body, h.Hypothesis); cut != tt.wantNotTexts {
				t.Errorf("hypothesis text cut = %v, want %v", cut, tt.wantNotTexts)
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
	low.Fingerprint = "00000000000000b1"
	resLow, err := bridge.HandleHypothesis(context.Background(), fixedNow, deps, hypPost(low), bridge.PolicyHighConfidence)
	if err != nil {
		t.Fatalf("HandleHypothesis (medium): %v", err)
	}
	if resLow.Ticketed {
		t.Error("Ticketed = true for medium confidence, want false")
	}

	high := validHypothesis()
	high.Confidence = contract.ConfidenceHigh
	high.Fingerprint = "00000000000000b2"
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

// wj is U+2060 WORD JOINER, what the bridge inserts after every '@'.
const wj = "\u2060"

// TestHandleHypothesisHonoursAHypothesisMute: the notifier's [Not useful ->
// mute 30d] writes a hypothesis-scope suppression; while it is active the
// hypothesis goes nowhere — no analyst message, no ticket.
func TestHandleHypothesisHonoursAHypothesisMute(t *testing.T) {
	authority, skipped := suppress.NewAuthority(nil, []suppress.Suppression{{
		Key: "btn-t3-deadbeefcafef00d", Scope: suppress.ScopeHypothesis,
		Matcher: suppress.Matcher{HypFP: "deadbeefcafef00d"},
		Until:   fixedNow.Add(30 * 24 * time.Hour).Format(time.RFC3339), CumulativeDays: 30,
		Reason: "muted via Telegram [Not useful -> mute 30d]", Actor: "ops", Source: suppress.SourceRuntime,
	}})
	if skipped != 0 {
		t.Fatalf("authority skipped %d", skipped)
	}
	deps, ft := testDeps(t, 10, authority)
	got, err := bridge.HandleHypothesis(context.Background(), fixedNow, deps, hypPost(validHypothesis()), bridge.PolicyAlways)
	if err != nil {
		t.Fatalf("HandleHypothesis: %v", err)
	}
	if diff := cmp.Diff(bridge.HypResult{Suppressed: true}, got); diff != "" {
		t.Errorf("result mismatch (-want +got):\n%s", diff)
	}
	pending, err := deps.Outbox.Pending(0)
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	if len(pending) != 0 || len(ft.opens) != 0 {
		t.Errorf("pending = %d, opens = %d; want nothing sent or ticketed", len(pending), len(ft.opens))
	}
}

// TestHandleHypothesisRedeliversAfterTheCooldown: the key "t3-<fp>" never
// changes (the notifier parses it), yet a hypothesis the analyst re-posts
// after its 7-day cooldown must reach the channel again — while a re-post
// inside the window (a retry), or one whose first delivery is still
// pending, stays a no-op.
func TestHandleHypothesisRedeliversAfterTheCooldown(t *testing.T) {
	cases := []struct {
		name      string
		sentFirst bool
		after     time.Duration
		want      bridge.HypResult
	}{
		{"retry inside the cooldown", true, 24 * time.Hour, bridge.HypResult{Deduped: true}},
		{"recurrence after the cooldown", true, 8 * 24 * time.Hour, bridge.HypResult{Enqueued: true, Rearmed: true}},
		// The analyst's own 7 days run from its run START, so its re-post of
		// a hypothesis whose first post landed after a slow LLM call can
		// arrive minutes short of 7 days by the bridge's clock. That is
		// still the recurrence, not a retry.
		{"analyst re-post a few minutes short of 7 days", true, bridge.HypothesisCooldown - 5*time.Minute, bridge.HypResult{Enqueued: true, Rearmed: true}},
		{"first delivery still pending", false, 8 * 24 * time.Hour, bridge.HypResult{Deduped: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			deps, _ := testDeps(t, 10, nil)
			if _, err := bridge.HandleHypothesis(context.Background(), fixedNow, deps, hypPost(validHypothesis()), bridge.PolicyTelegramOnly); err != nil {
				t.Fatalf("first: %v", err)
			}
			if tc.sentFirst {
				markAllSent(t, deps, fixedNow)
			}
			again := hypPost(validHypothesis())
			again.RunID = "run-0999"
			got, err := bridge.HandleHypothesis(context.Background(), fixedNow.Add(tc.after), deps, again, bridge.PolicyTelegramOnly)
			if err != nil {
				t.Fatalf("second: %v", err)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("result mismatch (-want +got):\n%s", diff)
			}
			pending, err := deps.Outbox.Pending(0)
			if err != nil {
				t.Fatalf("Pending: %v", err)
			}
			for _, e := range pending {
				if e.IdemKey != "t3-deadbeefcafef00d" {
					t.Errorf("idem key = %q, want the unchanged t3-deadbeefcafef00d", e.IdemKey)
				}
			}
		})
	}
}

// TestHandleHypothesisCannotMentionAnyone: model text naming a human would
// notify them (Telegram links @username even in plain text; YouTrack
// @login notifies) — a page by another name. Every '@' is neutralised in
// the analyst message, the ticket summary and the (fenced) ticket body.
func TestHandleHypothesisCannotMentionAnyone(t *testing.T) {
	deps, ft := testDeps(t, 10, nil)
	h := validHypothesis()
	h.Hypothesis = "@oncall wake up, disk on 192.0.2.10 is dying"
	h.Targets = []string{"@ops"}
	if _, err := bridge.HandleHypothesis(context.Background(), fixedNow, deps, hypPost(h), bridge.PolicyAlways); err != nil {
		t.Fatalf("HandleHypothesis: %v", err)
	}
	pending, err := deps.Outbox.Pending(0)
	if err != nil || len(pending) != 1 {
		t.Fatalf("Pending: %v (%d)", err, len(pending))
	}
	if len(ft.opens) != 1 {
		t.Fatalf("opens = %d, want 1", len(ft.opens))
	}
	for name, text := range map[string]string{
		"analyst message": pending[0].Body,
		"ticket summary":  ft.opens[0].Summary,
		"ticket body":     ft.opens[0].Description,
	} {
		for _, live := range []string{"@oncall", "@ops"} {
			if strings.Contains(text, live) {
				t.Errorf("%s carries a live mention %q:\n%s", name, live, text)
			}
		}
		if !strings.Contains(text, "@"+wj+"oncall") {
			t.Errorf("%s = %q, want the neutralised @%soncall", name, text, wj)
		}
	}
	if !strings.Contains(ft.opens[0].Description, "```\n") {
		t.Errorf("ticket body = %q, want the hypothesis fenced", ft.opens[0].Description)
	}
}
