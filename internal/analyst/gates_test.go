package analyst_test

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/google/go-cmp/cmp"

	"github.com/lazarevtill/heimdall/internal/analyst"
	"github.com/lazarevtill/heimdall/internal/contract"
	"github.com/lazarevtill/heimdall/internal/llm"
)

// The digest goes to the LLM egress as a JSON DOCUMENT (llm.Request.UserJSON),
// so the egress redacts it string by string rather than as one serialized
// blob — and when nothing needs redacting, what the model is given decodes
// to exactly the digest Run was handed.
func TestRunSendsTheDigestAsJSONForPerFieldRedaction(t *testing.T) {
	a := &fakeAnalyzer{result: mustAnalyzeResult(t, contract.AnalystOutput{NothingNotable: true})}
	dg := testDigest()
	var persisted contract.AnalystRun
	if _, err := analyst.Run(context.Background(), a, openTestStore(t), &fakePoster{},
		capturePersist(&persisted, nil), baseParams(fixedNow, dg)); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if a.req.User != "" {
		t.Errorf("Request.User = %q, want empty: the digest must travel as UserJSON", a.req.User)
	}
	var got contract.Digest
	if err := json.Unmarshal(a.req.UserJSON, &got); err != nil {
		t.Fatalf("Request.UserJSON is not a digest: %v", err)
	}
	if diff := cmp.Diff(dg, got); diff != "" {
		t.Errorf("digest sent to the model differs from the input (-want +got):\n%s", diff)
	}
}

// Redact FIRST, then truncate (contract/redact.go): cutting first can leave
// the head of a secret behind, too short for its pattern to recognise.
// Each field is padded so the secret straddles the rune cap.
func TestRunRedactsBeforeTruncating(t *testing.T) {
	secretHead := "glp" + "at-" // split literal: see TestRunRedactsSecretShapedTextAtEgress
	secret := secretHead + strings.Repeat("A", 24)
	padded := strings.Repeat("x", contract.HypMaxText-20) + secret // 480 + 30 runes

	tests := []struct {
		name  string
		set   func(*contract.HypothesisFinding)
		field func(contract.HypothesisFinding) string
	}{
		{"hypothesis", func(f *contract.HypothesisFinding) { f.Hypothesis = padded },
			func(f contract.HypothesisFinding) string { return f.Hypothesis }},
		{"suggested_check", func(f *contract.HypothesisFinding) { f.SuggestedCheck = padded },
			func(f contract.HypothesisFinding) string { return f.SuggestedCheck }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := validFinding("row-1")
			tt.set(&f)
			a := &fakeAnalyzer{result: mustAnalyzeResult(t, contract.AnalystOutput{Findings: []contract.HypothesisFinding{f}})}
			var persisted contract.AnalystRun
			if _, err := analyst.Run(context.Background(), a, openTestStore(t), &fakePoster{},
				capturePersist(&persisted, nil), baseParams(fixedNow, testDigest())); err != nil {
				t.Fatalf("Run: %v", err)
			}
			got := tt.field(persisted.Findings[0])
			if strings.Contains(got, secretHead) {
				t.Errorf("persisted %s kept part of the secret: ...%q", tt.name, got[len(got)-30:])
			}
			if n := utf8.RuneCountInString(got); n > contract.HypMaxText {
				t.Errorf("persisted %s is %d runes, want <= %d", tt.name, n, contract.HypMaxText)
			}
		})
	}
}

// Two findings the model worded differently but that cite the same rows are
// ONE hypothesis (same wrapper hyp_fp). The second must not take a cap slot
// that a distinct hypothesis needs, nor be posted twice in one run.
func TestRunDropsARepeatedFingerprintWithinOneRun(t *testing.T) {
	first := validFinding("row-1")
	repeat := validFinding("row-1", "row-1") // same row set, same hyp_fp
	repeat.Hypothesis = "the same observation, reworded"
	distinct := validFinding("row-2")
	distinct.Confidence = contract.ConfidenceLow

	a := &fakeAnalyzer{result: mustAnalyzeResult(t, contract.AnalystOutput{
		Findings: []contract.HypothesisFinding{first, repeat, distinct},
	})}
	poster := &fakePoster{}
	var persisted contract.AnalystRun
	p := baseParams(fixedNow, testDigest())
	p.MaxPerRun = 2
	out, err := analyst.Run(context.Background(), a, openTestStore(t), poster, capturePersist(&persisted, nil), p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	var gotFPs []string
	for _, h := range poster.posted {
		gotFPs = append(gotFPs, h.Fingerprint)
	}
	wantFPs := []string{contract.HypFingerprint([]string{"row-1"}), contract.HypFingerprint([]string{"row-2"})}
	sort.Strings(gotFPs)
	sort.Strings(wantFPs)
	if diff := cmp.Diff(wantFPs, gotFPs); diff != "" {
		t.Errorf("posted fingerprints (-want +got):\n%s", diff)
	}
	if out.Deduped != 1 || out.CapDropped != 0 {
		t.Errorf("Deduped = %d, CapDropped = %d, want 1 and 0", out.Deduped, out.CapDropped)
	}
	if persisted.Findings[0].Hypothesis != first.Hypothesis && persisted.Findings[1].Hypothesis != first.Hypothesis {
		t.Errorf("the FIRST of the repeated findings should survive, persisted = %+v", persisted.Findings)
	}
}

// evidence_rows are de-duplicated and sorted BEFORE the slice bound, so the
// rows kept — and the hyp_fp computed from them — depend only on the SET the
// model cited, never on its ordering or repetition.
func TestRunEvidenceRowsAreCanonicalBeforeBounding(t *testing.T) {
	var rows []contract.DigestRow
	var ids []string
	for i := 0; i < 20; i++ {
		id := "row-" + string(rune('a'+i))
		rows = append(rows, contract.DigestRow{RowID: id})
		ids = append(ids, id)
	}
	dg := contract.Digest{SchemaVersion: 1, Rows: rows}
	wantRows := append([]string(nil), ids[:16]...) // sorted, first 16

	reversed := make([]string, 0, len(ids)+3)
	for i := len(ids) - 1; i >= 0; i-- {
		reversed = append(reversed, ids[i])
	}
	reversed = append(reversed, ids[19], ids[18], ids[0]) // repeats

	tests := []struct {
		name  string
		cited []string
	}{
		{"model order", ids},
		{"reversed with repeats", reversed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := validFinding(tt.cited...)
			a := &fakeAnalyzer{result: mustAnalyzeResult(t, contract.AnalystOutput{Findings: []contract.HypothesisFinding{f}})}
			var persisted contract.AnalystRun
			if _, err := analyst.Run(context.Background(), a, openTestStore(t), &fakePoster{},
				capturePersist(&persisted, nil), baseParams(fixedNow, dg)); err != nil {
				t.Fatalf("Run: %v", err)
			}
			got := persisted.Findings[0]
			if diff := cmp.Diff(wantRows, got.EvidenceRows); diff != "" {
				t.Errorf("persisted evidence_rows (-want +got):\n%s", diff)
			}
			if want := contract.HypFingerprint(wantRows); got.Fingerprint != want {
				t.Errorf("hyp_fp = %q, want %q", got.Fingerprint, want)
			}
		})
	}
}

// The model's reply must have the schema's shape before anything in it is
// believed. A reply that is missing a required key, or carries the wrong
// schema_version, is a hard failure — in particular `{}` and `null` must
// NOT read as the all-clear, which is only ever an explicit
// nothing_notable:true with an empty findings array (contract/hypothesis.go).
func TestRunRejectsOutputOutsideTheSchemaShape(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{"empty object", `{}`},
		{"null", `null`},
		{"findings missing", `{"schema_version":1,"nothing_notable":true}`},
		{"findings null", `{"schema_version":1,"nothing_notable":true,"findings":null}`},
		{"nothing_notable missing", `{"schema_version":1,"findings":[]}`},
		{"schema_version missing", `{"nothing_notable":true,"findings":[]}`},
		{"schema_version 0", `{"schema_version":0,"nothing_notable":true,"findings":[]}`},
		{"schema_version 2", `{"schema_version":2,"nothing_notable":true,"findings":[]}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &fakeAnalyzer{result: llm.Result{Content: []byte(tt.content)}}
			poster := &fakePoster{}
			persist := func(contract.AnalystRun) error {
				t.Error("persist must not be called for an output outside the schema shape")
				return nil
			}
			if _, err := analyst.Run(context.Background(), a, openTestStore(t), poster, persist, baseParams(fixedNow, testDigest())); err == nil {
				t.Fatal("Run: want a hard error, got nil")
			}
			if len(poster.posted) != 0 {
				t.Errorf("poster.posted = %+v, want nothing", poster.posted)
			}
		})
	}
}

// The sanctioned all-clear is accepted as such.
func TestRunAcceptsTheSanctionedAllClear(t *testing.T) {
	a := &fakeAnalyzer{result: llm.Result{Content: []byte(`{"schema_version":1,"nothing_notable":true,"findings":[]}`)}}
	var persisted contract.AnalystRun
	if _, err := analyst.Run(context.Background(), a, openTestStore(t), &fakePoster{},
		capturePersist(&persisted, nil), baseParams(fixedNow, testDigest())); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !persisted.NothingNotable || len(persisted.Findings) != 0 {
		t.Errorf("persisted = %+v, want an empty nothing_notable run", persisted)
	}
}

// What the bridge did with each POST decides what the run counts and
// whether the cooldown starts. Only a NEW enqueue is Posted; a bridge-side
// dedup is accepted (the bridge already holds it, so the cooldown starts)
// but is not a delivery; a failure is counted, handed back to the caller to
// log, and leaves the hypothesis eligible to post again next run.
func TestRunCountsWhatTheBridgeDid(t *testing.T) {
	postErr := errors.New("bridge said 503")
	tests := []struct {
		name         string
		poster       *fakePoster
		want         analyst.Outcome
		wantRecorded bool
	}{
		{"enqueued", &fakePoster{delivery: analyst.DeliveryEnqueued},
			analyst.Outcome{Posted: 1}, true},
		{"deduped by the bridge", &fakePoster{delivery: analyst.DeliveryDeduped},
			analyst.Outcome{BridgeDeduped: 1}, true},
		{"muted by an operator", &fakePoster{delivery: analyst.DeliverySuppressed},
			analyst.Outcome{BridgeSuppressed: 1}, true},
		{"post failed", &fakePoster{err: postErr},
			analyst.Outcome{PostFailed: 1}, false},
		{"poster reported no outcome", &fakePoster{noResult: true},
			analyst.Outcome{PostFailed: 1}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &fakeAnalyzer{result: mustAnalyzeResult(t, contract.AnalystOutput{Findings: []contract.HypothesisFinding{validFinding("row-1")}})}
			store := openTestStore(t)
			var persisted contract.AnalystRun
			out, err := analyst.Run(context.Background(), a, store, tt.poster, capturePersist(&persisted, nil), baseParams(fixedNow, testDigest()))
			if err != nil {
				t.Fatalf("Run: a POST outcome is never a hard failure, got %v", err)
			}
			got := analyst.Outcome{Posted: out.Posted, BridgeDeduped: out.BridgeDeduped, BridgeSuppressed: out.BridgeSuppressed, PostFailed: out.PostFailed}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("delivery counters (-want +got):\n%s", diff)
			}
			if tt.want.PostFailed > 0 {
				if len(out.Errors) != tt.want.PostFailed {
					t.Errorf("Errors = %v, want one per failed POST for the caller to log", out.Errors)
				}
				if tt.poster.err != nil && !errors.Is(out.Errors[0], postErr) {
					t.Errorf("Errors[0] = %v, want it to wrap the Poster's error", out.Errors[0])
				}
			} else if len(out.Errors) != 0 {
				t.Errorf("Errors = %v, want none", out.Errors)
			}
			recent, err := store.RecentlyPosted(fixedNow, contract.HypFingerprint([]string{"row-1"}), testCooldown)
			if err != nil {
				t.Fatalf("RecentlyPosted: %v", err)
			}
			if recent != tt.wantRecorded {
				t.Errorf("cooldown recorded = %v, want %v", recent, tt.wantRecorded)
			}
		})
	}
}
