package suppress_test

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/lazarevtill/heimdall/internal/suppress"
)

func TestNewAuthorityUnionAndFindingSuppression(t *testing.T) {
	declarative := []suppress.Suppression{validFingerprintRec()}
	runtime := []suppress.Suppression{validGroupCheckRec()}

	auth, skipped := suppress.NewAuthority(declarative, runtime)
	if skipped != 0 {
		t.Fatalf("skipped = %d, want 0 for two valid records", skipped)
	}

	f := mustFinding(t, "smart-fail", "disk", "192.0.2.30")
	got := auth.FindingSuppression(fixedNow, f)
	if got == nil {
		t.Fatal("FindingSuppression = nil, want the runtime group_check record")
	}
	if got.Key != "gc-1" {
		t.Errorf("FindingSuppression key = %q, want gc-1", got.Key)
	}

	unmatched := mustFinding(t, "other-check", "other-group", "192.0.2.31")
	if got := auth.FindingSuppression(fixedNow, unmatched); got != nil {
		t.Errorf("FindingSuppression = %+v, want nil for an unmatched finding", got)
	}

	// At a time after the record has expired, it must no longer suppress.
	farFuture := fixedNow.Add(365 * 24 * time.Hour)
	if got := auth.FindingSuppression(farFuture, f); got != nil {
		t.Errorf("FindingSuppression at an expired time = %+v, want nil", got)
	}
}

func TestNewAuthoritySkipsInvalidRuntimeRows(t *testing.T) {
	valid := validGroupCheckRec()
	invalid := validGroupCheckRec()
	invalid.Key = "bad-1"
	invalid.Reason = "" // invalid: empty reason

	auth, skipped := suppress.NewAuthority(nil, []suppress.Suppression{valid, invalid})
	if skipped != 1 {
		t.Fatalf("skipped = %d, want 1", skipped)
	}
	f := mustFinding(t, "smart-fail", "disk", "192.0.2.32")
	if got := auth.FindingSuppression(fixedNow, f); got == nil {
		t.Error("the valid record must still be present in the union")
	}
}

func TestAuthorityMatchFields(t *testing.T) {
	declarative := []suppress.Suppression{validFingerprintRec()}
	runtime := []suppress.Suppression{validGroupCheckRec()}
	auth, skipped := suppress.NewAuthority(declarative, runtime)
	if skipped != 0 {
		t.Fatalf("skipped = %d, want 0", skipped)
	}

	// Same scenario as TestNewAuthorityUnionAndFindingSuppression, but
	// driven off raw fields instead of a contract.Finding — this is the
	// exact shape internal/bridge calls with (Alertmanager labels), never
	// having built a contract.Finding at all.
	got := auth.MatchFields(fixedNow, "irrelevant-fp", "disk", "smart-fail", "192.0.2.30")
	if got == nil {
		t.Fatal("MatchFields = nil, want the runtime group_check record")
	}
	if got.Key != "gc-1" {
		t.Errorf("MatchFields key = %q, want gc-1", got.Key)
	}

	if got := auth.MatchFields(fixedNow, "irrelevant-fp", "other-group", "other-check", "192.0.2.31"); got != nil {
		t.Errorf("MatchFields = %+v, want nil for an unmatched group/check", got)
	}

	// The fingerprint-scoped record matches on fingerprint regardless of
	// group/check/target.
	if got := auth.MatchFields(fixedNow, "deadbeefcafef00d", "unrelated-group", "unrelated-check", "192.0.2.99"); got == nil {
		t.Error("MatchFields = nil, want the declarative fingerprint record to match on fingerprint alone")
	}

	// Expired-time check mirrors FindingSuppression's.
	farFuture := fixedNow.Add(365 * 24 * time.Hour)
	if got := auth.MatchFields(farFuture, "irrelevant-fp", "disk", "smart-fail", "192.0.2.30"); got != nil {
		t.Errorf("MatchFields at an expired time = %+v, want nil", got)
	}
}

func TestHypothesisSuppressed(t *testing.T) {
	auth, _ := suppress.NewAuthority([]suppress.Suppression{validHypothesisRec()}, nil)
	if !auth.HypothesisSuppressed(fixedNow, "hyp-fp-abc123") {
		t.Error("want suppressed for matching hyp_fp")
	}
	if auth.HypothesisSuppressed(fixedNow, "some-other-fp") {
		t.Error("want not suppressed for a different hyp_fp")
	}
}

func TestAnalystFeatureExcluded(t *testing.T) {
	auth, _ := suppress.NewAuthority([]suppress.Suppression{validAnalystRec()}, nil)
	if !auth.AnalystFeatureExcluded(fixedNow, "node-a", "cpu_p95_creep") {
		t.Error("want excluded for matching (target,feature)")
	}
	if auth.AnalystFeatureExcluded(fixedNow, "node-b", "cpu_p95_creep") {
		t.Error("want not excluded for a different target")
	}
}

func TestActiveAnnotationsSortedAndActiveOnly(t *testing.T) {
	active1 := validFingerprintRec()
	active1.Key = "zz-active"
	active2 := validTargetRec()
	active2.Key = "aa-active"
	expired := validGroupCheckRec()
	expired.Key = "mm-expired"
	expired.Until = pastRFC3339()

	auth, _ := suppress.NewAuthority([]suppress.Suppression{active1, active2, expired}, nil)
	got := auth.ActiveAnnotations(fixedNow)
	if len(got) != 2 {
		t.Fatalf("len(ActiveAnnotations) = %d, want 2 (expired excluded)", len(got))
	}
	want := []string{active2.Annotation(), active1.Annotation()} // aa-active before zz-active
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("ActiveAnnotations not sorted by key (-want +got):\n%s", diff)
	}
}

func TestActiveSilencesProjection(t *testing.T) {
	fp := validFingerprintRec()
	fp.Key = "sil-fp"
	gc := validGroupCheckRec()
	gc.Key = "sil-gc"
	tgt := validTargetRec()
	tgt.Key = "sil-tgt"
	hyp := validHypothesisRec()
	hyp.Key = "sil-hyp"
	an := validAnalystRec()
	an.Key = "sil-an"
	never := validNeverRec()
	never.Key = "sil-never"
	expired := validTargetRec()
	expired.Key = "sil-expired"
	expired.Until = pastRFC3339()

	auth, _ := suppress.NewAuthority([]suppress.Suppression{fp, gc, tgt, hyp, an, never, expired}, nil)
	silences := auth.ActiveSilences(fixedNow)

	byKey := map[string]suppress.Silence{}
	for _, s := range silences {
		byKey[s.Key] = s
	}

	if len(silences) != 3 {
		t.Fatalf("len(ActiveSilences) = %d, want 3 (only fingerprint/group_check/target scopes, dated+active)", len(silences))
	}
	for _, key := range []string{"sil-hyp", "sil-an", "sil-never", "sil-expired"} {
		if _, ok := byKey[key]; ok {
			t.Errorf("Silence for %s must not be materialized", key)
		}
	}

	wantEndsAt, err := time.Parse(time.RFC3339, fp.Until)
	if err != nil {
		t.Fatalf("parse fixture until: %v", err)
	}

	if s, ok := byKey["sil-fp"]; !ok {
		t.Error("missing fingerprint silence")
	} else {
		if diff := cmp.Diff(map[string]string{"fingerprint": fp.Matcher.Fingerprint}, s.Matchers); diff != "" {
			t.Errorf("fingerprint silence matchers (-want +got):\n%s", diff)
		}
		if !s.EndsAt.Equal(wantEndsAt) {
			t.Errorf("fingerprint silence EndsAt = %v, want %v", s.EndsAt, wantEndsAt)
		}
	}
	if s, ok := byKey["sil-gc"]; !ok {
		t.Error("missing group_check silence")
	} else if diff := cmp.Diff(map[string]string{"group": gc.Matcher.Group, "check": gc.Matcher.Check}, s.Matchers); diff != "" {
		t.Errorf("group_check silence matchers (-want +got):\n%s", diff)
	}
	if s, ok := byKey["sil-tgt"]; !ok {
		t.Error("missing target silence")
	} else if diff := cmp.Diff(map[string]string{"target": tgt.Matcher.Target}, s.Matchers); diff != "" {
		t.Errorf("target silence matchers (-want +got):\n%s", diff)
	}
}
