package suppress_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lazarevtill/heimdall/internal/contract"
	"github.com/lazarevtill/heimdall/internal/suppress"
)

var fixedNow = time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)

func futureRFC3339() string { return fixedNow.Add(48 * time.Hour).Format(time.RFC3339) }
func pastRFC3339() string   { return fixedNow.Add(-48 * time.Hour).Format(time.RFC3339) }

func validFingerprintRec() suppress.Suppression {
	return suppress.Suppression{
		Key:            "fp-1",
		Scope:          suppress.ScopeFingerprint,
		Matcher:        suppress.Matcher{Fingerprint: "deadbeefcafef00d"},
		Until:          futureRFC3339(),
		CumulativeDays: 5,
		Reason:         "known flapping NIC, RMA pending",
		Actor:          "ops",
		Source:         suppress.SourceDeclarative,
	}
}

func validGroupCheckRec() suppress.Suppression {
	return suppress.Suppression{
		Key:            "gc-1",
		Scope:          suppress.ScopeGroupCheck,
		Matcher:        suppress.Matcher{Group: "disk", Check: "smart-fail"},
		Until:          futureRFC3339(),
		CumulativeDays: 3,
		Reason:         "vendor tool false-positive",
		Actor:          "ops",
		Source:         suppress.SourceRuntime,
	}
}

func validTargetRec() suppress.Suppression {
	return suppress.Suppression{
		Key:            "tgt-1",
		Scope:          suppress.ScopeTarget,
		Matcher:        suppress.Matcher{Target: "192.0.2.10"},
		Until:          futureRFC3339(),
		CumulativeDays: 1,
		Reason:         "maintenance window",
		Actor:          "ops",
		Source:         suppress.SourceRuntime,
	}
}

func validHypothesisRec() suppress.Suppression {
	return suppress.Suppression{
		Key:            "hyp-1",
		Scope:          suppress.ScopeHypothesis,
		Matcher:        suppress.Matcher{HypFP: "hyp-fp-abc123"},
		Until:          futureRFC3339(),
		CumulativeDays: 2,
		Reason:         "already triaged, tracked in ticket",
		Actor:          "analyst",
		Source:         suppress.SourceDeclarative,
	}
}

func validAnalystRec() suppress.Suppression {
	return suppress.Suppression{
		Key:            "an-1",
		Scope:          suppress.ScopeAnalyst,
		Matcher:        suppress.Matcher{Feature: "cpu_p95_creep", Target: "node-a"},
		Until:          futureRFC3339(),
		CumulativeDays: 0,
		Reason:         "known seasonal creep, already explained",
		Actor:          "analyst",
		Source:         suppress.SourceDeclarative,
	}
}

func validNeverRec() suppress.Suppression {
	return suppress.Suppression{
		Key:            "never-1",
		Scope:          suppress.ScopeTarget,
		Matcher:        suppress.Matcher{Target: "192.0.2.11"},
		Until:          "never",
		ReviewAfter:    futureRFC3339(),
		CumulativeDays: 0,
		Reason:         "permanently decommissioned pending hardware pull",
		Actor:          "ops",
		Source:         suppress.SourceDeclarative,
	}
}

func TestValidate(t *testing.T) {
	cases := []struct {
		name    string
		rec     suppress.Suppression
		wantErr bool
	}{
		{"valid fingerprint", validFingerprintRec(), false},
		{"valid group_check", validGroupCheckRec(), false},
		{"valid target", validTargetRec(), false},
		{"valid hypothesis", validHypothesisRec(), false},
		{"valid analyst", validAnalystRec(), false},
		{"valid never+review_after", validNeverRec(), false},
		{"missing until", func() suppress.Suppression {
			r := validFingerprintRec()
			r.Until = ""
			return r
		}(), true},
		{"never without review_after", func() suppress.Suppression {
			r := validTargetRec()
			r.Until = "never"
			r.ReviewAfter = ""
			return r
		}(), true},
		{"group_check missing check", func() suppress.Suppression {
			r := validGroupCheckRec()
			r.Matcher.Check = ""
			return r
		}(), true},
		{"group_check stray fingerprint", func() suppress.Suppression {
			r := validGroupCheckRec()
			r.Matcher.Fingerprint = "stray"
			return r
		}(), true},
		{"fingerprint missing fingerprint", func() suppress.Suppression {
			r := validFingerprintRec()
			r.Matcher.Fingerprint = ""
			return r
		}(), true},
		{"target missing target", func() suppress.Suppression {
			r := validTargetRec()
			r.Matcher.Target = ""
			return r
		}(), true},
		{"hypothesis missing hyp_fp", func() suppress.Suppression {
			r := validHypothesisRec()
			r.Matcher.HypFP = ""
			return r
		}(), true},
		{"analyst missing feature", func() suppress.Suppression {
			r := validAnalystRec()
			r.Matcher.Feature = ""
			return r
		}(), true},
		{"cumulative_days > 30 dated", func() suppress.Suppression {
			r := validFingerprintRec()
			r.CumulativeDays = 31
			return r
		}(), true},
		{"cumulative_days == 30 dated ok", func() suppress.Suppression {
			r := validFingerprintRec()
			r.CumulativeDays = 30
			return r
		}(), false},
		{"bad scope", func() suppress.Suppression {
			r := validFingerprintRec()
			r.Scope = "bogus"
			return r
		}(), true},
		{"empty reason", func() suppress.Suppression {
			r := validFingerprintRec()
			r.Reason = ""
			return r
		}(), true},
		{"until not RFC3339", func() suppress.Suppression {
			r := validFingerprintRec()
			r.Until = "not-a-date"
			return r
		}(), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.rec.Validate(fixedNow)
			if (err != nil) != tc.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func mustFinding(t *testing.T, check, group, target string) contract.Finding {
	t.Helper()
	f, err := contract.NewFinding(fixedNow, contract.FindingSpec{
		Check: check, Group: group, Target: target, Node: "node-a",
		Severity: contract.SeverityWarning, Class: contract.ClassHard,
		State: contract.StateFiring, Title: "t", Evidence: "e",
	})
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}
	return f
}

func TestMatchesFinding(t *testing.T) {
	fpRec := validFingerprintRec()
	f := mustFinding(t, "c-x", "grp", "tgt")
	f.Fingerprint = fpRec.Matcher.Fingerprint
	if !fpRec.MatchesFinding(fixedNow, f) {
		t.Error("fingerprint scope: want match on equal fingerprint")
	}
	other := mustFinding(t, "c-x", "grp", "tgt")
	other.Fingerprint = "different-fingerprint"
	if fpRec.MatchesFinding(fixedNow, other) {
		t.Error("fingerprint scope: want no match on different fingerprint")
	}

	gcRec := validGroupCheckRec()
	hit := mustFinding(t, "smart-fail", "disk", "192.0.2.20")
	if !gcRec.MatchesFinding(fixedNow, hit) {
		t.Error("group_check scope: want match on equal group+check")
	}
	missGroup := mustFinding(t, "smart-fail", "other-group", "192.0.2.20")
	if gcRec.MatchesFinding(fixedNow, missGroup) {
		t.Error("group_check scope: want no match on different group")
	}
	missCheck := mustFinding(t, "other-check", "disk", "192.0.2.20")
	if gcRec.MatchesFinding(fixedNow, missCheck) {
		t.Error("group_check scope: want no match on different check")
	}

	tgtRec := validTargetRec()
	hitT := mustFinding(t, "c", "g", tgtRec.Matcher.Target)
	if !tgtRec.MatchesFinding(fixedNow, hitT) {
		t.Error("target scope: want match on equal target")
	}
	missT := mustFinding(t, "c", "g", "192.0.2.99")
	if tgtRec.MatchesFinding(fixedNow, missT) {
		t.Error("target scope: want no match on different target")
	}

	// Expired record never matches even though the matcher would hit.
	expired := fpRec
	expired.Until = pastRFC3339()
	if expired.MatchesFinding(fixedNow, f) {
		t.Error("expired record must never match a Finding")
	}

	// hypothesis/analyst scopes never match a Finding, even with a
	// matcher that would otherwise coincide.
	hypRec := validHypothesisRec()
	if hypRec.MatchesFinding(fixedNow, f) {
		t.Error("hypothesis scope must never match a Finding")
	}
	anRec := validAnalystRec()
	if anRec.MatchesFinding(fixedNow, f) {
		t.Error("analyst scope must never match a Finding")
	}
}

func TestMatchesHypothesis(t *testing.T) {
	rec := validHypothesisRec()
	if !rec.MatchesHypothesis(fixedNow, rec.Matcher.HypFP) {
		t.Error("want match on equal hyp_fp")
	}
	if rec.MatchesHypothesis(fixedNow, "some-other-hyp-fp") {
		t.Error("want no match on different hyp_fp")
	}
	expired := rec
	expired.Until = pastRFC3339()
	if expired.MatchesHypothesis(fixedNow, rec.Matcher.HypFP) {
		t.Error("expired record must never match a hypothesis")
	}
	// scope isolation: a non-hypothesis-scoped record never matches.
	other := validFingerprintRec()
	if other.MatchesHypothesis(fixedNow, other.Matcher.Fingerprint) {
		t.Error("fingerprint scope must never match a hypothesis")
	}
}

func TestMatchesAnalystFeature(t *testing.T) {
	rec := validAnalystRec() // feature=cpu_p95_creep, target=node-a
	if !rec.MatchesAnalystFeature(fixedNow, "node-a", "cpu_p95_creep") {
		t.Error("want match on equal (target,feature)")
	}
	if rec.MatchesAnalystFeature(fixedNow, "node-b", "cpu_p95_creep") {
		t.Error("want no match: target-scoped analyst record must not cross targets")
	}
	if rec.MatchesAnalystFeature(fixedNow, "node-a", "other_feature") {
		t.Error("want no match on different feature")
	}

	// Feature-only (no target) matches across all targets.
	featureOnly := validAnalystRec()
	featureOnly.Matcher.Target = ""
	if !featureOnly.MatchesAnalystFeature(fixedNow, "node-z", "cpu_p95_creep") {
		t.Error("feature-only analyst record should match any target")
	}

	expired := rec
	expired.Until = pastRFC3339()
	if expired.MatchesAnalystFeature(fixedNow, "node-a", "cpu_p95_creep") {
		t.Error("expired record must never match")
	}

	other := validTargetRec()
	if other.MatchesAnalystFeature(fixedNow, other.Matcher.Target, "anything") {
		t.Error("target scope must never match an analyst-feature query")
	}
}

func TestAnnotationDeterministic(t *testing.T) {
	rec := validGroupCheckRec()
	a1 := rec.Annotation()
	a2 := rec.Annotation()
	if a1 != a2 {
		t.Fatalf("Annotation not deterministic: %q vs %q", a1, a2)
	}
	if !strings.Contains(a1, "group_check") || !strings.Contains(a1, "disk/smart-fail") ||
		!strings.Contains(a1, rec.Actor) || !strings.Contains(a1, rec.Reason) {
		t.Errorf("Annotation missing expected components: %q", a1)
	}
}

func writeFixture(t *testing.T, name, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

func TestLoadDeclarativeValid(t *testing.T) {
	body := `[
		{"key":"d-1","scope":"fingerprint","matcher":{"fingerprint":"abc123"},
		 "until":"2026-08-01T00:00:00Z","cumulative_days":1,"reason":"r1","actor":"ops"},
		{"key":"d-2","scope":"group_check","matcher":{"group":"disk","check":"smart-fail"},
		 "until":"2026-08-01T00:00:00Z","cumulative_days":0,"reason":"r2","actor":"ops"}
	]`
	path := writeFixture(t, "suppressions.json", body)
	recs, err := suppress.LoadDeclarative(path, fixedNow)
	if err != nil {
		t.Fatalf("LoadDeclarative: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("len(recs) = %d, want 2", len(recs))
	}
	for _, r := range recs {
		if r.Source != suppress.SourceDeclarative {
			t.Errorf("record %s: Source = %q, want declarative", r.Key, r.Source)
		}
	}
}

func TestLoadDeclarativeOneInvalidFailsLoud(t *testing.T) {
	body := `[
		{"key":"d-1","scope":"fingerprint","matcher":{"fingerprint":"abc123"},
		 "until":"2026-08-01T00:00:00Z","cumulative_days":1,"reason":"r1","actor":"ops"},
		{"key":"d-2","scope":"group_check","matcher":{"group":"disk"},
		 "until":"2026-08-01T00:00:00Z","cumulative_days":0,"reason":"r2","actor":"ops"}
	]`
	path := writeFixture(t, "suppressions.json", body)
	if _, err := suppress.LoadDeclarative(path, fixedNow); err == nil {
		t.Fatal("want error for a fixture containing one invalid record (missing check)")
	}
}

func TestLoadDeclarativeMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.json")
	if _, err := suppress.LoadDeclarative(path, fixedNow); err == nil {
		t.Fatal("want error for a missing declarative file")
	}
}

func TestLoadDeclarativeEmptyArray(t *testing.T) {
	path := writeFixture(t, "suppressions.json", `[]`)
	recs, err := suppress.LoadDeclarative(path, fixedNow)
	if err != nil {
		t.Fatalf("LoadDeclarative: %v", err)
	}
	if len(recs) != 0 {
		t.Fatalf("len(recs) = %d, want 0", len(recs))
	}
}
