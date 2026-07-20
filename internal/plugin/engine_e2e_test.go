package plugin

import (
	"context"
	"testing"
	"time"

	"github.com/lazarevtill/heimdall/internal/contract"
	"github.com/lazarevtill/heimdall/internal/detect"
	"github.com/lazarevtill/heimdall/internal/manifest"
	"github.com/lazarevtill/heimdall/internal/source"
)

// TestEndToEndManifestToEngineToPluginSubprocessToFinding is the headline
// proof for this slice: a manifest.Manifest built DIRECTLY in code (not via
// manifest.Load, whose verify.backend enum only allows
// prometheus/victorialogs/pbs — bypassing Load here is correct for this
// integration test and keeps S3-b self-contained without touching manifest
// validation) routes two expectations to a *SourcePlugin backed by the REAL
// compiled plugins/source-reference subprocess, through detect.Engine.Run,
// producing real contract.Finding values.
//
// This proves the full path: manifest -> detect.Engine -> SourcePlugin ->
// subprocess -> tri-state Signal -> Finding.
//
// The check under test is detect.Threshold (manifest check id
// "c4-signature"): it sums the Signal's sample values and fires iff the
// total >= Verify.MinCount. The reference plugin always answers StateOK
// with one sample whose value is the rune-count of the query's Expr (see
// plugins/source-reference's doc comment) — for expr "vector(1)" that is
// 9.0. One expectation sets MinCount to exactly that value (9 >= 9: fires);
// a sibling expectation sets MinCount one higher (9 >= 10 is false: no
// finding at all, per Threshold's contract of an empty slice on non-fire).
// Asserting both in one manifest shows the OK-signal path is correctly wired
// end to end in both directions, not just the firing one.
func TestEndToEndManifestToEngineToPluginSubprocessToFinding(t *testing.T) {
	m := testSourceManifest("refsrc")
	sp, err := NewSourcePlugin(m, refsrcPath, "s3cr3t-fake")
	if err != nil {
		t.Fatalf("NewSourcePlugin: %v", err)
	}

	const expr = "vector(1)" // 9 runes: v,e,c,t,o,r,(,1,)
	wantValue := float64(len([]rune(expr)))
	if wantValue != 9 {
		t.Fatalf("sanity: rune count of %q = %v, want 9 (fixture assumption changed?)", expr, wantValue)
	}

	fires := manifest.Expectation{
		ID: "refsrc-fires", Check: "c4-signature", Group: "g", Target: "t-fires", Node: "node-a",
		SeverityOnMiss: contract.SeverityWarning,
		Verify:         manifest.Verify{Backend: "refsrc", Query: expr, MinCount: wantValue},
	}
	quiet := manifest.Expectation{
		ID: "refsrc-quiet", Check: "c4-signature", Group: "g", Target: "t-quiet", Node: "node-a",
		SeverityOnMiss: contract.SeverityWarning,
		Verify:         manifest.Verify{Backend: "refsrc", Query: expr, MinCount: wantValue + 1},
	}
	man := &manifest.Manifest{Expectations: []manifest.Expectation{fires, quiet}}

	checks := map[string]detect.Check{"c4-signature": detect.Threshold}
	srcs := map[string]source.Source{"refsrc": sp}
	eng := detect.New(srcs, checks, 4)

	now := time.Unix(1752900000, 0)
	findings := eng.Run(context.Background(), now, man)

	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want exactly 1 (the firing expectation only; the quiet one emits none)", len(findings))
	}
	f := findings[0]
	if f.Target != "t-fires" {
		t.Errorf("finding Target = %q, want %q", f.Target, "t-fires")
	}
	if f.Check != "c4-signature" {
		t.Errorf("finding Check = %q, want %q", f.Check, "c4-signature")
	}
	if f.State != contract.StateFiring {
		t.Errorf("finding State = %v, want StateFiring", f.State)
	}
	if f.Severity != contract.SeverityWarning {
		t.Errorf("finding Severity = %v, want SeverityWarning", f.Severity)
	}
	if f.ObservedAt != now {
		t.Errorf("finding ObservedAt = %v, want %v (injected clock)", f.ObservedAt, now)
	}
}
