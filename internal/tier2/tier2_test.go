package tier2_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/lazarevtill/heimdall/internal/baseline"
	"github.com/lazarevtill/heimdall/internal/contract"
	"github.com/lazarevtill/heimdall/internal/manifest"
	"github.com/lazarevtill/heimdall/internal/source"
	"github.com/lazarevtill/heimdall/internal/tier2"
)

func openStore(t *testing.T) *baseline.Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := baseline.Open(path)
	if err != nil {
		t.Fatalf("baseline.Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// quantileSpec is a C6-style creep-quantile spec: higher-is-worse.
func quantileSpec() manifest.Tier2Spec {
	return manifest.Tier2Spec{
		ID:                    "c6-quantile-creep",
		Signal:                "quantile",
		Check:                 "c6-quantile-creep",
		Group:                 "node",
		Entity:                "host",
		Target:                "node-a",
		Node:                  "node-a",
		Feature:               "cpu_p95_creep",
		Unit:                  "ratio",
		Backend:               "prometheus",
		Query:                 "quantile_over_time(...)",
		WindowSeconds:         300,
		BaselineWindowSeconds: int64((7 * 24 * time.Hour) / time.Second),
		GraduateThreshold:     0.9,
		ClearThreshold:        0.7,
		MinHoldSeconds:        int64(time.Hour / time.Second),
		Digest:                true,
	}
}

// slopeSpec is a C8-style exhaustion-horizon spec: lower-is-worse (a SHORTER
// horizon in days is worse).
func slopeSpec() manifest.Tier2Spec {
	return manifest.Tier2Spec{
		ID:                    "c8-exhaustion-slope",
		Signal:                "slope",
		Check:                 "c8-exhaustion-slope",
		Group:                 "node",
		Entity:                "fs",
		Target:                "node-c:/var",
		Node:                  "node-c",
		Feature:               "disk_exhaustion_days",
		Unit:                  "days",
		Backend:               "prometheus",
		Query:                 "predict_linear(...)",
		WindowSeconds:         300,
		BaselineWindowSeconds: int64((7 * 24 * time.Hour) / time.Second),
		GraduateThreshold:     7,  // <=7 days to exhaustion graduates
		ClearThreshold:        14, // >=14 days clears
		MinHoldSeconds:        int64(time.Hour / time.Second),
		Digest:                true,
	}
}

func okSignal(vals ...float64) source.Signal {
	sig := source.Signal{QueryID: "q", State: contract.StateOK}
	for _, v := range vals {
		sig.Samples = append(sig.Samples, source.Sample{Value: v})
	}
	return sig
}

var t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func TestEvalUnknownSignal(t *testing.T) {
	s := openStore(t)
	spec := quantileSpec()
	spec.Digest = false // must surface regardless

	sig := source.Signal{QueryID: "q", State: contract.StateUnknown, Err: "backend timeout"}
	res, err := tier2.Eval(t0, spec, sig, s)
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if res.Finding != nil {
		t.Errorf("Finding = %+v, want nil", res.Finding)
	}
	if res.Row == nil {
		t.Fatal("Row = nil, want unknown row surfaced even with spec.Digest=false")
	}
	if res.Row.Status != contract.StatusUnknown {
		t.Errorf("Row.Status = %v, want StatusUnknown", res.Row.Status)
	}
	wantMarker := spec.Target + "/" + spec.Feature
	if res.UnknownMarker != wantMarker {
		t.Errorf("UnknownMarker = %q, want %q", res.UnknownMarker, wantMarker)
	}
}

func TestEvalEmptyVectorIsUnknown(t *testing.T) {
	s := openStore(t)
	spec := quantileSpec()
	spec.Digest = false

	sig := source.Signal{QueryID: "q", State: contract.StateOK} // OK but zero samples
	res, err := tier2.Eval(t0, spec, sig, s)
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if res.Finding != nil {
		t.Errorf("Finding = %+v, want nil", res.Finding)
	}
	if res.Row == nil {
		t.Fatal("Row = nil, want unknown row surfaced for empty vector")
	}
	if res.Row.Status != contract.StatusUnknown {
		t.Errorf("Row.Status = %v, want StatusUnknown (empty vector must never read as calm 0)", res.Row.Status)
	}
	if res.Row.Value != 0 {
		t.Errorf("Row.Value = %v, want 0 for unmeasured", res.Row.Value)
	}
	wantMarker := spec.Target + "/" + spec.Feature
	if res.UnknownMarker != wantMarker {
		t.Errorf("UnknownMarker = %q, want %q", res.UnknownMarker, wantMarker)
	}
}

func TestEvalWarmupGateBlocksGraduation(t *testing.T) {
	s := openStore(t)
	spec := quantileSpec()

	// First eval enables warm-up at t0. Metric is already well past
	// graduate_threshold (0.9), but must not graduate: still inside warmup.
	res, err := tier2.Eval(t0, spec, okSignal(0.95), s)
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if res.Finding != nil {
		t.Errorf("Finding minted during warm-up: %+v, want nil", res.Finding)
	}
	if res.Row == nil || res.Row.Status != contract.StatusBaselineWarming {
		t.Fatalf("Row = %+v, want status=BaselineWarming", res.Row)
	}

	// Confirm the warming eval did NOT accumulate hold time: probing
	// MarkCrossing directly at a later instant must show no earlier crossing
	// (since would equal the probe's own now, not t0).
	probe := t0.Add(30 * time.Minute)
	since, err := s.MarkCrossing(probe, spec.Check, spec.Target)
	if err != nil {
		t.Fatalf("MarkCrossing probe: %v", err)
	}
	if !since.Equal(probe) {
		t.Errorf("crossing since = %v, want %v (warming eval must not have created a crossing row)", since, probe)
	}
	// Clean up the probe crossing so it doesn't leak into later assertions
	// in this test (there are none, but keep the store tidy).
	if err := s.ClearCrossing(spec.Check, spec.Target); err != nil {
		t.Fatalf("ClearCrossing cleanup: %v", err)
	}

	// A later eval still inside the 7-day window, with a seeded baseline,
	// must still read BaselineWarming even though baseOK could be true.
	for i, v := range []float64{0.1, 0.2, 0.3, 0.4} {
		ts := t0.Add(time.Duration(i+1) * time.Hour)
		if _, err := tier2.Eval(ts, spec, okSignal(v), s); err != nil {
			t.Fatalf("Eval seed %d: %v", i, err)
		}
	}
	justBeforeWarmupEnds := t0.Add(tier2.WarmupWindow).Add(-time.Second)
	res2, err := tier2.Eval(justBeforeWarmupEnds, spec, okSignal(0.95), s)
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if res2.Finding != nil {
		t.Errorf("Finding minted just before warmup ends: %+v, want nil", res2.Finding)
	}
	if res2.Row.Status != contract.StatusBaselineWarming {
		t.Errorf("Row.Status = %v, want BaselineWarming just before warmup ends", res2.Row.Status)
	}
}

func TestEvalGraduatesAfterMinHold(t *testing.T) {
	s := openStore(t)
	spec := quantileSpec() // graduate=0.9, clear=0.7, min_hold=1h

	// Enable warm-up and seed baseline feature history, staying in the
	// clear zone (<=0.7) throughout so no crossing is recorded during seeding.
	for i, v := range []float64{0.1, 0.2, 0.3, 0.4, 0.5} {
		ts := t0.Add(time.Duration(i) * time.Hour)
		if _, err := tier2.Eval(ts, spec, okSignal(v), s); err != nil {
			t.Fatalf("Eval seed %d: %v", i, err)
		}
	}

	// Past the 7-day warm-up window, with baseline samples still inside the
	// 7-day baseline window.
	enter := t0.Add(tier2.WarmupWindow).Add(time.Hour)
	res, err := tier2.Eval(enter, spec, okSignal(0.95), s)
	if err != nil {
		t.Fatalf("Eval (enter): %v", err)
	}
	if res.Finding != nil {
		t.Errorf("Finding minted on first entry (elapsed=0): %+v, want nil", res.Finding)
	}
	if res.Row.Status != contract.StatusOK {
		t.Fatalf("Row.Status = %v, want StatusOK (warmup elapsed, baseline present)", res.Row.Status)
	}

	// Still above graduate, but hold not yet elapsed (30min < 1h min_hold).
	mid := enter.Add(30 * time.Minute)
	res2, err := tier2.Eval(mid, spec, okSignal(0.95), s)
	if err != nil {
		t.Fatalf("Eval (mid-hold): %v", err)
	}
	if res2.Finding != nil {
		t.Errorf("Finding minted before min_hold elapsed: %+v, want nil", res2.Finding)
	}

	// Hold elapsed (61min >= 1h): must graduate now.
	after := enter.Add(61 * time.Minute)
	res3, err := tier2.Eval(after, spec, okSignal(0.95), s)
	if err != nil {
		t.Fatalf("Eval (graduate): %v", err)
	}
	if res3.Finding == nil {
		t.Fatal("Finding = nil, want graduated finding after min_hold elapsed")
	}
	f := res3.Finding
	if f.Class != contract.ClassTrend {
		t.Errorf("Class = %v, want ClassTrend", f.Class)
	}
	if f.Severity != contract.SeverityInfo {
		t.Errorf("Severity = %v, want SeverityInfo (default)", f.Severity)
	}
	if f.State != contract.StateFiring {
		t.Errorf("State = %v, want StateFiring", f.State)
	}
	wantFP := contract.Fingerprint(spec.Check, spec.Target)
	if f.Fingerprint != wantFP {
		t.Errorf("Fingerprint = %q, want %q", f.Fingerprint, wantFP)
	}
}

func TestEvalSeverityCappedAtWarning(t *testing.T) {
	s := openStore(t)
	spec := quantileSpec()
	spec.Target = "node-b" // isolate crossing/baseline state from other tests
	spec.Severity = contract.SeverityWarning

	for i, v := range []float64{0.1, 0.2, 0.3, 0.4, 0.5} {
		ts := t0.Add(time.Duration(i) * time.Hour)
		if _, err := tier2.Eval(ts, spec, okSignal(v), s); err != nil {
			t.Fatalf("Eval seed %d: %v", i, err)
		}
	}
	enter := t0.Add(tier2.WarmupWindow).Add(time.Hour)
	if _, err := tier2.Eval(enter, spec, okSignal(0.95), s); err != nil {
		t.Fatalf("Eval (enter): %v", err)
	}
	after := enter.Add(61 * time.Minute)
	res, err := tier2.Eval(after, spec, okSignal(0.95), s)
	if err != nil {
		t.Fatalf("Eval (graduate): %v", err)
	}
	if res.Finding == nil {
		t.Fatal("Finding = nil, want graduated finding")
	}
	if res.Finding.Severity != contract.SeverityWarning {
		t.Errorf("Severity = %v, want SeverityWarning (spec asked for warning, not critical)", res.Finding.Severity)
	}
	if res.Finding.Class != contract.ClassTrend {
		t.Errorf("Class = %v, want ClassTrend (contract caps trend at warning)", res.Finding.Class)
	}
}

func TestEvalHysteresisHoldBandThenClearThenFreshEntry(t *testing.T) {
	s := openStore(t)
	spec := quantileSpec()
	spec.Target = "node-hyst"

	for i, v := range []float64{0.1, 0.2, 0.3, 0.4, 0.5} {
		ts := t0.Add(time.Duration(i) * time.Hour)
		if _, err := tier2.Eval(ts, spec, okSignal(v), s); err != nil {
			t.Fatalf("Eval seed %d: %v", i, err)
		}
	}

	enter := t0.Add(tier2.WarmupWindow).Add(time.Hour)
	if _, err := tier2.Eval(enter, spec, okSignal(0.95), s); err != nil {
		t.Fatalf("Eval (enter): %v", err)
	}
	graduated := enter.Add(61 * time.Minute)
	res, err := tier2.Eval(graduated, spec, okSignal(0.95), s)
	if err != nil {
		t.Fatalf("Eval (graduate): %v", err)
	}
	if res.Finding == nil {
		t.Fatal("expected graduation before hold-band test")
	}

	// Drop into the HOLD band (0.7 < 0.8 < 0.9): crossing must persist
	// (no clear), no new finding.
	hold := graduated.Add(time.Minute)
	resHold, err := tier2.Eval(hold, spec, okSignal(0.8), s)
	if err != nil {
		t.Fatalf("Eval (hold band): %v", err)
	}
	if resHold.Finding != nil {
		t.Errorf("Finding minted in hold band: %+v, want nil", resHold.Finding)
	}

	// Re-enter immediately: since crossing was never cleared, this should
	// graduate INSTANTLY (original since is still far in the past).
	reenterFast := hold.Add(time.Minute)
	resReenter, err := tier2.Eval(reenterFast, spec, okSignal(0.95), s)
	if err != nil {
		t.Fatalf("Eval (re-enter after hold): %v", err)
	}
	if resReenter.Finding == nil {
		t.Error("Finding = nil after re-entering post-hold-band, want immediate graduation (crossing was never cleared)")
	}

	// Now drop below clear_threshold (0.7): crossing must clear.
	clear := reenterFast.Add(time.Minute)
	resClear, err := tier2.Eval(clear, spec, okSignal(0.5), s)
	if err != nil {
		t.Fatalf("Eval (clear): %v", err)
	}
	if resClear.Finding != nil {
		t.Errorf("Finding minted on clear: %+v, want nil", resClear.Finding)
	}

	// Re-entering now must NOT graduate instantly: a fresh hold timer starts.
	freshEnter := clear.Add(time.Minute)
	resFresh, err := tier2.Eval(freshEnter, spec, okSignal(0.95), s)
	if err != nil {
		t.Fatalf("Eval (fresh entry): %v", err)
	}
	if resFresh.Finding != nil {
		t.Error("Finding minted immediately on fresh entry after ClearCrossing, want a fresh min_hold wait")
	}
	stillWithinHold := freshEnter.Add(30 * time.Minute)
	resStill, err := tier2.Eval(stillWithinHold, spec, okSignal(0.95), s)
	if err != nil {
		t.Fatalf("Eval (still within fresh hold): %v", err)
	}
	if resStill.Finding != nil {
		t.Error("Finding minted before fresh min_hold elapsed")
	}
	pastFreshHold := freshEnter.Add(61 * time.Minute)
	resPast, err := tier2.Eval(pastFreshHold, spec, okSignal(0.95), s)
	if err != nil {
		t.Fatalf("Eval (past fresh hold): %v", err)
	}
	if resPast.Finding == nil {
		t.Error("Finding = nil after fresh hold elapsed, want graduation")
	}
}

func TestEvalLowerIsWorseSlope(t *testing.T) {
	s := openStore(t)
	spec := slopeSpec() // graduate<=7 days, clear>=14 days

	// Seed baseline staying in the clear zone (>=14) throughout.
	for i, v := range []float64{20, 21, 22, 23, 24} {
		ts := t0.Add(time.Duration(i) * time.Hour)
		if _, err := tier2.Eval(ts, spec, okSignal(v), s); err != nil {
			t.Fatalf("Eval seed %d: %v", i, err)
		}
	}

	enter := t0.Add(tier2.WarmupWindow).Add(time.Hour)
	res, err := tier2.Eval(enter, spec, okSignal(5), s) // 5 days: below graduate(7)
	if err != nil {
		t.Fatalf("Eval (enter): %v", err)
	}
	if res.Finding != nil {
		t.Errorf("Finding minted on first entry: %+v, want nil", res.Finding)
	}

	after := enter.Add(61 * time.Minute)
	res2, err := tier2.Eval(after, spec, okSignal(5), s)
	if err != nil {
		t.Fatalf("Eval (graduate): %v", err)
	}
	if res2.Finding == nil {
		t.Fatal("Finding = nil, want graduation for lower-is-worse slope past min_hold")
	}

	// Rising back above clear_threshold(14) must clear the crossing.
	cleared := after.Add(time.Minute)
	res3, err := tier2.Eval(cleared, spec, okSignal(20), s)
	if err != nil {
		t.Fatalf("Eval (clear): %v", err)
	}
	if res3.Finding != nil {
		t.Errorf("Finding minted on clear (%v >= clear_threshold): want nil", res3.Finding)
	}
}

func TestEvalZScoreDeterministicAndEpsilonGuarded(t *testing.T) {
	s := openStore(t)
	spec := quantileSpec()
	spec.Target = "node-z"

	for i, v := range []float64{0.1, 0.2, 0.3, 0.4} {
		ts := t0.Add(time.Duration(i) * time.Hour)
		if _, err := tier2.Eval(ts, spec, okSignal(v), s); err != nil {
			t.Fatalf("Eval seed %d: %v", i, err)
		}
	}
	probe := t0.Add(tier2.WarmupWindow).Add(time.Hour)

	res1, err := tier2.Eval(probe, spec, okSignal(0.5), s)
	if err != nil {
		t.Fatalf("Eval (probe 1): %v", err)
	}

	// Re-derive an identical store state (fresh store, identical seed +
	// probe inputs) and confirm the resulting Row is byte-identical.
	s2 := openStore(t)
	for i, v := range []float64{0.1, 0.2, 0.3, 0.4} {
		ts := t0.Add(time.Duration(i) * time.Hour)
		if _, err := tier2.Eval(ts, spec, okSignal(v), s2); err != nil {
			t.Fatalf("Eval seed(2) %d: %v", i, err)
		}
	}
	res2, err := tier2.Eval(probe, spec, okSignal(0.5), s2)
	if err != nil {
		t.Fatalf("Eval (probe 2): %v", err)
	}
	if diff := cmp.Diff(res1.Row, res2.Row); diff != "" {
		t.Errorf("Row not deterministic across identical inputs (-got1 +got2):\n%s", diff)
	}

	// Tight baseline (IQR≈0): all seed values identical -> ZScore must be 0,
	// not Inf/NaN.
	s3 := openStore(t)
	spec3 := quantileSpec()
	spec3.Target = "node-tight"
	for i := 0; i < 4; i++ {
		ts := t0.Add(time.Duration(i) * time.Hour)
		if _, err := tier2.Eval(ts, spec3, okSignal(0.3), s3); err != nil {
			t.Fatalf("Eval tight-seed %d: %v", i, err)
		}
	}
	probe3 := t0.Add(tier2.WarmupWindow).Add(time.Hour)
	res3, err := tier2.Eval(probe3, spec3, okSignal(0.3), s3)
	if err != nil {
		t.Fatalf("Eval (tight probe): %v", err)
	}
	if res3.Row == nil {
		t.Fatal("Row = nil")
	}
	if res3.Row.ZScore != 0 {
		t.Errorf("ZScore = %v, want 0 for a tight (IQR≈0) baseline", res3.Row.ZScore)
	}
}
