package detect_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lazarevtill/heimdall/internal/contract"
	"github.com/lazarevtill/heimdall/internal/detect"
	"github.com/lazarevtill/heimdall/internal/manifest"
	"github.com/lazarevtill/heimdall/internal/source"
)

type fakeSource struct {
	id string
	fn func(ctx context.Context, q source.Query) (source.Signal, error)
}

func (f *fakeSource) ID() string { return f.id }
func (f *fakeSource) Query(ctx context.Context, q source.Query) (source.Signal, error) {
	return f.fn(ctx, q)
}

func thresholdExp(id, target string) manifest.Expectation {
	return manifest.Expectation{
		ID: id, Check: "c4-signature", Group: "g", Target: target, Node: "node-a",
		SeverityOnMiss: contract.SeverityWarning,
		Verify:         manifest.Verify{Backend: "prometheus", Query: "q", MinCount: 1},
	}
}

func engineChecks() map[string]detect.Check {
	return map[string]detect.Check{"c1-deadman": detect.DeadMan, "c4-signature": detect.Threshold}
}

// THE load-bearing regression test: a failing source yields exactly one
// Unknown finding for ITS expectation, and does NOT cancel or blank the
// other sources' evaluations (no errgroup sibling-cancellation).
func TestRunSourceErrorIsUnknownAndDoesNotBlankSiblings(t *testing.T) {
	firing := &fakeSource{id: "prometheus", fn: func(_ context.Context, q source.Query) (source.Signal, error) {
		if q.ID == "exp-broken" {
			return source.Signal{QueryID: q.ID, State: contract.StateUnknown, Err: "conn refused"},
				errors.New("conn refused")
		}
		return source.Signal{QueryID: q.ID, State: contract.StateOK,
			Samples: []source.Sample{{Value: 5}}}, nil
	}}
	m := &manifest.Manifest{Expectations: []manifest.Expectation{
		thresholdExp("exp-a", "t-a"), thresholdExp("exp-broken", "t-b"), thresholdExp("exp-c", "t-c"),
	}}
	fs := detect.New(map[string]source.Source{"prometheus": firing}, engineChecks(), 4).
		Run(context.Background(), time.Unix(1752900000, 0), m)
	if len(fs) != 3 {
		t.Fatalf("len(findings) = %d, want 3 (2 firing + 1 unknown)", len(fs))
	}
	// manifest order is preserved
	if fs[0].Target != "t-a" || fs[1].Target != "t-b" || fs[2].Target != "t-c" {
		t.Errorf("order not deterministic: %v %v %v", fs[0].Target, fs[1].Target, fs[2].Target)
	}
	if fs[1].State != contract.StateUnknown {
		t.Errorf("broken source finding State = %v, want StateUnknown", fs[1].State)
	}
	if fs[0].State != contract.StateFiring || fs[2].State != contract.StateFiring {
		t.Error("sibling evaluations were blanked by the failing source")
	}
}

// A panicking check must degrade to one Unknown finding for its own
// expectation — never crash the run and lose every other result.
func TestRunCheckPanicIsUnknownAndDoesNotBlankSiblings(t *testing.T) {
	src := &fakeSource{id: "prometheus", fn: func(_ context.Context, q source.Query) (source.Signal, error) {
		return source.Signal{QueryID: q.ID, State: contract.StateOK,
			Samples: []source.Sample{{Value: 5}}}, nil
	}}
	checks := engineChecks()
	checks["c9-panics"] = func(time.Time, manifest.Expectation, source.Signal) []contract.Finding {
		panic("malformed sample blew up the check")
	}
	panicking := thresholdExp("exp-panics", "t-b")
	panicking.Check = "c9-panics"
	m := &manifest.Manifest{Expectations: []manifest.Expectation{
		thresholdExp("exp-a", "t-a"), panicking, thresholdExp("exp-c", "t-c"),
	}}
	fs := detect.New(map[string]source.Source{"prometheus": src}, checks, 4).
		Run(context.Background(), time.Unix(1752900000, 0), m)
	if len(fs) != 3 {
		t.Fatalf("len(findings) = %d, want 3 (2 firing + 1 unknown-from-panic)", len(fs))
	}
	if fs[1].State != contract.StateUnknown {
		t.Errorf("panicking check finding State = %v, want StateUnknown", fs[1].State)
	}
	if fs[0].State != contract.StateFiring || fs[2].State != contract.StateFiring {
		t.Error("sibling evaluations were blanked by the panicking check")
	}
}

func TestRunUnknownBackendAndCheckAreAlertable(t *testing.T) {
	src := &fakeSource{id: "prometheus", fn: func(_ context.Context, q source.Query) (source.Signal, error) {
		return source.Signal{State: contract.StateOK}, nil
	}}
	badBackend := thresholdExp("exp-nb", "t-nb")
	badBackend.Verify.Backend = "victorialogs" // valid in manifest, not wired in this engine
	badCheck := thresholdExp("exp-nc", "t-nc")
	badCheck.Check = "c99-not-implemented"
	m := &manifest.Manifest{Expectations: []manifest.Expectation{badBackend, badCheck}}
	fs := detect.New(map[string]source.Source{"prometheus": src}, engineChecks(), 4).
		Run(context.Background(), time.Unix(1752900000, 0), m)
	if len(fs) != 2 {
		t.Fatalf("len(findings) = %d, want 2 unknowns", len(fs))
	}
	for _, f := range fs {
		if f.State != contract.StateUnknown {
			t.Errorf("finding %q State = %v, want StateUnknown", f.Target, f.State)
		}
	}
}

func TestRunBoundedParallelism(t *testing.T) {
	var inFlight, peak atomic.Int64
	src := &fakeSource{id: "prometheus", fn: func(_ context.Context, q source.Query) (source.Signal, error) {
		cur := inFlight.Add(1)
		for {
			p := peak.Load()
			if cur <= p || peak.CompareAndSwap(p, cur) {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
		inFlight.Add(-1)
		return source.Signal{State: contract.StateOK, Samples: []source.Sample{{Value: 0}}}, nil
	}}
	var exps []manifest.Expectation
	for i := 0; i < 10; i++ {
		exps = append(exps, thresholdExp(string(rune('a'+i))+"-exp", string(rune('a'+i))))
	}
	detect.New(map[string]source.Source{"prometheus": src}, engineChecks(), 2).
		Run(context.Background(), time.Unix(1752900000, 0), &manifest.Manifest{Expectations: exps})
	if p := peak.Load(); p > 2 {
		t.Errorf("peak concurrency = %d, want <= 2 (SetLimit)", p)
	}
}
