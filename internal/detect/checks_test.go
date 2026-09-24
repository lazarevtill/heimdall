package detect_test

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/lazarevtill/heimdall/internal/contract"
	"github.com/lazarevtill/heimdall/internal/detect"
	"github.com/lazarevtill/heimdall/internal/manifest"
	"github.com/lazarevtill/heimdall/internal/source"
)

var now = time.Unix(1752900000, 0).UTC() // injected clock: checks never call time.Now()

func deadmanExp() manifest.Expectation {
	return manifest.Expectation{
		ID: "backup-vm-100", Check: "c1-deadman", Group: "backup-ds1",
		Target: "backup:ds1/vm-100", Node: "node-a", GraceSeconds: 3600,
		SeverityOnMiss: contract.SeverityCritical,
		Verify:         manifest.Verify{Backend: "prometheus", Query: "max(...)"},
	}
}

func okSignal(vals ...float64) source.Signal {
	s := source.Signal{QueryID: "q", State: contract.StateOK}
	for _, v := range vals {
		s.Samples = append(s.Samples, source.Sample{Value: v})
	}
	return s
}

func TestDeadMan(t *testing.T) {
	grace := int64(3600)
	cases := []struct {
		name      string
		sig       source.Signal
		wantCount int
		wantState contract.State
	}{
		// both sides of the grace boundary, deterministic via injected now
		{"inside grace ok", okSignal(float64(now.Unix() - grace + 1)), 0, 0},
		{"exactly at grace ok", okSignal(float64(now.Unix() - grace)), 0, 0},
		{"outside grace fires", okSignal(float64(now.Unix() - grace - 1)), 1, contract.StateFiring},
		{"newest of several samples wins", okSignal(float64(now.Unix()-7200), float64(now.Unix()-60)), 0, 0},
		{"no samples ever fires", okSignal(), 1, contract.StateFiring},
		{"unknown signal is alertable", source.Signal{State: contract.StateUnknown, Err: "boom"}, 1, contract.StateUnknown},
		// A success timestamp in the future is not "fresh", it is malformed: a
		// millisecond-unit metric or a skewed exporter clock. Read as a
		// negative age it used to pass the grace check forever.
		{"just inside the future-skew tolerance ok", okSignal(float64(now.Unix() + 300)), 0, 0},
		{"beyond the future-skew tolerance is unknown", okSignal(float64(now.Unix() + 301)), 1, contract.StateUnknown},
		{"millisecond-unit timestamp is unknown", okSignal(float64(now.Add(-time.Minute).UnixMilli())), 1, contract.StateUnknown},
		{"future sample beside a fresh one is unknown", okSignal(float64(now.Unix()-60), float64(now.Unix()+7200)), 1, contract.StateUnknown},
		{"NaN newest is unknown", okSignal(math.NaN()), 1, contract.StateUnknown},
		{"NaN beside a fresh sample is unknown", okSignal(float64(now.Unix()-60), math.NaN()), 1, contract.StateUnknown},
		{"+Inf is unknown", okSignal(math.Inf(1)), 1, contract.StateUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := detect.DeadMan(now, deadmanExp(), tc.sig)
			if len(fs) != tc.wantCount {
				t.Fatalf("len(findings) = %d, want %d", len(fs), tc.wantCount)
			}
			if tc.wantCount == 1 {
				f := fs[0]
				if f.State != tc.wantState {
					t.Errorf("State = %v, want %v", f.State, tc.wantState)
				}
				if f.Fingerprint != "d86c07b5a41742c1" {
					t.Errorf("Fingerprint = %q, want golden d86c07b5a41742c1", f.Fingerprint)
				}
				if f.Severity != contract.SeverityCritical {
					t.Errorf("Severity = %q, want critical (severity_on_miss)", f.Severity)
				}
			}
		})
	}
}

// The Unknown evidence must name the likely cause so an operator does not
// have to rediscover it: a wrong unit (ms vs s) or a skewed clock.
func TestDeadManFutureEvidenceNamesTheCause(t *testing.T) {
	fs := detect.DeadMan(now, deadmanExp(), okSignal(float64(now.UnixMilli())))
	if len(fs) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(fs))
	}
	for _, want := range []string{"future", "unit", "clock skew"} {
		if !strings.Contains(fs[0].Evidence, want) {
			t.Errorf("Evidence = %q, want it to mention %q", fs[0].Evidence, want)
		}
	}
}

func TestThreshold(t *testing.T) {
	exp := manifest.Expectation{
		ID: "unit-failures-node-a", Check: "c4-signature", Group: "node-a",
		Target: "node-a", Node: "node-a", SeverityOnMiss: contract.SeverityWarning,
		Verify: manifest.Verify{Backend: "prometheus", Query: "sum(...)", MinCount: 2},
	}
	cases := []struct {
		name      string
		sig       source.Signal
		wantCount int
		wantState contract.State
	}{
		{"below threshold ok", okSignal(1), 0, 0},
		{"at threshold fires", okSignal(2), 1, contract.StateFiring},
		{"summed across samples", okSignal(1, 1), 1, contract.StateFiring},
		{"unknown signal is alertable", source.Signal{State: contract.StateUnknown, Err: "boom"}, 1, contract.StateUnknown},
		// NaN makes `total >= min_count` false, so a non-finite sample used to
		// read as a silent ok even beside a sample that alone crosses the
		// threshold. It is unmeasurable: Unknown, never ok.
		{"NaN sample is unknown", okSignal(math.NaN()), 1, contract.StateUnknown},
		{"NaN beside a crossing sample is unknown", okSignal(5, math.NaN()), 1, contract.StateUnknown},
		{"-Inf sample is unknown", okSignal(math.Inf(-1), 10), 1, contract.StateUnknown},
		{"+Inf sample is unknown", okSignal(math.Inf(1)), 1, contract.StateUnknown},
		{"finite samples overflowing to +Inf is unknown", okSignal(math.MaxFloat64, math.MaxFloat64), 1, contract.StateUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := detect.Threshold(now, exp, tc.sig)
			if len(fs) != tc.wantCount {
				t.Fatalf("len(findings) = %d, want %d", len(fs), tc.wantCount)
			}
			if tc.wantCount == 1 && fs[0].State != tc.wantState {
				t.Errorf("State = %v, want %v", fs[0].State, tc.wantState)
			}
		})
	}
}
