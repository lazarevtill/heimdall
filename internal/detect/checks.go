// Package detect holds the pure check functions and the engine that runs
// them. Checks do no I/O and never call time.Now(): the clock is injected,
// which is what makes dead-man window boundaries table-testable.
//
// Evidence strings are stored RAW in findings here; redaction happens once,
// at egress (internal/emit), which is the only boundary where content
// leaves the process.
package detect

import (
	"fmt"
	"time"

	"github.com/lazarevtill/heimdall/internal/contract"
	"github.com/lazarevtill/heimdall/internal/manifest"
	"github.com/lazarevtill/heimdall/internal/source"
)

// Check evaluates one expectation against its fetched Signal.
// Contract: OK evaluations return an empty slice; Firing and Unknown
// evaluations return exactly one Finding. An Unknown signal MUST surface
// as an Unknown finding — never a silent ok.
type Check func(now time.Time, exp manifest.Expectation, sig source.Signal) []contract.Finding

// DeadMan (C1): fires when the newest success timestamp is older than the
// expectation's grace window, or when no success has ever been recorded.
func DeadMan(now time.Time, exp manifest.Expectation, sig source.Signal) []contract.Finding {
	if sig.State == contract.StateUnknown {
		return one(now, exp, contract.StateUnknown, "dead-man evidence unavailable: "+sig.Err)
	}
	var newest float64
	found := false
	for _, s := range sig.Samples {
		if !found || s.Value > newest {
			newest, found = s.Value, true
		}
	}
	if !found {
		return one(now, exp, contract.StateFiring, "no success event recorded for target")
	}
	age := now.Sub(time.Unix(int64(newest), 0))
	if age > exp.Grace() {
		return one(now, exp, contract.StateFiring,
			fmt.Sprintf("last success %s ago exceeds grace %s", age.Round(time.Second), exp.Grace()))
	}
	return nil
}

// Threshold (C4-style): fires when the summed sample value reaches
// min_count (manifest validation guarantees min_count >= 1).
func Threshold(now time.Time, exp manifest.Expectation, sig source.Signal) []contract.Finding {
	if sig.State == contract.StateUnknown {
		return one(now, exp, contract.StateUnknown, "threshold evidence unavailable: "+sig.Err)
	}
	var total float64
	for _, s := range sig.Samples {
		total += s.Value
	}
	if total >= exp.Verify.MinCount {
		return one(now, exp, contract.StateFiring,
			fmt.Sprintf("count %.0f >= min_count %.0f", total, exp.Verify.MinCount))
	}
	return nil
}

// one mints the single finding for a non-ok evaluation. A malformed
// expectation must STILL be alertable, so constructor failure degrades to an
// internal unknown finding rather than dropping the signal.
func one(now time.Time, exp manifest.Expectation, state contract.State, evidence string) []contract.Finding {
	f, err := contract.NewFinding(now, contract.FindingSpec{
		Check: exp.Check, Group: exp.Group, Target: exp.Target, Node: exp.Node,
		Severity: exp.SeverityOnMiss, Class: contract.ClassHard, State: state,
		Title: exp.ID, Evidence: evidence,
	})
	if err != nil {
		// Fallback spec is statically valid, so this NewFinding cannot fail.
		fb, _ := contract.NewFinding(now, contract.FindingSpec{
			Check: "heimdall-internal", Group: "heimdall", Target: exp.ID, Node: exp.Node,
			Severity: contract.SeverityWarning, Class: contract.ClassHard,
			State: contract.StateUnknown, Title: "invalid expectation",
			Evidence: err.Error(),
		})
		return []contract.Finding{fb}
	}
	return []contract.Finding{f}
}
