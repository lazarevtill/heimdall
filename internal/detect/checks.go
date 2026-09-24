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
	"math"
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

// maxFutureSkew is how far past now a success timestamp may sit before it is
// treated as malformed rather than fresh. A few minutes absorbs ordinary
// clock drift between the exporter and this host; anything beyond it is a
// wrong unit (a millisecond timestamp reads ~50,000 years ahead) or a broken
// clock, and a negative age would otherwise pass the grace check forever.
const maxFutureSkew = 5 * time.Minute

// DeadMan (C1): fires when the newest success timestamp is older than the
// expectation's grace window, or when no success has ever been recorded. A
// non-finite sample, or a newest timestamp beyond maxFutureSkew in the
// future, is unmeasurable evidence and surfaces as Unknown — never as a
// fresh success.
func DeadMan(now time.Time, exp manifest.Expectation, sig source.Signal) []contract.Finding {
	if sig.State == contract.StateUnknown {
		return one(now, exp, contract.StateUnknown, "dead-man evidence unavailable: "+sig.Err)
	}
	var newest float64
	found := false
	for _, s := range sig.Samples {
		if !finite(s.Value) {
			// Checked per sample, not just on the max: NaN loses every
			// comparison, so a NaN would otherwise be skipped silently.
			return one(now, exp, contract.StateUnknown,
				fmt.Sprintf("dead-man evidence unusable: non-finite success timestamp %v", s.Value))
		}
		if !found || s.Value > newest {
			newest, found = s.Value, true
		}
	}
	if !found {
		return one(now, exp, contract.StateFiring, "no success event recorded for target")
	}
	// Compared in float seconds BEFORE any int64 conversion, which is
	// implementation-defined for out-of-range values.
	if limit := float64(now.Unix()) + maxFutureSkew.Seconds(); newest > limit {
		return one(now, exp, contract.StateUnknown, fmt.Sprintf(
			"dead-man evidence unusable: newest success timestamp %.0f is more than %s in the future (now %d) — wrong unit (milliseconds, not seconds?) or clock skew",
			newest, maxFutureSkew, now.Unix()))
	}
	age := now.Sub(time.Unix(int64(newest), 0))
	if age > exp.Grace() {
		return one(now, exp, contract.StateFiring,
			fmt.Sprintf("last success %s ago exceeds grace %s", age.Round(time.Second), exp.Grace()))
	}
	return nil
}

// Threshold (C4-style): fires when the summed sample value reaches
// min_count (manifest validation guarantees min_count >= 1). A non-finite
// sample or sum is Unknown: NaN makes the comparison false, so it would
// otherwise read as a silent ok even beside a sample that crosses alone.
func Threshold(now time.Time, exp manifest.Expectation, sig source.Signal) []contract.Finding {
	if sig.State == contract.StateUnknown {
		return one(now, exp, contract.StateUnknown, "threshold evidence unavailable: "+sig.Err)
	}
	var total float64
	for _, s := range sig.Samples {
		if !finite(s.Value) {
			return one(now, exp, contract.StateUnknown,
				fmt.Sprintf("threshold evidence unusable: non-finite sample %v", s.Value))
		}
		total += s.Value
	}
	if !finite(total) {
		return one(now, exp, contract.StateUnknown, "threshold evidence unusable: sample sum overflowed")
	}
	if total >= exp.Verify.MinCount {
		return one(now, exp, contract.StateFiring,
			fmt.Sprintf("count %.0f >= min_count %.0f", total, exp.Verify.MinCount))
	}
	return nil
}

// finite reports whether v is a real measurement (not NaN, not ±Inf).
func finite(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) }

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
