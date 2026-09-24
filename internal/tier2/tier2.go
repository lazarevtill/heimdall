// Package tier2 evaluates Heimdall's Tier-2 soft-signal checks (C6-C9):
// deterministic, pure functions that turn one fetched source.Signal into
// EITHER a graduated contract.Finding (class=trend, which the contract caps
// at warning — Tier-2 can NEVER page) OR a digest row, gated by the 7-day
// warm-up window and fail-closed whenever the signal is unmeasurable.
//
// No time.Now() anywhere in this package: every function that needs "now"
// takes an injected `now time.Time` parameter (ADR-G10). Findings are minted
// ONLY via contract.NewFinding (ADR-G09) — never a Finding composite literal.
package tier2

import (
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/lazarevtill/heimdall/internal/baseline"
	"github.com/lazarevtill/heimdall/internal/contract"
	"github.com/lazarevtill/heimdall/internal/manifest"
	"github.com/lazarevtill/heimdall/internal/source"
)

// WarmupWindow is the fixed 7-day trust-building period after a
// (check,target) is first evaluated. While inside it, a spec's digest row is
// forced to StatusBaselineWarming and graduation is refused outright,
// regardless of how far past graduate_threshold the metric sits.
const WarmupWindow = 7 * 24 * time.Hour

// zEpsilon guards the robust-zscore denominator against a degenerate
// (near-zero) IQR, so a tight baseline yields ZScore==0 rather than Inf/NaN.
const zEpsilon = 1e-9

// Result is one Tier-2 spec's evaluation. Finding is set while the spec is
// graduated (see Eval for when that holds); Row is the digest row (always
// produced when spec.Digest, and ALSO always produced when the status is not
// StatusOK — StatusUnknown or StatusBaselineWarming — because a blind spot is
// never dropped just because the manifest didn't ask for that feature's
// healthy rows in the digest). Marker fields feed the digest's top-level echo
// arrays so the analyst is always told what was unmeasurable / surprising.
//
// Every Result Eval returns carries a Row or is a calm, measured, non-digest
// spec — including when Eval also returns an error: a failed evaluation is an
// explicit unknown row + marker, never an empty Result.
type Result struct {
	Finding       *contract.Finding   // class=trend: StateFiring while graduated, StateUnknown while graduated but unmeasurable
	Row           *contract.DigestRow // the feature row (nil only when spec.Digest==false AND status==StatusOK)
	UnknownMarker string              // "<target>/<feature>" when the evaluation was unmeasurable
	Flap          string              // C7 only: flap descriptor when flapping
	NewTemplate   string              // C9 only: new-template descriptor when surprising
}

// zone is which side of the hysteresis band a reduced metric currently sits
// in, relative to a spec's graduate/clear thresholds.
type zone int

const (
	zoneClear zone = iota // safely below (or above, for lower-is-worse) clear_threshold
	zoneHold              // between the two thresholds: neither enter nor clear
	zoneEnter             // at or past graduate_threshold: in the graduating zone
)

// classify determines the hysteresis zone per signal direction:
//
//   - higher-is-worse (quantile, flap, template_surprise): enters the
//     graduating zone at metric >= graduate_threshold, clears at
//     metric <= clear_threshold. The manifest author sets
//     clear_threshold < graduate_threshold.
//   - lower-is-worse (slope — e.g. an exhaustion-horizon in days, where a
//     SHORTER horizon is worse): enters at metric <= graduate_threshold,
//     clears at metric >= clear_threshold. The manifest author sets
//     clear_threshold > graduate_threshold.
//
// Between the two thresholds is the HOLD band: neither enter-fresh nor
// clear — the existing crossing state (if any) persists, so a metric
// hovering at the boundary cannot open/close/open (flap) the crossing.
func classify(signal string, metric, graduate, clear float64) zone {
	if signal == "slope" {
		switch {
		case metric <= graduate:
			return zoneEnter
		case metric >= clear:
			return zoneClear
		default:
			return zoneHold
		}
	}
	// quantile, flap, template_surprise: higher-is-worse.
	switch {
	case metric >= graduate:
		return zoneEnter
	case metric <= clear:
		return zoneClear
	default:
		return zoneHold
	}
}

// reduceMetric reduces a Signal's samples to a single scalar per the
// reduction table:
//
//   - quantile, flap, template_surprise (higher-is-worse signals): MAX
//     across samples.
//   - slope (lower-is-worse: a shorter exhaustion horizon is worse): MIN
//     across samples.
//
// A StateUnknown signal, or an OK signal with an empty sample vector, is NOT
// measured — an empty vector is not an observed value, so a Tier-2 blind
// spot must never be silently read as 0/calm. Neither is a vector holding a
// non-finite sample: NaN loses every comparison (so MAX/MIN would silently
// skip it or keep it depending on position) and ±Inf can be neither stored
// as a baseline nor JSON-encoded into the digest. The sources already refuse
// both; this is the second line. reason says why when measured is false.
func reduceMetric(signal string, sig source.Signal) (metric float64, measured bool, reason string) {
	if sig.State == contract.StateUnknown {
		return 0, false, "signal unknown: " + sig.Err
	}
	if len(sig.Samples) == 0 {
		return 0, false, "empty sample vector"
	}
	for _, s := range sig.Samples {
		if !finite(s.Value) {
			return 0, false, fmt.Sprintf("non-finite sample %v", s.Value)
		}
	}
	if signal == "slope" {
		m := sig.Samples[0].Value
		for _, s := range sig.Samples[1:] {
			if s.Value < m {
				m = s.Value
			}
		}
		return m, true, ""
	}
	m := sig.Samples[0].Value
	for _, s := range sig.Samples[1:] {
		if s.Value > m {
			m = s.Value
		}
	}
	return m, true, ""
}

// finite reports whether v is a real number (not NaN, not ±Inf).
func finite(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) }

// sevOrInfo defaults an unset manifest severity to info (contract.NewFinding
// additionally caps class=trend at warning regardless of what is passed).
func sevOrInfo(sev contract.Severity) contract.Severity {
	if sev == "" {
		return contract.SeverityInfo
	}
	return sev
}

// Eval runs one Tier-2 spec against its fetched signal. It is a PURE
// function of its inputs plus the injected clock and the baseline store; it
// performs no network I/O. It records the current observation into the
// baseline (RecordFeature), consults the warm-up gate, computes the digest
// row, and — only when NOT warming and the signal is measured and a
// trustworthy baseline exists — applies graduation hysteresis to decide
// whether to mint a trend finding.
//
// Eval calls store.MarkEnabled(now, spec.Check, spec.Target) at the very
// top, every call, unconditionally. MarkEnabled is idempotent/earliest-wins,
// so this is what starts the 7-day warm-up window the FIRST time a spec is
// ever evaluated — the engine (S2-c) does not need to call it separately.
//
// Emission is STATE, not an event: the .prom is rewritten whole every run,
// so a finding Eval does not return is a series that disappears, and
// Alertmanager resolves it (the bridge then auto-closes its ticket). So once
// a crossing has served its min_hold, the finding is returned on EVERY
// evaluation until a measured value reaches the clear zone:
//
//   - graduating zone or hold band: StateFiring (the hold band holds the
//     alert, not just the crossing row — otherwise a metric hovering at the
//     graduate threshold fires and resolves on alternate runs);
//   - unmeasured, warming, no trustworthy baseline, or a store failure:
//     StateUnknown (same fingerprint, so the same series — a backend outage
//     is never a resolve).
//
// Only a measured clear resolves. None of the non-graduating paths above
// touch the crossing row: they read it (store.Crossing), never mark or clear.
//
// On any store error Eval still returns a usable Result — an explicit unknown
// row + marker, plus the held Unknown finding when the crossing is readable —
// alongside the error, so the caller can log it and keep the row.
func Eval(now time.Time, spec manifest.Tier2Spec, sig source.Signal, store *baseline.Store) (Result, error) {
	if err := store.MarkEnabled(now, spec.Check, spec.Target); err != nil {
		return blind(now, spec, store, fmt.Errorf("tier2: mark enabled %s/%s: %w", spec.Check, spec.Target, err))
	}
	warming, err := store.Warming(now, spec.Check, spec.Target, WarmupWindow)
	if err != nil {
		return blind(now, spec, store, fmt.Errorf("tier2: warming %s/%s: %w", spec.Check, spec.Target, err))
	}

	metric, measured, unmeasuredWhy := reduceMetric(spec.Signal, sig)

	if measured {
		if err := store.RecordFeature(now, spec.Entity, spec.Target, spec.Feature, metric); err != nil {
			return blind(now, spec, store, fmt.Errorf("tier2: record feature %s/%s: %w", spec.Target, spec.Feature, err))
		}
	}

	// Baseline: q=0.95 is the baseline_7d reference the design compares
	// creep against; p25/p50/p75 are fetched additionally for a robust
	// (IQR-based) zscore. Fetched unconditionally — independent of
	// measured/warming — so a digest row can still show what the baseline
	// looks like even on an eval where the current sample is unmeasurable.
	base, _, baseOK, err := store.Quantile(now, spec.Target, spec.Feature, spec.BaselineWindow(), 0.95)
	if err != nil {
		return blind(now, spec, store, fmt.Errorf("tier2: baseline quantile %s/%s: %w", spec.Target, spec.Feature, err))
	}
	var p25, p50, p75 float64
	if baseOK {
		var ok25, ok50, ok75 bool
		if p25, _, ok25, err = store.Quantile(now, spec.Target, spec.Feature, spec.BaselineWindow(), 0.25); err != nil {
			return blind(now, spec, store, fmt.Errorf("tier2: p25 quantile %s/%s: %w", spec.Target, spec.Feature, err))
		}
		if p50, _, ok50, err = store.Quantile(now, spec.Target, spec.Feature, spec.BaselineWindow(), 0.50); err != nil {
			return blind(now, spec, store, fmt.Errorf("tier2: p50 quantile %s/%s: %w", spec.Target, spec.Feature, err))
		}
		if p75, _, ok75, err = store.Quantile(now, spec.Target, spec.Feature, spec.BaselineWindow(), 0.75); err != nil {
			return blind(now, spec, store, fmt.Errorf("tier2: p75 quantile %s/%s: %w", spec.Target, spec.Feature, err))
		}
		// Defensive: p25/p50/p75 query the exact same (target,feature,window)
		// row set as the p95 call above, so they are expected to agree on ok;
		// a disagreement is fail-closed (treated as no baseline).
		baseOK = ok25 && ok50 && ok75
	}

	// Robust (IQR-based) zscore — deterministic, NOT a Gaussian assumption.
	// z = (metric - p50) / max((p75-p25)/1.349, epsilon); the 1.349 divisor
	// makes the IQR comparable to a Gaussian standard deviation, and the
	// epsilon floor keeps a near-zero IQR from producing Inf/NaN.
	var zscore float64
	if measured && baseOK {
		denom := (p75 - p25) / 1.349
		if denom < zEpsilon {
			denom = zEpsilon
		}
		zscore = (metric - p50) / denom
	}

	// Non-finite guard. Finite inputs can still produce a non-finite output
	// (a huge metric over the epsilon floor overflows the zscore; quantile
	// interpolation between huge values overflows), and a ±Inf/NaN in a row
	// cannot be JSON-encoded — one used to fail digest.Write and with it the
	// whole detector run, Tier 1 included. Such an evaluation is unmeasurable:
	// status unknown, every float zeroed.
	if !finite(base) || !finite(p25) || !finite(p50) || !finite(p75) || !finite(zscore) {
		measured, unmeasuredWhy = false, "non-finite baseline or zscore"
		base, zscore = 0, 0
	}

	var status contract.DigestStatus
	switch {
	case !measured:
		status = contract.StatusUnknown
	case warming || !baseOK:
		status = contract.StatusBaselineWarming
	default:
		status = contract.StatusOK
	}

	rowValue := 0.0
	if measured {
		rowValue = metric
	}
	row := contract.DigestRow{
		RowID:      contract.Fingerprint(spec.Check, spec.Target),
		Entity:     spec.Entity,
		Target:     spec.Target,
		Feature:    spec.Feature,
		Value:      rowValue,
		Baseline7d: base,
		ZScore:     zscore,
		Unit:       spec.Unit,
		Status:     status,
	}

	var result Result
	if spec.Digest || status != contract.StatusOK {
		result.Row = &row
	}

	if !measured {
		// Fail-closed unknown path: the crossing state is untouched (a blind
		// eval must never advance or reset the hold timer), but a trend that
		// has already graduated stays present as Unknown rather than
		// resolving on a blind spot.
		result.UnknownMarker = spec.Target + "/" + spec.Feature
		f, err := held(now, spec, store, contract.StateUnknown, "unmeasurable: "+unmeasuredWhy)
		result.Finding = f
		return result, err
	}

	z := classify(spec.Signal, metric, spec.GraduateThreshold, spec.ClearThreshold)

	// C7/C9 descriptive markers are best-effort surfaces for the digest —
	// they reflect the metric-vs-threshold comparison alone, independent of
	// the warm-up/baseline graduation gate below (a warming flap is still
	// worth flagging to the analyst as "flapping", even though it cannot
	// graduate into a finding yet).
	if spec.Signal == "flap" && z == zoneEnter {
		result.Flap = fmt.Sprintf("%s: %d changes", spec.Target, int64(math.Round(metric)))
	}
	if spec.Signal == "template_surprise" && z == zoneEnter {
		result.NewTemplate = spec.Target + "/" + spec.Feature
	}

	if warming || !baseOK {
		// Warming or missing-baseline: NEVER graduate, and do NOT touch
		// crossing state either — a warming/blind eval must not accumulate
		// hold time toward a graduation it is not yet allowed to make. A
		// crossing that already served its hold (e.g. the warmup table was
		// lost in a restore while the crossing row survived) is held as
		// Unknown: this baseline cannot confirm it, and cannot clear it.
		f, err := held(now, spec, store, contract.StateUnknown, "baseline not trustworthy (warming or no baseline in window)")
		result.Finding = f
		return result, err
	}

	switch z {
	case zoneClear:
		if err := store.ClearCrossing(spec.Check, spec.Target); err != nil {
			return result, fmt.Errorf("tier2: clear crossing %s/%s: %w", spec.Check, spec.Target, err)
		}
	case zoneHold:
		// Neither a fresh entry nor a clear: the crossing is left as-is, and
		// a crossing that has served its hold keeps its alert firing.
		f, err := held(now, spec, store, contract.StateFiring, fmt.Sprintf(
			"metric=%.4f in hold band (clear_threshold=%.4f graduate_threshold=%.4f) baseline_7d=%.4f",
			metric, spec.ClearThreshold, spec.GraduateThreshold, base))
		result.Finding = f
		return result, err
	case zoneEnter:
		since, err := store.MarkCrossing(now, spec.Check, spec.Target)
		if err != nil {
			// The metric IS in the graduating zone; if the crossing is still
			// readable and has served its hold, it keeps firing.
			f, herr := held(now, spec, store, contract.StateFiring, fmt.Sprintf(
				"metric=%.4f graduate_threshold=%.4f baseline_7d=%.4f", metric, spec.GraduateThreshold, base))
			result.Finding = f
			return result, errors.Join(fmt.Errorf("tier2: mark crossing %s/%s: %w", spec.Check, spec.Target, err), herr)
		}
		if elapsed := now.Sub(since); elapsed >= minHold(spec) {
			evidence := fmt.Sprintf(
				"metric=%.4f graduate_threshold=%.4f baseline_7d=%.4f hold_elapsed=%s (min_hold=%s)",
				metric, spec.GraduateThreshold, base, elapsed.Round(time.Second), minHold(spec),
			)
			f, ferr := mint(now, spec, contract.StateFiring, evidence)
			if ferr != nil {
				// A graduation that can't be minted must not crash the run:
				// the row (and any markers) are still returned; Finding
				// stays nil and the wrapped error is surfaced for the
				// caller (S2-c) to log.
				return result, ferr
			}
			result.Finding = f
		}
	}

	return result, nil
}

func minHold(spec manifest.Tier2Spec) time.Duration {
	return time.Duration(spec.MinHoldSeconds) * time.Second
}

// mint builds the spec's trend finding via contract.NewFinding (ADR-G09),
// which additionally caps class=trend at warning.
func mint(now time.Time, spec manifest.Tier2Spec, state contract.State, evidence string) (*contract.Finding, error) {
	f, err := contract.NewFinding(now, contract.FindingSpec{
		Check:    spec.Check,
		Group:    spec.Group,
		Target:   spec.Target,
		Node:     spec.Node,
		Severity: sevOrInfo(spec.Severity),
		Class:    contract.ClassTrend,
		State:    state,
		Title:    spec.ID,
		Evidence: evidence,
	})
	if err != nil {
		return nil, fmt.Errorf("tier2: mint finding %s/%s: %w", spec.Check, spec.Target, err)
	}
	return &f, nil
}

// held returns the spec's trend finding in the given state IF a crossing
// exists that has already served its min_hold — i.e. the spec is graduated —
// and nil otherwise. It READS the crossing (store.Crossing) and never marks
// or clears it, so calling it cannot move the hold timer.
func held(now time.Time, spec manifest.Tier2Spec, store *baseline.Store, state contract.State, why string) (*contract.Finding, error) {
	since, ok, err := store.Crossing(spec.Check, spec.Target)
	if err != nil {
		return nil, fmt.Errorf("tier2: read crossing %s/%s: %w", spec.Check, spec.Target, err)
	}
	if !ok {
		return nil, nil
	}
	elapsed := now.Sub(since)
	if elapsed < minHold(spec) {
		return nil, nil // in the zone, but never graduated: nothing to hold
	}
	return mint(now, spec, state, fmt.Sprintf("%s; graduated trend held (crossing since %s, hold_elapsed=%s)",
		why, since.Format(time.RFC3339), elapsed.Round(time.Second)))
}

// blind is the fail-closed Result for an evaluation the store could not
// complete: an explicit unknown row (all floats zeroed) and marker — so the
// spec never silently vanishes from the digest — plus the held Unknown
// finding when the crossing is still readable, so a graduated trend is not
// resolved by a store failure either. err is returned (joined with any
// crossing-read failure) for the caller to log.
func blind(now time.Time, spec manifest.Tier2Spec, store *baseline.Store, err error) (Result, error) {
	row := contract.DigestRow{
		RowID:   contract.Fingerprint(spec.Check, spec.Target),
		Entity:  spec.Entity,
		Target:  spec.Target,
		Feature: spec.Feature,
		Unit:    spec.Unit,
		Status:  contract.StatusUnknown,
	}
	result := Result{Row: &row, UnknownMarker: spec.Target + "/" + spec.Feature}
	f, herr := held(now, spec, store, contract.StateUnknown, "unmeasurable: baseline store failure")
	result.Finding = f
	return result, errors.Join(err, herr)
}
