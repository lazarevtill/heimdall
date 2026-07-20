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

// Result is one Tier-2 spec's evaluation. At most one of Finding is set
// (graduated); Row is the digest row (always produced when spec.Digest, and
// ALSO always produced when the status is not StatusOK — StatusUnknown or
// StatusBaselineWarming — because a blind spot is never dropped just because
// the manifest didn't ask for that feature's healthy rows in the digest).
// Marker fields feed the digest's top-level echo arrays so the analyst is
// always told what was unmeasurable / surprising.
type Result struct {
	Finding       *contract.Finding   // non-nil ONLY when graduated: class=trend, StateFiring
	Row           *contract.DigestRow // the feature row (nil only when spec.Digest==false AND status==StatusOK)
	UnknownMarker string              // "<target>/<feature>" when the signal was unknown
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
// spot must never be silently read as 0/calm.
func reduceMetric(signal string, sig source.Signal) (metric float64, measured bool) {
	if sig.State == contract.StateUnknown {
		return 0, false
	}
	if len(sig.Samples) == 0 {
		return 0, false
	}
	if signal == "slope" {
		m := sig.Samples[0].Value
		for _, s := range sig.Samples[1:] {
			if s.Value < m {
				m = s.Value
			}
		}
		return m, true
	}
	m := sig.Samples[0].Value
	for _, s := range sig.Samples[1:] {
		if s.Value > m {
			m = s.Value
		}
	}
	return m, true
}

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
func Eval(now time.Time, spec manifest.Tier2Spec, sig source.Signal, store *baseline.Store) (Result, error) {
	if err := store.MarkEnabled(now, spec.Check, spec.Target); err != nil {
		return Result{}, fmt.Errorf("tier2: mark enabled %s/%s: %w", spec.Check, spec.Target, err)
	}
	warming, err := store.Warming(now, spec.Check, spec.Target, WarmupWindow)
	if err != nil {
		return Result{}, fmt.Errorf("tier2: warming %s/%s: %w", spec.Check, spec.Target, err)
	}

	metric, measured := reduceMetric(spec.Signal, sig)

	if measured {
		if err := store.RecordFeature(now, spec.Entity, spec.Target, spec.Feature, metric); err != nil {
			return Result{}, fmt.Errorf("tier2: record feature %s/%s: %w", spec.Target, spec.Feature, err)
		}
	}

	// Baseline: q=0.95 is the baseline_7d reference the design compares
	// creep against; p25/p50/p75 are fetched additionally for a robust
	// (IQR-based) zscore. Fetched unconditionally — independent of
	// measured/warming — so a digest row can still show what the baseline
	// looks like even on an eval where the current sample is unmeasurable.
	base, _, baseOK, err := store.Quantile(now, spec.Target, spec.Feature, spec.BaselineWindow(), 0.95)
	if err != nil {
		return Result{}, fmt.Errorf("tier2: baseline quantile %s/%s: %w", spec.Target, spec.Feature, err)
	}
	var p25, p50, p75 float64
	if baseOK {
		var ok25, ok50, ok75 bool
		if p25, _, ok25, err = store.Quantile(now, spec.Target, spec.Feature, spec.BaselineWindow(), 0.25); err != nil {
			return Result{}, fmt.Errorf("tier2: p25 quantile %s/%s: %w", spec.Target, spec.Feature, err)
		}
		if p50, _, ok50, err = store.Quantile(now, spec.Target, spec.Feature, spec.BaselineWindow(), 0.50); err != nil {
			return Result{}, fmt.Errorf("tier2: p50 quantile %s/%s: %w", spec.Target, spec.Feature, err)
		}
		if p75, _, ok75, err = store.Quantile(now, spec.Target, spec.Feature, spec.BaselineWindow(), 0.75); err != nil {
			return Result{}, fmt.Errorf("tier2: p75 quantile %s/%s: %w", spec.Target, spec.Feature, err)
		}
		// Defensive: p25/p50/p75 query the exact same (target,feature,window)
		// row set as the p95 call above, so they are expected to agree on ok;
		// a disagreement is fail-closed (treated as no baseline).
		baseOK = ok25 && ok50 && ok75
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
		// Fail-closed unknown path: no finding, crossing state untouched (a
		// blind eval must never advance or reset the hold timer).
		result.UnknownMarker = spec.Target + "/" + spec.Feature
		return result, nil
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
		// hold time toward a graduation it is not yet allowed to make.
		return result, nil
	}

	minHold := time.Duration(spec.MinHoldSeconds) * time.Second
	switch z {
	case zoneClear:
		if err := store.ClearCrossing(spec.Check, spec.Target); err != nil {
			return result, fmt.Errorf("tier2: clear crossing %s/%s: %w", spec.Check, spec.Target, err)
		}
	case zoneHold:
		// Leave crossing as-is: neither a fresh entry nor a clear.
	case zoneEnter:
		since, err := store.MarkCrossing(now, spec.Check, spec.Target)
		if err != nil {
			return result, fmt.Errorf("tier2: mark crossing %s/%s: %w", spec.Check, spec.Target, err)
		}
		if elapsed := now.Sub(since); elapsed >= minHold {
			evidence := fmt.Sprintf(
				"metric=%.4f graduate_threshold=%.4f baseline_7d=%.4f hold_elapsed=%s (min_hold=%s)",
				metric, spec.GraduateThreshold, base, elapsed.Round(time.Second), minHold,
			)
			f, ferr := contract.NewFinding(now, contract.FindingSpec{
				Check:    spec.Check,
				Group:    spec.Group,
				Target:   spec.Target,
				Node:     spec.Node,
				Severity: sevOrInfo(spec.Severity),
				Class:    contract.ClassTrend,
				State:    contract.StateFiring,
				Title:    spec.ID,
				Evidence: evidence,
			})
			if ferr != nil {
				// A graduation that can't be minted must not crash the run:
				// the row (and any markers) are still returned; Finding
				// stays nil and the wrapped error is surfaced for the
				// caller (S2-c) to log.
				return result, fmt.Errorf("tier2: mint graduation finding %s/%s: %w", spec.Check, spec.Target, ferr)
			}
			result.Finding = &f
		}
	}

	return result, nil
}
