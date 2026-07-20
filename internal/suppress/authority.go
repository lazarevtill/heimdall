package suppress

import (
	"sort"
	"time"

	"github.com/lazarevtill/heimdall/internal/contract"
)

// Authority is the read-side union of declarative records and the runtime
// store, evaluated at a single now. Build it once per run (the design:
// "re-reading suppressions.json + the suppressions table each run").
type Authority struct {
	records []Suppression
}

// NewAuthority unions declarative + runtime records into one evaluated set.
// Declarative records are trusted as already-Validated (LoadDeclarative does
// this at load time) and are included verbatim. Runtime rows are
// defensively re-checked with Validate — this should never reject anything
// (AddMute validates before it ever persists a row), but the runtime store
// must never be able to wedge detection, so an invalid row is
// skipped-and-counted via the returned skipped count rather than failing
// the whole Authority. The now passed to that defensive Validate call is
// irrelevant to its outcome (Validate does not consult it; see its
// doc-comment), so the zero time.Time is used.
func NewAuthority(declarative, runtime []Suppression) (*Authority, int) {
	records := make([]Suppression, 0, len(declarative)+len(runtime))
	records = append(records, declarative...)
	skipped := 0
	for _, r := range runtime {
		if err := r.Validate(time.Time{}); err != nil {
			skipped++
			continue
		}
		records = append(records, r)
	}
	return &Authority{records: records}, skipped
}

// FindingSuppression returns the FIRST active record suppressing f, or nil.
func (a *Authority) FindingSuppression(now time.Time, f contract.Finding) *Suppression {
	for i := range a.records {
		if a.records[i].MatchesFinding(now, f) {
			rec := a.records[i]
			return &rec
		}
	}
	return nil
}

// MatchFields is FindingSuppression's raw-field counterpart: it evaluates
// the same fingerprint / group_check / target matching WITHOUT requiring a
// contract.Finding value. internal/bridge mute-gates its recurrence
// comments from Alertmanager webhook LABELS, not a contract.Finding it
// mints itself — and ADR-G09's `make lint` gate bans contract.Finding
// composite literals everywhere outside internal/contract (the whole point
// being that NewFinding's caps can't be bypassed by literal construction),
// so bridge has no sanctioned way to build one just to pass it here.
// MatchFields lets it match directly on the four raw strings instead; the
// returned FIRST active match is identical in meaning to
// FindingSuppression's, just reached without the contract dependency.
func (a *Authority) MatchFields(now time.Time, fingerprint, group, check, target string) *Suppression {
	for i := range a.records {
		if a.records[i].Active(now) && a.records[i].matchesFields(fingerprint, group, check, target) {
			rec := a.records[i]
			return &rec
		}
	}
	return nil
}

// HypothesisSuppressed reports whether any active record suppresses hypFP.
func (a *Authority) HypothesisSuppressed(now time.Time, hypFP string) bool {
	for i := range a.records {
		if a.records[i].MatchesHypothesis(now, hypFP) {
			return true
		}
	}
	return false
}

// AnalystFeatureExcluded reports whether any active analyst-scope record
// excludes (target,feature) from the digest view.
func (a *Authority) AnalystFeatureExcluded(now time.Time, target, feature string) bool {
	for i := range a.records {
		if a.records[i].MatchesAnalystFeature(now, target, feature) {
			return true
		}
	}
	return false
}

// ActiveAnnotations returns the Annotation() of every active record, sorted
// deterministically by key — this is what the detector folds into the
// digest's Suppressed[] so the analyst is told what is muted.
func (a *Authority) ActiveAnnotations(now time.Time) []string {
	type keyed struct{ key, annotation string }
	var active []keyed
	for _, r := range a.records {
		if r.Active(now) {
			active = append(active, keyed{r.Key, r.Annotation()})
		}
	}
	sort.Slice(active, func(i, j int) bool { return active[i].key < active[j].key })
	out := make([]string, len(active))
	for i, k := range active {
		out[i] = k.annotation
	}
	return out
}

// Silence is the downstream projection the notifier materializes into
// Alertmanager (loopback :9093). This package PRODUCES it; it does NOT talk
// to Alertmanager (that is S7). Matchers are label=value equalities on the
// wire label set {group, check, target, fingerprint} as the scope implies.
type Silence struct {
	Key      string
	Matchers map[string]string // e.g. {"group":.., "check":..} for group_check
	EndsAt   time.Time         // = until; "never" records are omitted (unbounded silences are not materialized)
	Comment  string            // reason + actor
}

// ActiveSilences returns one Silence per active record whose scope maps to
// wire labels (fingerprint/group_check/target), sorted deterministically by
// key. analyst/hypothesis scopes produce NO silence (they gate the
// digest/bridge, not Alertmanager). "never"/undated records produce no
// silence (a materialized silence must have an endsAt).
func (a *Authority) ActiveSilences(now time.Time) []Silence {
	var out []Silence
	for _, r := range a.records {
		if !r.Active(now) {
			continue
		}
		if r.Until == "never" {
			continue
		}
		var matchers map[string]string
		switch r.Scope {
		case ScopeFingerprint:
			matchers = map[string]string{"fingerprint": r.Matcher.Fingerprint}
		case ScopeGroupCheck:
			matchers = map[string]string{"group": r.Matcher.Group, "check": r.Matcher.Check}
		case ScopeTarget:
			matchers = map[string]string{"target": r.Matcher.Target}
		default:
			continue // analyst / hypothesis: no wire representation
		}
		endsAt, err := time.Parse(time.RFC3339, r.Until)
		if err != nil {
			continue // should not happen on a Validated record; fail-safe skip
		}
		out = append(out, Silence{
			Key:      r.Key,
			Matchers: matchers,
			EndsAt:   endsAt,
			Comment:  r.Reason + " (" + r.Actor + ")",
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}
