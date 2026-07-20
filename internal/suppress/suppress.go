package suppress

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/lazarevtill/heimdall/internal/contract"
)

// Scope is the kind of subject a Suppression matches.
type Scope string

const (
	// ScopeFingerprint matches a Finding whose Fingerprint equals
	// Matcher.Fingerprint.
	ScopeFingerprint Scope = "fingerprint"
	// ScopeGroupCheck matches a Finding whose Group AND Check both equal
	// Matcher.Group / Matcher.Check. Telegram button mutes are scoped here.
	ScopeGroupCheck Scope = "group_check"
	// ScopeTarget matches a Finding whose Target equals Matcher.Target.
	ScopeTarget Scope = "target"
	// ScopeAnalyst excludes a (target,feature) pair from the Tier-3 digest
	// view. It never matches a Tier-1/2 Finding.
	ScopeAnalyst Scope = "analyst"
	// ScopeHypothesis matches a hypothesis by hyp_fp. It never matches a
	// Tier-1/2 Finding.
	ScopeHypothesis Scope = "hypothesis"
)

// Source identifies where a Suppression record came from.
type Source string

const (
	// SourceDeclarative records are loaded from the tofu-rendered
	// suppressions.json (IaC-authored).
	SourceDeclarative Source = "declarative"
	// SourceRuntime records are written by the notifier's Telegram buttons
	// into this package's SQLite store.
	SourceRuntime Source = "runtime"
)

// Matcher holds the scope-specific fields of one Suppression. Only the
// fields relevant to the record's Scope are populated; Validate enforces
// which are required (and which must be empty) per scope.
type Matcher struct {
	Fingerprint string `json:"fingerprint,omitempty"`
	Group       string `json:"group,omitempty"`
	Check       string `json:"check,omitempty"`
	Target      string `json:"target,omitempty"`
	Feature     string `json:"feature,omitempty"`
	HypFP       string `json:"hyp_fp,omitempty"`
}

// Suppression is one authority record (declarative or runtime).
type Suppression struct {
	Key     string  `json:"key"`
	Scope   Scope   `json:"scope"`
	Matcher Matcher `json:"matcher"`
	// Until is RFC3339 or the sentinel "never".
	Until string `json:"until"`
	// ReviewAfter (RFC3339) is required iff Until=="never".
	ReviewAfter    string `json:"review_after,omitempty"`
	CumulativeDays int    `json:"cumulative_days"`
	Reason         string `json:"reason"`
	Actor          string `json:"actor"`
	Source         Source `json:"source"`
}

// Validate checks one record fail-loud: scope in-set; matcher has exactly
// the required non-empty fields for its scope (e.g. group_check needs group
// AND check, and rejects a stray fingerprint); until present and
// RFC3339-parseable OR "never"+review_after present (review_after, when
// present, must itself be RFC3339); cumulative_days in [0,30] unless
// until=="never" (a "never" record bypasses the day-cap entirely — its
// review_after is the accountability mechanism instead); key/reason/actor
// non-empty; source in-set. now is accepted for signature symmetry with the
// rest of the package (ADR-G10: every time-aware function takes an injected
// now) but is not itself consulted — expiry is a matter for Active, never
// for Validate, since an expired record is inactive, not invalid.
func (s Suppression) Validate(now time.Time) error {
	_ = now
	if s.Key == "" {
		return errors.New("suppress: invalid record: empty key")
	}
	switch s.Scope {
	case ScopeFingerprint, ScopeGroupCheck, ScopeTarget, ScopeAnalyst, ScopeHypothesis:
	default:
		return fmt.Errorf("suppress: %s: invalid scope %q", s.Key, s.Scope)
	}
	if err := s.validateMatcher(); err != nil {
		return fmt.Errorf("suppress: %s: %w", s.Key, err)
	}
	if s.Reason == "" {
		return fmt.Errorf("suppress: %s: empty reason", s.Key)
	}
	if s.Actor == "" {
		return fmt.Errorf("suppress: %s: empty actor", s.Key)
	}
	switch s.Source {
	case SourceDeclarative, SourceRuntime:
	default:
		return fmt.Errorf("suppress: %s: invalid source %q", s.Key, s.Source)
	}
	if s.Until == "never" {
		if s.ReviewAfter == "" {
			return fmt.Errorf("suppress: %s: until=\"never\" requires review_after", s.Key)
		}
		if _, err := time.Parse(time.RFC3339, s.ReviewAfter); err != nil {
			return fmt.Errorf("suppress: %s: review_after not RFC3339: %w", s.Key, err)
		}
		if s.CumulativeDays < 0 {
			return fmt.Errorf("suppress: %s: negative cumulative_days", s.Key)
		}
		return nil
	}
	if s.Until == "" {
		return fmt.Errorf("suppress: %s: missing until (expiry is mandatory)", s.Key)
	}
	if _, err := time.Parse(time.RFC3339, s.Until); err != nil {
		return fmt.Errorf("suppress: %s: until not RFC3339: %w", s.Key, err)
	}
	if s.ReviewAfter != "" {
		if _, err := time.Parse(time.RFC3339, s.ReviewAfter); err != nil {
			return fmt.Errorf("suppress: %s: review_after not RFC3339: %w", s.Key, err)
		}
	}
	if s.CumulativeDays < 0 || s.CumulativeDays > 30 {
		return fmt.Errorf("suppress: %s: cumulative_days %d exceeds the 30-day cap", s.Key, s.CumulativeDays)
	}
	return nil
}

// validateMatcher enforces exactly the required (and no extraneous) matcher
// fields for s.Scope.
func (s Suppression) validateMatcher() error {
	m := s.Matcher
	switch s.Scope {
	case ScopeFingerprint:
		if m.Fingerprint == "" {
			return errors.New("fingerprint scope requires matcher.fingerprint")
		}
		if m.Group != "" || m.Check != "" || m.Target != "" || m.Feature != "" || m.HypFP != "" {
			return errors.New("fingerprint scope: matcher has extraneous fields set")
		}
	case ScopeGroupCheck:
		if m.Group == "" || m.Check == "" {
			return errors.New("group_check scope requires matcher.group and matcher.check")
		}
		if m.Fingerprint != "" || m.Target != "" || m.Feature != "" || m.HypFP != "" {
			return errors.New("group_check scope: matcher has extraneous fields set")
		}
	case ScopeTarget:
		if m.Target == "" {
			return errors.New("target scope requires matcher.target")
		}
		if m.Fingerprint != "" || m.Group != "" || m.Check != "" || m.Feature != "" || m.HypFP != "" {
			return errors.New("target scope: matcher has extraneous fields set")
		}
	case ScopeHypothesis:
		if m.HypFP == "" {
			return errors.New("hypothesis scope requires matcher.hyp_fp")
		}
		if m.Fingerprint != "" || m.Group != "" || m.Check != "" || m.Target != "" || m.Feature != "" {
			return errors.New("hypothesis scope: matcher has extraneous fields set")
		}
	case ScopeAnalyst:
		// matcher {feature} and/or {target}: feature is mandatory, target
		// optionally narrows the exclusion further.
		if m.Feature == "" {
			return errors.New("analyst scope requires matcher.feature")
		}
		if m.Fingerprint != "" || m.Group != "" || m.Check != "" || m.HypFP != "" {
			return errors.New("analyst scope: matcher has extraneous fields set")
		}
	}
	return nil
}

// Active reports whether the record is currently in force at now (not
// expired). The "never" sentinel is always active until review —
// review_after does not deactivate it, it only flags it for the weekly
// digest, which is a later consumer. An unparseable Until (should not
// happen on a Validated record) is treated as inactive: fail-safe, a
// corrupt record can never suppress anything.
func (s Suppression) Active(now time.Time) bool {
	if s.Until == "never" {
		return true
	}
	until, err := time.Parse(time.RFC3339, s.Until)
	if err != nil {
		return false
	}
	return !now.After(until)
}

// MatchesFinding reports whether this record suppresses f. Only the
// fingerprint / group_check / target scopes can match a Finding;
// hypothesis/analyst scopes never do. An inactive record never matches.
func (s Suppression) MatchesFinding(now time.Time, f contract.Finding) bool {
	if !s.Active(now) {
		return false
	}
	return s.matchesFields(f.Fingerprint, f.Group, f.Check, f.Target)
}

// matchesFields is the scope-comparison core shared by MatchesFinding
// (which derives the four fields from a contract.Finding) and
// Authority.MatchFields (which the bridge calls directly on raw
// Alertmanager label strings, without ever constructing a contract.Finding
// — see Authority.MatchFields' doc comment for why). Active is NOT checked
// here; both callers gate on it themselves before calling in.
func (s Suppression) matchesFields(fingerprint, group, check, target string) bool {
	switch s.Scope {
	case ScopeFingerprint:
		return s.Matcher.Fingerprint == fingerprint
	case ScopeGroupCheck:
		return s.Matcher.Group == group && s.Matcher.Check == check
	case ScopeTarget:
		return s.Matcher.Target == target
	default:
		return false
	}
}

// MatchesHypothesis reports whether this record suppresses a hypothesis with
// the given hyp_fp. Only the hypothesis scope matches; everything else is
// false. An inactive record never matches.
func (s Suppression) MatchesHypothesis(now time.Time, hypFP string) bool {
	if !s.Active(now) || s.Scope != ScopeHypothesis {
		return false
	}
	return s.Matcher.HypFP == hypFP
}

// MatchesAnalystFeature reports whether this record (analyst scope) excludes
// a (target,feature) pair from the Tier-3 digest view. Only the analyst
// scope matches. When Matcher.Target is empty the exclusion applies to
// feature across all targets; when set, target must also match.
func (s Suppression) MatchesAnalystFeature(now time.Time, target, feature string) bool {
	if !s.Active(now) || s.Scope != ScopeAnalyst {
		return false
	}
	if s.Matcher.Feature != feature {
		return false
	}
	if s.Matcher.Target != "" && s.Matcher.Target != target {
		return false
	}
	return true
}

// matcherSummary renders a short human-readable identity for the record's
// matcher, scope-appropriate.
func (s Suppression) matcherSummary() string {
	switch s.Scope {
	case ScopeFingerprint:
		return s.Matcher.Fingerprint
	case ScopeGroupCheck:
		return s.Matcher.Group + "/" + s.Matcher.Check
	case ScopeTarget:
		return s.Matcher.Target
	case ScopeHypothesis:
		return s.Matcher.HypFP
	case ScopeAnalyst:
		if s.Matcher.Target != "" {
			return s.Matcher.Feature + "@" + s.Matcher.Target
		}
		return s.Matcher.Feature
	default:
		return ""
	}
}

// Annotation renders the "suppressed(until/by/why)" string the digest
// carries for a muted subject, e.g.:
//
//	group_check:disk/smart-fail suppressed until 2026-08-01T00:00:00Z by ops: known bad drive RMA pending
//
// Deterministic. Redaction of this string is the CALLER's egress
// responsibility (the digest writer already redacts), so this stays
// pure/textual.
func (s Suppression) Annotation() string {
	return fmt.Sprintf("%s:%s suppressed until %s by %s: %s",
		s.Scope, s.matcherSummary(), s.Until, s.Actor, s.Reason)
}

// LoadDeclarative reads a tofu-rendered suppressions.json (a JSON array of
// records) from path, forces Source=declarative on each, and Validates each
// at now. Returns a descriptive error on the FIRST invalid record (fail-loud
// — a malformed authority file must not silently partially load). A missing
// file is an error (the caller decides whether absence is acceptable; this
// function does not treat missing as empty). An empty JSON array yields an
// empty slice and a nil error.
func LoadDeclarative(path string, now time.Time) ([]Suppression, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("suppress: load declarative %s: %w", path, err)
	}
	var recs []Suppression
	if err := json.Unmarshal(data, &recs); err != nil {
		return nil, fmt.Errorf("suppress: parse declarative %s: %w", path, err)
	}
	for i := range recs {
		recs[i].Source = SourceDeclarative
		if err := recs[i].Validate(now); err != nil {
			return nil, fmt.Errorf("suppress: load declarative %s: record %d (key=%q): %w", path, i, recs[i].Key, err)
		}
	}
	return recs, nil
}
