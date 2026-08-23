package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lazarevtill/heimdall/internal/ledger"
	"github.com/lazarevtill/heimdall/internal/notify"
	"github.com/lazarevtill/heimdall/internal/suppress"
)

// This file is the UI's view model: everything between "what the stores
// hold" and "what the page says". It is deliberately free of net/http and
// of time.Now() — every function takes an injected now — so the whole of
// the console's behaviour is table-testable without a server or a clock.

// Severity/state tiers, ordered by how loudly they should be read. This is
// the ONLY place the console decides what outranks what.
const (
	tierFiring  = 0
	tierUnknown = 1
	tierWarning = 2
	tierOK      = 3
)

// FindingView is one row of the signals list.
type FindingView struct {
	Fingerprint string
	Check       string
	Target      string
	State       string
	Severity    string
	FirstSeen   time.Time
	LastSeen    time.Time
	Count       int64

	// Age is LastSeen relative to now, pre-rendered for the template.
	Age string
	// FirstSeenAge is FirstSeen relative to now.
	FirstSeenAge string

	// Tier drives ordering and the left-rule treatment.
	Tier int
	// Label is the badge text ("Firing", "Unknown", "Warning", "Ok").
	Label string

	// Muted reports whether the suppression authority currently holds this
	// finding back. A muted finding KEEPS its series and stays in this list
	// — suppression silences notification, never detection — so the UI must
	// show it rather than filter it away.
	Muted bool
	// MuteReason is the active suppression's reason, when muted.
	MuteReason string
	// MuteUntil is the active suppression's expiry, when muted.
	MuteUntil string
}

// classify assigns the reading tier and badge label for a ledger entry.
//
// `unknown` is deliberately NOT ranked below `warning`. It is the absence of
// a verdict, not a milder problem: a source that timed out could be hiding
// anything, and the engine treats it as alertable for exactly that reason.
// Ranking it under warning here would quietly contradict the detector.
func classify(state, severity string) (tier int, label string) {
	switch strings.ToLower(state) {
	case "unknown":
		return tierUnknown, "Unknown"
	case "firing":
		if strings.EqualFold(severity, "warning") {
			return tierWarning, "Warning"
		}
		return tierFiring, "Firing"
	case "ok":
		return tierOK, "Ok"
	default:
		// An unrecognised state is treated as Unknown rather than dropped:
		// silently omitting a row the UI does not understand is the exact
		// failure mode this system exists to prevent.
		return tierUnknown, "Unknown"
	}
}

// BuildFindings turns ledger entries into ordered view rows, annotating each
// with its active suppression (if any).
//
// Ordering is (tier, then most-recently-seen, then fingerprint). The
// fingerprint tiebreak matters: one detector run stamps every finding with
// an identical last_seen, so without it the list would reshuffle between
// renders for no reason.
func BuildFindings(now time.Time, entries []ledger.Entry, authority *suppress.Authority) []FindingView {
	out := make([]FindingView, 0, len(entries))
	for _, e := range entries {
		tier, label := classify(e.State, e.Severity)
		v := FindingView{
			Fingerprint:  e.Fingerprint,
			Check:        e.Check,
			Target:       e.Target,
			State:        e.State,
			Severity:     e.Severity,
			FirstSeen:    e.FirstSeen,
			LastSeen:     e.LastSeen,
			Count:        e.Count,
			Age:          HumanAge(now, e.LastSeen),
			FirstSeenAge: HumanAge(now, e.FirstSeen),
			Tier:         tier,
			Label:        label,
		}
		if authority != nil {
			// MatchFields is used rather than FindingSuppression because the
			// ledger stores the identity fields, not a reconstructed
			// contract.Finding — and fabricating one here would mean
			// inventing a class and severity the ledger never recorded.
			if s := authority.MatchFields(now, e.Fingerprint, "", e.Check, e.Target); s != nil {
				v.Muted = true
				v.MuteReason = s.Reason
				v.MuteUntil = s.Until
			}
		}
		out = append(out, v)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Tier != out[j].Tier {
			return out[i].Tier < out[j].Tier
		}
		if !out[i].LastSeen.Equal(out[j].LastSeen) {
			return out[i].LastSeen.After(out[j].LastSeen)
		}
		return out[i].Fingerprint < out[j].Fingerprint
	})
	return out
}

// Counts summarises the signals list for the header strip.
type Counts struct {
	Firing  int
	Unknown int
	Warning int
	OK      int
	Muted   int
}

// Summarise counts each tier. Muted rows are counted in BOTH their tier and
// the muted total — a muted finding is still firing, which is the whole
// point of the distinction.
func Summarise(views []FindingView) Counts {
	var c Counts
	for _, v := range views {
		switch v.Tier {
		case tierFiring:
			c.Firing++
		case tierUnknown:
			c.Unknown++
		case tierWarning:
			c.Warning++
		case tierOK:
			c.OK++
		}
		if v.Muted {
			c.Muted++
		}
	}
	return c
}

// SinkView is one row of the delivery table.
type SinkView struct {
	SinkID     string
	Channel    string
	Backlog    string
	Seconds    int64
	Stalled    bool
	Delivering bool
}

// backlogStalledSeconds is the age at which the console calls a sink
// stalled. It matches the HeimdallSinkBacklogCritical meta-rule's threshold
// so the page and the pager never disagree about what "stuck" means.
const backlogStalledSeconds = 900

// BuildSinks renders the per-(sink, channel) backlog rows.
func BuildSinks(backlogs []notify.SinkBacklog) []SinkView {
	out := make([]SinkView, 0, len(backlogs))
	for _, b := range backlogs {
		out = append(out, SinkView{
			SinkID:     b.SinkID,
			Channel:    string(b.Channel),
			Seconds:    b.Seconds,
			Backlog:    HumanDuration(time.Duration(b.Seconds) * time.Second),
			Stalled:    b.Seconds >= backlogStalledSeconds,
			Delivering: b.Seconds < backlogStalledSeconds,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].SinkID != out[j].SinkID {
			return out[i].SinkID < out[j].SinkID
		}
		return out[i].Channel < out[j].Channel
	})
	return out
}

// SuppressionView is one row of the "what is being held back" table.
type SuppressionView struct {
	Key            string
	Scope          string
	Matcher        string
	Until          string
	Expires        string
	CumulativeDays int
	Reason         string
	Actor          string
	Source         string
	Active         bool
}

// BuildSuppressions renders the suppression rows, active ones first, then
// by expiry. Inactive (expired) records are retained rather than hidden:
// "why did this stop being muted" is a question the console should answer.
func BuildSuppressions(now time.Time, sups []suppress.Suppression) []SuppressionView {
	out := make([]SuppressionView, 0, len(sups))
	for _, s := range sups {
		v := SuppressionView{
			Key:            s.Key,
			Scope:          string(s.Scope),
			Matcher:        matcherSummary(s),
			Until:          s.Until,
			CumulativeDays: s.CumulativeDays,
			Reason:         s.Reason,
			Actor:          s.Actor,
			Source:         string(s.Source),
			Active:         s.Active(now),
		}
		v.Expires = expiresIn(now, s.Until)
		out = append(out, v)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Active != out[j].Active {
			return out[i].Active
		}
		return out[i].Key < out[j].Key
	})
	return out
}

// matcherSummary renders the scope-relevant matcher fields. suppress's own
// summary is unexported, so this mirrors it for display only.
func matcherSummary(s suppress.Suppression) string {
	m := s.Matcher
	switch s.Scope {
	case suppress.ScopeFingerprint:
		return m.Fingerprint
	case suppress.ScopeGroupCheck:
		return m.Group + " / " + m.Check
	case suppress.ScopeTarget:
		return m.Target
	case suppress.ScopeAnalyst:
		return m.Target + " / " + m.Feature
	case suppress.ScopeHypothesis:
		return m.HypFP
	default:
		return ""
	}
}

// expiresIn renders a suppression's Until as a relative phrase. The "never"
// sentinel is passed through verbatim — it is a deliberate, review-gated
// state, not a duration.
func expiresIn(now time.Time, until string) string {
	if until == "never" {
		return "never"
	}
	t, err := time.Parse(time.RFC3339, until)
	if err != nil {
		return until
	}
	if !t.After(now) {
		return "expired"
	}
	return "in " + HumanDuration(t.Sub(now))
}

// ComponentView is one heartbeat row.
type ComponentView struct {
	Name  string
	Age   string
	Stale bool
	// Present is false when the heartbeat series is ABSENT entirely, which
	// is a distinct and worse condition than stale: nothing has ever been
	// written, or the file was removed.
	Present bool
}

// heartbeatStaleAfter matches the meta-rules' 15-minute staleness window.
const heartbeatStaleAfter = 15 * time.Minute

// BuildComponents renders the component liveness strip from parsed
// heartbeat timestamps. A component with no entry in `seen` is reported
// ABSENT rather than omitted — a missing row would read as "fine".
func BuildComponents(now time.Time, seen map[string]time.Time) []ComponentView {
	names := []string{"detect", "analyst", "bridge", "notifier"}
	out := make([]ComponentView, 0, len(names))
	for _, n := range names {
		ts, ok := seen[n]
		if !ok {
			out = append(out, ComponentView{Name: n, Age: "absent", Stale: true, Present: false})
			continue
		}
		age := now.Sub(ts)
		out = append(out, ComponentView{
			Name:    n,
			Age:     HumanDuration(age),
			Stale:   age > heartbeatStaleAfter,
			Present: true,
		})
	}
	return out
}

// HumanAge renders how long ago t was, relative to now.
func HumanAge(now, t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	d := now.Sub(t)
	if d < 0 {
		return "just now"
	}
	return HumanDuration(d)
}

// HumanDuration renders a duration compactly: 42s, 11m, 4h12m, 6d.
// Deterministic and allocation-cheap; no dependency on a formatting lib.
func HumanDuration(d time.Duration) string {
	if d < 0 {
		d = -d
	}
	switch {
	case d < time.Minute:
		return strconv.Itoa(int(d.Seconds())) + "s"
	case d < time.Hour:
		return strconv.Itoa(int(d.Minutes())) + "m"
	case d < 24*time.Hour:
		h := int(d.Hours())
		m := int(d.Minutes()) - h*60
		if m == 0 {
			return strconv.Itoa(h) + "h"
		}
		return fmt.Sprintf("%dh%02dm", h, m)
	default:
		days := int(d.Hours()) / 24
		h := int(d.Hours()) - days*24
		if h == 0 {
			return strconv.Itoa(days) + "d"
		}
		return fmt.Sprintf("%dd%dh", days, h)
	}
}
