package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/lazarevtill/heimdall/internal/contract"
)

// The Tier-3 analyst's persisted runs: <HEIMDALL_ANALYST_RUN_DIR>/<run_id>.json,
// each a contract.AnalystRun written BEFORE any POST so nothing is lost when
// the bridge is down.
//
// FOUR THINGS THIS PAGE MUST NOT IMPLY, each of which the data would
// otherwise invite:
//
//  1. It is not "all hypotheses". The run file holds SURVIVORS — findings
//     dropped as hallucinated, invalid, deduped or over the per-run cap have
//     their text preserved nowhere; only counters survive, in Prometheus.
//  2. Presence is not delivery. persist() runs before any POST, runs in
//     dry-run with zero posts, and survives a POST failure. The file is a
//     strict superset of what reached anyone.
//  3. Confidence is not severity. A hypothesis structurally cannot page —
//     NewFinding refuses class=hypothesis — so confidence is metadata, and
//     styling it like a severity would misrepresent the trust boundary.
//  4. suggested_check is inert. The contract says it is "MR fodder only and
//     is NEVER applied"; it must never be rendered as a button, a link, or
//     anything that reads as runnable.
//
// hyp_fp shares the 16-lowercase-hex grammar with a finding fingerprint, so
// hypotheses get their OWN route and their own labelling. Feeding a hyp_fp
// to /finding/{fp} would 404 at best and show an unrelated finding at worst.

// maxRunFileBytes caps one run file. Text is bounded to 500 runes per
// hypothesis and items to 16, so a run is small by construction.
const maxRunFileBytes = 512 << 10

// maxRunsShown bounds how many runs the page lists.
const maxRunsShown = 20

// hypBoundedItems mirrors the analyst wrapper's per-list cap
// (internal/analyst's maxBoundedItems). A list AT the cap was probably
// truncated, and the caps are otherwise silent.
const hypBoundedItems = 16

// HypothesisView is one rendered hypothesis.
type HypothesisView struct {
	Fingerprint    string
	Kind           string
	Confidence     string
	Targets        []string
	Hypothesis     string
	EvidenceRows   []string
	SuggestedQuery []string
	SuggestedCheck string

	// TextTruncated / RowsTruncated flag a value sitting exactly at its cap.
	// The wrapper truncates silently, so without this the page would imply
	// the model said exactly this much.
	TextTruncated bool
	RowsTruncated bool

	// Muted reports an operator having already dismissed this hypothesis via
	// a ScopeHypothesis suppression.
	Muted      bool
	MuteReason string
}

// RunView is one analyst run.
type RunView struct {
	RunID          string
	GeneratedAt    time.Time
	Generated      string
	Age            string
	NothingNotable bool
	Findings       []HypothesisView
}

// HypothesesView is the whole page.
type HypothesesView struct {
	Present bool
	Reason  string
	Runs    []RunView
	// Total counts surviving hypotheses across the listed runs.
	Total int
	// Truncated is true when more runs exist on disk than are shown.
	Truncated bool
}

// ReadRuns loads the most recent analyst runs.
//
// Fail-soft and non-fabricating, like the spool and digest readers: an
// unreadable directory yields Present=false with a reason. One corrupt run
// file is skipped rather than blanking the page — but it is never rendered
// as an empty successful run, which would read as "the analyst found
// nothing".
func ReadRuns(dir string, now time.Time, muted map[string]contract2Suppression) HypothesesView {
	if dir == "" {
		return HypothesesView{Reason: "No analyst run directory is configured, so Tier-3 hypotheses are unavailable."}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return HypothesesView{Reason: "The analyst run directory does not exist. Tier 3 has never completed a run here."}
		}
		return HypothesesView{Reason: "The analyst run directory could not be read."}
	}

	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	if len(names) == 0 {
		return HypothesesView{Present: true, Reason: "No analyst runs have been written yet."}
	}
	// Run ids are fixed-width UTC (20060102T150405Z), so lexical order IS
	// chronological order. Newest first.
	sort.Sort(sort.Reverse(sort.StringSlice(names)))

	v := HypothesesView{Present: true}
	if len(names) > maxRunsShown {
		names = names[:maxRunsShown]
		v.Truncated = true
	}

	for _, name := range names {
		run, ok := readRunFile(filepath.Join(dir, name))
		if !ok {
			continue
		}
		rv := RunView{
			RunID:          run.RunID,
			NothingNotable: run.NothingNotable,
		}
		if rv.RunID == "" {
			rv.RunID = strings.TrimSuffix(name, ".json")
		}
		if t, err := time.Parse(time.RFC3339, run.GeneratedAt); err == nil {
			rv.GeneratedAt = t.UTC()
			rv.Generated = t.UTC().Format("2006-01-02 15:04:05Z")
			rv.Age = HumanAge(now, t)
		} else if t, err := time.Parse("20060102T150405Z", rv.RunID); err == nil {
			// Fall back to the run id, which carries the same instant.
			rv.GeneratedAt = t.UTC()
			rv.Generated = t.UTC().Format("2006-01-02 15:04:05Z")
			rv.Age = HumanAge(now, t)
		} else {
			rv.Age = "unknown"
		}

		for _, f := range run.Findings {
			hv := HypothesisView{
				Fingerprint:    f.Fingerprint,
				Kind:           string(f.Kind),
				Confidence:     string(f.Confidence),
				Targets:        f.Targets,
				Hypothesis:     f.Hypothesis,
				EvidenceRows:   f.EvidenceRows,
				SuggestedQuery: f.SuggestedQuery,
				SuggestedCheck: f.SuggestedCheck,
				TextTruncated:  utf8.RuneCountInString(f.Hypothesis) >= contract.HypMaxText,
				RowsTruncated:  len(f.EvidenceRows) >= hypBoundedItems,
			}
			if s, ok := muted[f.Fingerprint]; ok {
				hv.Muted = true
				hv.MuteReason = s.Reason
			}
			rv.Findings = append(rv.Findings, hv)
			v.Total++
		}
		v.Runs = append(v.Runs, rv)
	}
	return v
}

// contract2Suppression is the minimal suppression shape this page needs,
// declared locally so the reader does not depend on the suppress package's
// full record just to show a reason.
type contract2Suppression struct{ Reason string }

// readRunFile decodes one run file. contract.AnalystRun is plain strings and
// slices — no int-backed enum — so it round-trips through encoding/json
// without the contract.State hazard that forces the spool reader to use a
// local DTO.
func readRunFile(path string) (contract.AnalystRun, bool) {
	f, err := os.Open(path)
	if err != nil {
		return contract.AnalystRun{}, false
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil || info.Size() > maxRunFileBytes {
		return contract.AnalystRun{}, false
	}
	var run contract.AnalystRun
	if err := json.NewDecoder(f).Decode(&run); err != nil {
		return contract.AnalystRun{}, false
	}
	return run, true
}

// hypothesisNote is the standing caveat rendered above every run list. It is
// deliberately a constant rather than prose in the template, so the wording
// cannot drift away from what the data actually supports.
const hypothesisNote = "These are the hypotheses that survived the wrapper's gates and were eligible to post — " +
	"not everything the model produced. Hypotheses dropped as hallucinated, invalid, duplicate, or over the " +
	"per-run cap have their text retained nowhere; only counters survive, in Prometheus. Appearing here also " +
	"does not mean a hypothesis was delivered: the run is written before any POST, and survives a failed one."

// describeConfidence renders confidence as metadata, never as severity.
func describeConfidence(c string) string {
	switch contract.Confidence(c) {
	case contract.ConfidenceHigh:
		return "model-reported confidence: high"
	case contract.ConfidenceMedium:
		return "model-reported confidence: medium"
	case contract.ConfidenceLow:
		return "model-reported confidence: low"
	default:
		return "model-reported confidence: " + c
	}
}

// hypothesisRunCount renders a short run summary line.
func hypothesisRunCount(r RunView) string {
	if r.NothingNotable && len(r.Findings) == 0 {
		return "nothing notable"
	}
	return fmt.Sprintf("%d hypothesis(es)", len(r.Findings))
}
