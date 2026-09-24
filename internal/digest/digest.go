// Package digest assembles and writes Heimdall's Tier-2 feature digest: the
// entirety of Tier 3's input (/var/lib/heimdall/digest/latest.json). Build is
// pure (no I/O); Write is the mandatory redacted+atomic egress with a 14-day
// dated history and a final byte-cap guard.
//
// No time.Now() anywhere in this package: every function that needs "now"
// takes an injected `now time.Time` parameter (ADR-G10).
package digest

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/lazarevtill/heimdall/internal/contract"
	"github.com/lazarevtill/heimdall/internal/emit"
	"github.com/lazarevtill/heimdall/internal/tier2"
)

// SchemaVersion is contract.Digest.SchemaVersion for every digest this
// package builds. Additive-only: new fields never bump it, a breaking change
// would.
const SchemaVersion = 1

// maxDigestBytes is the final, post-redaction byte guard (Write). The
// 200-row cap (contract.MaxDigestRows, applied in Build) almost always keeps
// the digest well under this; this is a last-resort safety net for
// pathologically long target/feature strings.
const maxDigestBytes = 32 << 10

// MaxEchoItems bounds each top-level echo list (unknown_markers, flaps,
// new_templates, suppressed, open_tier1_findings) in Build. Without it the
// lists are unbounded: a Prometheus outage turns EVERY Tier-1 expectation
// into an open finding at once, and those alone could fill the byte budget,
// leaving the byte cap nothing to drop but every feature row. A capped string
// list ends in a truncatedFmt entry so the reader is told it is partial;
// open_tier1_findings is a cross-link aid only (the findings themselves page
// from the .prom), so it is cut without a marker.
const MaxEchoItems = 50

// truncatedFmt is the entry that closes a partial echo list: "[truncated: N
// more]" (contract.EchoTruncatedFmt, which readers parse with
// contract.EchoLen). Never a real marker (those are "<target>/<feature>"-shaped).
const truncatedFmt = contract.EchoTruncatedFmt

// historyRetention is how long dated history files under <dir>/history/ are
// kept; Write GCs anything older on every call.
const historyRetention = 14 * 24 * time.Hour

// historyTimeFormat is the dated-history filename's timestamp layout
// (RFC3339-compact, UTC, colon-free so it is filesystem-safe).
const historyTimeFormat = "20060102T150405Z"

// Build assembles the digest from this run's Tier-2 results. Rows come out
// in contract.CapRows' order (non-ok rows retained preferentially, then
// descending |zscore|, ties broken by row_id); the marker echo arrays are
// deduped and sorted. Identical input therefore yields byte-identical JSON.
func Build(now, manifestGeneratedAt time.Time, results []tier2.Result,
	openTier1 []contract.OpenTier1Finding, suppressed []string) contract.Digest {
	var rows []contract.DigestRow
	var unknowns, flaps, templates []string
	for _, r := range results {
		if r.Row != nil {
			rows = append(rows, *r.Row)
		}
		if r.UnknownMarker != "" {
			unknowns = append(unknowns, r.UnknownMarker)
		}
		if r.Flap != "" {
			flaps = append(flaps, r.Flap)
		}
		if r.NewTemplate != "" {
			templates = append(templates, r.NewTemplate)
		}
	}
	kept, truncated := contract.CapRows(rows, contract.MaxDigestRows)
	if len(openTier1) > MaxEchoItems {
		openTier1 = openTier1[:MaxEchoItems:MaxEchoItems]
	}
	return contract.Digest{
		SchemaVersion:       SchemaVersion,
		GeneratedAt:         now,
		ManifestGeneratedAt: manifestGeneratedAt,
		Rows:                kept,
		UnknownMarkers:      capEcho(dedupSorted(unknowns)),
		NewTemplates:        capEcho(dedupSorted(templates)),
		Flaps:               capEcho(dedupSorted(flaps)),
		OpenTier1Findings:   openTier1,
		Suppressed:          capEcho(suppressed),
		RowsTruncated:       truncated,
	}
}

// capEcho keeps the first MaxEchoItems entries of an echo list and closes a
// longer one with a truncatedFmt entry counting what was cut.
func capEcho(in []string) []string {
	if len(in) <= MaxEchoItems {
		return in
	}
	out := make([]string, 0, MaxEchoItems+1)
	out = append(out, in[:MaxEchoItems]...)
	return append(out, fmt.Sprintf(truncatedFmt, len(in)-MaxEchoItems))
}

// truncatedCount parses a truncatedFmt entry.
func truncatedCount(s string) (int, bool) { return contract.EchoTruncated(s) }

// dropEcho removes the last REAL entry of an echo list, keeping (or adding)
// the closing truncatedFmt entry with its count bumped. ok is false when the
// list holds no real entry left to drop.
func dropEcho(in []string) (out []string, ok bool) {
	n, k := 0, len(in)
	if k > 0 {
		if c, isMarker := truncatedCount(in[k-1]); isMarker {
			n, k = c, k-1
		}
	}
	if k == 0 {
		return in, false
	}
	out = append(in[:k-1:k-1], fmt.Sprintf(truncatedFmt, n+1))
	return out, true
}

func dedupSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// Write redacts a COPY of dg (the mandatory 4th egress), enforces the 32KB
// post-redaction byte cap by dropping the lowest-priority row (then, only if
// the rows are gone, echo entries — see capToByteBudget) and re-marshaling
// until under budget, then atomically writes <dir>/latest.json
// AND a dated history file <dir>/history/<RFC3339-compact>.json, and GCs
// history files older than 14 days. Returns the count of redaction failures
// (the caller folds this into heimdall_redaction_failures_total). A
// redaction failure on a string field withholds THAT field
// (contract.EvidenceOrWithheld) but never drops the row — a blind spot must
// survive redaction exactly like a finding fires even when its evidence is
// withheld.
//
// History GC failures are best-effort (log-and-continue: Write still returns
// nil for them); only a failed latest.json write is a hard error, since that
// is the artifact Tier 3 actually reads.
func Write(dir string, dg contract.Digest, now time.Time) (redactionFailures int, err error) {
	rep, err := WriteAndReport(dir, dg, now)
	return rep.RedactionFailures, err
}

// Report is what one WriteAndReport did, for the caller's metrics.
type Report struct {
	// RedactionFailures feeds heimdall_redaction_failures_total.
	RedactionFailures int
	// RowsTruncated is the run's TOTAL row truncation — Build's 200-row cap
	// plus Write's byte cap — i.e. the rows_truncated latest.json records.
	// The caller emits it as heimdall_digest_rows_truncated_total.
	RowsTruncated int
}

// WriteAndReport is Write, additionally reporting the final row truncation.
// Before redaction it rewrites any row holding a non-finite float as an
// unknown row with its floats zeroed (and echoes it in unknown_markers):
// encoding/json refuses NaN/±Inf, and a digest that cannot be marshalled
// fails the whole detector run, Tier 1 included. tier2.Eval already refuses
// to build such a row; this is the last line, whatever the producer.
func WriteAndReport(dir string, dg contract.Digest, now time.Time) (Report, error) {
	redacted, failures := redact(finiteRows(dg))
	rep := Report{RedactionFailures: failures}
	data, err := capToByteBudget(&redacted)
	if err != nil {
		return rep, fmt.Errorf("digest: marshal: %w", err)
	}
	rep.RowsTruncated = redacted.RowsTruncated

	latestPath := filepath.Join(dir, "latest.json")
	if err := emit.WriteFileAtomic(latestPath, data); err != nil {
		return rep, fmt.Errorf("digest: write %s: %w", latestPath, err)
	}

	histDir := filepath.Join(dir, "history")
	histPath := filepath.Join(histDir, now.UTC().Format(historyTimeFormat)+".json")
	if err := emit.WriteFileAtomic(histPath, data); err != nil {
		return rep, fmt.Errorf("digest: write %s: %w", histPath, err)
	}

	gcHistory(histDir, now) // best-effort; failures never fail the run

	return rep, nil
}

// finiteRows returns dg with every row that holds a NaN/±Inf float rewritten
// as unknown (floats zeroed) and its "<target>/<feature>" echoed in
// unknown_markers. It copies the slices it changes; dg is not mutated.
func finiteRows(dg contract.Digest) contract.Digest {
	var rows []contract.DigestRow
	for i, r := range dg.Rows {
		if finite(r.Value) && finite(r.Baseline7d) && finite(r.ZScore) {
			continue
		}
		if rows == nil {
			rows = append([]contract.DigestRow(nil), dg.Rows...)
		}
		r.Value, r.Baseline7d, r.ZScore, r.Status = 0, 0, 0, contract.StatusUnknown
		rows[i] = r
		dg.UnknownMarkers = addMarker(dg.UnknownMarkers, r.Target+"/"+r.Feature)
	}
	if rows != nil {
		dg.Rows = rows
	}
	return dg
}

func finite(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) }

// addMarker inserts m into a sorted echo list (copying it) unless present,
// keeping any closing truncatedFmt entry last.
func addMarker(in []string, m string) []string {
	k := len(in)
	var tail []string
	if k > 0 {
		if _, isMarker := truncatedCount(in[k-1]); isMarker {
			tail, k = in[k-1:], k-1
		}
	}
	for _, s := range in[:k] {
		if s == m {
			return in
		}
	}
	out := append(append([]string(nil), in[:k]...), m)
	sort.Strings(out)
	return append(out, tail...)
}

// redact walks a COPY of dg, passing every free-text/identifier string
// through contract.EvidenceOrWithheld: row Entity/Target/Feature/Unit; every
// element of UnknownMarkers/NewTemplates/Flaps/Suppressed; and
// OpenTier1Findings[].Target (Fingerprint/Check are registry-controlled, not
// free text). Numbers pass through untouched.
func redact(dg contract.Digest) (contract.Digest, int) {
	failures := 0
	one := func(s string) string {
		out, failed := contract.EvidenceOrWithheld(s)
		if failed {
			failures++
		}
		return out
	}
	many := func(in []string) []string {
		if in == nil {
			return nil
		}
		out := make([]string, len(in))
		for i, s := range in {
			out[i] = one(s)
		}
		return out
	}

	rows := make([]contract.DigestRow, len(dg.Rows))
	for i, r := range dg.Rows {
		r.Entity = one(r.Entity)
		r.Target = one(r.Target)
		r.Feature = one(r.Feature)
		r.Unit = one(r.Unit)
		rows[i] = r
	}
	dg.Rows = rows

	openTier1 := make([]contract.OpenTier1Finding, len(dg.OpenTier1Findings))
	for i, o := range dg.OpenTier1Findings {
		o.Target = one(o.Target)
		openTier1[i] = o
	}
	dg.OpenTier1Findings = openTier1

	dg.UnknownMarkers = many(dg.UnknownMarkers)
	dg.NewTemplates = many(dg.NewTemplates)
	dg.Flaps = many(dg.Flaps)
	dg.Suppressed = many(dg.Suppressed)

	return dg, failures
}

// capToByteBudget marshals dg to indented JSON; if the result exceeds
// maxDigestBytes it drops the lowest-priority row (the last one — dg.Rows is
// already in contract.CapRows priority order: non-ok rows first, then
// descending |zscore|) and re-marshals, repeating until under budget. Each
// row drop increments dg.RowsTruncated. Deterministic.
//
// The cap ALWAYS holds: once the rows are gone, echo entries are dropped one
// at a time, lowest priority first — suppressed, new_templates, flaps,
// open_tier1_findings, and unknown_markers last (a blind spot is the thing
// the analyst most needs to be told about) — each shrunk string list keeping
// its closing truncatedFmt entry. The empty skeleton is a few hundred bytes,
// so the final error is unreachable in practice; it exists so an impossible
// state fails the run (and pages) rather than writing an oversized digest.
func capToByteBudget(dg *contract.Digest) ([]byte, error) {
	for {
		data, err := json.MarshalIndent(dg, "", "  ")
		if err != nil {
			return nil, err
		}
		if len(data) <= maxDigestBytes {
			return data, nil
		}
		if len(dg.Rows) > 0 {
			dg.Rows = dg.Rows[:len(dg.Rows)-1]
			dg.RowsTruncated++
			continue
		}
		if !dropLowestEcho(dg) {
			return nil, fmt.Errorf("%d bytes with every row and echo entry dropped exceeds the %d-byte cap", len(data), maxDigestBytes)
		}
	}
}

// dropLowestEcho drops one entry from the lowest-priority echo list that
// still has one; false when none has.
func dropLowestEcho(dg *contract.Digest) bool {
	for _, list := range []*[]string{&dg.Suppressed, &dg.NewTemplates, &dg.Flaps} {
		if out, ok := dropEcho(*list); ok {
			*list = out
			return true
		}
	}
	if n := len(dg.OpenTier1Findings); n > 0 {
		dg.OpenTier1Findings = dg.OpenTier1Findings[:n-1]
		return true
	}
	if out, ok := dropEcho(dg.UnknownMarkers); ok {
		dg.UnknownMarkers = out
		return true
	}
	return false
}

// gcHistory deletes history files older than 14 days. Best-effort: any
// failure to list or remove is swallowed, never surfaced as a Write error —
// a stale history file is a disk-hygiene concern, not a correctness one.
func gcHistory(histDir string, now time.Time) {
	entries, err := os.ReadDir(histDir)
	if err != nil {
		return
	}
	cutoff := now.Add(-historyRetention)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".json")
		ts, err := time.Parse(historyTimeFormat, name)
		if err != nil {
			continue // not a digest history filename; leave it alone
		}
		if ts.Before(cutoff) {
			_ = os.Remove(filepath.Join(histDir, e.Name()))
		}
	}
}
