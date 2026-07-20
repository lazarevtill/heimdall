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
	return contract.Digest{
		SchemaVersion:       SchemaVersion,
		GeneratedAt:         now,
		ManifestGeneratedAt: manifestGeneratedAt,
		Rows:                kept,
		UnknownMarkers:      dedupSorted(unknowns),
		NewTemplates:        dedupSorted(templates),
		Flaps:               dedupSorted(flaps),
		OpenTier1Findings:   openTier1,
		Suppressed:          suppressed,
		RowsTruncated:       truncated,
	}
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
// post-redaction byte cap by dropping the lowest-priority row and
// re-marshaling until under budget, then atomically writes <dir>/latest.json
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
	redacted, failures := redact(dg)
	data, err := capToByteBudget(&redacted)
	if err != nil {
		return failures, fmt.Errorf("digest: marshal: %w", err)
	}

	latestPath := filepath.Join(dir, "latest.json")
	if err := emit.WriteFileAtomic(latestPath, data); err != nil {
		return failures, fmt.Errorf("digest: write %s: %w", latestPath, err)
	}

	histDir := filepath.Join(dir, "history")
	histPath := filepath.Join(histDir, now.UTC().Format(historyTimeFormat)+".json")
	if err := emit.WriteFileAtomic(histPath, data); err != nil {
		return failures, fmt.Errorf("digest: write %s: %w", histPath, err)
	}

	gcHistory(histDir, now) // best-effort; failures never fail the run

	return failures, nil
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
// descending |zscore|) and re-marshals, repeating until under budget or out
// of rows. Each drop increments dg.RowsTruncated. Deterministic.
func capToByteBudget(dg *contract.Digest) ([]byte, error) {
	for {
		data, err := json.MarshalIndent(dg, "", "  ")
		if err != nil {
			return nil, err
		}
		if len(data) <= maxDigestBytes || len(dg.Rows) == 0 {
			return data, nil
		}
		dg.Rows = dg.Rows[:len(dg.Rows)-1]
		dg.RowsTruncated++
	}
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
