package main

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"github.com/lazarevtill/heimdall/internal/contract"
)

// The Tier-2 digest is the trend surface: continuous, deterministic soft
// signals over a 7-day feature baseline. It is what answers "what is drifting
// toward a wall" before anything trips a threshold, and it is the analyst's
// entire input.
//
// Unlike the finding spool, contract.Digest DOES round-trip through
// encoding/json — DigestStatus has both MarshalJSON and a fail-closed
// UnmarshalJSON (contract/digest.go), so an unrecognised status decodes to
// StatusUnknown rather than to "ok". That asymmetry with contract.Finding
// (whose State has no UnmarshalJSON) is why this reader can reuse the real
// type while the spool reader cannot.

// maxDigestReadBytes caps a digest read. The writer enforces a 32 KB byte
// budget, so anything materially larger is not a digest.
const maxDigestReadBytes = 512 << 10

// digestStaleAfter is when a digest stops being worth reading as current. It
// matches the detector staleness the meta-rules page on.
const digestStaleAfter = 15 * time.Minute

// DigestRowView is one rendered feature row.
type DigestRowView struct {
	RowID    string
	Entity   string
	Target   string
	Feature  string
	Value    string
	Baseline string
	ZScore   string
	Unit     string
	Status   string
	// Tier drives ordering and treatment, reusing the signals page's scale
	// so the two pages never disagree about what outranks what.
	Tier int
	// Drift is a plain-language reading of the z-score's direction and size.
	Drift string
}

// DigestView is the whole Tier-2 page.
type DigestView struct {
	Present bool
	Reason  string

	GeneratedAt time.Time
	Generated   string
	Age         string
	Stale       bool

	Rows []DigestRowView

	// UnknownMarkers is the blind-spot list: every feature Tier 2 could not
	// measure this run. It is rendered FIRST and never collapsed — the
	// digest exists partly to say what it could not see.
	UnknownMarkers []string
	NewTemplates   []string
	Flaps          []string
	Suppressed     []string
	OpenTier1      []contract.OpenTier1Finding

	// RowsTruncated is how many rows the 200-row cap dropped. Persistent
	// truncation means the console is showing a subset and must say so.
	RowsTruncated int

	Counts DigestCounts
}

// DigestCounts summarises row status for the header.
type DigestCounts struct {
	Total   int
	OK      int
	Unknown int
	Warming int
}

// ReadDigest loads <dir>/latest.json.
//
// Fail-soft and non-fabricating, exactly like ReadSpool: every unusable
// state yields Present=false with an operator-readable reason. A digest that
// cannot be read must never render as an empty-but-healthy page, because
// "no rows" and "no digest" mean opposite things.
func ReadDigest(dir string, now time.Time) DigestView {
	if dir == "" {
		return DigestView{Reason: "No digest directory is configured, so Tier-2 signals are unavailable."}
	}
	path := filepath.Join(dir, "latest.json")
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return DigestView{Reason: "No digest has been written yet. Tier 2 needs a completed detector run — check the detect heartbeat."}
		}
		return DigestView{Reason: "The digest could not be opened."}
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return DigestView{Reason: "The digest could not be read."}
	}
	if info.Size() > maxDigestReadBytes {
		return DigestView{Reason: fmt.Sprintf("The digest is larger than the %d KB this console will read.", maxDigestReadBytes>>10)}
	}

	var dg contract.Digest
	if err := json.NewDecoder(f).Decode(&dg); err != nil {
		return DigestView{Reason: "The digest is present but could not be decoded."}
	}
	return buildDigestView(now, dg)
}

// buildDigestView renders a decoded digest. Split out from ReadDigest so the
// whole rendering is testable without touching a filesystem.
func buildDigestView(now time.Time, dg contract.Digest) DigestView {
	v := DigestView{
		Present:        true,
		GeneratedAt:    dg.GeneratedAt,
		UnknownMarkers: dg.UnknownMarkers,
		NewTemplates:   dg.NewTemplates,
		Flaps:          dg.Flaps,
		Suppressed:     dg.Suppressed,
		OpenTier1:      dg.OpenTier1Findings,
		RowsTruncated:  dg.RowsTruncated,
	}
	if !dg.GeneratedAt.IsZero() {
		v.Generated = dg.GeneratedAt.UTC().Format("2006-01-02 15:04:05Z")
		age := now.Sub(dg.GeneratedAt)
		v.Age = HumanDuration(age)
		v.Stale = age > digestStaleAfter
	} else {
		v.Age = "unknown"
		v.Stale = true
	}

	v.Rows = make([]DigestRowView, 0, len(dg.Rows))
	for _, r := range dg.Rows {
		rv := DigestRowView{
			RowID:    r.RowID,
			Entity:   r.Entity,
			Target:   r.Target,
			Feature:  r.Feature,
			Value:    formatFloat(r.Value),
			Baseline: formatFloat(r.Baseline7d),
			ZScore:   formatFloat(r.ZScore),
			Unit:     r.Unit,
			Status:   r.Status.String(),
			Tier:     digestTier(r.Status),
			Drift:    describeDrift(r),
		}
		v.Rows = append(v.Rows, rv)
		switch r.Status {
		case contract.StatusOK:
			v.Counts.OK++
		case contract.StatusBaselineWarming:
			v.Counts.Warming++
		default:
			v.Counts.Unknown++
		}
	}
	v.Counts.Total = len(v.Rows)

	// Order mirrors contract.CapRows: non-ok rows first, so a blind spot is
	// never buried under calm rows; then by |zscore| descending, so the most
	// anomalous is at the top; then row_id for determinism.
	sort.SliceStable(v.Rows, func(i, j int) bool {
		if v.Rows[i].Tier != v.Rows[j].Tier {
			return v.Rows[i].Tier < v.Rows[j].Tier
		}
		zi, zj := absFloat(v.Rows[i].ZScore), absFloat(v.Rows[j].ZScore)
		if zi != zj {
			return zi > zj
		}
		return v.Rows[i].RowID < v.Rows[j].RowID
	})
	return v
}

// digestTier maps a row status onto the signals page's reading scale.
// `unknown` outranks `baseline_warming` for the same reason it outranks
// `warning` on the signals page: it is a blind spot, not a mild one.
func digestTier(s contract.DigestStatus) int {
	switch s {
	case contract.StatusOK:
		return tierOK
	case contract.StatusBaselineWarming:
		return tierWarning
	default:
		return tierUnknown
	}
}

// describeDrift turns a z-score into a plain reading. Deliberately coarse:
// the number is shown alongside, and a false-precision phrase ("2.7 sigma
// above normal") reads as more certain than a robust-IQR estimate warrants.
func describeDrift(r contract.DigestRow) string {
	if r.Status != contract.StatusOK {
		return ""
	}
	z := r.ZScore
	dir := "above"
	if z < 0 {
		dir = "below"
		z = -z
	}
	switch {
	case z < 1:
		return "in line with its baseline"
	case z < 2:
		return "drifting " + dir + " baseline"
	case z < 3:
		return "clearly " + dir + " baseline"
	default:
		return "far " + dir + " baseline"
	}
}

// formatFloat renders a value compactly without false precision.
func formatFloat(f float64) string {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "—"
	}
	return strconv.FormatFloat(f, 'f', -1, 64)
}

// absFloat parses a rendered float back for comparison; unparseable values
// sort last rather than panicking.
func absFloat(s string) float64 {
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return -1
	}
	return math.Abs(f)
}
