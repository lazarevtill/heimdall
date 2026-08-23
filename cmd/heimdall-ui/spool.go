package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lazarevtill/heimdall/internal/contract"
)

// The spool is the detector's per-finding document: emit.WriteSpool writes
// one REDACTED <fingerprint>.json per finding, and it is the only place the
// finding's title and evidence survive. The ledger holds identity and
// counts; the evidence lives here.
//
// WHY A LOCAL SHAPE rather than contract.Finding. Two reasons, both binding:
//
//  1. contract.State has MarshalJSON but no UnmarshalJSON, so a spool doc
//     cannot be decoded back into a contract.Finding at all — "state":
//     "firing" will not parse into an int-backed State.
//  2. Even if it could, decoding into a contract.Finding would mint one
//     outside NewFinding, which is exactly what ADR-G09 forbids. A reader
//     has no business producing a Finding; it produces a DOCUMENT it read.
//
// internal/bridge decodes its own narrow shape for the same reason. This one
// is wider because the console displays more of the document, but it is
// still a read-only DTO and never becomes a Finding.

// maxSpoolBytes caps a spool read. Evidence is capped at 32 KB by
// contract.EvidenceOrWithheld before it is written, so a file materially
// larger than that is not a document this console should be rendering.
const maxSpoolBytes = 256 << 10

// SpoolDoc is the read-back shape of <spoolDir>/<fingerprint>.json.
type SpoolDoc struct {
	SchemaVersion int       `json:"schema_version"`
	Fingerprint   string    `json:"fingerprint"`
	Check         string    `json:"check"`
	Group         string    `json:"group"`
	Target        string    `json:"target"`
	Node          string    `json:"node"`
	Severity      string    `json:"severity"`
	Class         string    `json:"class"`
	State         string    `json:"state"`
	Title         string    `json:"title"`
	Evidence      string    `json:"evidence"`
	ObservedAt    time.Time `json:"observed_at"`
}

// EvidenceView is what the detail page renders for the evidence section.
// It distinguishes three outcomes that must never look alike: evidence
// present, evidence deliberately WITHHELD by a failed redaction, and no
// document at all.
type EvidenceView struct {
	// Present is true when a document was read and decoded.
	Present bool
	// Reason explains the absence when Present is false, in operator terms.
	Reason string

	Title      string
	Evidence   string
	Group      string
	Node       string
	Class      string
	ObservedAt time.Time
	Observed   string

	// Withheld is true when the redactor failed and the content was
	// deliberately withheld. This is a PAGING condition
	// (heimdall_redaction_failures_total), not a rendering quirk, so the
	// console must say so rather than showing an empty box.
	Withheld bool

	// Stale is true when the document's observed_at is older than the
	// ledger's last_seen — the finding has been seen again since this
	// evidence was captured, so the text may describe an earlier occurrence.
	Stale bool
}

// ReadSpool loads the spool document for fingerprint.
//
// Fail-soft and non-fabricating: a missing, unreadable, oversized,
// undecodable or MISMATCHED document yields Present=false with a reason the
// page can show. It never invents evidence, and it never returns another
// finding's document.
//
// The fingerprint is validated against contract.ValidFingerprint before it
// touches a path. It arrives here from a URL path segment, so it is
// untrusted input being used as a filename.
func ReadSpool(dir, fingerprint string, lastSeen time.Time) EvidenceView {
	if dir == "" {
		return EvidenceView{Reason: "No spool directory is configured, so per-finding evidence is unavailable."}
	}
	if !contract.ValidFingerprint(fingerprint) {
		return EvidenceView{Reason: "Not a well-formed fingerprint."}
	}

	path := filepath.Join(dir, fingerprint+".json")
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			// The common, benign case: the detector has not written this
			// finding yet, or the doc was reaped.
			return EvidenceView{Reason: "No spool document for this fingerprint — it may have been reaped, or the detector has not written one yet."}
		}
		return EvidenceView{Reason: "The spool document could not be opened."}
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return EvidenceView{Reason: "The spool document could not be read."}
	}
	if info.Size() > maxSpoolBytes {
		return EvidenceView{Reason: fmt.Sprintf("The spool document is larger than the %d KB this console will read.", maxSpoolBytes>>10)}
	}

	var doc SpoolDoc
	if err := json.NewDecoder(f).Decode(&doc); err != nil {
		return EvidenceView{Reason: "The spool document is present but could not be decoded."}
	}

	// A document whose own fingerprint disagrees with the file it was read
	// from means the spool and the request disagree about identity. Showing
	// it would attribute one finding's evidence to another.
	if doc.Fingerprint != "" && doc.Fingerprint != fingerprint {
		return EvidenceView{Reason: "The spool document names a different fingerprint than the file it was read from; it has not been shown."}
	}

	v := EvidenceView{
		Present:    true,
		Title:      doc.Title,
		Evidence:   doc.Evidence,
		Group:      doc.Group,
		Node:       doc.Node,
		Class:      doc.Class,
		ObservedAt: doc.ObservedAt,
		Withheld:   strings.Contains(doc.Evidence, contract.Withheld) || strings.Contains(doc.Title, contract.Withheld),
	}
	if !doc.ObservedAt.IsZero() {
		v.Observed = doc.ObservedAt.UTC().Format("2006-01-02 15:04:05Z")
		// Only meaningful when the ledger has a last_seen to compare with.
		// A minute of slack absorbs the ordinary gap between a finding being
		// observed and the ledger row being stamped in the same run.
		if !lastSeen.IsZero() && lastSeen.Sub(doc.ObservedAt) > time.Minute {
			v.Stale = true
		}
	}
	return v
}
