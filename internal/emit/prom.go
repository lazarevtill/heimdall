// Package emit writes Heimdall's outputs: the node_exporter textfile
// (hand-written exposition format — see ADR-G04) and the redacted finding
// spool. All writes are atomic whole-file replacements.
//
// Whole-file replacement is load-bearing beyond atomicity: it is what
// retires stale series when a finding disappears between runs. An
// append/partial writer would leave dead series serving forever — do not
// "optimize" this into partial writes.
package emit

import (
	"bytes"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lazarevtill/heimdall/internal/contract"
)

// HELP text must be defined in exactly one place and stay byte-identical:
// inconsistent HELP across .prom files poisons node_exporter's scrape.
const (
	helpFinding = "# HELP heimdall_finding Active Heimdall finding; 1 while firing or unknown.\n" +
		"# TYPE heimdall_finding gauge\n"
	helpRedaction = "# HELP heimdall_redaction_failures_total Redaction failures during the last run; any nonzero value pages.\n" +
		"# TYPE heimdall_redaction_failures_total counter\n"
	helpLastRun = "# HELP heimdall_last_run_timestamp_seconds Unix time of the last completed detector run.\n" +
		"# TYPE heimdall_last_run_timestamp_seconds gauge\n"
	helpDigest = "# HELP heimdall_digest_generated_timestamp_seconds Unix time the Tier-2 feature digest was last written.\n" +
		"# TYPE heimdall_digest_generated_timestamp_seconds gauge\n"

	helpAnalystLastSuccess = "# HELP heimdall_analyst_last_success_timestamp_seconds Unix time of the last successful Tier-3 analyst run.\n" +
		"# TYPE heimdall_analyst_last_success_timestamp_seconds gauge\n"
	helpAnalystPosted = "# HELP heimdall_analyst_hypotheses_posted_total Hypotheses POSTed to the bridge during the last analyst run.\n" +
		"# TYPE heimdall_analyst_hypotheses_posted_total counter\n"
	helpAnalystHallucinated = "# HELP heimdall_analyst_hypotheses_hallucinated_total Hypotheses dropped for citing an empty or nonexistent evidence row_id.\n" +
		"# TYPE heimdall_analyst_hypotheses_hallucinated_total counter\n"
	helpAnalystDeduped = "# HELP heimdall_analyst_hypotheses_deduped_total Hypotheses dropped: the same hyp_fp was posted within the cooldown window.\n" +
		"# TYPE heimdall_analyst_hypotheses_deduped_total counter\n"
	helpAnalystCapped = "# HELP heimdall_analyst_hypotheses_capped_total Hypotheses dropped for exceeding the per-run volume cap.\n" +
		"# TYPE heimdall_analyst_hypotheses_capped_total counter\n"
	helpAnalystInvalid = "# HELP heimdall_analyst_hypotheses_invalid_total Hypotheses dropped for an out-of-vocabulary kind or confidence.\n" +
		"# TYPE heimdall_analyst_hypotheses_invalid_total counter\n"
)

// Exposition format escapes for label values: backslash, quote, newline.
var labelEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)

// lv routes every label value through the redactor (uniform every-egress
// redaction), then escapes it per the exposition format.
func lv(s string) string { return labelEscaper.Replace(contract.Redact(s)) }

// RenderProm renders the full textfile body. Deterministic: findings sorted
// by (check, target), labels in fixed alphabetical order. NEVER emits
// line-level timestamps (node_exporter discards the whole file); freshness
// is the heimdall_last_run_timestamp_seconds sample VALUE.
//
// State is deliberately NOT a label: the wire label set is frozen as
// {check, class, fingerprint, group, node, severity, source, target} so a
// firing<->unknown transition keeps series identity (no stale-series
// resolve, no manufactured all-clear). State lives in the spool doc.
//
// digestGeneratedAt is the Tier-2 feature digest's GeneratedAt: when it is
// the zero time (a run that produced no digest), the
// heimdall_digest_generated_timestamp_seconds series is omitted entirely
// rather than emitted as a fake epoch-0 sample.
func RenderProm(now time.Time, fs []contract.Finding, redactionFailures int, digestGeneratedAt time.Time) []byte {
	sorted := make([]contract.Finding, len(fs))
	copy(sorted, fs)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Check != sorted[j].Check {
			return sorted[i].Check < sorted[j].Check
		}
		return sorted[i].Target < sorted[j].Target
	})
	var b bytes.Buffer
	b.WriteString(helpFinding)
	for _, f := range sorted {
		b.WriteString(`heimdall_finding{check="` + lv(f.Check) +
			`",class="` + lv(string(f.Class)) +
			`",fingerprint="` + lv(f.Fingerprint) +
			`",group="` + lv(f.Group) +
			`",node="` + lv(f.Node) +
			`",severity="` + lv(string(f.Severity)) +
			`",source="heimdall",target="` + lv(f.Target) + `"} 1` + "\n")
	}
	b.WriteString(helpRedaction)
	b.WriteString("heimdall_redaction_failures_total " + strconv.Itoa(redactionFailures) + "\n")
	b.WriteString(helpLastRun)
	b.WriteString(`heimdall_last_run_timestamp_seconds{plane="tier1"} ` +
		strconv.FormatInt(now.Unix(), 10) + "\n")
	if !digestGeneratedAt.IsZero() {
		b.WriteString(helpDigest)
		b.WriteString("heimdall_digest_generated_timestamp_seconds " +
			strconv.FormatInt(digestGeneratedAt.Unix(), 10) + "\n")
	}
	return b.Bytes()
}

// RenderAnalystProm renders heimdall-analyst's heartbeat + per-run drop
// counters. The caller (cmd/heimdall-analyst) must call this ONLY after a
// successful analyst.Run: this function has no fail-closed path of its own
// (unlike RenderProm, it takes no "did the run fail" input at all) — a hard
// analyst failure must withhold this file entirely so
// heimdall_analyst_last_success_timestamp_seconds stops advancing and the
// HeimdallAnalystStale staleness rule can fire (invariant 8). The counter
// ordering here is fixed and deterministic (no map iteration involved), so
// the output is stable for a golden test.
//
// heimdall_redaction_failures_total intentionally carries a plane="tier3"
// label here, unlike Tier-1's unlabeled series in RenderProm. Both binaries
// may write into the SAME HEIMDALL_TEXTFILE_DIR, and node_exporter's
// textfile collector merges every *.prom file it finds there into one
// scrape; two separate files exposing the identical metric name with an
// identical (empty) label set is a duplicate-series collision node_exporter
// rejects outright. A plane label avoids that collision while leaving the
// existing `heimdall_redaction_failures_total > 0` meta-alert working
// unchanged: it carries no label matcher, so it still evaluates every
// plane's series independently. HELP/TYPE text is reused byte-identical
// from helpRedaction (see the package doc: inconsistent HELP across files
// poisons the scrape).
func RenderAnalystProm(now time.Time, posted, hallucinated, deduped, capped, invalidDropped, redactionFailures int) []byte {
	var b bytes.Buffer
	b.WriteString(helpAnalystLastSuccess)
	b.WriteString("heimdall_analyst_last_success_timestamp_seconds " + strconv.FormatInt(now.Unix(), 10) + "\n")
	b.WriteString(helpAnalystPosted)
	b.WriteString("heimdall_analyst_hypotheses_posted_total " + strconv.Itoa(posted) + "\n")
	b.WriteString(helpAnalystHallucinated)
	b.WriteString("heimdall_analyst_hypotheses_hallucinated_total " + strconv.Itoa(hallucinated) + "\n")
	b.WriteString(helpAnalystDeduped)
	b.WriteString("heimdall_analyst_hypotheses_deduped_total " + strconv.Itoa(deduped) + "\n")
	b.WriteString(helpAnalystCapped)
	b.WriteString("heimdall_analyst_hypotheses_capped_total " + strconv.Itoa(capped) + "\n")
	b.WriteString(helpAnalystInvalid)
	b.WriteString("heimdall_analyst_hypotheses_invalid_total " + strconv.Itoa(invalidDropped) + "\n")
	b.WriteString(helpRedaction)
	b.WriteString(`heimdall_redaction_failures_total{plane="tier3"} ` + strconv.Itoa(redactionFailures) + "\n")
	return b.Bytes()
}
