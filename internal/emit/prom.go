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
func RenderProm(now time.Time, fs []contract.Finding, redactionFailures int) []byte {
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
	return b.Bytes()
}
