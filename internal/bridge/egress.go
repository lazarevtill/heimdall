package bridge

import (
	"strings"

	"github.com/lazarevtill/heimdall/internal/contract"
)

// This file is the bridge's single egress-sanitising path. Every free-text
// field the bridge sends OUT — to YouTrack (issue bodies, comments, ticket
// summaries) or to the outbox (whose body a sink transmits verbatim,
// invariant 4) — goes through redactor.text exactly once, in this order:
//
//  1. redact, fail-closed (contract.EvidenceOrWithheld): a redactor failure
//     yields the Withheld sentinel, never the raw string, and is COUNTED so
//     the caller can export it as heimdall_redaction_failures_total
//     {plane="bridge"}, which pages (invariant 3);
//  2. neutralise @-mentions (neutralizeMentions). This must come second:
//     the url-credentials pattern needs the raw "user:pass@" to match.
//
// Fields that are not free text never come through here, because they are
// grammar-constrained before use: group/check (tracker.FindingKey's
// [a-z0-9-] grammar), fingerprints and evidence row ids (16 lowercase hex,
// contract.ValidFingerprint), kind/confidence (closed enums), tracker issue
// ids (minted by the tracker).

// redactor applies the egress path and counts redaction failures across
// every field of one operation (one Reconcile, one hypothesis).
type redactor struct{ failures int }

// evidenceOrWithheld is contract.EvidenceOrWithheld, held in a variable
// only so this package's internal tests can prove a FAILING redactor is
// counted and withheld (the real one fails only on a panic, which no
// input can provoke). Production code never reassigns it.
var evidenceOrWithheld = contract.EvidenceOrWithheld

// text is the egress path for one free-text field. See the file comment.
func (r *redactor) text(s string) string {
	out, failed := evidenceOrWithheld(s)
	if failed {
		r.failures++
	}
	return neutralizeMentions(out)
}

// wordJoiner is U+2060 WORD JOINER: zero-width, invisible, and not a
// username character, so "@\u2060ops" renders as "@ops" to a reader but is
// not parsed as a mention by Telegram (which auto-links @username even in
// plain text) or by YouTrack (whose @login notifies that user).
const wordJoiner = "\u2060"

// neutralizeMentions inserts a word joiner after every '@'. The model (and
// any log line that becomes evidence) controls this text; a mention would
// let it notify a specific human — a page by another name, which neither
// the LLM (invariant 2) nor an arbitrary log line may do.
func neutralizeMentions(s string) string {
	return strings.ReplaceAll(s, "@", "@"+wordJoiner)
}

// fenced wraps s in a Markdown fenced code block so YouTrack renders it as
// inert text: no links, no emphasis, no mentions, no HTML. The fence is one
// backtick longer than the longest backtick run inside s (and at least
// three), so content cannot close the fence early and break back out into
// live Markdown — CommonMark only closes a fence with at least as many
// backticks as opened it.
func fenced(s string) string {
	longest, run := 0, 0
	for _, c := range s {
		if c == '`' {
			run++
			longest = max(longest, run)
		} else {
			run = 0
		}
	}
	fence := strings.Repeat("`", max(3, longest+1))
	return fence + "\n" + strings.TrimRight(s, "\n") + "\n" + fence
}
