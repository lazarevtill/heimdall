package notify

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/lazarevtill/heimdall/internal/silence"
	"github.com/lazarevtill/heimdall/internal/suppress"
)

// NotifierCreatedBy is the CreatedBy value the reconciler stamps on every
// silence it creates, and the value it filters List() results on: only
// silences carrying this CreatedBy are ever considered "ours" to delete.
// Anything else (a human's manual silence, or another tool's) is never
// touched.
const NotifierCreatedBy = "heimdall-notifier"

// SilenceClient is the subset of *silence.Client the reconciler needs
// (fakeable in tests). *silence.Client satisfies this interface
// structurally.
type SilenceClient interface {
	Create(ctx context.Context, s silence.Silence) (string, error)
	List(ctx context.Context) ([]silence.Silence, error)
	Delete(ctx context.Context, id string) error
}

var _ SilenceClient = (*silence.Client)(nil)

// ReconcileResult reports one reconcile pass, for metrics/logging.
type ReconcileResult struct {
	Created int
	Deleted int
	Kept    int
}

// commentIdentityPrefix is the fixed prefix commentFor/keyFromComment use to
// embed and recover the authority Key in a silence's Comment field. This is
// the reconciler's ONLY state: it carries no separate mapping table, so a
// restart (or a fresh process on a different host) can always re-derive
// "which silences are mine, and for which key" purely from what
// Alertmanager already reports back on List().
const commentIdentityPrefix = "hb-key="

// commentIdentitySep separates the embedded key from the free-text reason
// in a reconciler-authored comment.
const commentIdentitySep = " | "

// commentFor embeds the authority Key into a silence Comment alongside the
// human-readable reason, so keyFromComment can recover the Key on a later
// List() without any other state: "hb-key=<key> | <reason>".
func commentFor(key, reason string) string {
	return commentIdentityPrefix + key + commentIdentitySep + reason
}

// keyFromComment recovers the authority Key embedded by commentFor. ok is
// false for any comment not carrying the "hb-key=...|" shape — e.g. a
// foreign (non-heimdall-notifier-authored) comment, which must never be
// mistaken for one of ours even if its CreatedBy happened to collide.
func keyFromComment(comment string) (key string, ok bool) {
	if !strings.HasPrefix(comment, commentIdentityPrefix) {
		return "", false
	}
	rest := comment[len(commentIdentityPrefix):]
	key, _, found := strings.Cut(rest, commentIdentitySep)
	if !found || key == "" {
		return "", false
	}
	return key, true
}

// matchersFor renders m (an authority Silence's label=value map, PLUS the
// {"source":"heimdall"} scoping matcher already merged in by the caller)
// as a deterministically-ordered (sorted by name) []silence.Matcher, every
// entry an IsEqual/non-regex equality match. Sorting makes the created
// silence's wire shape stable across cycles (no spurious diff from Go's
// randomized map iteration), which matters for the golden-style assertions
// in this package's tests even though the reconciler itself never diffs
// matchers key-for-key (it matches by the embedded authority Key alone).
func matchersFor(m map[string]string) []silence.Matcher {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]silence.Matcher, 0, len(names))
	for _, name := range names {
		out = append(out, silence.Matcher{Name: name, Value: m[name], IsEqual: true, IsRegex: false})
	}
	return out
}

// ReconcileSilences makes Alertmanager's heimdall-notifier-owned silences
// EQUAL the authority's ActiveSilences(now) — the ledger is the only
// authority; AM's silences are a downstream projection recomputed every
// cycle:
//
//  1. desired := authority.ActiveSilences(now), indexed by Key.
//  2. existing := client.List(ctx), filtered to CreatedBy==NotifierCreatedBy
//     with a recoverable Key (keyFromComment) — anything else (foreign
//     CreatedBy, or a heimdall-notifier-created silence whose comment
//     doesn't parse, which should not happen but is left untouched
//     defensively) is never read from again.
//  3. A desired Key absent from existing -> Create (matchers = the
//     authority's label=value pairs PLUS {"source":"heimdall"}, sorted by
//     name; StartsAt=now, EndsAt=desired.EndsAt, both RFC3339;
//     CreatedBy=NotifierCreatedBy; Comment=commentFor(key, desired.Comment)).
//     Created++.
//  4. An existing heimdall-notifier silence whose Key is NOT in desired ->
//     Delete (the mute expired or was removed from the ledger). Deleted++.
//  5. Key present in both -> left untouched as-is. Kept++. (Re-creating an
//     identical silence every cycle would churn AM; matching by Key alone
//     avoids it. DECISION: this slice does NOT diff/refresh EndsAt on a
//     Key match — an extended mute keeps the same Key, so if the ledger's
//     EndsAt moved out, AM's copy will lag until the record eventually
//     leaves desired (natural expiry) and gets deleted+recreated on its
//     next active window, or until a future slice adds an explicit
//     delete+recreate-on-change path. Documented here rather than
//     silently: KEEP-as-is on a Key match is the accepted trade-off for
//     this slice.)
//
// A per-silence Create/Delete error stops the pass and is returned
// immediately alongside the ReconcileResult accumulated so far (the caller
// logs; the next cycle retries the remainder) — reconciliation is
// convergent, so a transient failure self-heals rather than needing its own
// retry logic here.
func ReconcileSilences(ctx context.Context, now time.Time, client SilenceClient, authority *suppress.Authority) (ReconcileResult, error) {
	var result ReconcileResult

	desiredList := authority.ActiveSilences(now)
	desired := make(map[string]suppress.Silence, len(desiredList))
	for _, d := range desiredList {
		desired[d.Key] = d
	}

	existingAll, err := client.List(ctx)
	if err != nil {
		return result, fmt.Errorf("notify: reconcile silences: list: %w", err)
	}

	existingByKey := make(map[string]silence.Silence)
	for _, s := range existingAll {
		if s.CreatedBy != NotifierCreatedBy {
			continue // foreign: never read from or touched
		}
		key, ok := keyFromComment(s.Comment)
		if !ok {
			continue // can't recover identity: leave alone, defensive
		}
		existingByKey[key] = s
	}

	desiredKeys := make([]string, 0, len(desired))
	for key := range desired {
		desiredKeys = append(desiredKeys, key)
	}
	sort.Strings(desiredKeys)

	for _, key := range desiredKeys {
		if _, ok := existingByKey[key]; ok {
			result.Kept++
			continue
		}
		d := desired[key]
		labels := make(map[string]string, len(d.Matchers)+1)
		for name, value := range d.Matchers {
			labels[name] = value
		}
		labels["source"] = "heimdall"

		newSilence := silence.Silence{
			Matchers:  matchersFor(labels),
			StartsAt:  now.UTC().Format(time.RFC3339),
			EndsAt:    d.EndsAt.UTC().Format(time.RFC3339),
			CreatedBy: NotifierCreatedBy,
			Comment:   commentFor(d.Key, d.Comment),
		}
		if _, err := client.Create(ctx, newSilence); err != nil {
			return result, fmt.Errorf("notify: reconcile silences: create %s: %w", key, err)
		}
		result.Created++
	}

	existingKeys := make([]string, 0, len(existingByKey))
	for key := range existingByKey {
		existingKeys = append(existingKeys, key)
	}
	sort.Strings(existingKeys)

	for _, key := range existingKeys {
		if _, ok := desired[key]; ok {
			continue // already counted Kept above
		}
		s := existingByKey[key]
		if err := client.Delete(ctx, s.ID); err != nil {
			return result, fmt.Errorf("notify: reconcile silences: delete %s (key=%s): %w", s.ID, key, err)
		}
		result.Deleted++
	}

	return result, nil
}
