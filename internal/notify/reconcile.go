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
// randomized map iteration). sameProjection compares matchers as a set, so
// Alertmanager reordering them is not drift.
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
//     with a recoverable Key (keyFromComment) and NOT expired. Anything else
//     (foreign CreatedBy, a heimdall-notifier-created silence whose comment
//     doesn't parse) is never read from or touched. Expired silences are
//     ignored too: Alertmanager keeps listing them for its whole retention
//     window (default 120h), and one silences nothing — counting it as
//     "already projected" once meant a re-mute of the same key within five
//     days was never projected at all, and deleting it again every cycle
//     was pure churn. Alertmanager garbage-collects them itself.
//  3. For each desired Key, the live silences carrying it are compared
//     with the projection the ledger wants (matchers PLUS
//     {"source":"heimdall"}, compared as a set; EndsAt compared to the
//     second). The first one that matches is kept (Kept++). If none
//     matches — the key is new, the mute was extended, a declarative
//     matcher was edited — a fresh silence is created (StartsAt=now,
//     EndsAt=desired.EndsAt, both RFC3339; CreatedBy=NotifierCreatedBy;
//     Comment=commentFor(key, desired.Comment)) BEFORE the stale ones are
//     deleted, so nothing is unsilenced in between (Created++). Every other
//     live silence for the key — drifted copies, duplicates — is deleted
//     (Deleted++).
//  4. A live heimdall-notifier silence whose Key is NOT in desired is
//     deleted (the mute expired or was removed from the ledger). Deleted++.
//
// Every Alertmanager call runs under its own DefaultCallTimeout deadline,
// so a hung Alertmanager cannot stall the notifier's loop.
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

	var existingAll []silence.Silence
	err := withDeadline(ctx, func(cctx context.Context) error {
		var err error
		existingAll, err = client.List(cctx)
		return err
	})
	if err != nil {
		return result, fmt.Errorf("notify: reconcile silences: list: %w", err)
	}

	existingByKey := make(map[string][]silence.Silence)
	for _, s := range existingAll {
		if s.CreatedBy != NotifierCreatedBy {
			continue // foreign: never read from or touched
		}
		if s.State == silence.StateExpired {
			continue // silences nothing; Alertmanager's to garbage-collect
		}
		key, ok := keyFromComment(s.Comment)
		if !ok {
			continue // can't recover identity: leave alone, defensive
		}
		existingByKey[key] = append(existingByKey[key], s)
	}

	del := func(key string, s silence.Silence) error {
		if err := withDeadline(ctx, func(cctx context.Context) error { return client.Delete(cctx, s.ID) }); err != nil {
			return fmt.Errorf("notify: reconcile silences: delete %s (key=%s): %w", s.ID, key, err)
		}
		result.Deleted++
		return nil
	}

	desiredKeys := make([]string, 0, len(desired))
	for key := range desired {
		desiredKeys = append(desiredKeys, key)
	}
	sort.Strings(desiredKeys)

	for _, key := range desiredKeys {
		want := projection(now, desired[key])
		live := existingByKey[key]

		keep := -1
		for i, s := range live {
			if sameProjection(s, want) {
				keep = i
				break
			}
		}
		if keep >= 0 {
			result.Kept++
		} else {
			if err := withDeadline(ctx, func(cctx context.Context) error {
				_, err := client.Create(cctx, want)
				return err
			}); err != nil {
				return result, fmt.Errorf("notify: reconcile silences: create %s: %w", key, err)
			}
			result.Created++
		}
		for i, s := range live {
			if i == keep {
				continue
			}
			if err := del(key, s); err != nil {
				return result, err
			}
		}
	}

	existingKeys := make([]string, 0, len(existingByKey))
	for key := range existingByKey {
		existingKeys = append(existingKeys, key)
	}
	sort.Strings(existingKeys)

	for _, key := range existingKeys {
		if _, ok := desired[key]; ok {
			continue // handled above
		}
		for _, s := range existingByKey[key] {
			if err := del(key, s); err != nil {
				return result, err
			}
		}
	}

	return result, nil
}

// withDeadline runs one Alertmanager call under its own DefaultCallTimeout.
func withDeadline(ctx context.Context, call func(context.Context) error) error {
	cctx, cancel := context.WithTimeout(ctx, DefaultCallTimeout)
	defer cancel()
	return call(cctx)
}

// projection is the silence the ledger wants for d: its label=value pairs
// PLUS {"source":"heimdall"}, sorted by name.
func projection(now time.Time, d suppress.Silence) silence.Silence {
	labels := make(map[string]string, len(d.Matchers)+1)
	for name, value := range d.Matchers {
		labels[name] = value
	}
	labels["source"] = "heimdall"
	return silence.Silence{
		Matchers:  matchersFor(labels),
		StartsAt:  now.UTC().Format(time.RFC3339),
		EndsAt:    d.EndsAt.UTC().Format(time.RFC3339),
		CreatedBy: NotifierCreatedBy,
		Comment:   commentFor(d.Key, d.Comment),
	}
}

// sameProjection reports whether a live silence already projects want: the
// same matcher SET (Alertmanager may reorder them) and the same EndsAt to
// the second (it echoes times with milliseconds). An unparseable EndsAt is a
// mismatch, so it is replaced rather than trusted. StartsAt and Comment are
// not compared: neither changes what is silenced or for how long.
func sameProjection(live, want silence.Silence) bool {
	liveEnd, err1 := time.Parse(time.RFC3339, live.EndsAt)
	wantEnd, err2 := time.Parse(time.RFC3339, want.EndsAt)
	if err1 != nil || err2 != nil || !liveEnd.Truncate(time.Second).Equal(wantEnd.Truncate(time.Second)) {
		return false
	}
	if len(live.Matchers) != len(want.Matchers) {
		return false
	}
	a, b := sortedMatchers(live.Matchers), sortedMatchers(want.Matchers)
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sortedMatchers(in []silence.Matcher) []silence.Matcher {
	out := append([]silence.Matcher(nil), in...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Value < out[j].Value
	})
	return out
}
