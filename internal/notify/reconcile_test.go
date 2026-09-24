package notify_test

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/lazarevtill/heimdall/internal/notify"
	"github.com/lazarevtill/heimdall/internal/silence"
	"github.com/lazarevtill/heimdall/internal/suppress"
)

// fakeSilenceClient is a hermetic notify.SilenceClient fake: an in-memory
// map keyed by a synthetic incrementing ID, no network involved.
type fakeSilenceClient struct {
	silences map[string]silence.Silence
	nextID   int
}

func newFakeSilenceClient() *fakeSilenceClient {
	return &fakeSilenceClient{silences: map[string]silence.Silence{}}
}

func (f *fakeSilenceClient) Create(_ context.Context, s silence.Silence) (string, error) {
	f.nextID++
	id := fmt.Sprintf("sil-new-%d", f.nextID)
	s.ID = id
	f.silences[id] = s
	return id, nil
}

func (f *fakeSilenceClient) List(_ context.Context) ([]silence.Silence, error) {
	ids := make([]string, 0, len(f.silences))
	for id := range f.silences {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]silence.Silence, 0, len(ids))
	for _, id := range ids {
		out = append(out, f.silences[id])
	}
	return out, nil
}

func (f *fakeSilenceClient) Delete(_ context.Context, id string) error {
	if _, ok := f.silences[id]; !ok {
		return fmt.Errorf("fake silence client: delete: unknown id %s", id)
	}
	delete(f.silences, id)
	return nil
}

func TestReconcileSilencesCreatesDeletesKeepsAndLeavesForeignAlone(t *testing.T) {
	groupCheckUntil := fixedNow.Add(7 * 24 * time.Hour).UTC().Format(time.RFC3339)
	targetUntil := fixedNow.Add(3 * 24 * time.Hour).UTC().Format(time.RFC3339)

	runtime := []suppress.Suppression{
		{
			Key: "gc-noise", Scope: suppress.ScopeGroupCheck,
			Matcher: suppress.Matcher{Group: "disk", Check: "smart-fail"},
			Until:   groupCheckUntil, Reason: "vendor noise", Actor: "ops",
			Source: suppress.SourceRuntime,
		},
		{
			Key: "tgt-decom", Scope: suppress.ScopeTarget,
			Matcher: suppress.Matcher{Target: "192.0.2.50"},
			Until:   targetUntil, Reason: "decommissioning", Actor: "ops",
			Source: suppress.SourceRuntime,
		},
	}
	authority, skipped := suppress.NewAuthority(nil, runtime)
	if skipped != 0 {
		t.Fatalf("NewAuthority skipped = %d, want 0", skipped)
	}

	client := newFakeSilenceClient()

	// (a) a pre-seeded heimdall-notifier silence matching the gc-noise
	// desired Key -> must be Kept, untouched.
	client.silences["sil-kept"] = silence.Silence{
		ID: "sil-kept",
		Matchers: []silence.Matcher{
			{Name: "check", Value: "smart-fail", IsEqual: true},
			{Name: "group", Value: "disk", IsEqual: true},
			{Name: "source", Value: "heimdall", IsEqual: true},
		},
		StartsAt:  fixedNow.Add(-24 * time.Hour).UTC().Format(time.RFC3339),
		EndsAt:    groupCheckUntil,
		CreatedBy: notify.NotifierCreatedBy,
		Comment:   "hb-key=gc-noise | vendor noise (ops)",
	}
	// (b) an orphaned heimdall-notifier silence whose key is NOT in desired
	// (the mute expired or was removed from the ledger) -> must be Deleted.
	client.silences["sil-orphan"] = silence.Silence{
		ID: "sil-orphan",
		Matchers: []silence.Matcher{
			{Name: "source", Value: "heimdall", IsEqual: true},
			{Name: "target", Value: "192.0.2.99", IsEqual: true},
		},
		StartsAt:  fixedNow.Add(-48 * time.Hour).UTC().Format(time.RFC3339),
		EndsAt:    fixedNow.Add(-time.Hour).UTC().Format(time.RFC3339),
		CreatedBy: notify.NotifierCreatedBy,
		Comment:   "hb-key=old-expired-key | some old reason (ops)",
	}
	// (c) a foreign silence, CreatedBy != heimdall-notifier -> never read
	// from or touched, regardless of its Comment shape.
	client.silences["sil-foreign"] = silence.Silence{
		ID: "sil-foreign",
		Matchers: []silence.Matcher{
			{Name: "target", Value: "192.0.2.77", IsEqual: true},
		},
		StartsAt:  fixedNow.UTC().Format(time.RFC3339),
		EndsAt:    fixedNow.Add(time.Hour).UTC().Format(time.RFC3339),
		CreatedBy: "a-human",
		Comment:   "manually silenced, unrelated to heimdall",
	}

	result, err := notify.ReconcileSilences(context.Background(), fixedNow, client, authority)
	if err != nil {
		t.Fatalf("ReconcileSilences: %v", err)
	}
	if result.Created != 1 || result.Deleted != 1 || result.Kept != 1 {
		t.Fatalf("ReconcileResult = %+v, want Created=1 Deleted=1 Kept=1", result)
	}

	all, err := client.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("len(all silences) after reconcile = %d, want 3 (kept + newly-created + foreign)", len(all))
	}

	if _, ok := client.silences["sil-orphan"]; ok {
		t.Error("orphaned silence sil-orphan was not deleted")
	}
	foreign, ok := client.silences["sil-foreign"]
	if !ok || foreign.CreatedBy != "a-human" || foreign.Comment != "manually silenced, unrelated to heimdall" {
		t.Errorf("foreign silence sil-foreign was touched: %+v (ok=%v)", foreign, ok)
	}
	kept, ok := client.silences["sil-kept"]
	if !ok || kept.Comment != "hb-key=gc-noise | vendor noise (ops)" {
		t.Errorf("kept silence sil-kept was mutated: %+v (ok=%v)", kept, ok)
	}

	var created silence.Silence
	found := false
	for id, s := range client.silences {
		if strings.HasPrefix(id, "sil-new-") {
			created = s
			found = true
		}
	}
	if !found {
		t.Fatal("no new silence was created for the missing desired key tgt-decom")
	}
	if created.CreatedBy != notify.NotifierCreatedBy {
		t.Errorf("created CreatedBy = %q, want %q", created.CreatedBy, notify.NotifierCreatedBy)
	}
	if created.StartsAt != fixedNow.UTC().Format(time.RFC3339) {
		t.Errorf("created StartsAt = %q, want now (%s)", created.StartsAt, fixedNow.UTC().Format(time.RFC3339))
	}
	if created.EndsAt != targetUntil {
		t.Errorf("created EndsAt = %q, want %q", created.EndsAt, targetUntil)
	}
	wantMatchers := []silence.Matcher{
		{Name: "source", Value: "heimdall", IsEqual: true},
		{Name: "target", Value: "192.0.2.50", IsEqual: true},
	}
	if diff := cmp.Diff(wantMatchers, created.Matchers); diff != "" {
		t.Errorf("created Matchers (-want +got):\n%s", diff)
	}
	if !strings.Contains(created.Comment, "hb-key=tgt-decom") {
		t.Errorf("created Comment = %q, want it to carry hb-key=tgt-decom", created.Comment)
	}
}

func TestReconcileSilencesNoDesiredNoExistingIsNoop(t *testing.T) {
	authority, skipped := suppress.NewAuthority(nil, nil)
	if skipped != 0 {
		t.Fatalf("NewAuthority skipped = %d, want 0", skipped)
	}
	client := newFakeSilenceClient()

	result, err := notify.ReconcileSilences(context.Background(), fixedNow, client, authority)
	if err != nil {
		t.Fatalf("ReconcileSilences: %v", err)
	}
	if result != (notify.ReconcileResult{}) {
		t.Errorf("ReconcileResult = %+v, want zero value", result)
	}
}

// gcAuthority is a one-record authority: key gc-noise muting disk/smart-fail
// until fixedNow+7d.
func gcAuthority(t *testing.T) (*suppress.Authority, string) {
	t.Helper()
	until := fixedNow.Add(7 * 24 * time.Hour).UTC().Format(time.RFC3339)
	a, skipped := suppress.NewAuthority(nil, []suppress.Suppression{{
		Key: "gc-noise", Scope: suppress.ScopeGroupCheck,
		Matcher: suppress.Matcher{Group: "disk", Check: "smart-fail"},
		Until:   until, Reason: "vendor noise", Actor: "ops", Source: suppress.SourceRuntime,
	}})
	if skipped != 0 {
		t.Fatalf("NewAuthority skipped = %d", skipped)
	}
	return a, until
}

func gcMatchers() []silence.Matcher {
	return []silence.Matcher{
		{Name: "check", Value: "smart-fail", IsEqual: true},
		{Name: "group", Value: "disk", IsEqual: true},
		{Name: "source", Value: "heimdall", IsEqual: true},
	}
}

func ours(id, key, endsAt, state string, m []silence.Matcher) silence.Silence {
	return silence.Silence{
		ID: id, Matchers: m, EndsAt: endsAt, State: state,
		StartsAt:  fixedNow.Add(-24 * time.Hour).UTC().Format(time.RFC3339),
		CreatedBy: notify.NotifierCreatedBy, Comment: "hb-key=" + key + " | r (ops)",
	}
}

// Alertmanager keeps an EXPIRED silence in its list for its whole retention
// window (default 120h). The reconciler used to count one as "already
// projected": a re-mute of the same key within those five days was never
// projected at all, and an expired silence whose key had left the ledger
// was re-DELETEd on every cycle. Expired silences are now invisible to it.
func TestReconcileSilencesIgnoresExpiredSilences(t *testing.T) {
	past := fixedNow.Add(-48 * time.Hour).UTC().Format(time.RFC3339)
	cases := []struct {
		name     string
		desired  bool
		existing silence.Silence
		want     notify.ReconcileResult
	}{
		{
			name: "an expired copy does not stand in for an active mute", desired: true,
			existing: ours("old", "gc-noise", past, silence.StateExpired, gcMatchers()),
			want:     notify.ReconcileResult{Created: 1},
		},
		{
			name: "an expired copy of a removed mute is left alone", desired: false,
			existing: ours("old", "gc-noise", past, silence.StateExpired, gcMatchers()),
			want:     notify.ReconcileResult{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			authority, _ := suppress.NewAuthority(nil, nil)
			if tc.desired {
				authority, _ = gcAuthority(t)
			}
			client := newFakeSilenceClient()
			client.silences[tc.existing.ID] = tc.existing

			got, err := notify.ReconcileSilences(context.Background(), fixedNow, client, authority)
			if err != nil {
				t.Fatalf("ReconcileSilences: %v", err)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("ReconcileResult (-want +got):\n%s", diff)
			}
			if _, ok := client.silences["old"]; !ok {
				t.Error("the expired silence was deleted; it is Alertmanager's to garbage-collect")
			}
		})
	}
}

// Matching on the key alone let a projection drift from the ledger for the
// life of the record: an extended mute's silence ended early, and an edited
// declarative matcher kept silencing the OLD labels. A live silence whose
// matchers or endsAt differ from the ledger's is now replaced (create the
// new one first, then delete the stale one, so nothing is unsilenced in
// between); duplicates for one key are collapsed to one.
func TestReconcileSilencesReplacesDriftAndCollapsesDuplicates(t *testing.T) {
	_, until := gcAuthority(t)
	earlier := fixedNow.Add(24 * time.Hour).UTC().Format(time.RFC3339)
	// Alertmanager echoes times with milliseconds; the same instant must
	// still count as a match.
	untilMillis := strings.TrimSuffix(until, "Z") + ".000Z"
	reversed := []silence.Matcher{gcMatchers()[2], gcMatchers()[1], gcMatchers()[0]}
	oldTarget := []silence.Matcher{
		{Name: "check", Value: "smart-fail", IsEqual: true},
		{Name: "group", Value: "disk-old", IsEqual: true},
		{Name: "source", Value: "heimdall", IsEqual: true},
	}

	cases := []struct {
		name        string
		existing    []silence.Silence
		want        notify.ReconcileResult
		wantDeleted []string
	}{
		{
			name:     "identical (order and time precision aside) is kept",
			existing: []silence.Silence{ours("s1", "gc-noise", untilMillis, silence.StateActive, reversed)},
			want:     notify.ReconcileResult{Kept: 1},
		},
		{
			name:        "endsAt drift is replaced",
			existing:    []silence.Silence{ours("s1", "gc-noise", earlier, silence.StateActive, gcMatchers())},
			want:        notify.ReconcileResult{Created: 1, Deleted: 1},
			wantDeleted: []string{"s1"},
		},
		{
			name:        "matcher drift is replaced",
			existing:    []silence.Silence{ours("s1", "gc-noise", until, silence.StateActive, oldTarget)},
			want:        notify.ReconcileResult{Created: 1, Deleted: 1},
			wantDeleted: []string{"s1"},
		},
		{
			name: "a duplicate for one key is collapsed",
			existing: []silence.Silence{
				ours("s1", "gc-noise", until, silence.StateActive, gcMatchers()),
				ours("s2", "gc-noise", until, silence.StatePending, gcMatchers()),
			},
			want:        notify.ReconcileResult{Kept: 1, Deleted: 1},
			wantDeleted: []string{"s2"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			authority, _ := gcAuthority(t)
			client := newFakeSilenceClient()
			for _, s := range tc.existing {
				client.silences[s.ID] = s
			}
			got, err := notify.ReconcileSilences(context.Background(), fixedNow, client, authority)
			if err != nil {
				t.Fatalf("ReconcileSilences: %v", err)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("ReconcileResult (-want +got):\n%s", diff)
			}
			for _, id := range tc.wantDeleted {
				if _, ok := client.silences[id]; ok {
					t.Errorf("stale silence %s survived", id)
				}
			}
			// Convergence: a second pass changes nothing.
			again, err := notify.ReconcileSilences(context.Background(), fixedNow, client, authority)
			if err != nil {
				t.Fatalf("second ReconcileSilences: %v", err)
			}
			if diff := cmp.Diff(notify.ReconcileResult{Kept: 1}, again); diff != "" {
				t.Errorf("second pass is not a no-op (-want +got):\n%s", diff)
			}
		})
	}
}

// deadlineCheckingClient wraps a SilenceClient and records any call whose
// context had no deadline.
type deadlineCheckingClient struct {
	notify.SilenceClient
	missing []string
}

func (c *deadlineCheckingClient) check(ctx context.Context, op string) {
	if _, ok := ctx.Deadline(); !ok {
		c.missing = append(c.missing, op)
	}
}

func (c *deadlineCheckingClient) Create(ctx context.Context, s silence.Silence) (string, error) {
	c.check(ctx, "create")
	return c.SilenceClient.Create(ctx, s)
}

func (c *deadlineCheckingClient) List(ctx context.Context) ([]silence.Silence, error) {
	c.check(ctx, "list")
	return c.SilenceClient.List(ctx)
}

func (c *deadlineCheckingClient) Delete(ctx context.Context, id string) error {
	c.check(ctx, "delete")
	return c.SilenceClient.Delete(ctx, id)
}

// Every Alertmanager call runs under its own deadline, so a hung
// Alertmanager cannot stall the notifier's loop.
func TestReconcileSilencesEveryCallHasADeadline(t *testing.T) {
	authority, _ := gcAuthority(t)
	inner := newFakeSilenceClient()
	inner.silences["orphan"] = ours("orphan", "gone", fixedNow.Add(time.Hour).UTC().Format(time.RFC3339), silence.StateActive, gcMatchers())
	client := &deadlineCheckingClient{SilenceClient: inner}

	if _, err := notify.ReconcileSilences(context.Background(), fixedNow, client, authority); err != nil {
		t.Fatalf("ReconcileSilences: %v", err)
	}
	if len(client.missing) != 0 {
		t.Errorf("calls without a deadline: %v", client.missing)
	}
}
