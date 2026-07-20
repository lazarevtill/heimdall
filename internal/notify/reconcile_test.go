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
