package ledger_test

import (
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/lazarevtill/heimdall/internal/contract"
	"github.com/lazarevtill/heimdall/internal/ledger"
)

func testFinding(t *testing.T) contract.Finding {
	t.Helper()
	f, err := contract.NewFinding(time.Unix(1752900000, 0).UTC(), contract.FindingSpec{
		Check: "c1-deadman", Group: "backup-ds1", Target: "backup:ds1/vm-100",
		Node: "node-a", Severity: contract.SeverityCritical, Class: contract.ClassHard,
		State: contract.StateFiring, Title: "backup missed", Evidence: "e",
	})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestUpsertLifecycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	l, err := ledger.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	f := testFinding(t)
	t0 := time.Unix(1752900000, 0).UTC()
	t1 := t0.Add(5 * time.Minute)

	if err := l.Upsert(t0, []contract.Finding{f}); err != nil {
		t.Fatalf("first Upsert: %v", err)
	}
	e, ok, err := l.Get(f.Fingerprint)
	if err != nil || !ok {
		t.Fatalf("Get: ok=%v err=%v", ok, err)
	}
	if e.Count != 1 || !e.FirstSeen.Equal(t0) || !e.LastSeen.Equal(t0) {
		t.Errorf("after first upsert: %+v", e)
	}

	if err := l.Upsert(t1, []contract.Finding{f}); err != nil {
		t.Fatalf("second Upsert: %v", err)
	}
	e, _, _ = l.Get(f.Fingerprint)
	if e.Count != 2 {
		t.Errorf("Count = %d, want 2", e.Count)
	}
	if !e.FirstSeen.Equal(t0) {
		t.Errorf("FirstSeen moved: %v, want %v (must be preserved)", e.FirstSeen, t0)
	}
	if !e.LastSeen.Equal(t1) {
		t.Errorf("LastSeen = %v, want %v", e.LastSeen, t1)
	}

	// persistence across reopen
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	l2, err := ledger.Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer l2.Close()
	e, ok, err = l2.Get(f.Fingerprint)
	if err != nil || !ok || e.Count != 2 {
		t.Errorf("after reopen: ok=%v err=%v entry=%+v", ok, err, e)
	}
}

func TestGetMissing(t *testing.T) {
	l, err := ledger.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	_, ok, err := l.Get("0000000000000000")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if ok {
		t.Error("ok = true for missing fingerprint")
	}
}

// MaxOpenConns(1) must serialize concurrent writers with no
// "database is locked" errors.
func TestConcurrentUpserts(t *testing.T) {
	l, err := ledger.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	f := testFinding(t)
	var wg sync.WaitGroup
	errs := make(chan error, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs <- l.Upsert(time.Unix(1752900000+int64(i), 0), []contract.Finding{f})
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("concurrent Upsert: %v", err)
		}
	}
	e, _, _ := l.Get(f.Fingerprint)
	if e.Count != 10 {
		t.Errorf("Count = %d, want 10", e.Count)
	}
}

// A check that evaluates OK emits no finding, so ResolveAbsent resolves
// every row a complete run did not produce, and only those. Unknown stays
// open (fail-closed), a re-fire reopens, and lifetime figures survive a
// resolve.
func TestResolveAbsentResolvesWhatARunNoLongerProduces(t *testing.T) {
	l, err := ledger.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	mk := func(target string, state contract.State) contract.Finding {
		t.Helper()
		f, err := contract.NewFinding(time.Unix(1752900000, 0).UTC(), contract.FindingSpec{
			Check: "c1-deadman", Group: "backup-ds1", Target: target, Node: "node-a",
			Severity: contract.SeverityCritical, Class: contract.ClassHard,
			State: state, Title: "t", Evidence: "e",
		})
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	stale, broken := mk("backup:ds1/vm-100", contract.StateFiring), mk("backup:ds1/vm-101", contract.StateUnknown)
	states := func() map[string]string {
		t.Helper()
		entries, err := l.List()
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]string{}
		for _, e := range entries {
			out[e.Target] = e.State
		}
		return out
	}
	t0 := time.Unix(1752900000, 0).UTC()
	steps := []struct {
		name string
		run  []contract.Finding
		want map[string]string
	}{
		{"both open", []contract.Finding{stale, broken},
			map[string]string{"backup:ds1/vm-100": "firing", "backup:ds1/vm-101": "unknown"}},
		{"stale recovers, broken stays unknown", []contract.Finding{broken},
			map[string]string{"backup:ds1/vm-100": "ok", "backup:ds1/vm-101": "unknown"}},
		{"a clean run resolves everything", nil,
			map[string]string{"backup:ds1/vm-100": "ok", "backup:ds1/vm-101": "ok"}},
		{"a re-fire reopens", []contract.Finding{stale},
			map[string]string{"backup:ds1/vm-100": "firing", "backup:ds1/vm-101": "ok"}},
	}
	for i, st := range steps {
		if err := l.Upsert(t0.Add(time.Duration(i)*5*time.Minute), st.run); err != nil {
			t.Fatalf("%s: Upsert: %v", st.name, err)
		}
		if err := l.ResolveAbsent(st.run); err != nil {
			t.Fatalf("%s: ResolveAbsent: %v", st.name, err)
		}
		if diff := cmp.Diff(st.want, states()); diff != "" {
			t.Errorf("%s: states (-want +got):\n%s", st.name, diff)
		}
	}
	e, _, _ := l.Get(stale.Fingerprint)
	if e.Count != 2 || !e.FirstSeen.Equal(t0) || !e.LastSeen.Equal(t0.Add(15*time.Minute)) {
		t.Errorf("stale entry = %+v, want count 2, first_seen kept, last_seen the re-fire", e)
	}
	e, _, _ = l.Get(broken.Fingerprint)
	if !e.LastSeen.Equal(t0.Add(5 * time.Minute)) {
		t.Errorf("broken last_seen = %v, want the last run that saw it (a resolve does not touch it)", e.LastSeen)
	}
}
