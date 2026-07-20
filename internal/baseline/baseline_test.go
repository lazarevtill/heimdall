package baseline_test

import (
	"math"
	"path/filepath"
	"testing"
	"time"

	"github.com/lazarevtill/heimdall/internal/baseline"
)

func openTest(t *testing.T) (*baseline.Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := baseline.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s, path
}

func closeEnough(a, b float64) bool {
	return math.Abs(a-b) < 1e-9
}

func TestQuantileGoldenType7(t *testing.T) {
	s, _ := openTest(t)
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	// values 1..10 inserted 1 second apart, all well within the window.
	for i := 1; i <= 10; i++ {
		ts := now.Add(-time.Duration(10-i) * time.Second)
		if err := s.RecordFeature(ts, "host", "node-a", "cpu_p95", float64(i)); err != nil {
			t.Fatalf("RecordFeature(%d): %v", i, err)
		}
	}
	window := time.Hour

	cases := []struct {
		q    float64
		want float64
	}{
		{0.0, 1.0},
		{0.5, 5.5},
		{0.95, 9.55},
		{1.0, 10.0},
	}
	for _, tc := range cases {
		v, n, ok, err := s.Quantile(now, "node-a", "cpu_p95", window, tc.q)
		if err != nil {
			t.Fatalf("Quantile(q=%v): %v", tc.q, err)
		}
		if !ok {
			t.Fatalf("Quantile(q=%v): ok = false, want true", tc.q)
		}
		if n != 10 {
			t.Errorf("Quantile(q=%v): n = %d, want 10", tc.q, n)
		}
		if !closeEnough(v, tc.want) {
			t.Errorf("Quantile(q=%v) = %v, want %v", tc.q, v, tc.want)
		}
	}
}

func TestQuantileNoRowsInRange(t *testing.T) {
	s, _ := openTest(t)
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	if err := s.RecordFeature(now, "host", "node-a", "cpu_p95", 1.0); err != nil {
		t.Fatal(err)
	}
	// Different feature/target: zero rows in range.
	_, n, ok, err := s.Quantile(now, "node-a", "mem_p95", time.Hour, 0.5)
	if err != nil {
		t.Fatalf("Quantile: %v", err)
	}
	if ok {
		t.Error("ok = true, want false for unrelated feature")
	}
	if n != 0 {
		t.Errorf("n = %d, want 0", n)
	}

	_, _, ok, err = s.Quantile(now, "node-b", "cpu_p95", time.Hour, 0.5)
	if err != nil {
		t.Fatalf("Quantile: %v", err)
	}
	if ok {
		t.Error("ok = true, want false for unrelated target")
	}
}

func TestQuantileWindowBoundary(t *testing.T) {
	s, _ := openTest(t)
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	window := time.Hour

	// Exactly at now-window: included.
	atBoundary := now.Add(-window)
	if err := s.RecordFeature(atBoundary, "host", "node-a", "cpu_p95", 42.0); err != nil {
		t.Fatal(err)
	}
	v, n, ok, err := s.Quantile(now, "node-a", "cpu_p95", window, 0.5)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || n != 1 || !closeEnough(v, 42.0) {
		t.Fatalf("boundary row: v=%v n=%d ok=%v, want 42.0/1/true", v, n, ok)
	}

	// One second older: excluded.
	s2, _ := openTest(t)
	older := now.Add(-window).Add(-time.Second)
	if err := s2.RecordFeature(older, "host", "node-a", "cpu_p95", 99.0); err != nil {
		t.Fatal(err)
	}
	_, n2, ok2, err := s2.Quantile(now, "node-a", "cpu_p95", window, 0.5)
	if err != nil {
		t.Fatal(err)
	}
	if ok2 || n2 != 0 {
		t.Fatalf("older-than-window row included: n=%d ok=%v, want 0/false", n2, ok2)
	}
}

func TestPurgeFeaturesOlderThan(t *testing.T) {
	s, _ := openTest(t)
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	cutoff := now.Add(-24 * time.Hour)

	// Two rows older than cutoff, two newer-or-equal.
	if err := s.RecordFeature(cutoff.Add(-time.Hour), "host", "node-a", "f", 1); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordFeature(cutoff.Add(-time.Minute), "host", "node-a", "f", 2); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordFeature(cutoff, "host", "node-a", "f", 3); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordFeature(cutoff.Add(time.Hour), "host", "node-a", "f", 4); err != nil {
		t.Fatal(err)
	}

	n, err := s.PurgeFeaturesOlderThan(cutoff)
	if err != nil {
		t.Fatalf("PurgeFeaturesOlderThan: %v", err)
	}
	if n != 2 {
		t.Errorf("purged = %d, want 2", n)
	}

	_, remaining, _, err := s.Quantile(now, "node-a", "f", 48*time.Hour, 0.5)
	if err != nil {
		t.Fatal(err)
	}
	if remaining != 2 {
		t.Errorf("remaining rows = %d, want 2", remaining)
	}
}

func TestWarmup(t *testing.T) {
	s, _ := openTest(t)
	warmDur := 7 * 24 * time.Hour
	t0 := time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC)

	// Never enabled: fail-closed warming=true.
	warming, err := s.Warming(t0, "c6-quantile-creep", "node-a", warmDur)
	if err != nil {
		t.Fatalf("Warming: %v", err)
	}
	if !warming {
		t.Error("never-enabled Warming = false, want true (fail-closed)")
	}

	if err := s.MarkEnabled(t0, "c6-quantile-creep", "node-a"); err != nil {
		t.Fatalf("MarkEnabled: %v", err)
	}

	justBefore := t0.Add(warmDur).Add(-time.Second)
	warming, err = s.Warming(justBefore, "c6-quantile-creep", "node-a", warmDur)
	if err != nil {
		t.Fatal(err)
	}
	if !warming {
		t.Error("Warming just before warmDur elapsed = false, want true")
	}

	justAfter := t0.Add(warmDur).Add(time.Second)
	warming, err = s.Warming(justAfter, "c6-quantile-creep", "node-a", warmDur)
	if err != nil {
		t.Fatal(err)
	}
	if warming {
		t.Error("Warming just after warmDur elapsed = true, want false")
	}

	// Idempotent earliest-wins: a later MarkEnabled must not move enabled_at forward.
	later := t0.Add(time.Hour)
	if err := s.MarkEnabled(later, "c6-quantile-creep", "node-a"); err != nil {
		t.Fatalf("second MarkEnabled: %v", err)
	}
	// If enabled_at had moved to `later`, then at time later+warmDur-1s we'd
	// still be warming under the later baseline. Since it must stay t0, that
	// same instant is well past warmDur from t0 and warming should be false.
	warming, err = s.Warming(later.Add(warmDur).Add(-time.Second), "c6-quantile-creep", "node-a", warmDur)
	if err != nil {
		t.Fatal(err)
	}
	if warming {
		t.Error("earliest enabled_at was not preserved: Warming still true well after original warmDur")
	}
}

func TestTemplateEWMA(t *testing.T) {
	s, _ := openTest(t)
	t0 := time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC)
	alpha := 0.3

	tmpl, isNew, err := s.UpsertTemplate(t0, "node-a", "gitlab", "hash1", 10, alpha)
	if err != nil {
		t.Fatalf("UpsertTemplate (new): %v", err)
	}
	if !isNew {
		t.Error("isNew = false on first observation, want true")
	}
	if tmpl.EWMA != 10 {
		t.Errorf("new EWMA = %v, want 10", tmpl.EWMA)
	}
	if !tmpl.FirstSeen.Equal(t0) || !tmpl.LastSeen.Equal(t0) {
		t.Errorf("new template FirstSeen/LastSeen = %v/%v, want both %v", tmpl.FirstSeen, tmpl.LastSeen, t0)
	}
	if tmpl.Host != "node-a" || tmpl.App != "gitlab" || tmpl.Hash != "hash1" {
		t.Errorf("unexpected template identity: %+v", tmpl)
	}

	t1 := t0.Add(time.Hour)
	wantEWMA := alpha*20 + (1-alpha)*10
	tmpl2, isNew2, err := s.UpsertTemplate(t1, "node-a", "gitlab", "hash1", 20, alpha)
	if err != nil {
		t.Fatalf("UpsertTemplate (existing): %v", err)
	}
	if isNew2 {
		t.Error("isNew = true on second observation, want false")
	}
	if !closeEnough(tmpl2.EWMA, wantEWMA) {
		t.Errorf("updated EWMA = %v, want %v", tmpl2.EWMA, wantEWMA)
	}
	if !tmpl2.FirstSeen.Equal(t0) {
		t.Errorf("FirstSeen moved: %v, want %v", tmpl2.FirstSeen, t0)
	}
	if !tmpl2.LastSeen.Equal(t1) {
		t.Errorf("LastSeen = %v, want %v", tmpl2.LastSeen, t1)
	}
}

func TestPurgeTemplatesOlderThan(t *testing.T) {
	s, _ := openTest(t)
	t0 := time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC)
	cutoff := t0.Add(24 * time.Hour)

	if _, _, err := s.UpsertTemplate(t0, "node-a", "gitlab", "old", 1, 0.3); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.UpsertTemplate(cutoff.Add(time.Hour), "node-a", "gitlab", "new", 1, 0.3); err != nil {
		t.Fatal(err)
	}

	n, err := s.PurgeTemplatesOlderThan(cutoff)
	if err != nil {
		t.Fatalf("PurgeTemplatesOlderThan: %v", err)
	}
	if n != 1 {
		t.Errorf("purged = %d, want 1", n)
	}

	// The "new" template observation must remain: bump it again and check
	// first_seen is unchanged (it was never purged).
	tmpl, isNew, err := s.UpsertTemplate(cutoff.Add(2*time.Hour), "node-a", "gitlab", "new", 2, 0.3)
	if err != nil {
		t.Fatal(err)
	}
	if isNew {
		t.Error("surviving template reported isNew=true after purge of a different row")
	}
	if !tmpl.FirstSeen.Equal(cutoff.Add(time.Hour)) {
		t.Errorf("surviving template FirstSeen = %v, want %v", tmpl.FirstSeen, cutoff.Add(time.Hour))
	}
}

func TestMarkCrossingEarliestWins(t *testing.T) {
	s, _ := openTest(t)
	t0 := time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC)

	since, err := s.MarkCrossing(t0, "c6-quantile-creep", "node-a")
	if err != nil {
		t.Fatalf("MarkCrossing (first): %v", err)
	}
	if !since.Equal(t0) {
		t.Errorf("first MarkCrossing since = %v, want %v", since, t0)
	}

	later := t0.Add(time.Hour)
	since2, err := s.MarkCrossing(later, "c6-quantile-creep", "node-a")
	if err != nil {
		t.Fatalf("MarkCrossing (second): %v", err)
	}
	if !since2.Equal(t0) {
		t.Errorf("second MarkCrossing since = %v, want original %v (earliest-wins)", since2, t0)
	}
}

func TestClearCrossingThenMarkCrossingStartsFresh(t *testing.T) {
	s, _ := openTest(t)
	t0 := time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC)

	if _, err := s.MarkCrossing(t0, "c6-quantile-creep", "node-a"); err != nil {
		t.Fatalf("MarkCrossing: %v", err)
	}

	if err := s.ClearCrossing("c6-quantile-creep", "node-a"); err != nil {
		t.Fatalf("ClearCrossing: %v", err)
	}

	t1 := t0.Add(24 * time.Hour)
	since, err := s.MarkCrossing(t1, "c6-quantile-creep", "node-a")
	if err != nil {
		t.Fatalf("MarkCrossing (fresh): %v", err)
	}
	if !since.Equal(t1) {
		t.Errorf("MarkCrossing after ClearCrossing since = %v, want fresh %v", since, t1)
	}
}

func TestClearCrossingNoRowIsNoop(t *testing.T) {
	s, _ := openTest(t)
	if err := s.ClearCrossing("never-crossed", "node-z"); err != nil {
		t.Fatalf("ClearCrossing on absent row: %v", err)
	}
}

func TestSharedFileTwoHandles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	s1, err := baseline.Open(path)
	if err != nil {
		t.Fatalf("Open s1: %v", err)
	}
	defer s1.Close()

	s2, err := baseline.Open(path)
	if err != nil {
		t.Fatalf("Open s2 on same path: %v", err)
	}
	defer s2.Close()

	now := time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC)
	if err := s1.RecordFeature(now, "host", "node-a", "f", 1); err != nil {
		t.Fatalf("s1.RecordFeature: %v", err)
	}
	// s2 must see s1's write (same underlying file, WAL-shared).
	_, n, ok, err := s2.Quantile(now, "node-a", "f", time.Hour, 0.5)
	if err != nil {
		t.Fatalf("s2.Quantile: %v", err)
	}
	if !ok || n != 1 {
		t.Fatalf("s2 did not observe s1's write: n=%d ok=%v", n, ok)
	}

	if err := s2.MarkEnabled(now, "c-test", "node-a"); err != nil {
		t.Fatalf("s2.MarkEnabled: %v", err)
	}
	// Warming right at enabled_at is true regardless of visibility (a
	// never-enabled check is ALSO fail-closed true), so that instant can't
	// distinguish "s1 saw the write" from "s1 didn't". Check well past the
	// warm-up window instead: if s1 observes s2's row, warming must have
	// flipped to false; if s1 still thinks it was never enabled, it stays
	// (wrongly) true.
	warmDur := time.Hour
	warming, err := s1.Warming(now.Add(warmDur).Add(time.Second), "c-test", "node-a", warmDur)
	if err != nil {
		t.Fatalf("s1.Warming: %v", err)
	}
	if warming {
		t.Error("s1 did not observe s2's MarkEnabled write")
	}
}
