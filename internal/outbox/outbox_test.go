package outbox_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/lazarevtill/heimdall/internal/outbox"
)

var fixedNow = time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)

func openTest(t *testing.T) *outbox.Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bridge.db")
	s, err := outbox.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestEnqueueThenPending(t *testing.T) {
	s := openTest(t)
	enqueued, err := s.Enqueue(fixedNow, outbox.ChannelMain, "hello world", "idem-1")
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if !enqueued {
		t.Fatal("Enqueue: want enqueued=true for a fresh idem_key")
	}

	pending, err := s.Pending(0)
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("Pending: len=%d, want 1", len(pending))
	}
	e := pending[0]
	if e.Channel != outbox.ChannelMain {
		t.Errorf("Channel = %q, want main", e.Channel)
	}
	if e.Body != "hello world" {
		t.Errorf("Body = %q, want %q", e.Body, "hello world")
	}
	if e.IdemKey != "idem-1" {
		t.Errorf("IdemKey = %q, want idem-1", e.IdemKey)
	}
	if !e.CreatedAt.Equal(fixedNow) {
		t.Errorf("CreatedAt = %v, want %v", e.CreatedAt, fixedNow)
	}
	if !e.SentAt.IsZero() {
		t.Errorf("SentAt = %v, want zero (pending)", e.SentAt)
	}
}

func TestEnqueueDuplicateIdemKeyIsNoOp(t *testing.T) {
	s := openTest(t)
	if _, err := s.Enqueue(fixedNow, outbox.ChannelMain, "first body", "dup-key"); err != nil {
		t.Fatalf("Enqueue #1: %v", err)
	}
	enqueued, err := s.Enqueue(fixedNow.Add(time.Minute), outbox.ChannelMain, "second body", "dup-key")
	if err != nil {
		t.Fatalf("Enqueue #2: %v", err)
	}
	if enqueued {
		t.Error("Enqueue #2: want enqueued=false for a repeat idem_key")
	}

	pending, err := s.Pending(0)
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("Pending: len=%d, want 1 (duplicate must not create a second row)", len(pending))
	}
	if pending[0].Body != "first body" {
		t.Errorf("Body = %q, want %q (the repeat must not overwrite the original)", pending[0].Body, "first body")
	}
}

func TestEnqueueUnknownChannel(t *testing.T) {
	s := openTest(t)
	_, err := s.Enqueue(fixedNow, outbox.Channel("carrier-pigeon"), "body", "idem-x")
	if err == nil {
		t.Fatal("Enqueue: want error for unknown channel, got nil")
	}
	pending, err := s.Pending(0)
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	if len(pending) != 0 {
		t.Errorf("Pending: len=%d, want 0 (rejected channel must not be inserted)", len(pending))
	}
}

func TestMarkSentRemovesFromPending(t *testing.T) {
	s := openTest(t)
	if _, err := s.Enqueue(fixedNow, outbox.ChannelAnalyst, "body", "idem-sent"); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	pending, err := s.Pending(0)
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("Pending before MarkSent: len=%d, want 1", len(pending))
	}
	sentAt := fixedNow.Add(time.Hour)
	if err := s.MarkSent(sentAt, pending[0].ID); err != nil {
		t.Fatalf("MarkSent: %v", err)
	}

	pendingAfter, err := s.Pending(0)
	if err != nil {
		t.Fatalf("Pending after MarkSent: %v", err)
	}
	if len(pendingAfter) != 0 {
		t.Fatalf("Pending after MarkSent: len=%d, want 0", len(pendingAfter))
	}

	// MarkSent a second time is harmless (idempotent).
	if err := s.MarkSent(sentAt.Add(time.Minute), pending[0].ID); err != nil {
		t.Fatalf("MarkSent (second call): %v", err)
	}
}

func TestPendingOrderingOldestFirst(t *testing.T) {
	s := openTest(t)
	if _, err := s.Enqueue(fixedNow.Add(2*time.Minute), outbox.ChannelMain, "third", "k3"); err != nil {
		t.Fatalf("Enqueue k3: %v", err)
	}
	if _, err := s.Enqueue(fixedNow, outbox.ChannelMain, "first", "k1"); err != nil {
		t.Fatalf("Enqueue k1: %v", err)
	}
	if _, err := s.Enqueue(fixedNow.Add(1*time.Minute), outbox.ChannelMain, "second", "k2"); err != nil {
		t.Fatalf("Enqueue k2: %v", err)
	}

	pending, err := s.Pending(0)
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	if len(pending) != 3 {
		t.Fatalf("Pending: len=%d, want 3", len(pending))
	}
	wantOrder := []string{"first", "second", "third"}
	for i, want := range wantOrder {
		if pending[i].Body != want {
			t.Errorf("Pending[%d].Body = %q, want %q", i, pending[i].Body, want)
		}
	}
}

func TestPendingLimit(t *testing.T) {
	s := openTest(t)
	for i, key := range []string{"k1", "k2", "k3"} {
		if _, err := s.Enqueue(fixedNow.Add(time.Duration(i)*time.Minute), outbox.ChannelMain, "body", key); err != nil {
			t.Fatalf("Enqueue %s: %v", key, err)
		}
	}
	pending, err := s.Pending(2)
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	if len(pending) != 2 {
		t.Fatalf("Pending(2): len=%d, want 2", len(pending))
	}
}

func TestTwoEntriesDifferentIdemKeysBothLand(t *testing.T) {
	s := openTest(t)
	if _, err := s.Enqueue(fixedNow, outbox.ChannelMain, "body-a", "idem-a"); err != nil {
		t.Fatalf("Enqueue idem-a: %v", err)
	}
	if _, err := s.Enqueue(fixedNow, outbox.ChannelAnalyst, "body-b", "idem-b"); err != nil {
		t.Fatalf("Enqueue idem-b: %v", err)
	}
	pending, err := s.Pending(0)
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	if len(pending) != 2 {
		t.Fatalf("Pending: len=%d, want 2", len(pending))
	}
}

// TestEnqueueOrRearm pins the recurring-event contract: insert when new;
// re-arm (new body, created_at=now, per-sink deliveries cleared) only a SENT
// entry created before the cutoff; leave everything else untouched —
// crucially a still-pending entry, whose age the backlog gauge relies on.
func TestEnqueueOrRearm(t *testing.T) {
	const key = "t3-0123456789abcdef"
	rearmAt := fixedNow.Add(8 * 24 * time.Hour)
	cutoff := rearmAt.Add(-7 * 24 * time.Hour)

	type seed struct {
		channel outbox.Channel
		sent    bool
		created time.Time
	}
	type want struct {
		outcome   outbox.EnqueueOutcome
		pending   []outbox.Entry // IDs zeroed before comparing
		delivered bool           // telegram delivery row still present
	}
	cases := []struct {
		name string
		seed *seed
		want want
	}{
		{
			name: "no entry: inserted",
			want: want{outcome: outbox.Inserted, pending: []outbox.Entry{
				{Channel: outbox.ChannelAnalyst, Body: "new", IdemKey: key, CreatedAt: rearmAt}}},
		},
		{
			name: "sent before the cutoff: rearmed with the new body",
			seed: &seed{channel: outbox.ChannelAnalyst, sent: true, created: fixedNow},
			want: want{outcome: outbox.Rearmed, pending: []outbox.Entry{
				{Channel: outbox.ChannelAnalyst, Body: "new", IdemKey: key, CreatedAt: rearmAt}}},
		},
		{
			name: "sent after the cutoff: deduped",
			seed: &seed{channel: outbox.ChannelAnalyst, sent: true, created: cutoff.Add(time.Hour)},
			want: want{outcome: outbox.Deduped, delivered: true},
		},
		{
			name: "still pending, however old: deduped and untouched",
			seed: &seed{channel: outbox.ChannelAnalyst, created: fixedNow},
			want: want{outcome: outbox.Deduped, pending: []outbox.Entry{
				{Channel: outbox.ChannelAnalyst, Body: "old", IdemKey: key, CreatedAt: fixedNow}}},
		},
		{
			name: "same key on another channel: deduped",
			seed: &seed{channel: outbox.ChannelMain, sent: true, created: fixedNow},
			want: want{outcome: outbox.Deduped, delivered: true},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := openTest(t)
			if tc.seed != nil {
				if _, err := s.Enqueue(tc.seed.created, tc.seed.channel, "old", key); err != nil {
					t.Fatalf("seed Enqueue: %v", err)
				}
				if tc.seed.sent {
					p, err := s.Pending(0)
					if err != nil || len(p) != 1 {
						t.Fatalf("seed Pending: %v (%d)", err, len(p))
					}
					if err := s.MarkDelivered(tc.seed.created, p[0].ID, "telegram"); err != nil {
						t.Fatalf("seed MarkDelivered: %v", err)
					}
					if err := s.MarkSent(tc.seed.created, p[0].ID); err != nil {
						t.Fatalf("seed MarkSent: %v", err)
					}
				}
			}

			got, err := s.EnqueueOrRearm(rearmAt, outbox.ChannelAnalyst, "new", key, cutoff)
			if err != nil {
				t.Fatalf("EnqueueOrRearm: %v", err)
			}
			if got != tc.want.outcome {
				t.Errorf("outcome = %v, want %v", got, tc.want.outcome)
			}
			pending, err := s.Pending(0)
			if err != nil {
				t.Fatalf("Pending: %v", err)
			}
			var ids []int64
			for i := range pending {
				ids = append(ids, pending[i].ID)
				pending[i].ID = 0
			}
			if diff := cmp.Diff(tc.want.pending, pending); diff != "" {
				t.Errorf("pending mismatch (-want +got):\n%s", diff)
			}
			if tc.seed != nil && tc.seed.sent {
				// Entry id 1 is the only row; its telegram delivery row must be
				// cleared exactly when it was re-armed.
				delivered, err := s.DeliveredTo(1, "telegram")
				if err != nil {
					t.Fatalf("DeliveredTo: %v", err)
				}
				if delivered != tc.want.delivered {
					t.Errorf("telegram delivery row present = %v, want %v (pending ids %v)", delivered, tc.want.delivered, ids)
				}
			}
		})
	}
}

func TestEnqueueOrRearmUnknownChannel(t *testing.T) {
	s := openTest(t)
	if _, err := s.EnqueueOrRearm(fixedNow, outbox.Channel("bogus"), "b", "k", fixedNow); err == nil {
		t.Fatal("EnqueueOrRearm: want error for an unknown channel, got nil")
	}
}
