package outbox_test

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/lazarevtill/heimdall/internal/outbox"
	_ "modernc.org/sqlite"
)

func TestMarkDeliveredIsPerSinkAndIdempotent(t *testing.T) {
	s := openTest(t)
	if _, err := s.Enqueue(fixedNow, outbox.ChannelMain, "body", "idem-1"); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	entries, err := s.Pending(0)
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	id := entries[0].ID

	for _, sinkID := range []string{"telegram", "gotify"} {
		delivered, err := s.DeliveredTo(id, sinkID)
		if err != nil {
			t.Fatalf("DeliveredTo: %v", err)
		}
		if delivered {
			t.Fatalf("%s: want not-yet-delivered before any mark", sinkID)
		}
	}

	if err := s.MarkDelivered(fixedNow, id, "telegram"); err != nil {
		t.Fatalf("MarkDelivered: %v", err)
	}

	telegramDone, err := s.DeliveredTo(id, "telegram")
	if err != nil {
		t.Fatalf("DeliveredTo: %v", err)
	}
	gotifyDone, err := s.DeliveredTo(id, "gotify")
	if err != nil {
		t.Fatalf("DeliveredTo: %v", err)
	}
	if !telegramDone {
		t.Error("telegram should be marked delivered")
	}
	if gotifyDone {
		t.Error("gotify must NOT be marked delivered by telegram's mark")
	}

	// A repeat mark is a no-op, never an error and never a duplicate row.
	if err := s.MarkDelivered(fixedNow.Add(time.Hour), id, "telegram"); err != nil {
		t.Fatalf("MarkDelivered (repeat): %v", err)
	}
}

func TestMarkDeliveredRejectsEmptySinkID(t *testing.T) {
	s := openTest(t)
	if err := s.MarkDelivered(fixedNow, 1, ""); err == nil {
		t.Fatal("MarkDelivered: want error for an empty sink id, got nil")
	}
}

func TestOldestPendingByChannelIsScopedToRoutedChannels(t *testing.T) {
	s := openTest(t)
	if _, err := s.Enqueue(fixedNow, outbox.ChannelMain, "m", "idem-main"); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if _, err := s.Enqueue(fixedNow.Add(time.Minute), outbox.ChannelAnalyst, "a", "idem-analyst"); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	// A sink routed for main only must not see the analyst entry as its
	// own backlog — otherwise it would alert forever on a queue it was
	// never meant to drain.
	got, err := s.OldestPendingByChannel("gotify", []outbox.Channel{outbox.ChannelMain})
	if err != nil {
		t.Fatalf("OldestPendingByChannel: %v", err)
	}
	want := []outbox.OldestPending{
		{SinkID: "gotify", Channel: outbox.ChannelMain, CreatedAt: fixedNow},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}
}

func TestOldestPendingByChannelExcludesDeliveredAndReportsTheOldest(t *testing.T) {
	s := openTest(t)
	for i, body := range []string{"first", "second"} {
		if _, err := s.Enqueue(fixedNow.Add(time.Duration(i)*time.Minute), outbox.ChannelMain, body, "idem-"+body); err != nil {
			t.Fatalf("Enqueue: %v", err)
		}
	}
	entries, err := s.Pending(0)
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}

	// Oldest-first: "first" is the backlog head.
	got, err := s.OldestPendingByChannel("gotify", []outbox.Channel{outbox.ChannelMain})
	if err != nil {
		t.Fatalf("OldestPendingByChannel: %v", err)
	}
	if len(got) != 1 || !got[0].CreatedAt.Equal(fixedNow) {
		t.Fatalf("want the oldest entry (%v), got %+v", fixedNow, got)
	}

	// Deliver the head; the backlog moves to the next entry.
	if err := s.MarkDelivered(fixedNow, entries[0].ID, "gotify"); err != nil {
		t.Fatalf("MarkDelivered: %v", err)
	}
	got, err = s.OldestPendingByChannel("gotify", []outbox.Channel{outbox.ChannelMain})
	if err != nil {
		t.Fatalf("OldestPendingByChannel: %v", err)
	}
	if len(got) != 1 || !got[0].CreatedAt.Equal(fixedNow.Add(time.Minute)) {
		t.Fatalf("want the second entry to become the head, got %+v", got)
	}

	// Deliver the rest; the channel drops out of the result entirely (the
	// caller renders an explicit zero for it).
	if err := s.MarkDelivered(fixedNow, entries[1].ID, "gotify"); err != nil {
		t.Fatalf("MarkDelivered: %v", err)
	}
	got, err = s.OldestPendingByChannel("gotify", []outbox.Channel{outbox.ChannelMain})
	if err != nil {
		t.Fatalf("OldestPendingByChannel: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("want no rows once everything is delivered, got %+v", got)
	}
}

func TestOldestPendingByChannelWithNoChannelsIsEmpty(t *testing.T) {
	s := openTest(t)
	got, err := s.OldestPendingByChannel("gotify", nil)
	if err != nil {
		t.Fatalf("OldestPendingByChannel: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("want no rows for a sink routed nowhere, got %+v", got)
	}
}

// A database written before notify_delivery existed must come forward
// cleanly: its already-sent entries belong to Telegram, which was the only
// sink at the time. Getting this wrong would re-send every historical
// message the first time the new binary starts.
func TestOpenBackfillsLegacySentEntriesToTelegram(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")

	// Build a pre-migration database by hand: the old schema only.
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if _, err := db.Exec(`
CREATE TABLE notify_outbox (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  channel       TEXT NOT NULL,
  body          TEXT NOT NULL,
  idem_key      TEXT NOT NULL,
  created_at    INTEGER NOT NULL,
  sent_at       INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX idx_outbox_idem ON notify_outbox(idem_key);
INSERT INTO notify_outbox (channel, body, idem_key, created_at, sent_at)
VALUES ('main', 'already sent', 'idem-sent', 100, 200),
       ('main', 'still pending', 'idem-pending', 100, 0);`); err != nil {
		t.Fatalf("seed legacy schema: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close seed handle: %v", err)
	}

	s, err := outbox.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	entries, err := s.Pending(0)
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	if len(entries) != 1 || entries[0].Body != "still pending" {
		t.Fatalf("want only the un-sent entry pending, got %+v", entries)
	}

	// The historically-sent entry must be attributed to telegram, so the
	// new drain does not re-send it.
	backlog, err := s.OldestPendingByChannel("telegram", []outbox.Channel{outbox.ChannelMain})
	if err != nil {
		t.Fatalf("OldestPendingByChannel: %v", err)
	}
	if len(backlog) != 1 || !backlog[0].CreatedAt.Equal(time.Unix(100, 0).UTC()) {
		t.Fatalf("want only the pending entry in telegram's backlog, got %+v", backlog)
	}

	// A second Open must be harmless — the backfill runs on every start.
	s2, err := outbox.Open(path)
	if err != nil {
		t.Fatalf("Open (second): %v", err)
	}
	defer s2.Close()
}
