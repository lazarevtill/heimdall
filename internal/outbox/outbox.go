// Package outbox is the BRIDGE's notify_outbox: a channel-typed SQLite queue
// over the bridge's OWN state db file (a new path, distinct from the
// Tier-1/Tier-2 engine's state.db and the analyst's state.db). The bridge
// ENQUEUES post-redaction message bodies here; the notifier (S7) DRAINS
// them. This decouples "decide to notify" from "deliver", so one dead
// channel never blocks the others.
//
// DB-ownership: this package opens its own *sql.DB handle, configured
// identically to internal/baseline and internal/analyst (WAL,
// synchronous(NORMAL), busy_timeout(5000), foreign_keys(ON),
// MaxOpenConns(1)). Tables are created with CREATE TABLE IF NOT EXISTS,
// which is naturally idempotent and needs no migration counter of its own —
// this package deliberately does NOT touch PRAGMA user_version, per the same
// rationale as internal/baseline: that counter belongs to whichever migrator
// owns the file, and a second migrator on the same counter would collide.
//
// No time.Now() anywhere in this package: every function that needs "now"
// takes an injected `now time.Time` parameter (ADR-G10).
package outbox

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite" // driver name "sqlite"
)

// Channel identifies a notification destination. The notifier (S7) drains
// each channel independently, so a dead channel never blocks the others.
type Channel string

const (
	// ChannelMain is the primary operator-facing notification channel.
	ChannelMain Channel = "main"
	// ChannelAnalyst is the low-urgency Tier-3 hypothesis channel.
	ChannelAnalyst Channel = "analyst"
)

// Channels returns every valid channel, in a stable order. Config
// validation uses it to insist that every channel has a route: an unrouted
// channel would discard its messages silently, which is exactly the failure
// mode Heimdall exists to prevent.
func Channels() []Channel { return []Channel{ChannelMain, ChannelAnalyst} }

// Valid reports whether c is a known channel.
func (c Channel) Valid() bool {
	switch c {
	case ChannelMain, ChannelAnalyst:
		return true
	default:
		return false
	}
}

// Entry is one notify_outbox row.
type Entry struct {
	ID        int64
	Channel   Channel
	Body      string // POST-redaction rendered message body
	IdemKey   string // idempotency key; a repeat enqueue is a no-op
	CreatedAt time.Time
	SentAt    time.Time // zero value means pending (not yet sent)
}

// schema is the notify_outbox table, its idempotency index, and the
// per-sink notify_delivery table.
//
// TWO LAYERS OF IDEMPOTENCY, deliberately kept separate:
//
//   - notify_outbox.idem_key is UNIQUE and means "one row per EVENT". It is
//     the bridge's enqueue-side guarantee: re-enqueueing on every webhook
//     never duplicates a message.
//   - notify_delivery(entry_id, sink_id) is the PRIMARY KEY and means
//     "at-most-once DELIVERY per sink". It is the notifier's drain-side
//     guarantee, and it is what makes partial delivery expressible: with
//     Telegram up and Gotify down, one delivery row exists and one does
//     not, so the retry re-sends to Gotify ONLY.
//
// notify_outbox.sent_at is retained and still means exactly what it always
// did — "delivered to every sink this entry was routed to" — so Pending()
// keeps its original semantics for callers that only care whether an entry
// is fully discharged. PendingFor() is the per-sink view underneath it.
const schema = `
CREATE TABLE IF NOT EXISTS notify_outbox (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  channel       TEXT NOT NULL,
  body          TEXT NOT NULL,
  idem_key      TEXT NOT NULL,
  created_at    INTEGER NOT NULL,
  sent_at       INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_outbox_idem ON notify_outbox(idem_key);
CREATE TABLE IF NOT EXISTS notify_delivery (
  entry_id      INTEGER NOT NULL,
  sink_id       TEXT NOT NULL,
  sent_at       INTEGER NOT NULL,
  PRIMARY KEY (entry_id, sink_id)
);`

// backfillLegacyDeliveries records a delivery row for every entry that was
// already marked sent before notify_delivery existed. Attributing those to
// "telegram" is historically true: it was the only sink until this table
// was added. INSERT OR IGNORE makes it safe to re-run on every Open, which
// is why this needs no migration counter — matching this package's standing
// decision never to touch PRAGMA user_version (see the package doc).
const backfillLegacyDeliveries = `
INSERT OR IGNORE INTO notify_delivery (entry_id, sink_id, sent_at)
SELECT id, 'telegram', sent_at FROM notify_outbox WHERE sent_at != 0;`

// Store is the bridge's notify_outbox store.
type Store struct{ db *sql.DB }

// Open configures a handle to the db at path and ensures the notify_outbox
// schema exists. path is the BRIDGE'S OWN db file — a new path, not the
// Tier-1/Tier-2 engine state.db. WAL config mirrors internal/baseline /
// internal/analyst exactly (see package doc).
func Open(path string) (*Store, error) {
	dsn := "file:" + path +
		"?_pragma=journal_mode(WAL)" +
		"&_pragma=synchronous(NORMAL)" +
		"&_pragma=busy_timeout(5000)" +
		"&_pragma=foreign_keys(ON)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("outbox: open %s: %w", path, err)
	}
	// Single writer: eliminates SQLITE_BUSY under concurrency entirely.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("outbox: create schema: %w", err)
	}
	if _, err := db.Exec(backfillLegacyDeliveries); err != nil {
		db.Close()
		return nil, fmt.Errorf("outbox: backfill legacy deliveries: %w", err)
	}
	return &Store{db: db}, nil
}

// Close closes the underlying handle.
func (s *Store) Close() error { return s.db.Close() }

// Enqueue inserts a pending entry for channel/body under idemKey, stamped
// created_at=now. A repeat idemKey is a NO-OP (returns enqueued=false, nil)
// — the unique index makes delivery idempotent, so the bridge can
// re-enqueue on every webhook without duplicating a message. channel is
// validated: an unknown channel is an error and nothing is inserted.
func (s *Store) Enqueue(now time.Time, channel Channel, body, idemKey string) (enqueued bool, err error) {
	if !channel.Valid() {
		return false, fmt.Errorf("outbox: enqueue %s: unknown channel %q", idemKey, channel)
	}
	res, err := s.db.Exec(`
INSERT INTO notify_outbox (channel, body, idem_key, created_at, sent_at)
VALUES (?, ?, ?, ?, 0)
ON CONFLICT(idem_key) DO NOTHING`,
		string(channel), body, idemKey, now.Unix(),
	)
	if err != nil {
		return false, fmt.Errorf("outbox: enqueue %s: %w", idemKey, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("outbox: enqueue %s rows affected: %w", idemKey, err)
	}
	return n > 0, nil
}

// Pending returns up to limit unsent entries oldest-first (the notifier
// drains these). limit<=0 returns all pending.
func (s *Store) Pending(limit int) ([]Entry, error) {
	query := `
SELECT id, channel, body, idem_key, created_at, sent_at
FROM notify_outbox
WHERE sent_at = 0
ORDER BY created_at ASC, id ASC`
	args := []any{}
	if limit > 0 {
		query += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("outbox: pending: %w", err)
	}
	defer rows.Close()

	entries, err := scanEntries(rows)
	if err != nil {
		return nil, fmt.Errorf("outbox: pending: %w", err)
	}
	return entries, nil
}

// MarkSent stamps sent_at=now for id, meaning "discharged to every sink
// this entry was routed to". Idempotent: a second call for an already-sent
// id is harmless (it simply rewrites sent_at). The notifier calls this only
// after every routed sink has a delivery row; per-sink progress is recorded
// by MarkDelivered.
func (s *Store) MarkSent(now time.Time, id int64) error {
	if _, err := s.db.Exec(`UPDATE notify_outbox SET sent_at = ? WHERE id = ?`, now.Unix(), id); err != nil {
		return fmt.Errorf("outbox: mark sent %d: %w", id, err)
	}
	return nil
}

// MarkDelivered records that entry id was accepted by sinkID at now.
// Idempotent via INSERT OR IGNORE + the (entry_id, sink_id) primary key: a
// repeat call is a no-op and never rewrites the original delivery time.
func (s *Store) MarkDelivered(now time.Time, id int64, sinkID string) error {
	if sinkID == "" {
		return fmt.Errorf("outbox: mark delivered %d: empty sink id", id)
	}
	if _, err := s.db.Exec(
		`INSERT OR IGNORE INTO notify_delivery (entry_id, sink_id, sent_at) VALUES (?, ?, ?)`,
		id, sinkID, now.Unix(),
	); err != nil {
		return fmt.Errorf("outbox: mark delivered %d to %s: %w", id, sinkID, err)
	}
	return nil
}

// DeliveredTo reports whether entry id already has a delivery row for
// sinkID.
func (s *Store) DeliveredTo(id int64, sinkID string) (bool, error) {
	var n int
	err := s.db.QueryRow(
		`SELECT COUNT(1) FROM notify_delivery WHERE entry_id = ? AND sink_id = ?`,
		id, sinkID,
	).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("outbox: delivered to %s for %d: %w", sinkID, id, err)
	}
	return n > 0, nil
}

// OldestPending is one (sink, channel) backlog datapoint: the creation time
// of the oldest entry on that channel not yet delivered to that sink.
type OldestPending struct {
	SinkID    string
	Channel   Channel
	CreatedAt time.Time
}

// OldestPendingByChannel returns, for sinkID, the oldest entry not yet
// delivered to it — restricted to `channels`, the channels that sink is
// actually routed for. The restriction matters: without it a sink routed
// only for `main` would count every `analyst` entry as its own backlog
// forever, and the gauge would alert on a queue that sink was never meant
// to drain.
//
// Channels with nothing pending are ABSENT from the result rather than
// reported as zero; the caller emits an explicit 0 for every routed
// (sink, channel) pair, so the series exists even when the backlog is
// clear. An absent series cannot alert — that is the trap this gauge
// exists to close, and it would be self-defeating to reintroduce it here.
// Results are ordered by channel for deterministic rendering.
func (s *Store) OldestPendingByChannel(sinkID string, channels []Channel) ([]OldestPending, error) {
	if sinkID == "" {
		return nil, fmt.Errorf("outbox: oldest pending: empty sink id")
	}
	if len(channels) == 0 {
		return nil, nil
	}
	args := []any{sinkID}
	placeholders := make([]string, 0, len(channels))
	for _, c := range channels {
		placeholders = append(placeholders, "?")
		args = append(args, string(c))
	}
	rows, err := s.db.Query(`
SELECT o.channel, MIN(o.created_at)
FROM notify_outbox o
WHERE NOT EXISTS (
  SELECT 1 FROM notify_delivery d WHERE d.entry_id = o.id AND d.sink_id = ?
)
AND o.channel IN (`+strings.Join(placeholders, ",")+`)
GROUP BY o.channel
ORDER BY o.channel ASC`, args...)
	if err != nil {
		return nil, fmt.Errorf("outbox: oldest pending for %s: %w", sinkID, err)
	}
	defer rows.Close()

	var out []OldestPending
	for rows.Next() {
		var (
			channel   string
			createdAt int64
		)
		if err := rows.Scan(&channel, &createdAt); err != nil {
			return nil, fmt.Errorf("outbox: oldest pending for %s scan: %w", sinkID, err)
		}
		out = append(out, OldestPending{
			SinkID:    sinkID,
			Channel:   Channel(channel),
			CreatedAt: time.Unix(createdAt, 0).UTC(),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("outbox: oldest pending for %s rows: %w", sinkID, err)
	}
	return out, nil
}

// scanEntries decodes a row set selecting the full Entry column list in the
// canonical order (id, channel, body, idem_key, created_at, sent_at).
func scanEntries(rows interface {
	Next() bool
	Scan(...any) error
	Err() error
}) ([]Entry, error) {
	var entries []Entry
	for rows.Next() {
		var (
			e                 Entry
			channel           string
			createdAt, sentAt int64
		)
		if err := rows.Scan(&e.ID, &channel, &e.Body, &e.IdemKey, &createdAt, &sentAt); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		e.Channel = Channel(channel)
		e.CreatedAt = time.Unix(createdAt, 0).UTC()
		if sentAt != 0 {
			e.SentAt = time.Unix(sentAt, 0).UTC()
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows: %w", err)
	}
	return entries, nil
}
