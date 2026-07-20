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

// valid reports whether c is a known channel.
func (c Channel) valid() bool {
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

// schema is the notify_outbox table plus its idempotency index.
const schema = `
CREATE TABLE IF NOT EXISTS notify_outbox (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  channel       TEXT NOT NULL,
  body          TEXT NOT NULL,
  idem_key      TEXT NOT NULL,
  created_at    INTEGER NOT NULL,
  sent_at       INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_outbox_idem ON notify_outbox(idem_key);`

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
	if !channel.valid() {
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

	var entries []Entry
	for rows.Next() {
		var (
			e                 Entry
			channel           string
			createdAt, sentAt int64
		)
		if err := rows.Scan(&e.ID, &channel, &e.Body, &e.IdemKey, &createdAt, &sentAt); err != nil {
			return nil, fmt.Errorf("outbox: pending scan: %w", err)
		}
		e.Channel = Channel(channel)
		e.CreatedAt = time.Unix(createdAt, 0).UTC()
		if sentAt != 0 {
			e.SentAt = time.Unix(sentAt, 0).UTC()
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("outbox: pending rows: %w", err)
	}
	return entries, nil
}

// MarkSent stamps sent_at=now for id. Idempotent: a second call for an
// already-sent id is harmless (it simply rewrites sent_at).
func (s *Store) MarkSent(now time.Time, id int64) error {
	if _, err := s.db.Exec(`UPDATE notify_outbox SET sent_at = ? WHERE id = ?`, now.Unix(), id); err != nil {
		return fmt.Errorf("outbox: mark sent %d: %w", id, err)
	}
	return nil
}
