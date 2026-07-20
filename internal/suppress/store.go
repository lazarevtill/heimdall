package suppress

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "modernc.org/sqlite" // driver name "sqlite"
)

// schema is the runtime-mute half of the suppression authority, over the
// SAME state.db file the ledger/baseline use. DB-ownership mirrors
// internal/baseline exactly: own *sql.DB handle, identical WAL pragmas,
// single-writer MaxOpenConns(1), CREATE TABLE IF NOT EXISTS (idempotent, no
// migration counter of its own), and this package deliberately does NOT
// touch PRAGMA user_version — that counter is owned by the ledger's
// migrator.
const schema = `
CREATE TABLE IF NOT EXISTS suppressions (
  key             TEXT PRIMARY KEY,
  scope           TEXT NOT NULL,
  matcher_json    TEXT NOT NULL,
  until           TEXT NOT NULL,          -- RFC3339 or 'never'
  review_after    TEXT NOT NULL DEFAULT '',
  cumulative_days INTEGER NOT NULL DEFAULT 0,
  reason          TEXT NOT NULL,
  actor           TEXT NOT NULL,
  source          TEXT NOT NULL           -- always 'runtime' in this table
);
CREATE TABLE IF NOT EXISTS feedback (
  key   TEXT NOT NULL,
  event TEXT NOT NULL,                     -- ack|mute|noise|useful|not_useful|wontfix|fixed|auto_recovered|extend
  actor TEXT NOT NULL,
  ts    INTEGER NOT NULL
);`

// validFeedbackEvents is the closed event vocabulary RecordFeedback accepts.
var validFeedbackEvents = map[string]bool{
	"ack":            true,
	"mute":           true,
	"noise":          true,
	"useful":         true,
	"not_useful":     true,
	"wontfix":        true,
	"fixed":          true,
	"auto_recovered": true,
	"extend":         true,
}

// Store is the SQLite-backed runtime-mute half of the suppression
// authority: the notifier's Telegram buttons (S7) write here; NewAuthority
// reads ListRuntime to union it with the declarative side.
type Store struct{ db *sql.DB }

// OpenStore configures a handle to the state.db at path and ensures the
// suppressions/feedback schema exists. WAL config mirrors
// internal/baseline/internal/ledger exactly (single-writer MaxOpenConns(1);
// WAL permits multiple single-writer handles against the same file safely).
func OpenStore(path string) (*Store, error) {
	dsn := "file:" + path +
		"?_pragma=journal_mode(WAL)" +
		"&_pragma=synchronous(NORMAL)" +
		"&_pragma=busy_timeout(5000)" +
		"&_pragma=foreign_keys(ON)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("suppress: open %s: %w", path, err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("suppress: create schema: %w", err)
	}
	return &Store{db: db}, nil
}

// Close closes the underlying handle.
func (s *Store) Close() error { return s.db.Close() }

// ListRuntime returns all runtime mutes (Source=runtime), ordered by key.
// Callers filter by Active(now) as needed; this returns raw rows so
// expired/archived records stay visible to the weekly digest consumer.
func (s *Store) ListRuntime() ([]Suppression, error) {
	rows, err := s.db.Query(`
SELECT key, scope, matcher_json, until, review_after, cumulative_days, reason, actor, source
FROM suppressions ORDER BY key`)
	if err != nil {
		return nil, fmt.Errorf("suppress: list runtime: %w", err)
	}
	defer rows.Close()

	var out []Suppression
	for rows.Next() {
		var rec Suppression
		var scope, matcherJSON, source string
		if err := rows.Scan(&rec.Key, &scope, &matcherJSON, &rec.Until, &rec.ReviewAfter,
			&rec.CumulativeDays, &rec.Reason, &rec.Actor, &source); err != nil {
			return nil, fmt.Errorf("suppress: list runtime scan: %w", err)
		}
		rec.Scope = Scope(scope)
		rec.Source = Source(source)
		if err := json.Unmarshal([]byte(matcherJSON), &rec.Matcher); err != nil {
			return nil, fmt.Errorf("suppress: list runtime %s: unmarshal matcher: %w", rec.Key, err)
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("suppress: list runtime rows: %w", err)
	}
	return out, nil
}

// AddMute inserts or EXTENDS a runtime mute keyed by key, adding addDays to
// the record's cumulative_days. until selects the mode: passing the literal
// "never" produces an unbounded mute (Until="never"), which REQUIRES
// reviewAfter to be non-empty and BYPASSES the 30-day cap (its review_after
// is the accountability mechanism instead — the design: "never past the cap
// without an MR"). Any other value of until selects the dated path, where
// the persisted Until is always computed as now+addDays (RFC3339) — the
// resulting cumulative_days (existing + addDays) must not exceed 30, or the
// call is REJECTED with an error naming the cap and the row is NOT mutated.
//
// AddMute is upsert-by-key: a second call for the same key is the "extend"
// path — the existing cumulative_days is read, addDays is added on top, the
// cap is enforced against that new total, and the row is replaced via
// ON CONFLICT(key) DO UPDATE. A first call for a new key starts
// cumulative_days at addDays. The resulting record is Validated before it is
// persisted.
func (s *Store) AddMute(now time.Time, key string, scope Scope, m Matcher,
	addDays int, until, reviewAfter, reason, actor string) (Suppression, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return Suppression{}, fmt.Errorf("suppress: add mute %s: begin: %w", key, err)
	}
	defer tx.Rollback()

	var existingCumulative int
	err = tx.QueryRow(`SELECT cumulative_days FROM suppressions WHERE key = ?`, key).Scan(&existingCumulative)
	switch {
	case err == sql.ErrNoRows:
		existingCumulative = 0
	case err != nil:
		return Suppression{}, fmt.Errorf("suppress: add mute %s: read existing: %w", key, err)
	}

	var newUntil string
	if until == "never" {
		if reviewAfter == "" {
			return Suppression{}, fmt.Errorf("suppress: add mute %s: until=\"never\" requires review_after", key)
		}
		newUntil = "never"
	} else {
		newUntil = now.Add(time.Duration(addDays) * 24 * time.Hour).UTC().Format(time.RFC3339)
	}

	newCumulative := existingCumulative + addDays
	if newUntil != "never" && newCumulative > 30 {
		return Suppression{}, fmt.Errorf(
			"suppress: add mute %s: cumulative_days %d would exceed the 30-day cap (never past the cap without an MR)",
			key, newCumulative)
	}

	rec := Suppression{
		Key:            key,
		Scope:          scope,
		Matcher:        m,
		Until:          newUntil,
		ReviewAfter:    reviewAfter,
		CumulativeDays: newCumulative,
		Reason:         reason,
		Actor:          actor,
		Source:         SourceRuntime,
	}
	if err := rec.Validate(now); err != nil {
		return Suppression{}, fmt.Errorf("suppress: add mute %s: invalid record: %w", key, err)
	}

	matcherJSON, err := json.Marshal(m)
	if err != nil {
		return Suppression{}, fmt.Errorf("suppress: add mute %s: marshal matcher: %w", key, err)
	}

	if _, err := tx.Exec(`
INSERT INTO suppressions (key, scope, matcher_json, until, review_after, cumulative_days, reason, actor, source)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'runtime')
ON CONFLICT(key) DO UPDATE SET
  scope = excluded.scope, matcher_json = excluded.matcher_json, until = excluded.until,
  review_after = excluded.review_after, cumulative_days = excluded.cumulative_days,
  reason = excluded.reason, actor = excluded.actor, source = 'runtime'`,
		key, string(scope), string(matcherJSON), newUntil, reviewAfter, newCumulative, reason, actor,
	); err != nil {
		return Suppression{}, fmt.Errorf("suppress: add mute %s: upsert: %w", key, err)
	}

	if err := tx.Commit(); err != nil {
		return Suppression{}, fmt.Errorf("suppress: add mute %s: commit: %w", key, err)
	}
	return rec, nil
}

// RecordFeedback appends one feedback row. The event vocabulary is
// validated against a closed set (ack/mute/noise/useful/not_useful/wontfix/
// fixed/auto_recovered/extend); an unknown event is rejected.
func (s *Store) RecordFeedback(now time.Time, key, event, actor string) error {
	if !validFeedbackEvents[event] {
		return fmt.Errorf("suppress: record feedback %s: invalid event %q", key, event)
	}
	if _, err := s.db.Exec(
		`INSERT INTO feedback (key, event, actor, ts) VALUES (?, ?, ?, ?)`,
		key, event, actor, now.Unix(),
	); err != nil {
		return fmt.Errorf("suppress: record feedback %s: %w", key, err)
	}
	return nil
}
