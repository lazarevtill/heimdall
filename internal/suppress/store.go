package suppress

import (
	"database/sql"
	"encoding/json"
	"errors"
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

// ErrCapExceeded is wrapped by AddMute's refusal when a dated mute would
// push cumulative_days past the 30-day cap. Callers test it with errors.Is
// to tell "your budget is spent" apart from a store fault — the Telegram
// dispatcher toasts the difference back to the presser.
var ErrCapExceeded = errors.New("suppress: 30-day cumulative mute cap exceeded")

// maxCumulativeDays is the dated-mute cap, in whole days.
const maxCumulativeDays = 30

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
	rows, err := s.db.Query(`SELECT ` + runtimeColumns + ` FROM suppressions ORDER BY key`)
	if err != nil {
		return nil, fmt.Errorf("suppress: list runtime: %w", err)
	}
	defer rows.Close()

	var out []Suppression
	for rows.Next() {
		rec, err := scanRuntime(rows)
		if err != nil {
			return nil, fmt.Errorf("suppress: list runtime: %w", err)
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("suppress: list runtime rows: %w", err)
	}
	return out, nil
}

// runtimeColumns is the canonical column list scanRuntime decodes.
const runtimeColumns = `key, scope, matcher_json, until, review_after, cumulative_days, reason, actor, source`

// scanRuntime decodes one suppressions row selected as runtimeColumns.
func scanRuntime(row interface{ Scan(...any) error }) (Suppression, error) {
	var rec Suppression
	var scope, matcherJSON, source string
	if err := row.Scan(&rec.Key, &scope, &matcherJSON, &rec.Until, &rec.ReviewAfter,
		&rec.CumulativeDays, &rec.Reason, &rec.Actor, &source); err != nil {
		return Suppression{}, fmt.Errorf("scan: %w", err)
	}
	rec.Scope = Scope(scope)
	rec.Source = Source(source)
	if err := json.Unmarshal([]byte(matcherJSON), &rec.Matcher); err != nil {
		return Suppression{}, fmt.Errorf("%s: unmarshal matcher: %w", rec.Key, err)
	}
	return rec, nil
}

// AddMute inserts or EXTENDS a runtime mute keyed by key. until selects the
// mode.
//
// UNBOUNDED ("never"). Passing the literal "never" produces Until="never",
// which REQUIRES reviewAfter to be non-empty and BYPASSES the 30-day cap
// (its review_after is the accountability mechanism instead — the design:
// "never past the cap without an MR"); cumulative_days still grows by
// addDays, for the record.
//
// DATED (any other until value; the argument is otherwise ignored). The
// press asks for "muted until at least now+addDays", and what it costs is
// the days it ACTUALLY adds:
//
//   - no row yet, or a row whose dated Until is already before now (a
//     LAPSED mute — the previous episode is over): a fresh episode,
//     Until = now+addDays, cumulative_days = addDays;
//   - an ACTIVE dated row: Until = max(existingUntil, now+addDays), and
//     cumulative_days grows by the whole days that adds,
//     ceil((newUntil-existingUntil)/24h). A press that would not move Until
//     (a shorter button, a double-tap in the same second) changes NOTHING —
//     the row, its reason and its actor stay as they were and the existing
//     record is returned — so a shorter press can never shorten a mute and
//     never spends budget;
//   - a dated press over an unbounded ("never") row keeps the pre-cap
//     behaviour: Until = now+addDays, cumulative_days = existing + addDays.
//
// Times are compared at whole-second precision, the precision Until is
// stored at. The resulting cumulative_days must not exceed 30, or the call
// is REJECTED with an error wrapping ErrCapExceeded and the row is NOT
// mutated. So the cap bounds one continuous mute episode of a key to 30
// days; once it lapses, the key starts again.
//
// KNOWN LIMITATION: the cap is per KEY, not per silenced finding. Callers
// key their own records ("btn-<group>--<check>" from a Telegram button,
// "ui-<fingerprint>" from the console), so one finding covered by both a
// group_check mute and a fingerprint mute has two independent 30-day
// budgets. Closing that needs a per-subject ledger; it is not done here.
//
// AddMute is upsert-by-key: it never creates a second row for a key, and
// the resulting record is Validated before it is persisted. A row that
// Validates badly on read (corrupt Until) is treated as lapsed, matching
// Active's fail-safe reading of it.
func (s *Store) AddMute(now time.Time, key string, scope Scope, m Matcher,
	addDays int, until, reviewAfter, reason, actor string) (Suppression, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return Suppression{}, fmt.Errorf("suppress: add mute %s: begin: %w", key, err)
	}
	defer tx.Rollback()

	existing, err := scanRuntime(tx.QueryRow(`SELECT `+runtimeColumns+` FROM suppressions WHERE key = ?`, key))
	found := true
	switch {
	case errors.Is(err, sql.ErrNoRows):
		found = false
	case err != nil:
		return Suppression{}, fmt.Errorf("suppress: add mute %s: read existing: %w", key, err)
	}

	var (
		newUntil      string
		newCumulative int
	)
	if until == "never" {
		if reviewAfter == "" {
			return Suppression{}, fmt.Errorf("suppress: add mute %s: until=\"never\" requires review_after", key)
		}
		newUntil = "never"
		newCumulative = addDays
		if found {
			newCumulative += existing.CumulativeDays
		}
	} else {
		requested := now.Add(time.Duration(addDays) * 24 * time.Hour).UTC().Truncate(time.Second)
		newUntil = requested.Format(time.RFC3339)
		newCumulative = addDays

		if found {
			existingUntil, perr := time.Parse(time.RFC3339, existing.Until)
			switch {
			case existing.Until == "never":
				newCumulative = existing.CumulativeDays + addDays
			case perr != nil || existingUntil.Before(now):
				// Lapsed (or unreadable, which Active also treats as
				// inactive): a fresh episode — the defaults above.
			case !requested.After(existingUntil):
				// Already muted at least this long: nothing to add, so
				// nothing to write and nothing to charge.
				return existing, nil
			default:
				extra := requested.Sub(existingUntil)
				extraDays := int((extra + 24*time.Hour - 1) / (24 * time.Hour))
				newCumulative = existing.CumulativeDays + extraDays
			}
		}
		if newCumulative > maxCumulativeDays {
			return Suppression{}, fmt.Errorf(
				"suppress: add mute %s: cumulative_days %d would exceed the 30-day cap (never past the cap without an MR): %w",
				key, newCumulative, ErrCapExceeded)
		}
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

// CountFeedbackSince returns event->count for feedback rows with ts >= since
// (inclusive), across every key. A row with ts < since is excluded. Feeds
// the weekly digest's "feedback over the past week" section; the caller
// picks the window (e.g. since = now.Add(-7*24*time.Hour)).
func (s *Store) CountFeedbackSince(since time.Time) (map[string]int, error) {
	rows, err := s.db.Query(
		`SELECT event, COUNT(*) FROM feedback WHERE ts >= ? GROUP BY event`, since.Unix())
	if err != nil {
		return nil, fmt.Errorf("suppress: count feedback since: %w", err)
	}
	defer rows.Close()

	out := make(map[string]int)
	for rows.Next() {
		var event string
		var count int
		if err := rows.Scan(&event, &count); err != nil {
			return nil, fmt.Errorf("suppress: count feedback since scan: %w", err)
		}
		out[event] = count
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("suppress: count feedback since rows: %w", err)
	}
	return out, nil
}
