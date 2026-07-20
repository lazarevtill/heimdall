package bridge

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite" // driver name "sqlite"
)

// schema is the bridge's own issue ledger, over the bridge's own db file
// (the same file internal/outbox's notify_outbox table lives in is a fine,
// deliberate choice: OpenStore and outbox.Open can both be pointed at the
// same path — a new "issues" table, not shared with the Tier-1/Tier-2
// engine's state.db or the analyst's state.db). CREATE TABLE IF NOT EXISTS
// is naturally idempotent; per internal/outbox/internal/baseline's
// precedent this package deliberately does NOT touch PRAGMA user_version —
// that counter belongs to whichever migrator owns the file, and a second
// migrator on the same counter would collide.
//
// The ledger is the FAST PATH / bookkeeping store (opened_at, firing_since,
// escalated, acked — none of which the tracker itself carries); the tracker
// (via FindByMarker) is the DURABLE fallback and the source of truth for
// "does an issue exist" and "does it carry heimdall-auto" (its Tags), since
// it survives a ledger loss that this SQLite file would not. See
// reconcile.go step 3.
const schema = `
CREATE TABLE IF NOT EXISTS issues (
  marker        TEXT PRIMARY KEY,
  issue_id      TEXT NOT NULL,
  grp           TEXT NOT NULL,
  check_id      TEXT NOT NULL,
  severity      TEXT NOT NULL,
  firing_since  INTEGER NOT NULL,
  opened_at     INTEGER NOT NULL,
  state         TEXT NOT NULL,
  escalated     INTEGER NOT NULL DEFAULT 0,
  acked         INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS issue_targets (
  marker      TEXT NOT NULL,
  target      TEXT NOT NULL,
  firing      INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL,
  PRIMARY KEY (marker, target)
);`

// Store is the bridge's issue ledger.
type Store struct{ db *sql.DB }

// OpenStore configures a handle to the db at path and ensures the ledger
// schema exists. WAL config mirrors internal/outbox/internal/baseline/
// internal/analyst exactly (single-writer MaxOpenConns(1); WAL permits
// multiple single-writer handles against the same file safely, which is
// what lets this share a file with internal/outbox's notify_outbox table
// if the caller chooses to).
func OpenStore(path string) (*Store, error) {
	dsn := "file:" + path +
		"?_pragma=journal_mode(WAL)" +
		"&_pragma=synchronous(NORMAL)" +
		"&_pragma=busy_timeout(5000)" +
		"&_pragma=foreign_keys(ON)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("bridge: open store %s: %w", path, err)
	}
	// Single writer: eliminates SQLITE_BUSY under concurrency entirely.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("bridge: create schema: %w", err)
	}
	return &Store{db: db}, nil
}

// Close closes the underlying handle.
func (s *Store) Close() error { return s.db.Close() }

// IssueRow is one ledger row: the bridge's own bookkeeping for a
// [hb:<group>--<check>] issue.
type IssueRow struct {
	Marker, IssueID, Group, Check, Severity string
	FiringSince, OpenedAt                   time.Time
	State                                   string // "open" | "resolved"
	Escalated, Acked                        bool
}

// GetIssue returns the ledger row for marker (found=false if none).
func (s *Store) GetIssue(marker string) (IssueRow, bool, error) {
	var (
		row                   IssueRow
		firingSince, openedAt int64
		escalated, acked      int
	)
	err := s.db.QueryRow(`
SELECT marker, issue_id, grp, check_id, severity, firing_since, opened_at, state, escalated, acked
FROM issues WHERE marker = ?`, marker,
	).Scan(
		&row.Marker, &row.IssueID, &row.Group, &row.Check, &row.Severity,
		&firingSince, &openedAt, &row.State, &escalated, &acked,
	)
	if err == sql.ErrNoRows {
		return IssueRow{}, false, nil
	}
	if err != nil {
		return IssueRow{}, false, fmt.Errorf("bridge: get issue %s: %w", marker, err)
	}
	row.FiringSince = time.Unix(firingSince, 0).UTC()
	row.OpenedAt = time.Unix(openedAt, 0).UTC()
	row.Escalated = escalated != 0
	row.Acked = acked != 0
	return row, true, nil
}

// UpsertIssue records/updates the issue row for row.Marker (insert if new,
// full overwrite of every column otherwise — the caller is expected to
// have read the prior row first via GetIssue if it needs to preserve any
// field, e.g. OpenedAt across a reconcile that keeps the issue open).
func (s *Store) UpsertIssue(row IssueRow) error {
	escalated, acked := 0, 0
	if row.Escalated {
		escalated = 1
	}
	if row.Acked {
		acked = 1
	}
	_, err := s.db.Exec(`
INSERT INTO issues (marker, issue_id, grp, check_id, severity, firing_since, opened_at, state, escalated, acked)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(marker) DO UPDATE SET
  issue_id     = excluded.issue_id,
  grp          = excluded.grp,
  check_id     = excluded.check_id,
  severity     = excluded.severity,
  firing_since = excluded.firing_since,
  opened_at    = excluded.opened_at,
  state        = excluded.state,
  escalated    = excluded.escalated,
  acked        = excluded.acked`,
		row.Marker, row.IssueID, row.Group, row.Check, row.Severity,
		row.FiringSince.Unix(), row.OpenedAt.Unix(), row.State, escalated, acked,
	)
	if err != nil {
		return fmt.Errorf("bridge: upsert issue %s: %w", row.Marker, err)
	}
	return nil
}

// SetTargets replaces the FULL checklist state for marker with
// firingByTarget (delete-then-insert inside one transaction) — the
// reconcile engine writes the complete current target set on every
// webhook, so a target absent from firingByTarget is dropped from the
// checklist entirely (it left the group).
func (s *Store) SetTargets(now time.Time, marker string, firingByTarget map[string]bool) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("bridge: set targets %s: begin: %w", marker, err)
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`DELETE FROM issue_targets WHERE marker = ?`, marker); err != nil {
		return fmt.Errorf("bridge: set targets %s: delete: %w", marker, err)
	}
	for target, firing := range firingByTarget {
		f := 0
		if firing {
			f = 1
		}
		if _, err := tx.Exec(`
INSERT INTO issue_targets (marker, target, firing, updated_at) VALUES (?, ?, ?, ?)`,
			marker, target, f, now.Unix(),
		); err != nil {
			return fmt.Errorf("bridge: set targets %s: insert %s: %w", marker, target, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("bridge: set targets %s: commit: %w", marker, err)
	}
	return nil
}

// GetTargets returns the current checklist state for marker (target ->
// firing). An unknown marker returns an empty, non-nil map and no error.
func (s *Store) GetTargets(marker string) (map[string]bool, error) {
	rows, err := s.db.Query(`SELECT target, firing FROM issue_targets WHERE marker = ?`, marker)
	if err != nil {
		return nil, fmt.Errorf("bridge: get targets %s: %w", marker, err)
	}
	defer rows.Close()

	out := map[string]bool{}
	for rows.Next() {
		var target string
		var firing int
		if err := rows.Scan(&target, &firing); err != nil {
			return nil, fmt.Errorf("bridge: get targets %s: scan: %w", marker, err)
		}
		out[target] = firing != 0
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("bridge: get targets %s: rows: %w", marker, err)
	}
	return out, nil
}

// OpensSince counts issues with opened_at >= cutoff — the storm-fuse
// rolling-window query. An issue's opened_at never moves once set (see
// UpsertIssue's caller discipline in reconcile.go), so this is a stable
// count of how many NEW issues the bridge has opened in [cutoff, now],
// regardless of whether any of them have since been resolved.
func (s *Store) OpensSince(cutoff time.Time) (int, error) {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM issues WHERE opened_at >= ?`, cutoff.Unix()).Scan(&n); err != nil {
		return 0, fmt.Errorf("bridge: opens since %s: %w", cutoff, err)
	}
	return n, nil
}

// ListOpen returns every ledger row with state="open" (the escalation
// sweep's candidate set), oldest firing_since first — so a sweep that
// errors partway through (see EscalationSweep's per-issue error handling)
// has already escalated the longest-overdue issues first.
func (s *Store) ListOpen() ([]IssueRow, error) {
	rows, err := s.db.Query(`
SELECT marker, issue_id, grp, check_id, severity, firing_since, opened_at, state, escalated, acked
FROM issues WHERE state = 'open'
ORDER BY firing_since ASC, marker ASC`)
	if err != nil {
		return nil, fmt.Errorf("bridge: list open: %w", err)
	}
	defer rows.Close()

	var out []IssueRow
	for rows.Next() {
		var (
			row                   IssueRow
			firingSince, openedAt int64
			escalated, acked      int
		)
		if err := rows.Scan(
			&row.Marker, &row.IssueID, &row.Group, &row.Check, &row.Severity,
			&firingSince, &openedAt, &row.State, &escalated, &acked,
		); err != nil {
			return nil, fmt.Errorf("bridge: list open: scan: %w", err)
		}
		row.FiringSince = time.Unix(firingSince, 0).UTC()
		row.OpenedAt = time.Unix(openedAt, 0).UTC()
		row.Escalated = escalated != 0
		row.Acked = acked != 0
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("bridge: list open: rows: %w", err)
	}
	return out, nil
}

// MarkEscalated sets escalated=1 for marker. Idempotent: a second call for
// an already-escalated marker is a harmless no-op rewrite. A marker with no
// row is silently a no-op (0 rows affected) — the caller only ever calls
// this right after reading the row via ListOpen, so this should not arise
// in practice, but it is not an error either way.
func (s *Store) MarkEscalated(marker string) error {
	if _, err := s.db.Exec(`UPDATE issues SET escalated = 1 WHERE marker = ?`, marker); err != nil {
		return fmt.Errorf("bridge: mark escalated %s: %w", marker, err)
	}
	return nil
}

// SetAcked sets acked to the given value for marker (idempotent). S6-c only
// READS acked (EscalationSweep's qualification predicate); this setter is
// provided now so S7's mute/ack feedback handler can call it without a
// further store change.
func (s *Store) SetAcked(marker string, acked bool) error {
	a := 0
	if acked {
		a = 1
	}
	if _, err := s.db.Exec(`UPDATE issues SET acked = ? WHERE marker = ?`, a, marker); err != nil {
		return fmt.Errorf("bridge: set acked %s: %w", marker, err)
	}
	return nil
}
