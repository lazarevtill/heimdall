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
);

CREATE TABLE IF NOT EXISTS issue_opens (
  marker     TEXT NOT NULL,
  issue_id   TEXT NOT NULL,
  opened_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS issue_opens_opened_at ON issue_opens (opened_at);`

// opensRetention is how long an issue_opens row is kept. The storm fuse and
// the console look back one hour; a day leaves room without letting an
// append-only table grow for ever.
const opensRetention = 24 * time.Hour

// autoTagPendingColumn is added to an EXISTING issues table by OpenStore
// (ALTER TABLE ... ADD COLUMN, guarded by a pragma_table_info check) rather
// than declared in schema above, because a ledger created before it existed
// must gain it too — and, per this package's no-user_version rule, an
// idempotent guarded ALTER is the migration. Its DEFAULT 0 is the correct
// value for every pre-existing row: those issues were either fully tagged
// at open or deliberately de-tagged by a human, and neither must be touched.
const autoTagPendingColumn = "auto_tag_pending"

// Ledger states (IssueRow.State). The ledger's state tracks the GROUP's
// episode, not the tracker's issue state: "resolved" means the group
// recovered, whether or not a human still holds the issue open.
const (
	// StateOpening is the intent row Reconcile writes BEFORE asking the
	// tracker to create an issue, so a crash between the tracker's create
	// and the ledger write is recognisable on the next delivery (the issue
	// exists, the row says the bridge was creating it). Never a candidate
	// for escalation (ListOpen skips it).
	StateOpening = "opening"
	// StateOpen: the group is firing and its issue is known.
	StateOpen = "open"
	// StateResolved: the group recovered. The next firing is a NEW episode.
	StateResolved = "resolved"
)

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
	if err := ensureColumn(db, "issues", autoTagPendingColumn, "INTEGER NOT NULL DEFAULT 0"); err != nil {
		db.Close()
		return nil, fmt.Errorf("bridge: migrate schema: %w", err)
	}
	if err := backfillIssueOpens(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("bridge: migrate schema: %w", err)
	}
	return &Store{db: db}, nil
}

// backfillIssueOpens copies into issue_opens the issues a bridge created
// before issue_opens existed. Without it an upgrade forgot every issue opened
// in the hour before the restart, and a storm in progress got a fresh full
// MaxPerHour batch. It takes every created issue (issue_id set; an
// "opening" intent row created nothing) opened within opensRetention of the
// newest open, which is the same window RecordOpened keeps, so a row it has
// pruned is never copied back. A (marker, issue_id) already present is
// skipped, which makes it idempotent: the bridge and the console both run it
// on every open, and it is one statement, so two openers cannot both insert.
func backfillIssueOpens(db *sql.DB) error {
	_, err := db.Exec(`
INSERT INTO issue_opens (marker, issue_id, opened_at)
SELECT i.marker, i.issue_id, i.opened_at FROM issues i
WHERE i.issue_id <> ''
  AND i.opened_at >= (SELECT MAX(opened_at) FROM issues) - ?
  AND NOT EXISTS (SELECT 1 FROM issue_opens o WHERE o.marker = i.marker AND o.issue_id = i.issue_id)`,
		int64(opensRetention/time.Second))
	if err != nil {
		return fmt.Errorf("backfill issue_opens: %w", err)
	}
	return nil
}

// ensureColumn adds column to table if it is not already there. Two
// processes opening the same file (the bridge and the console both call
// OpenStore) can race the ALTER; the loser's "duplicate column" failure is
// resolved by re-checking rather than by matching error text.
func ensureColumn(db *sql.DB, table, column, decl string) error {
	has := func() (bool, error) {
		var n int
		err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info(?) WHERE name = ?`, table, column).Scan(&n)
		return n > 0, err
	}
	ok, err := has()
	if err != nil {
		return fmt.Errorf("inspect %s.%s: %w", table, column, err)
	}
	if ok {
		return nil
	}
	if _, alterErr := db.Exec(`ALTER TABLE ` + table + ` ADD COLUMN ` + column + ` ` + decl); alterErr != nil {
		if ok, err := has(); err == nil && ok {
			return nil // a concurrent opener added it first
		}
		return fmt.Errorf("add %s.%s: %w", table, column, alterErr)
	}
	return nil
}

// Close closes the underlying handle.
func (s *Store) Close() error { return s.db.Close() }

// IssueRow is one ledger row: the bridge's own bookkeeping for a
// [hb:<group>--<check>] issue.
type IssueRow struct {
	Marker, IssueID, Group, Check, Severity string
	FiringSince, OpenedAt                   time.Time
	State                                   string // StateOpening | StateOpen | StateResolved
	Escalated, Acked                        bool
	// AutoTagPending marks an issue the BRIDGE created whose ownership tags
	// ("heimdall", "heimdall-auto") are not yet known to be applied — the
	// tracker's create succeeded but tagging failed, or the process died in
	// between. Reconcile finishes the tagging on the next delivery and
	// clears it. Only this flag distinguishes "never got its tag" from "a
	// human removed the tag to take ownership", which must be respected.
	AutoTagPending bool
}

// issueColumns is the canonical column list every issues SELECT uses, in
// scanIssue's order.
const issueColumns = `marker, issue_id, grp, check_id, severity, firing_since, opened_at, state, escalated, acked, auto_tag_pending`

// scanIssue decodes one row selected with issueColumns.
func scanIssue(scan func(...any) error) (IssueRow, error) {
	var (
		row                          IssueRow
		firingSince, openedAt        int64
		escalated, acked, tagPending int
	)
	if err := scan(
		&row.Marker, &row.IssueID, &row.Group, &row.Check, &row.Severity,
		&firingSince, &openedAt, &row.State, &escalated, &acked, &tagPending,
	); err != nil {
		return IssueRow{}, err
	}
	row.FiringSince = time.Unix(firingSince, 0).UTC()
	row.OpenedAt = time.Unix(openedAt, 0).UTC()
	row.Escalated = escalated != 0
	row.Acked = acked != 0
	row.AutoTagPending = tagPending != 0
	return row, nil
}

// b2i is SQLite's boolean encoding.
func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// GetIssue returns the ledger row for marker (found=false if none).
func (s *Store) GetIssue(marker string) (IssueRow, bool, error) {
	row, err := scanIssue(s.db.QueryRow(`SELECT `+issueColumns+` FROM issues WHERE marker = ?`, marker).Scan)
	if err == sql.ErrNoRows {
		return IssueRow{}, false, nil
	}
	if err != nil {
		return IssueRow{}, false, fmt.Errorf("bridge: get issue %s: %w", marker, err)
	}
	return row, true, nil
}

// UpsertIssue records/updates the issue row for row.Marker: insert if new
// (every column from row), otherwise overwrite every column Reconcile owns —
// but NEVER escalated or acked. Those two are written by other actors
// (EscalationSweep's MarkEscalated, an ack's SetAcked) that run
// concurrently with Reconcile; a read-modify-write here would race them and
// could reset escalated=0 behind the sweep's back, re-escalating an issue
// that already had its one re-ping. The ONLY sanctioned reset is a new
// episode, via StartEpisode. The caller is still expected to have read the
// prior row via GetIssue if it needs to preserve a field it does own (e.g.
// OpenedAt across a reconcile that keeps the issue open).
func (s *Store) UpsertIssue(row IssueRow) error {
	if err := s.upsert(row, false); err != nil {
		return fmt.Errorf("bridge: upsert issue %s: %w", row.Marker, err)
	}
	return nil
}

// StartEpisode is UpsertIssue for the first row of a NEW episode of the
// group: a first-ever open, a re-open after the previous issue resolved,
// or a re-fire after the ledger recorded the group as recovered. It
// overwrites every column AND resets escalated/acked to 0 — the previous
// episode's escalation (and its one re-ping) says nothing about this one.
func (s *Store) StartEpisode(row IssueRow) error {
	row.Escalated, row.Acked = false, false
	if err := s.upsert(row, true); err != nil {
		return fmt.Errorf("bridge: start episode %s: %w", row.Marker, err)
	}
	return nil
}

// RecordOpened is UpsertIssue for the row of an issue the bridge has just
// CREATED in the tracker. It also appends the open to issue_opens, in the
// same transaction, which is what the storm fuse counts. The issues table
// has one row per marker and each new episode overwrites its opened_at, so
// counting there saw one flapping group opening a fresh issue every few
// minutes as a single open, and the fuse never tripped. Rows older than
// opensRetention are pruned here.
func (s *Store) RecordOpened(row IssueRow) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("bridge: record opened %s: begin: %w", row.Marker, err)
	}
	defer tx.Rollback()
	if err := upsertIssue(tx, row, false); err != nil {
		return fmt.Errorf("bridge: record opened %s: %w", row.Marker, err)
	}
	at := row.OpenedAt.Unix()
	if _, err := tx.Exec(`INSERT INTO issue_opens (marker, issue_id, opened_at) VALUES (?, ?, ?)`,
		row.Marker, row.IssueID, at); err != nil {
		return fmt.Errorf("bridge: record opened %s: append: %w", row.Marker, err)
	}
	if _, err := tx.Exec(`DELETE FROM issue_opens WHERE opened_at < ?`,
		row.OpenedAt.Add(-opensRetention).Unix()); err != nil {
		return fmt.Errorf("bridge: record opened %s: prune: %w", row.Marker, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("bridge: record opened %s: commit: %w", row.Marker, err)
	}
	return nil
}

func (s *Store) upsert(row IssueRow, resetFlags bool) error {
	return upsertIssue(s.db, row, resetFlags)
}

// execer is what upsertIssue needs: a *sql.DB or a *sql.Tx.
type execer interface {
	Exec(query string, args ...any) (sql.Result, error)
}

func upsertIssue(db execer, row IssueRow, resetFlags bool) error {
	flagUpdate := ""
	if resetFlags {
		flagUpdate = `,
  escalated        = excluded.escalated,
  acked            = excluded.acked`
	}
	_, err := db.Exec(`
INSERT INTO issues (`+issueColumns+`)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(marker) DO UPDATE SET
  issue_id         = excluded.issue_id,
  grp              = excluded.grp,
  check_id         = excluded.check_id,
  severity         = excluded.severity,
  firing_since     = excluded.firing_since,
  opened_at        = excluded.opened_at,
  state            = excluded.state,
  auto_tag_pending = excluded.auto_tag_pending`+flagUpdate,
		row.Marker, row.IssueID, row.Group, row.Check, row.Severity,
		row.FiringSince.Unix(), row.OpenedAt.Unix(), row.State,
		b2i(row.Escalated), b2i(row.Acked), b2i(row.AutoTagPending),
	)
	return err
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

// OpensSince counts the issues the bridge created at or after cutoff: the
// storm fuse's rolling-window query. It counts issue_opens (one row per
// created issue, see RecordOpened), not markers, so a group that resolves
// and re-fires counts each new issue it opens. An open the tracker refused
// created nothing and is not counted.
func (s *Store) OpensSince(cutoff time.Time) (int, error) {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM issue_opens WHERE opened_at >= ?`, cutoff.Unix()).Scan(&n); err != nil {
		return 0, fmt.Errorf("bridge: opens since %s: %w", cutoff, err)
	}
	return n, nil
}

// ListOpen returns every ledger row with state="open" (the escalation
// sweep's candidate set), oldest firing_since first — so the sweep reaches
// the longest-overdue issues first. StateOpening intent rows are excluded:
// no issue is known for them yet.
func (s *Store) ListOpen() ([]IssueRow, error) {
	rows, err := s.db.Query(`
SELECT `+issueColumns+`
FROM issues WHERE state = ?
ORDER BY firing_since ASC, marker ASC`, StateOpen)
	if err != nil {
		return nil, fmt.Errorf("bridge: list open: %w", err)
	}
	defer rows.Close()

	var out []IssueRow
	for rows.Next() {
		row, err := scanIssue(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("bridge: list open: scan: %w", err)
		}
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
	if _, err := s.db.Exec(`UPDATE issues SET acked = ? WHERE marker = ?`, b2i(acked), marker); err != nil {
		return fmt.Errorf("bridge: set acked %s: %w", marker, err)
	}
	return nil
}
