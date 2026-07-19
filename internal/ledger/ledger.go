// Package ledger persists finding state in SQLite via modernc.org/sqlite
// (pure Go — keeps the release build CGO_ENABLED=0 and the static-binary
// guarantee; see ADR-G03). One writer connection; pragmas ride the DSN so
// every lazily opened connection is configured identically.
//
// Scope note: the ledger is WRITE-ONLY in this slice (insert/bump). State
// transitions, resolution, and findings GC arrive with the bridge/notifier
// slice — do not invent resolve semantics here.
package ledger

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite" // driver name "sqlite"

	"github.com/lazarevtill/heimdall/internal/contract"
)

const schemaVersion = 1

type Ledger struct{ db *sql.DB }

func Open(path string) (*Ledger, error) {
	dsn := "file:" + path +
		"?_pragma=journal_mode(WAL)" +
		"&_pragma=synchronous(NORMAL)" +
		"&_pragma=busy_timeout(5000)" +
		"&_pragma=foreign_keys(ON)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("ledger: open %s: %w", path, err)
	}
	// Single writer: eliminates SQLITE_BUSY under concurrency entirely.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	return &Ledger{db: db}, nil
}

func migrate(db *sql.DB) error {
	var v int
	if err := db.QueryRow("PRAGMA user_version").Scan(&v); err != nil {
		return fmt.Errorf("ledger: read user_version: %w", err)
	}
	if v >= schemaVersion {
		return nil
	}
	const schema = `
CREATE TABLE IF NOT EXISTS findings (
  fingerprint TEXT PRIMARY KEY,
  check_id    TEXT NOT NULL,
  target      TEXT NOT NULL,
  state       TEXT NOT NULL,
  severity    TEXT NOT NULL,
  first_seen  INTEGER NOT NULL,
  last_seen   INTEGER NOT NULL,
  count       INTEGER NOT NULL
);`
	if _, err := db.Exec(schema); err != nil {
		return fmt.Errorf("ledger: create schema: %w", err)
	}
	if _, err := db.Exec(fmt.Sprintf("PRAGMA user_version = %d", schemaVersion)); err != nil {
		return fmt.Errorf("ledger: set user_version: %w", err)
	}
	return nil
}

// Upsert records the run's findings: new fingerprints insert with count 1;
// recurring ones bump count and last_seen, preserving first_seen.
// Transactions stay short: diffing happens in Go, writes are one quick tx.
func (l *Ledger) Upsert(now time.Time, fs []contract.Finding) error {
	if len(fs) == 0 {
		return nil
	}
	tx, err := l.db.Begin()
	if err != nil {
		return fmt.Errorf("ledger: begin: %w", err)
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`
INSERT INTO findings (fingerprint, check_id, target, state, severity, first_seen, last_seen, count)
VALUES (?, ?, ?, ?, ?, ?, ?, 1)
ON CONFLICT(fingerprint) DO UPDATE SET
  state = excluded.state, severity = excluded.severity,
  last_seen = excluded.last_seen, count = count + 1`)
	if err != nil {
		return fmt.Errorf("ledger: prepare upsert: %w", err)
	}
	defer stmt.Close()
	ts := now.Unix()
	for _, f := range fs {
		if _, err := stmt.Exec(f.Fingerprint, f.Check, f.Target, f.State.String(), string(f.Severity), ts, ts); err != nil {
			return fmt.Errorf("ledger: upsert %s: %w", f.Fingerprint, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("ledger: commit: %w", err)
	}
	return nil
}

type Entry struct {
	Fingerprint, Check, Target, State, Severity string
	FirstSeen, LastSeen                         time.Time
	Count                                       int64
}

func (l *Ledger) Get(fp string) (Entry, bool, error) {
	var e Entry
	var first, last int64
	err := l.db.QueryRow(`SELECT fingerprint, check_id, target, state, severity, first_seen, last_seen, count
FROM findings WHERE fingerprint = ?`, fp).
		Scan(&e.Fingerprint, &e.Check, &e.Target, &e.State, &e.Severity, &first, &last, &e.Count)
	if err == sql.ErrNoRows {
		return Entry{}, false, nil
	}
	if err != nil {
		return Entry{}, false, fmt.Errorf("ledger: get %s: %w", fp, err)
	}
	e.FirstSeen = time.Unix(first, 0).UTC()
	e.LastSeen = time.Unix(last, 0).UTC()
	return e, true, nil
}

func (l *Ledger) Close() error { return l.db.Close() }
