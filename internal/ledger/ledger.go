// Package ledger persists finding state in SQLite via modernc.org/sqlite
// (pure Go — keeps the release build CGO_ENABLED=0 and the static-binary
// guarantee; see ADR-G03). One writer connection; pragmas ride the DSN so
// every lazily opened connection is configured identically.
//
// The detector is the ledger's only writer. Each run records its complete
// result with RecordRun, which is also how a finding resolves: an OK
// evaluation emits no finding, so a fingerprint that a complete run did not
// produce has recovered. Findings are never deleted (no GC yet).
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

// Upsert records findings without resolving anything: new fingerprints
// insert with count 1; recurring ones bump count and last_seen, preserving
// first_seen. It suits a partial write (a test seeding one finding); the
// detector records a complete run with RecordRun instead.
func (l *Ledger) Upsert(now time.Time, fs []contract.Finding) error {
	return l.write(now, fs, false)
}

// RecordRun records one complete detector run. Every finding the run
// produced is upserted exactly as Upsert does, and every other row still
// firing or unknown is resolved to "ok": a check that evaluated OK emits no
// finding, so leaving a complete run's output IS the recovery. Without it a
// recovered finding read "firing" in the console forever, long after its
// series left heimdall.prom and Alertmanager resolved it. An empty run
// resolves everything. Both happen in one transaction, so a reader never
// sees a half-resolved ledger. first_seen and count are lifetime figures
// and survive a resolve; last_seen stays the last run that saw it non-ok.
func (l *Ledger) RecordRun(now time.Time, fs []contract.Finding) error {
	return l.write(now, fs, true)
}

// write runs the upsert, and with resolveAbsent the resolve, in one short
// transaction; diffing happens in SQL, not in Go.
func (l *Ledger) write(now time.Time, fs []contract.Finding, resolveAbsent bool) error {
	if len(fs) == 0 && !resolveAbsent {
		return nil
	}
	tx, err := l.db.Begin()
	if err != nil {
		return fmt.Errorf("ledger: begin: %w", err)
	}
	defer tx.Rollback()
	if resolveAbsent {
		// Resolve every open row, then let the upsert below set this run's
		// findings back to their real state. Inside one transaction that
		// is exactly "resolve what this run did not produce".
		ok := contract.StateOK.String()
		if _, err := tx.Exec(`UPDATE findings SET state = ? WHERE state <> ?`, ok, ok); err != nil {
			return fmt.Errorf("ledger: resolve: %w", err)
		}
	}
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

// List returns every ledger entry, most-recently-seen first. It is a pure
// read — the operator UI renders from it and must never mutate finding
// state (that authority belongs to the detector's RecordRun alone).
//
// Ordering is (last_seen DESC, fingerprint ASC): the fingerprint tiebreak
// keeps the result deterministic when several findings share a run's
// timestamp, which is the normal case since one detector run stamps them
// all identically.
func (l *Ledger) List() ([]Entry, error) {
	rows, err := l.db.Query(`
SELECT fingerprint, check_id, target, state, severity, first_seen, last_seen, count
FROM findings
ORDER BY last_seen DESC, fingerprint ASC`)
	if err != nil {
		return nil, fmt.Errorf("ledger: list: %w", err)
	}
	defer rows.Close()

	var out []Entry
	for rows.Next() {
		var (
			e           Entry
			first, last int64
		)
		if err := rows.Scan(&e.Fingerprint, &e.Check, &e.Target, &e.State, &e.Severity, &first, &last, &e.Count); err != nil {
			return nil, fmt.Errorf("ledger: list scan: %w", err)
		}
		e.FirstSeen = time.Unix(first, 0).UTC()
		e.LastSeen = time.Unix(last, 0).UTC()
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ledger: list rows: %w", err)
	}
	return out, nil
}

func (l *Ledger) Close() error { return l.db.Close() }
