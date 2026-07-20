package analyst

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite" // driver name "sqlite"
)

// schema is the analyst's OWN state, over its OWN state.db file (a separate
// path from the Tier-1/Tier-2 state.db — see HEIMDALL_ANALYST_STATE_DB).
// analyst_posted is the 7-day per-hyp_fp dedup cooldown ledger: it is the
// mechanism (combined with MaxPerRun) that makes a storming model unable to
// flood the bridge. CREATE TABLE IF NOT EXISTS is naturally idempotent; per
// internal/baseline's precedent this package deliberately does NOT touch
// PRAGMA user_version — that counter belongs to whichever migrator owns the
// file the analyst is pointed at, and a second migrator on the same counter
// would collide.
const schema = `
CREATE TABLE IF NOT EXISTS analyst_posted (
  hyp_fp      TEXT PRIMARY KEY,
  last_posted INTEGER NOT NULL
);`

// Store is the analyst's dedup store.
type Store struct{ db *sql.DB }

// OpenStore configures a handle to the state.db at path and ensures the
// analyst_posted table exists. WAL config mirrors internal/baseline /
// internal/ledger exactly (single-writer MaxOpenConns(1); WAL permits
// multiple single-writer handles against the same file safely if this path
// is ever shared).
func OpenStore(path string) (*Store, error) {
	dsn := "file:" + path +
		"?_pragma=journal_mode(WAL)" +
		"&_pragma=synchronous(NORMAL)" +
		"&_pragma=busy_timeout(5000)" +
		"&_pragma=foreign_keys(ON)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("analyst: open %s: %w", path, err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("analyst: create schema: %w", err)
	}
	return &Store{db: db}, nil
}

// Close closes the underlying handle.
func (s *Store) Close() error { return s.db.Close() }

// RecentlyPosted reports whether hyp_fp was posted within cooldown before
// now. A hyp_fp never seen before is, by definition, not recently posted.
func (s *Store) RecentlyPosted(now time.Time, hypFP string, cooldown time.Duration) (bool, error) {
	var lastPosted int64
	err := s.db.QueryRow(`SELECT last_posted FROM analyst_posted WHERE hyp_fp = ?`, hypFP).Scan(&lastPosted)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("analyst: recently posted %s: %w", hypFP, err)
	}
	elapsed := now.Sub(time.Unix(lastPosted, 0).UTC())
	return elapsed < cooldown, nil
}

// RecordPosted upserts last_posted=now for hyp_fp. Call ONLY after a
// successful Post — recording a fingerprint that was never actually
// delivered would let a real recurrence hide behind a phantom cooldown.
func (s *Store) RecordPosted(now time.Time, hypFP string) error {
	_, err := s.db.Exec(`
INSERT INTO analyst_posted (hyp_fp, last_posted) VALUES (?, ?)
ON CONFLICT(hyp_fp) DO UPDATE SET last_posted = excluded.last_posted`,
		hypFP, now.Unix(),
	)
	if err != nil {
		return fmt.Errorf("analyst: record posted %s: %w", hypFP, err)
	}
	return nil
}
