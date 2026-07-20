// Package baseline is Heimdall's Tier-2 feature/warm-up/template store: a
// SQLite-backed baseline over the SAME state.db file the ledger uses.
//
// DB-ownership: this package opens its own *sql.DB handle to the same path,
// configured identically to the ledger (WAL, synchronous(NORMAL),
// busy_timeout(5000), foreign_keys(ON), MaxOpenConns(1)). There is one engine
// DB; WAL permits multiple single-writer handles against the same file
// safely. Tables here are created with CREATE TABLE IF NOT EXISTS, which is
// naturally idempotent and needs no migration counter of its own — this
// package deliberately does NOT touch PRAGMA user_version, since that
// counter is owned by the ledger's migrator and a second migrator on the
// same counter would collide.
//
// No time.Now() anywhere in this package: every function that needs "now"
// takes an injected `now time.Time` parameter (ADR-G10).
package baseline

import (
	"database/sql"
	"fmt"
	"sort"
	"time"

	_ "modernc.org/sqlite" // driver name "sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS features (
  ts      INTEGER NOT NULL,
  entity  TEXT NOT NULL,
  target  TEXT NOT NULL,
  feature TEXT NOT NULL,
  value   REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_features_lookup ON features(target, feature, ts);

CREATE TABLE IF NOT EXISTS warmup (
  check_id   TEXT NOT NULL,
  target     TEXT NOT NULL,
  enabled_at INTEGER NOT NULL,
  PRIMARY KEY (check_id, target)
);

CREATE TABLE IF NOT EXISTS template_baseline (
  host          TEXT NOT NULL,
  app           TEXT NOT NULL,
  template_hash TEXT NOT NULL,
  first_seen    INTEGER NOT NULL,
  last_seen     INTEGER NOT NULL,
  ewma          REAL NOT NULL,
  PRIMARY KEY (host, app, template_hash)
);`

// Store is the Tier-2 baseline store.
type Store struct{ db *sql.DB }

// Open configures a handle to the state.db at path and ensures the Tier-2
// schema exists. It does not touch PRAGMA user_version (see package doc).
func Open(path string) (*Store, error) {
	dsn := "file:" + path +
		"?_pragma=journal_mode(WAL)" +
		"&_pragma=synchronous(NORMAL)" +
		"&_pragma=busy_timeout(5000)" +
		"&_pragma=foreign_keys(ON)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("baseline: open %s: %w", path, err)
	}
	// Single writer: eliminates SQLITE_BUSY under concurrency entirely.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("baseline: create schema: %w", err)
	}
	return &Store{db: db}, nil
}

// Close closes the underlying handle.
func (s *Store) Close() error { return s.db.Close() }

// RecordFeature appends one observed feature value at now.
func (s *Store) RecordFeature(now time.Time, entity, target, feature string, value float64) error {
	_, err := s.db.Exec(
		`INSERT INTO features (ts, entity, target, feature, value) VALUES (?, ?, ?, ?, ?)`,
		now.Unix(), entity, target, feature, value,
	)
	if err != nil {
		return fmt.Errorf("baseline: record feature %s/%s: %w", target, feature, err)
	}
	return nil
}

// Quantile returns the q-quantile (0<=q<=1) of feature values for
// (target,feature) observed within [now-window, now]. ok is false when there
// are zero rows in range (the caller must treat "no baseline" as
// baseline_warming / unknown, never as calm). n is the sample count used.
// Algorithm: type-7 linear interpolation between closest ranks (the
// numpy/Go-stdlib-conventional default) over the ascending-sorted values.
func (s *Store) Quantile(now time.Time, target, feature string, window time.Duration, q float64) (value float64, n int, ok bool, err error) {
	from := now.Add(-window).Unix()
	to := now.Unix()
	rows, err := s.db.Query(
		`SELECT value FROM features WHERE target=? AND feature=? AND ts>=? AND ts<=? ORDER BY value ASC`,
		target, feature, from, to,
	)
	if err != nil {
		return 0, 0, false, fmt.Errorf("baseline: quantile query %s/%s: %w", target, feature, err)
	}
	defer rows.Close()
	var values []float64
	for rows.Next() {
		var v float64
		if err := rows.Scan(&v); err != nil {
			return 0, 0, false, fmt.Errorf("baseline: quantile scan %s/%s: %w", target, feature, err)
		}
		values = append(values, v)
	}
	if err := rows.Err(); err != nil {
		return 0, 0, false, fmt.Errorf("baseline: quantile rows %s/%s: %w", target, feature, err)
	}
	n = len(values)
	if n == 0 {
		return 0, 0, false, nil
	}
	if n == 1 {
		return values[0], 1, true, nil
	}
	if q < 0 {
		q = 0
	}
	if q > 1 {
		q = 1
	}
	// values arrive pre-sorted ascending from the query's ORDER BY, but sort
	// defensively — driver/collation behavior across value types is not a
	// contract worth trusting blindly here.
	sort.Float64s(values)
	h := float64(n-1) * q
	lo := int(h)
	if lo >= n-1 {
		return values[n-1], n, true, nil
	}
	frac := h - float64(lo)
	value = values[lo] + frac*(values[lo+1]-values[lo])
	return value, n, true, nil
}

// PurgeFeaturesOlderThan deletes feature rows with ts < cutoff; returns rows
// deleted.
func (s *Store) PurgeFeaturesOlderThan(cutoff time.Time) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM features WHERE ts < ?`, cutoff.Unix())
	if err != nil {
		return 0, fmt.Errorf("baseline: purge features: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("baseline: purge features rows affected: %w", err)
	}
	return n, nil
}

// MarkEnabled records the first time (check_id,target) began collecting a
// baseline. Idempotent: keeps the EARLIEST enabled_at (a later call never
// moves it forward).
func (s *Store) MarkEnabled(now time.Time, checkID, target string) error {
	_, err := s.db.Exec(`
INSERT INTO warmup (check_id, target, enabled_at) VALUES (?, ?, ?)
ON CONFLICT(check_id, target) DO UPDATE SET
  enabled_at = MIN(enabled_at, excluded.enabled_at)`,
		checkID, target, now.Unix(),
	)
	if err != nil {
		return fmt.Errorf("baseline: mark enabled %s/%s: %w", checkID, target, err)
	}
	return nil
}

// Warming reports whether (check_id,target) is still inside the warm-up
// window (now - enabled_at < warmDur). A (check_id,target) that was never
// MarkEnabled'd is treated as warming=true (fail-closed: no baseline trust
// yet). This is what re-arms the 7-day warm-up automatically after a
// state.db restore drops the warmup table.
func (s *Store) Warming(now time.Time, checkID, target string, warmDur time.Duration) (bool, error) {
	var enabledAt int64
	err := s.db.QueryRow(
		`SELECT enabled_at FROM warmup WHERE check_id=? AND target=?`,
		checkID, target,
	).Scan(&enabledAt)
	if err == sql.ErrNoRows {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("baseline: warming %s/%s: %w", checkID, target, err)
	}
	elapsed := now.Sub(time.Unix(enabledAt, 0).UTC())
	return elapsed < warmDur, nil
}

// Template is one row of template_baseline.
type Template struct {
	Host, App, Hash     string
	FirstSeen, LastSeen time.Time
	EWMA                float64
}

// UpsertTemplate records a template observation of `count` occurrences at
// now. New (host,app,hash): inserts first_seen=last_seen=now, ewma=count,
// isNew=true. Existing: last_seen=now, ewma = alpha*count + (1-alpha)*ewma,
// isNew=false. Returns the post-update row. 0<alpha<=1.
func (s *Store) UpsertTemplate(now time.Time, host, app, hash string, count, alpha float64) (tmpl Template, isNew bool, err error) {
	tx, err := s.db.Begin()
	if err != nil {
		return Template{}, false, fmt.Errorf("baseline: upsert template begin: %w", err)
	}
	defer tx.Rollback()

	var firstSeen, lastSeen int64
	var ewma float64
	err = tx.QueryRow(
		`SELECT first_seen, last_seen, ewma FROM template_baseline WHERE host=? AND app=? AND template_hash=?`,
		host, app, hash,
	).Scan(&firstSeen, &lastSeen, &ewma)
	switch {
	case err == sql.ErrNoRows:
		isNew = true
		firstSeen = now.Unix()
		lastSeen = now.Unix()
		ewma = count
		if _, err := tx.Exec(
			`INSERT INTO template_baseline (host, app, template_hash, first_seen, last_seen, ewma) VALUES (?, ?, ?, ?, ?, ?)`,
			host, app, hash, firstSeen, lastSeen, ewma,
		); err != nil {
			return Template{}, false, fmt.Errorf("baseline: upsert template insert %s/%s/%s: %w", host, app, hash, err)
		}
	case err != nil:
		return Template{}, false, fmt.Errorf("baseline: upsert template select %s/%s/%s: %w", host, app, hash, err)
	default:
		isNew = false
		lastSeen = now.Unix()
		ewma = alpha*count + (1-alpha)*ewma
		if _, err := tx.Exec(
			`UPDATE template_baseline SET last_seen=?, ewma=? WHERE host=? AND app=? AND template_hash=?`,
			lastSeen, ewma, host, app, hash,
		); err != nil {
			return Template{}, false, fmt.Errorf("baseline: upsert template update %s/%s/%s: %w", host, app, hash, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return Template{}, false, fmt.Errorf("baseline: upsert template commit %s/%s/%s: %w", host, app, hash, err)
	}
	return Template{
		Host:      host,
		App:       app,
		Hash:      hash,
		FirstSeen: time.Unix(firstSeen, 0).UTC(),
		LastSeen:  time.Unix(lastSeen, 0).UTC(),
		EWMA:      ewma,
	}, isNew, nil
}

// PurgeTemplatesOlderThan deletes template rows with last_seen < cutoff;
// returns rows deleted.
func (s *Store) PurgeTemplatesOlderThan(cutoff time.Time) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM template_baseline WHERE last_seen < ?`, cutoff.Unix())
	if err != nil {
		return 0, fmt.Errorf("baseline: purge templates: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("baseline: purge templates rows affected: %w", err)
	}
	return n, nil
}
