// Package suppress is Heimdall's single suppression authority governing all
// three tiers (Tier-1 pages, Tier-2 graduated alerts + digest annotations,
// Tier-3 hypotheses). It is the union of two sources: durable declarative
// suppressions authored as YAML in IaC and rendered by tofu to a JSON file
// this package reads (encoding/json — no YAML parser here), and runtime
// mutes written by the notifier's Telegram buttons into this package's own
// SQLite table over the engine state.db.
//
// THE core invariant: suppression silences NOTIFICATION, never DETECTION. A
// muted finding keeps its metric series (no false send_resolved), stays
// counted, and remains in the digest annotated suppressed(until/by/why).
// This package therefore never deletes, hides, or resolves anything — it
// only answers questions ("is this finding/hypothesis currently suppressed,
// by which record?", "what are the active suppressions (for digest
// annotation)?", "what silences should exist downstream (for the notifier to
// materialize into Alertmanager)?"). Callers decide what to do with those
// answers; the series always stays.
//
// Design ref: design/2026-07-19-final-design.md (+ at-scale doc), §suppression.
package suppress
