// Package bridge is the ACTION layer's alert-reconciliation half: it turns
// Alertmanager v4 webhooks (webhook.go) into ONE YouTrack issue per
// (group,check), reconciled every delivery, via the S6-a tracker.Tracker
// seam and its own SQLite issue ledger (store.go). reconcile.go is the pure
// engine: open/update-checklist/close plus the storm fuse that bounds
// new-issue creation to a rolling per-hour cap.
//
// This slice (S6-b) deliberately does NOT import internal/contract: the
// mute-gating decision point (Reconcile step 5b) needs only
// suppress.Authority.MatchFields' four raw strings (fingerprint, group,
// check, target) taken straight off the webhook's alert labels — there is
// no sanctioned way to build a contract.Finding composite literal outside
// internal/contract (`make lint`'s ADR-G09 gate), and minting one via
// contract.NewFinding would be both the wrong tool (that constructor is for
// EMITTING findings, with its own fingerprint/severity-cap rules) and
// unnecessary, since MatchFields reads exactly the fields already in hand.
// See the S6-b report for the full rationale.
//
// Hypothesis routing + escalation (S6-c) and the HTTP server wiring (S6-d)
// build on top of this package; neither exists yet in this slice.
//
// Design ref: design/2026-07-19-final-design.md (+ at-scale doc).
package bridge
