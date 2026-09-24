// Package bridge is the ACTION layer's alert-reconciliation half: it turns
// Alertmanager v4 webhooks (webhook.go) into ONE YouTrack issue per
// (group,check), reconciled every delivery, via the S6-a tracker.Tracker
// seam and its own SQLite issue ledger (store.go). reconcile.go is the pure
// engine: open/update-checklist/close plus the storm fuse that bounds
// new-issue creation to a rolling per-hour cap.
//
// S6-b deliberately did NOT import internal/contract: the mute-gating
// decision point (Reconcile step 5b) needs only
// suppress.Authority.MatchFields' four raw strings (fingerprint, group,
// check, target) taken straight off the webhook's alert labels — there is
// no sanctioned way to build a contract.Finding composite literal outside
// internal/contract (`make lint`'s ADR-G09 gate), and minting one via
// contract.NewFinding would be both the wrong tool (that constructor is for
// EMITTING findings, with its own fingerprint/severity-cap rules) and
// unnecessary, since MatchFields reads exactly the fields already in hand.
// See the S6-b report for the full rationale.
//
// S6-c (hypothesis.go, escalate.go) adds the /hypothesis ingress and the
// periodic escalation sweep. hypothesis.go DOES import internal/contract —
// for contract.HypothesisFinding (arrives via json.Unmarshal, never a
// composite literal), contract.ValidFingerprint and the HypMax* bounds —
// but still never constructs a contract.Finding composite literal; the
// ADR-G09 gate is unaffected. The hypothesis path (HandleHypothesis) is
// structurally unable to page (G1): its only side effects are
// outbox.EnqueueOrRearm(ChannelAnalyst, ...) and, optionally,
// tracker.Open(...) a Task-priority ticket — never ChannelMain, never
// Transition/Priority.
//
// egress.go is the ONE sanitising path for every free-text field the bridge
// sends to YouTrack or the outbox: fail-closed redaction with a failure
// count (invariant 3), then @-mention neutralising; log-derived evidence is
// additionally fenced in issue bodies.
//
// The HTTP server (cmd/heimdall-bridge) serialises Reconcile and
// HandleHypothesis: both are check-then-act against the tracker and are not
// safe to run concurrently.
//
// Design ref: design/2026-07-19-final-design.md (+ at-scale doc).
package bridge
