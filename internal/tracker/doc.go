// Package tracker is the BRIDGE's issue-backend seam: the Tracker interface
// (FindByMarker, Open, Comment, Transition, Tag) plus the YouTrack HTTP
// implementation (youtrack.go) and the [hb:<key>] marker grammar (marker.go).
//
// The reconciliation engine (S6-b) depends on the Tracker INTERFACE only, so
// it is testable with a fake; YouTrack is the first (and, as of this slice,
// only) real backend. A marker embeds a stable key in an issue's
// summary/description so the bridge can find its own issue by full-text
// search — it never needs to persist a tracker-assigned ID to survive a
// bridge-state loss.
//
// Design ref: design/2026-07-19-final-design.md (+ at-scale doc).
package tracker
