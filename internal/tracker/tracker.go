package tracker

import "context"

// Issue is the minimal view of a tracker issue the bridge reconciles
// against.
type Issue struct {
	ID       string // tracker-internal id (YouTrack idReadable, e.g. "HEIM-42")
	Summary  string
	State    string // e.g. "Open", "Resolved" — tracker's own state names
	Assignee string // login or "" if unassigned
	Tags     []string
	Marker   string // the [hb:<key>] found in the issue, "" if none parsed
}

// OpenRequest is the payload to create a new issue.
type OpenRequest struct {
	Summary     string
	Description string   // already redacted by the caller
	Type        string   // e.g. "Task"
	Priority    string   // e.g. "Minor"
	Assignee    string   // login to assign the issue to (e.g. "lazarevtill"); "" leaves it unassigned
	Tags        []string // e.g. ["heimdall","heimdall-hypothesis"]
	Marker      string   // the [hb:<key>] to embed (in summary or description per impl)
}

// Tracker is the issue-backend seam. YouTrack is the first implementation;
// the bridge depends on this interface so its reconciliation logic is
// testable with a fake. All methods take a context for the per-call
// deadline.
type Tracker interface {
	// FindByMarker returns the issue carrying [hb:<key>], or (nil, nil) if
	// none exists. It is the duplicate-proof lookup that survives bridge
	// state loss.
	FindByMarker(ctx context.Context, marker string) (*Issue, error)
	// Open creates a new issue and returns it (with its assigned ID).
	Open(ctx context.Context, req OpenRequest) (*Issue, error)
	// Comment appends a comment (already redacted) to an issue.
	Comment(ctx context.Context, issueID, body string) error
	// Transition moves an issue to a new state (e.g. "Resolved").
	Transition(ctx context.Context, issueID, state string) error
	// Tag adds a tag (e.g. "heimdall-auto") to an issue.
	Tag(ctx context.Context, issueID, tag string) error
	// Priority sets an issue's priority (e.g. "Show-stopper", "Minor").
	Priority(ctx context.Context, issueID, priority string) error
}
