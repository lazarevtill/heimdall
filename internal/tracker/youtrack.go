package tracker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// issueFields is the YouTrack `fields` selector used on every read/write that
// returns an issue: idReadable to identify it, summary/description to parse
// the marker back out, customFields for State/Assignee/Type/Priority, and
// tags. `value(name,login)` covers both enum-shaped fields (State, Priority,
// Type — read via .name) and user-shaped fields (Assignee — read via
// .login); see VerifyIdentity's doc and the report for why this is the field
// shape most likely to need live adjustment.
const issueFields = "idReadable,summary,description,customFields(name,value(name,login)),tags(name)"

// markerRE extracts a "[hb:<key>]" marker embedded in an issue's
// summary/description text.
var markerRE = regexp.MustCompile(`\[hb:[a-z0-9-]{1,64}\]`)

// YouTrack implements Tracker over the YouTrack REST API. Auth is a
// permanent token (Bearer). project is the short name (e.g. "HEIM"). All
// URLs/tokens arrive here — nothing is hardcoded.
type YouTrack struct {
	baseURL string
	token   string
	project string
	httpc   *http.Client
}

// NewYouTrack returns a YouTrack client for baseURL (trailing slash
// trimmed), authenticating with token as a permanent Bearer token, scoped to
// project (the short name, e.g. "HEIM"). If httpc is nil, a default
// http.Client is used; callers SHOULD pass one with a timeout, but the
// primary deadline mechanism is the ctx passed to each call.
func NewYouTrack(baseURL, token, project string, httpc *http.Client) *YouTrack {
	if httpc == nil {
		httpc = &http.Client{}
	}
	return &YouTrack{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		project: project,
		httpc:   httpc,
	}
}

// youtrackProject is the minimal shape of GET /api/admin/projects/{id}.
type youtrackProject struct {
	ID        string `json:"id"`
	ShortName string `json:"shortName"`
}

// VerifyIdentity does GET /api/admin/projects/<project> and returns nil iff
// the endpoint answers with a project whose shortName matches the configured
// project — the design's deploy-time identity check that catches a
// misconfigured baseURL/project pointed at the wrong YouTrack instance or
// the wrong project on the right instance. Fail-closed: any
// transport/non-2xx/mismatch is an error.
func (y *YouTrack) VerifyIdentity(ctx context.Context) error {
	path := "/api/admin/projects/" + url.PathEscape(y.project) + "?fields=id,shortName"
	req, err := y.newRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return fmt.Errorf("youtrack: verify identity: %w", err)
	}
	var p youtrackProject
	if err := y.do(req, &p); err != nil {
		return fmt.Errorf("youtrack: verify identity: %w", err)
	}
	if !strings.EqualFold(p.ShortName, y.project) {
		return fmt.Errorf("youtrack: verify identity: server project shortName %q does not match configured %q", p.ShortName, y.project)
	}
	return nil
}

// youtrackCustomFieldValue is the read-side shape of a customField's value:
// enum-shaped fields (State, Priority, Type) carry Name; the Assignee field
// is user-shaped and carries Login instead.
type youtrackCustomFieldValue struct {
	Name  string `json:"name"`
	Login string `json:"login"`
}

// youtrackCustomField is the read-side shape of one entry in an issue's
// customFields array.
type youtrackCustomField struct {
	Name  string                   `json:"name"`
	Value youtrackCustomFieldValue `json:"value"`
}

// youtrackTag is the read/write shape of one tag reference.
type youtrackTag struct {
	Name string `json:"name"`
}

// youtrackIssue is the read-side shape of a YouTrack issue as returned by
// the `fields` selector in issueFields.
type youtrackIssue struct {
	IDReadable   string                `json:"idReadable"`
	Summary      string                `json:"summary"`
	Description  string                `json:"description"`
	CustomFields []youtrackCustomField `json:"customFields"`
	Tags         []youtrackTag         `json:"tags"`
}

// field returns the .name of the first customField named name, or "" if
// absent.
func (yi youtrackIssue) field(name string) string {
	for _, cf := range yi.CustomFields {
		if cf.Name == name {
			return cf.Value.Name
		}
	}
	return ""
}

// assignee returns the .login of the Assignee customField, or "" if absent
// or unassigned.
func (yi youtrackIssue) assignee() string {
	for _, cf := range yi.CustomFields {
		if cf.Name == "Assignee" {
			return cf.Value.Login
		}
	}
	return ""
}

// toIssue converts the wire shape into the package's Issue, extracting the
// marker from the summary first, then falling back to the description.
func toIssue(yi youtrackIssue) *Issue {
	tags := make([]string, 0, len(yi.Tags))
	for _, t := range yi.Tags {
		tags = append(tags, t.Name)
	}
	marker := markerRE.FindString(yi.Summary)
	if marker == "" {
		marker = markerRE.FindString(yi.Description)
	}
	return &Issue{
		ID:       yi.IDReadable,
		Summary:  yi.Summary,
		State:    yi.field("State"),
		Assignee: yi.assignee(),
		Tags:     tags,
		Marker:   marker,
	}
}

// FindByMarker searches GET /api/issues?query=project:{project} {marker}
// (marker matched as a full-text phrase — YouTrack's search finds
// "[hb:...]" literally) and parses the FIRST matching issue, or (nil, nil)
// if none.
func (y *YouTrack) FindByMarker(ctx context.Context, marker string) (*Issue, error) {
	q := "project: " + y.project + " " + marker
	path := "/api/issues?fields=" + issueFields + "&query=" + url.QueryEscape(q)
	req, err := y.newRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("youtrack: find by marker %q: %w", marker, err)
	}
	var issues []youtrackIssue
	if err := y.do(req, &issues); err != nil {
		return nil, fmt.Errorf("youtrack: find by marker %q: %w", marker, err)
	}
	if len(issues) == 0 {
		return nil, nil
	}
	return toIssue(issues[0]), nil
}

// youtrackProjectRef is the write-side {"shortName": "..."} project
// reference used when creating an issue.
type youtrackProjectRef struct {
	ShortName string `json:"shortName"`
}

// youtrackCustomFieldValueIn is the write-side value of a single/state enum
// custom field: {"name": "..."}.
type youtrackCustomFieldValueIn struct {
	Name string `json:"name"`
}

// youtrackCustomFieldIn is the write-side shape for setting one custom
// field, e.g. {"$type":"SingleEnumIssueCustomField","name":"Priority",
// "value":{"name":"Minor"}}. This is the standard form for
// SingleEnumIssueCustomField/StateIssueCustomField; it is the piece most
// likely to need adjustment against the live instance's actual custom-field
// scheme (see the report).
type youtrackCustomFieldIn struct {
	Type  string                     `json:"$type"`
	Name  string                     `json:"name"`
	Value youtrackCustomFieldValueIn `json:"value"`
}

// youtrackOpenBody is the POST /api/issues request body.
type youtrackOpenBody struct {
	Project      youtrackProjectRef      `json:"project"`
	Summary      string                  `json:"summary"`
	Description  string                  `json:"description"`
	CustomFields []youtrackCustomFieldIn `json:"customFields,omitempty"`
	Tags         []youtrackTag           `json:"tags,omitempty"`
}

// Open creates a new issue via POST /api/issues (project, summary,
// description, custom fields for Type/Priority) and returns it with its
// server-assigned ID. The marker is embedded at the end of the description
// (never the summary — summaries are user-facing short text and a bare
// "[hb:...]" suffix there would be noisy); FindByMarker's full-text search
// covers the description either way.
func (y *YouTrack) Open(ctx context.Context, req OpenRequest) (*Issue, error) {
	if req.Marker == "" {
		return nil, fmt.Errorf("youtrack: open: marker is required")
	}
	desc := req.Description
	if desc != "" {
		desc += "\n\n"
	}
	desc += req.Marker

	body := youtrackOpenBody{
		Project:     youtrackProjectRef{ShortName: y.project},
		Summary:     req.Summary,
		Description: desc,
	}
	if req.Type != "" {
		body.CustomFields = append(body.CustomFields, youtrackCustomFieldIn{
			Type: "SingleEnumIssueCustomField", Name: "Type",
			Value: youtrackCustomFieldValueIn{Name: req.Type},
		})
	}
	if req.Priority != "" {
		body.CustomFields = append(body.CustomFields, youtrackCustomFieldIn{
			Type: "SingleEnumIssueCustomField", Name: "Priority",
			Value: youtrackCustomFieldValueIn{Name: req.Priority},
		})
	}
	for _, t := range req.Tags {
		body.Tags = append(body.Tags, youtrackTag{Name: t})
	}

	httpReq, err := y.newRequest(ctx, http.MethodPost, "/api/issues?fields="+issueFields, body)
	if err != nil {
		return nil, fmt.Errorf("youtrack: open issue: %w", err)
	}
	var created youtrackIssue
	if err := y.do(httpReq, &created); err != nil {
		return nil, fmt.Errorf("youtrack: open issue: %w", err)
	}
	return toIssue(created), nil
}

// Comment appends a comment via POST /api/issues/{id}/comments {text}.
func (y *YouTrack) Comment(ctx context.Context, issueID, body string) error {
	payload := struct {
		Text string `json:"text"`
	}{Text: body}
	req, err := y.newRequest(ctx, http.MethodPost, "/api/issues/"+url.PathEscape(issueID)+"/comments", payload)
	if err != nil {
		return fmt.Errorf("youtrack: comment %s: %w", issueID, err)
	}
	if err := y.do(req, nil); err != nil {
		return fmt.Errorf("youtrack: comment %s: %w", issueID, err)
	}
	return nil
}

// Transition moves an issue to state via POST /api/issues/{id}, setting the
// State custom field. This is the standard StateIssueCustomField shape; see
// the report for the live-adjustment caveat.
func (y *YouTrack) Transition(ctx context.Context, issueID, state string) error {
	body := struct {
		CustomFields []youtrackCustomFieldIn `json:"customFields"`
	}{
		CustomFields: []youtrackCustomFieldIn{
			{Type: "StateIssueCustomField", Name: "State", Value: youtrackCustomFieldValueIn{Name: state}},
		},
	}
	req, err := y.newRequest(ctx, http.MethodPost, "/api/issues/"+url.PathEscape(issueID), body)
	if err != nil {
		return fmt.Errorf("youtrack: transition %s to %q: %w", issueID, state, err)
	}
	if err := y.do(req, nil); err != nil {
		return fmt.Errorf("youtrack: transition %s to %q: %w", issueID, state, err)
	}
	return nil
}

// Tag adds tag via POST /api/issues/{id}/tags {name}.
func (y *YouTrack) Tag(ctx context.Context, issueID, tag string) error {
	payload := youtrackTag{Name: tag}
	req, err := y.newRequest(ctx, http.MethodPost, "/api/issues/"+url.PathEscape(issueID)+"/tags", payload)
	if err != nil {
		return fmt.Errorf("youtrack: tag %s with %q: %w", issueID, tag, err)
	}
	if err := y.do(req, nil); err != nil {
		return fmt.Errorf("youtrack: tag %s with %q: %w", issueID, tag, err)
	}
	return nil
}

// newRequest builds a request against baseURL+path, marshaling body (if
// non-nil) as the JSON payload and setting the auth/content headers. It
// never issues the request.
func (y *YouTrack) newRequest(ctx context.Context, method, path string, body any) (*http.Request, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal %s %s body: %w", method, path, err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, y.baseURL+path, rdr)
	if err != nil {
		return nil, fmt.Errorf("build request %s %s: %w", method, path, err)
	}
	req.Header.Set("Authorization", "Bearer "+y.token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

// do executes req and, on a 2xx response, decodes the JSON body into out
// (skipped if out is nil). Fail-closed: a transport error, a non-2xx status
// (error carries the truncated response body), or a decode failure all
// return a non-nil error — never a silent success.
func (y *YouTrack) do(req *http.Request, out any) error {
	resp, err := y.httpc.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s %s: unexpected status %d: %s", req.Method, req.URL.Path, resp.StatusCode, bytes.TrimSpace(raw))
	}
	if out == nil {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<20))
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(out); err != nil {
		return fmt.Errorf("%s %s: decode response: %w", req.Method, req.URL.Path, err)
	}
	return nil
}
