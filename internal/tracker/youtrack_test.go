package tracker_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lazarevtill/heimdall/internal/tracker"
)

// fakeProject, fakeToken, fakeBaseURL are all obviously-fake fixtures (RFC
// 5737 TEST-NET-1 style hostnames are avoided in favor of the httptest
// server's own loopback URL; the project/token strings below are just
// placeholders, never real credentials).
const (
	fakeProject = "HEIM"
	fakeToken   = "perm:fake-token-0000000000" // defanged — not a real YouTrack token shape
)

func newTestYouTrack(t *testing.T, h http.HandlerFunc) (*tracker.YouTrack, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return tracker.NewYouTrack(srv.URL, fakeToken, fakeProject, srv.Client()), srv
}

func ctxWithDeadline(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func assertAuth(t *testing.T, r *http.Request) {
	t.Helper()
	if got := r.Header.Get("Authorization"); got != "Bearer "+fakeToken {
		t.Errorf("Authorization header = %q, want %q", got, "Bearer "+fakeToken)
	}
	if got := r.Header.Get("Accept"); got != "application/json" {
		t.Errorf("Accept header = %q, want application/json", got)
	}
}

// --- FindByMarker ---

func TestFindByMarkerHit(t *testing.T) {
	marker := "[hb:disk--smart-fail]"
	var gotPath, gotQuery string
	y, _ := newTestYouTrack(t, func(w http.ResponseWriter, r *http.Request) {
		assertAuth(t, r)
		gotPath = r.URL.Path
		gotQuery = r.URL.Query().Get("query")
		w.Write([]byte(`[{
			"idReadable": "HEIM-42",
			"summary": "disk smart failure on node-a",
			"description": "some evidence\n\n` + marker + `",
			"customFields": [
				{"name": "State", "value": {"name": "Open"}},
				{"name": "Assignee", "value": {"login": "opsuser"}}
			],
			"tags": [{"name": "heimdall"}, {"name": "heimdall-auto"}]
		}]`))
	})

	issue, err := y.FindByMarker(ctxWithDeadline(t), marker)
	if err != nil {
		t.Fatalf("FindByMarker: %v", err)
	}
	if issue == nil {
		t.Fatal("FindByMarker: want issue, got nil")
	}
	if issue.ID != "HEIM-42" {
		t.Errorf("ID = %q, want HEIM-42", issue.ID)
	}
	if issue.State != "Open" {
		t.Errorf("State = %q, want Open", issue.State)
	}
	if issue.Assignee != "opsuser" {
		t.Errorf("Assignee = %q, want opsuser", issue.Assignee)
	}
	if issue.Marker != marker {
		t.Errorf("Marker = %q, want %q", issue.Marker, marker)
	}
	if len(issue.Tags) != 2 || issue.Tags[0] != "heimdall" || issue.Tags[1] != "heimdall-auto" {
		t.Errorf("Tags = %v, want [heimdall heimdall-auto]", issue.Tags)
	}
	if gotPath != "/api/issues" {
		t.Errorf("path = %q, want /api/issues", gotPath)
	}
	if !strings.Contains(gotQuery, fakeProject) || !strings.Contains(gotQuery, marker) {
		t.Errorf("query = %q, want it to contain project %q and marker %q", gotQuery, fakeProject, marker)
	}
}

func TestFindByMarkerMiss(t *testing.T) {
	y, _ := newTestYouTrack(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[]`))
	})
	issue, err := y.FindByMarker(ctxWithDeadline(t), "[hb:no-such-issue]")
	if err != nil {
		t.Fatalf("FindByMarker: %v", err)
	}
	if issue != nil {
		t.Errorf("FindByMarker: want nil issue on miss, got %+v", issue)
	}
}

func TestFindByMarkerNon2xx(t *testing.T) {
	y, _ := newTestYouTrack(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	})
	if _, err := y.FindByMarker(ctxWithDeadline(t), "[hb:x]"); err == nil {
		t.Fatal("FindByMarker: want error on 500, got nil")
	}
}

// --- Open ---

func TestOpenReturnsServerAssignedID(t *testing.T) {
	marker := "[hb:t3-abc123]"
	var gotPath string
	var gotMethod string
	var gotBody map[string]any
	y, _ := newTestYouTrack(t, func(w http.ResponseWriter, r *http.Request) {
		assertAuth(t, r)
		gotPath = r.URL.Path
		gotMethod = r.Method
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", ct)
		}
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}
		if err := json.Unmarshal(raw, &gotBody); err != nil {
			t.Fatalf("unmarshal request body: %v", err)
		}
		resp := map[string]any{
			"idReadable":  "HEIM-99",
			"summary":     gotBody["summary"],
			"description": gotBody["description"],
			"customFields": []map[string]any{
				{"name": "State", "value": map[string]any{"name": "Open"}},
			},
			"tags": []map[string]any{{"name": "heimdall-hypothesis"}},
		}
		b, _ := json.Marshal(resp)
		w.Write(b)
	})

	req := tracker.OpenRequest{
		Summary:     "hypothesis: disk pressure on node-a",
		Description: "evidence goes here",
		Type:        "Task",
		Priority:    "Minor",
		Tags:        []string{"heimdall", "heimdall-hypothesis"},
		Marker:      marker,
	}
	issue, err := y.Open(ctxWithDeadline(t), req)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if issue.ID != "HEIM-99" {
		t.Errorf("ID = %q, want HEIM-99", issue.ID)
	}
	if issue.Marker != marker {
		t.Errorf("Marker = %q, want %q", issue.Marker, marker)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotPath != "/api/issues" {
		t.Errorf("path = %q, want /api/issues", gotPath)
	}
	proj, ok := gotBody["project"].(map[string]any)
	if !ok || proj["shortName"] != fakeProject {
		t.Errorf("request project = %v, want shortName %q", gotBody["project"], fakeProject)
	}
	desc, _ := gotBody["description"].(string)
	if !strings.Contains(desc, marker) {
		t.Errorf("request description = %q, want it to contain marker %q", desc, marker)
	}
	if !strings.Contains(desc, "evidence goes here") {
		t.Errorf("request description = %q, want it to contain the original description", desc)
	}
	cfs, ok := gotBody["customFields"].([]any)
	if !ok || len(cfs) != 2 {
		t.Fatalf("request customFields = %v, want 2 entries (Type, Priority)", gotBody["customFields"])
	}
}

func TestOpenRequiresMarker(t *testing.T) {
	y, _ := newTestYouTrack(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("Open: server should not be called when marker is missing")
	})
	if _, err := y.Open(ctxWithDeadline(t), tracker.OpenRequest{Summary: "no marker"}); err == nil {
		t.Fatal("Open: want error when Marker is empty, got nil")
	}
}

func TestOpenNon2xx(t *testing.T) {
	y, _ := newTestYouTrack(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("bad request"))
	})
	if _, err := y.Open(ctxWithDeadline(t), tracker.OpenRequest{Summary: "s", Marker: "[hb:x]"}); err == nil {
		t.Fatal("Open: want error on 400, got nil")
	}
}

// --- Comment / Transition / Tag ---

func TestCommentIssuesRightMethodAndPath(t *testing.T) {
	var gotPath, gotMethod string
	var gotBody map[string]any
	y, _ := newTestYouTrack(t, func(w http.ResponseWriter, r *http.Request) {
		assertAuth(t, r)
		gotPath = r.URL.Path
		gotMethod = r.Method
		raw, _ := io.ReadAll(r.Body)
		json.Unmarshal(raw, &gotBody)
		w.WriteHeader(http.StatusOK)
	})
	if err := y.Comment(ctxWithDeadline(t), "HEIM-1", "a redacted comment body"); err != nil {
		t.Fatalf("Comment: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotPath != "/api/issues/HEIM-1/comments" {
		t.Errorf("path = %q, want /api/issues/HEIM-1/comments", gotPath)
	}
	if gotBody["text"] != "a redacted comment body" {
		t.Errorf("body text = %v, want %q", gotBody["text"], "a redacted comment body")
	}
}

func TestCommentNon2xx(t *testing.T) {
	y, _ := newTestYouTrack(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("forbidden"))
	})
	if err := y.Comment(ctxWithDeadline(t), "HEIM-1", "body"); err == nil {
		t.Fatal("Comment: want error on 403, got nil")
	}
}

func TestTransitionIssuesRightMethodAndPath(t *testing.T) {
	var gotPath, gotMethod string
	var gotBody map[string]any
	y, _ := newTestYouTrack(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		raw, _ := io.ReadAll(r.Body)
		json.Unmarshal(raw, &gotBody)
		w.WriteHeader(http.StatusOK)
	})
	if err := y.Transition(ctxWithDeadline(t), "HEIM-1", "Resolved"); err != nil {
		t.Fatalf("Transition: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotPath != "/api/issues/HEIM-1" {
		t.Errorf("path = %q, want /api/issues/HEIM-1", gotPath)
	}
	cfs, ok := gotBody["customFields"].([]any)
	if !ok || len(cfs) != 1 {
		t.Fatalf("request customFields = %v, want 1 entry", gotBody["customFields"])
	}
	cf, _ := cfs[0].(map[string]any)
	if cf["name"] != "State" {
		t.Errorf("customFields[0].name = %v, want State", cf["name"])
	}
	val, _ := cf["value"].(map[string]any)
	if val["name"] != "Resolved" {
		t.Errorf("customFields[0].value.name = %v, want Resolved", val["name"])
	}
}

func TestTransitionNon2xx(t *testing.T) {
	y, _ := newTestYouTrack(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	if err := y.Transition(ctxWithDeadline(t), "HEIM-1", "Resolved"); err == nil {
		t.Fatal("Transition: want error on 500, got nil")
	}
}

func TestTagIssuesRightMethodAndPath(t *testing.T) {
	var gotPath, gotMethod string
	var gotBody map[string]any
	y, _ := newTestYouTrack(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		raw, _ := io.ReadAll(r.Body)
		json.Unmarshal(raw, &gotBody)
		w.WriteHeader(http.StatusOK)
	})
	if err := y.Tag(ctxWithDeadline(t), "HEIM-1", "heimdall-auto"); err != nil {
		t.Fatalf("Tag: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotPath != "/api/issues/HEIM-1/tags" {
		t.Errorf("path = %q, want /api/issues/HEIM-1/tags", gotPath)
	}
	if gotBody["name"] != "heimdall-auto" {
		t.Errorf("body name = %v, want heimdall-auto", gotBody["name"])
	}
}

func TestTagNon2xx(t *testing.T) {
	y, _ := newTestYouTrack(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	if err := y.Tag(ctxWithDeadline(t), "HEIM-1", "heimdall-auto"); err == nil {
		t.Fatal("Tag: want error on 404, got nil")
	}
}

// --- VerifyIdentity ---

func TestVerifyIdentityOK(t *testing.T) {
	var gotPath string
	y, _ := newTestYouTrack(t, func(w http.ResponseWriter, r *http.Request) {
		assertAuth(t, r)
		gotPath = r.URL.Path
		w.Write([]byte(`{"id": "0-1", "shortName": "` + fakeProject + `"}`))
	})
	if err := y.VerifyIdentity(ctxWithDeadline(t)); err != nil {
		t.Fatalf("VerifyIdentity: %v", err)
	}
	if gotPath != "/api/admin/projects/"+fakeProject {
		t.Errorf("path = %q, want /api/admin/projects/%s", gotPath, fakeProject)
	}
}

func TestVerifyIdentityMismatch(t *testing.T) {
	y, _ := newTestYouTrack(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"id": "0-1", "shortName": "WRONG"}`))
	})
	if err := y.VerifyIdentity(ctxWithDeadline(t)); err == nil {
		t.Fatal("VerifyIdentity: want error on project mismatch, got nil")
	}
}

func TestVerifyIdentityNon2xx(t *testing.T) {
	y, _ := newTestYouTrack(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	if err := y.VerifyIdentity(ctxWithDeadline(t)); err == nil {
		t.Fatal("VerifyIdentity: want error on 401, got nil")
	}
}

func TestVerifyIdentityTransportError(t *testing.T) {
	// A base URL nothing listens on: 127.0.0.1 port 1 is reserved/unused.
	y := tracker.NewYouTrack("http://127.0.0.1:1", fakeToken, fakeProject, &http.Client{Timeout: 2 * time.Second})
	if err := y.VerifyIdentity(ctxWithDeadline(t)); err == nil {
		t.Fatal("VerifyIdentity: want error on unreachable URL, got nil")
	}
}
