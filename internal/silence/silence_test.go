package silence_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lazarevtill/heimdall/internal/silence"
)

// fakeCreatedBy/fakeComment/the RFC3339 fixtures below are all placeholders;
// startsAt/endsAt are pre-formatted strings supplied by the caller (this
// test), never read from the clock by the client (ADR-G10 — no time.Now()
// under internal/).
const (
	fakeCreatedBy = "heimdall-notifier"
	fakeStartsAt  = "2026-07-20T00:00:00Z"
	fakeEndsAt    = "2026-07-20T01:00:00Z"
)

func newTestClient(t *testing.T, h http.HandlerFunc) *silence.Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return silence.NewClient(srv.URL, srv.Client())
}

func decodeBody(t *testing.T, r *http.Request) map[string]any {
	t.Helper()
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("read request body: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal request body: %v", err)
	}
	return m
}

func testSilence() silence.Silence {
	return silence.Silence{
		Matchers: []silence.Matcher{
			{Name: "alertname", Value: "DiskSmartFail", IsEqual: true},
			{Name: "instance", Value: "node-a", IsEqual: true},
		},
		StartsAt:  fakeStartsAt,
		EndsAt:    fakeEndsAt,
		CreatedBy: fakeCreatedBy,
		Comment:   "muted: known disk replacement in progress",
	}
}

// --- Create ---

func TestCreatePostsMatchersAndTimesReturnsID(t *testing.T) {
	var gotPath, gotMethod string
	var gotBody map[string]any
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		gotBody = decodeBody(t, r)
		w.Write([]byte(`{"silenceID":"11111111-2222-3333-4444-555555555555"}`))
	})

	id, err := c.Create(context.Background(), testSilence())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if id != "11111111-2222-3333-4444-555555555555" {
		t.Errorf("id = %q, want the server-assigned silenceID", id)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotPath != "/api/v2/silences" {
		t.Errorf("path = %q, want /api/v2/silences", gotPath)
	}
	if gotBody["startsAt"] != fakeStartsAt || gotBody["endsAt"] != fakeEndsAt {
		t.Errorf("startsAt/endsAt = %v/%v, want %v/%v", gotBody["startsAt"], gotBody["endsAt"], fakeStartsAt, fakeEndsAt)
	}
	if gotBody["createdBy"] != fakeCreatedBy {
		t.Errorf("createdBy = %v, want %q", gotBody["createdBy"], fakeCreatedBy)
	}
	matchers, ok := gotBody["matchers"].([]any)
	if !ok || len(matchers) != 2 {
		t.Fatalf("matchers = %v, want 2 entries", gotBody["matchers"])
	}
	m0, _ := matchers[0].(map[string]any)
	if m0["name"] != "alertname" || m0["value"] != "DiskSmartFail" {
		t.Errorf("matchers[0] = %v, want name=alertname value=DiskSmartFail", m0)
	}
	if _, present := gotBody["id"]; present {
		t.Errorf("request body has id = %v, want omitted on create", gotBody["id"])
	}
}

func TestCreateNon2xx(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("invalid matchers"))
	})
	if _, err := c.Create(context.Background(), testSilence()); err == nil {
		t.Fatal("Create: want error on 400, got nil")
	}
}

// --- List ---

func TestListDecodesArray(t *testing.T) {
	var gotPath, gotMethod string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		w.Write([]byte(`[
			{"id":"sil-1","matchers":[{"name":"alertname","value":"DiskSmartFail","isRegex":false,"isEqual":true}],
			 "startsAt":"` + fakeStartsAt + `","endsAt":"` + fakeEndsAt + `","createdBy":"` + fakeCreatedBy + `",
			 "comment":"muted","status":{"state":"active"}},
			{"id":"sil-2","matchers":[],"startsAt":"` + fakeStartsAt + `","endsAt":"` + fakeEndsAt + `",
			 "createdBy":"` + fakeCreatedBy + `","comment":"","status":{"state":"expired"}}
		]`))
	})

	sils, err := c.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if gotMethod != http.MethodGet {
		t.Errorf("method = %q, want GET", gotMethod)
	}
	if gotPath != "/api/v2/silences" {
		t.Errorf("path = %q, want /api/v2/silences", gotPath)
	}
	if len(sils) != 2 {
		t.Fatalf("len(silences) = %d, want 2", len(sils))
	}
	if sils[0].ID != "sil-1" || sils[0].EndsAt != fakeEndsAt || sils[0].CreatedBy != fakeCreatedBy {
		t.Errorf("silences[0] = %+v, want id=sil-1 endsAt=%s createdBy=%s", sils[0], fakeEndsAt, fakeCreatedBy)
	}
	if len(sils[0].Matchers) != 1 || sils[0].Matchers[0].Name != "alertname" {
		t.Errorf("silences[0].Matchers = %+v, want 1 matcher named alertname", sils[0].Matchers)
	}
	if sils[1].ID != "sil-2" {
		t.Errorf("silences[1].ID = %q, want sil-2", sils[1].ID)
	}
}

func TestListNon2xx(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	if _, err := c.List(context.Background()); err == nil {
		t.Fatal("List: want error on 500, got nil")
	}
}

// --- Delete ---

func TestDeleteHitsSilencePath(t *testing.T) {
	var gotPath, gotMethod string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		w.WriteHeader(http.StatusOK)
	})
	if err := c.Delete(context.Background(), "sil-1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if gotMethod != http.MethodDelete {
		t.Errorf("method = %q, want DELETE", gotMethod)
	}
	if gotPath != "/api/v2/silence/sil-1" {
		t.Errorf("path = %q, want /api/v2/silence/sil-1", gotPath)
	}
}

func TestDeleteNon2xx(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	if err := c.Delete(context.Background(), "sil-missing"); err == nil {
		t.Fatal("Delete: want error on 404, got nil")
	}
}
