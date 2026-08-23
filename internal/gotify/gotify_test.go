package gotify_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/lazarevtill/heimdall/internal/gotify"
)

const testToken = "AzyxTESTtoken0123456789"

// capture records what the fake server received.
type capture struct {
	path        string
	contentType string
	gotifyKey   string
	rawQuery    string
	body        map[string]any
}

func newServer(t *testing.T, status int, respBody string, got *capture) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.path = r.URL.Path
		got.rawQuery = r.URL.RawQuery
		got.contentType = r.Header.Get("Content-Type")
		got.gotifyKey = r.Header.Get("X-Gotify-Key")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &got.body)
		w.WriteHeader(status)
		_, _ = io.WriteString(w, respBody)
	}))
}

func TestSendPostsMessageWithTokenInHeaderNotURL(t *testing.T) {
	var got capture
	srv := newServer(t, http.StatusOK, `{"id":1}`, &got)
	defer srv.Close()

	c := gotify.NewClient(srv.URL, testToken, srv.Client())
	err := c.Send(context.Background(), gotify.Message{Title: "Heimdall", Body: "disk check firing", Priority: 8})
	if err != nil {
		t.Fatalf("Send: unexpected error: %v", err)
	}

	if got.path != "/message" {
		t.Errorf("path = %q, want /message", got.path)
	}
	if got.contentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got.contentType)
	}
	if got.gotifyKey != testToken {
		t.Errorf("X-Gotify-Key = %q, want the app token", got.gotifyKey)
	}
	// The token must never travel in the query string: net/http embeds the
	// full URL in its error strings, so a ?token= would leak into every
	// timeout and DNS error.
	if strings.Contains(got.rawQuery, testToken) {
		t.Errorf("token leaked into the query string: %q", got.rawQuery)
	}

	want := map[string]any{"title": "Heimdall", "message": "disk check firing", "priority": float64(8)}
	if diff := cmp.Diff(want, got.body); diff != "" {
		t.Errorf("request body mismatch (-want +got):\n%s", diff)
	}
}

// The verbatim-body contract: whatever the outbox handed over is exactly
// what goes on the wire. No trimming, no wrapping, no re-encoding.
func TestSendTransmitsBodyVerbatim(t *testing.T) {
	body := "  line one\nline two — em dash, \"quotes\", {braces}\n\n[REDACTED:gitlab-pat]  "
	var got capture
	srv := newServer(t, http.StatusOK, `{"id":1}`, &got)
	defer srv.Close()

	c := gotify.NewClient(srv.URL, testToken, srv.Client())
	if err := c.Send(context.Background(), gotify.Message{Title: "t", Body: body}); err != nil {
		t.Fatalf("Send: unexpected error: %v", err)
	}
	if got.body["message"] != body {
		t.Errorf("body was altered in transit:\n got %q\nwant %q", got.body["message"], body)
	}
}

func TestSendFailClosedOnNon2xx(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
	}{
		{"unauthorized", http.StatusUnauthorized},
		{"not found", http.StatusNotFound},
		{"server error", http.StatusInternalServerError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got capture
			srv := newServer(t, tc.status, `{"error":"nope"}`, &got)
			defer srv.Close()

			c := gotify.NewClient(srv.URL, testToken, srv.Client())
			err := c.Send(context.Background(), gotify.Message{Body: "x"})
			if err == nil {
				t.Fatalf("Send: want error for status %d, got nil", tc.status)
			}
			if !strings.Contains(err.Error(), "gotify:") {
				t.Errorf("error should name the package, got %q", err)
			}
		})
	}
}

// A failing server that echoes the token back must not put it in the error.
func TestSendScrubsTokenFromErrorText(t *testing.T) {
	var got capture
	srv := newServer(t, http.StatusUnauthorized, `{"error":"bad token `+testToken+`"}`, &got)
	defer srv.Close()

	c := gotify.NewClient(srv.URL, testToken, srv.Client())
	err := c.Send(context.Background(), gotify.Message{Body: "x"})
	if err == nil {
		t.Fatal("Send: want error, got nil")
	}
	if strings.Contains(err.Error(), testToken) {
		t.Errorf("token leaked into error text: %q", err)
	}
	if !strings.Contains(err.Error(), "[REDACTED:gotify-token]") {
		t.Errorf("want a redaction marker in %q", err)
	}
}

func TestSendFailClosedOnTransportError(t *testing.T) {
	srv := newServer(t, http.StatusOK, `{}`, &capture{})
	url := srv.URL
	srv.Close() // nothing is listening now

	c := gotify.NewClient(url, testToken, nil)
	if err := c.Send(context.Background(), gotify.Message{Body: "x"}); err == nil {
		t.Fatal("Send: want error against a closed server, got nil")
	}
}

func TestSendHonoursContextCancellation(t *testing.T) {
	var got capture
	srv := newServer(t, http.StatusOK, `{}`, &got)
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	c := gotify.NewClient(srv.URL, testToken, srv.Client())
	if err := c.Send(ctx, gotify.Message{Body: "x"}); err == nil {
		t.Fatal("Send: want error for a cancelled context, got nil")
	}
}

func TestNewClientTrimsTrailingSlash(t *testing.T) {
	var got capture
	srv := newServer(t, http.StatusOK, `{}`, &got)
	defer srv.Close()

	c := gotify.NewClient(srv.URL+"/", testToken, srv.Client())
	if err := c.Send(context.Background(), gotify.Message{Body: "x"}); err != nil {
		t.Fatalf("Send: unexpected error: %v", err)
	}
	if got.path != "/message" {
		t.Errorf("path = %q, want /message (trailing slash should be trimmed)", got.path)
	}
}
