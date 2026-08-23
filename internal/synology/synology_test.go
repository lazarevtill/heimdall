package synology_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/lazarevtill/heimdall/internal/synology"
)

const testTokenValue = "SYNOtoken0123456789abcdef"

type capture struct {
	contentType string
	rawBody     string
	payload     map[string]any
}

func newServer(t *testing.T, status int, respBody string, got *capture) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.contentType = r.Header.Get("Content-Type")
		raw, _ := io.ReadAll(r.Body)
		got.rawBody = string(raw)
		if vals, err := url.ParseQuery(got.rawBody); err == nil {
			_ = json.Unmarshal([]byte(vals.Get("payload")), &got.payload)
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, respBody)
	}))
}

// webhookURL builds a URL shaped like the one Synology hands out, including
// the literal double quotes it wraps the token in.
func webhookURL(base string) string {
	return base + `/webapi/entry.cgi?api=SYNO.Chat.External&method=incoming&version=2&token=%22` + testTokenValue + `%22`
}

// The API is form-encoded with a JSON `payload` field. Posting a plain JSON
// body is accepted with a 200 and delivers nothing, so this is pinned.
func TestSendUsesFormEncodedPayloadField(t *testing.T) {
	var got capture
	srv := newServer(t, http.StatusOK, `{"success":true}`, &got)
	defer srv.Close()

	c := synology.NewClient(webhookURL(srv.URL), srv.Client())
	if err := c.Send(context.Background(), synology.Message{Text: "disk check firing"}); err != nil {
		t.Fatalf("Send: unexpected error: %v", err)
	}

	if got.contentType != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type = %q, want application/x-www-form-urlencoded", got.contentType)
	}
	if !strings.HasPrefix(got.rawBody, "payload=") {
		t.Errorf("body must be a form with a payload field, got %q", got.rawBody)
	}
	if got.payload["text"] != "disk check firing" {
		t.Errorf("payload.text = %v, want the message text", got.payload["text"])
	}
}

func TestSendTransmitsTextVerbatim(t *testing.T) {
	text := "  line one\nline two — em dash, \"quotes\", &ampersands\n\n[REDACTED:vault-token]  "
	var got capture
	srv := newServer(t, http.StatusOK, `{"success":true}`, &got)
	defer srv.Close()

	c := synology.NewClient(webhookURL(srv.URL), srv.Client())
	if err := c.Send(context.Background(), synology.Message{Text: text}); err != nil {
		t.Fatalf("Send: unexpected error: %v", err)
	}
	if got.payload["text"] != text {
		t.Errorf("text was altered in transit:\n got %q\nwant %q", got.payload["text"], text)
	}
}

// THE load-bearing test for this connector: Synology reports a rejected
// message inside an HTTP 200. A status-only check would read it as
// delivered, mark the outbox entry sent, and lose the alert silently.
func TestSendFailClosedOnSuccessFalseInside200(t *testing.T) {
	var got capture
	srv := newServer(t, http.StatusOK, `{"success":false,"error":{"code":404}}`, &got)
	defer srv.Close()

	c := synology.NewClient(webhookURL(srv.URL), srv.Client())
	err := c.Send(context.Background(), synology.Message{Text: "x"})
	if err == nil {
		t.Fatal("Send: want error for success:false inside a 200, got nil")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("error should carry the Synology error code, got %q", err)
	}
}

func TestSendFailClosedOnNon2xxAndOnUndecodableBody(t *testing.T) {
	for _, tc := range []struct {
		name     string
		status   int
		respBody string
	}{
		{"non-2xx", http.StatusInternalServerError, `{"success":true}`},
		{"html error page behind a 200", http.StatusOK, `<html>captive portal</html>`},
		{"empty 200", http.StatusOK, ``},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got capture
			srv := newServer(t, tc.status, tc.respBody, &got)
			defer srv.Close()

			c := synology.NewClient(webhookURL(srv.URL), srv.Client())
			if err := c.Send(context.Background(), synology.Message{Text: "x"}); err == nil {
				t.Fatalf("Send: want error for %s, got nil", tc.name)
			}
		})
	}
}

// The whole webhook URL is a credential. net/http puts the request URL in
// its error strings, so a transport error must come back scrubbed.
func TestSendScrubsWebhookAndTokenFromTransportErrors(t *testing.T) {
	srv := newServer(t, http.StatusOK, `{"success":true}`, &capture{})
	raw := webhookURL(srv.URL)
	srv.Close() // force a transport error carrying the URL

	c := synology.NewClient(raw, nil)
	err := c.Send(context.Background(), synology.Message{Text: "x"})
	if err == nil {
		t.Fatal("Send: want error against a closed server, got nil")
	}
	if strings.Contains(err.Error(), testTokenValue) {
		t.Errorf("token leaked into error text: %q", err)
	}
	if !strings.Contains(err.Error(), "REDACTED") {
		t.Errorf("want a redaction marker in %q", err)
	}
}

func TestSendScrubsTokenEchoedInAnErrorBody(t *testing.T) {
	var got capture
	srv := newServer(t, http.StatusForbidden, `denied for token `+testTokenValue, &got)
	defer srv.Close()

	c := synology.NewClient(webhookURL(srv.URL), srv.Client())
	err := c.Send(context.Background(), synology.Message{Text: "x"})
	if err == nil {
		t.Fatal("Send: want error, got nil")
	}
	if strings.Contains(err.Error(), testTokenValue) {
		t.Errorf("token leaked into error text: %q", err)
	}
}

func TestSendHonoursContextCancellation(t *testing.T) {
	var got capture
	srv := newServer(t, http.StatusOK, `{"success":true}`, &got)
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	c := synology.NewClient(webhookURL(srv.URL), srv.Client())
	if err := c.Send(ctx, synology.Message{Text: "x"}); err == nil {
		t.Fatal("Send: want error for a cancelled context, got nil")
	}
}
