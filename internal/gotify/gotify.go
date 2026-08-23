// Package gotify is a thin stdlib-net/http client for the Gotify push
// server. Like internal/telegram it is pure transport — no policy, no
// state, no clock reads — so the notifier can drive it against a real
// httptest server or a fake.
//
// Fail-closed: a transport error, a non-2xx status, or an undecodable body
// all return a non-nil error. There is no partial success — the caller
// (internal/notify.Drain) leaves the outbox entry undelivered for this sink
// and retries on the next cycle.
//
// Secret hygiene: the app token is sent in the X-Gotify-Key HEADER, never
// as the `?token=` query parameter Gotify also accepts. net/http embeds the
// full request URL in its error strings, so a token in the URL would leak
// into every timeout/DNS error — and contract.Redact has no pattern for a
// bare Gotify token. sanitize() is the belt to that braces: it scrubs the
// token out of any error text this package returns, so the value cannot
// reach a log line even if it appears in an error from elsewhere.
package gotify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// maxErrBodyBytes bounds how much of a failing response body is folded into
// the returned error, for diagnostics only. A server that answers a push
// with a megabyte of HTML must not put that megabyte in a log line.
const maxErrBodyBytes = 512

// Client is a Gotify application client. baseURL is the server root
// (e.g. "https://gotify.example.com"); token is an APPLICATION token (not a
// client token — only application tokens may create messages).
type Client struct {
	baseURL string
	token   string
	httpc   *http.Client
}

// NewClient returns a Client for the given base URL (trailing slash
// trimmed) and application token. If httpc is nil a default http.Client is
// used; callers SHOULD pass one with a timeout, but the primary deadline
// mechanism is the ctx passed to Send.
func NewClient(baseURL, token string, httpc *http.Client) *Client {
	if httpc == nil {
		httpc = &http.Client{}
	}
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		httpc:   httpc,
	}
}

// Message is one Gotify push. Body is the message text and is sent
// VERBATIM — internal/notify.Drain passes the outbox entry's already-
// redacted body straight through, and this package must never re-wrap,
// template or truncate it (see internal/notify.Sink's contract).
//
// Priority drives Gotify's client-side notification behaviour (0 = silent,
// 8+ = high priority with sound on most clients). It is static per-channel
// configuration, not derived from message content.
type Message struct {
	Title    string
	Body     string
	Priority int
}

// wireMessage is the POST /message request shape.
type wireMessage struct {
	Title    string `json:"title"`
	Message  string `json:"message"`
	Priority int    `json:"priority"`
}

// Send POSTs one message to <baseURL>/message. Any non-2xx status is an
// error carrying the status and a bounded snippet of the response body.
func (c *Client) Send(ctx context.Context, m Message) error {
	payload, err := json.Marshal(wireMessage{Title: m.Title, Message: m.Body, Priority: m.Priority})
	if err != nil {
		return fmt.Errorf("gotify: marshal message: %w", c.sanitizeErr(err))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/message", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("gotify: build request: %w", c.sanitizeErr(err))
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Gotify-Key", c.token)

	resp, err := c.httpc.Do(req)
	if err != nil {
		return fmt.Errorf("gotify: post message: %w", c.sanitizeErr(err))
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrBodyBytes))
		return fmt.Errorf("gotify: post message: status %d: %s",
			resp.StatusCode, c.sanitize(strings.TrimSpace(string(snippet))))
	}
	// Drain-and-discard so the connection can be reused. The response body
	// is the created message object; nothing here needs it.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrBodyBytes))
	return nil
}

// sanitize replaces the app token with a marker wherever it appears. Only
// ever a no-op when the token is empty (a misconfiguration the notifier's
// config loader rejects before constructing a Client).
func (c *Client) sanitize(s string) string {
	if c.token == "" {
		return s
	}
	return strings.ReplaceAll(s, c.token, "[REDACTED:gotify-token]")
}

// sanitizeErr wraps err so its Error() text has the token scrubbed. The
// original error is preserved for errors.Is/As via Unwrap.
func (c *Client) sanitizeErr(err error) error {
	if err == nil || c.token == "" {
		return err
	}
	if !strings.Contains(err.Error(), c.token) {
		return err
	}
	return &sanitizedError{msg: c.sanitize(err.Error()), err: err}
}

// sanitizedError carries a scrubbed message while keeping the original
// error reachable through errors.Is / errors.As.
type sanitizedError struct {
	msg string
	err error
}

func (e *sanitizedError) Error() string { return e.msg }
func (e *sanitizedError) Unwrap() error { return e.err }
