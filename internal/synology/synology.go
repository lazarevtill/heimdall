// Package synology is a thin stdlib-net/http client for a Synology Chat
// INCOMING WEBHOOK. Like internal/telegram and internal/gotify it is pure
// transport — no policy, no state, no clock reads.
//
// Two properties of this API drive the implementation and are easy to get
// wrong:
//
//  1. The request is NOT JSON. Synology Chat expects
//     `application/x-www-form-urlencoded` with a single `payload` field
//     whose VALUE is a JSON document. Posting a JSON body directly is
//     accepted with a 200 and silently delivers nothing.
//  2. A failure is reported INSIDE a 200. The envelope is
//     `{"success":false,"error":{"code":N,...}}`, so a status-only check
//     reads a rejected message as delivered. This package therefore decodes
//     the envelope and treats `success:false` as an error — the same
//     fail-closed shape as internal/telegram's `"ok":false` handling.
//
// Secret hygiene: the webhook URL itself carries the token, so the whole
// URL is a credential. net/http embeds the request URL in its error
// strings, so every error this package returns is scrubbed of it (see
// sanitize) — otherwise a DNS or timeout error would write the token into
// the notifier's log.
package synology

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// maxRespBytes bounds how much of a response is read, for both decoding and
// diagnostics. The envelope is tiny; anything larger is a proxy error page.
const maxRespBytes = 4 << 10

// Client posts to one Synology Chat incoming webhook.
type Client struct {
	webhookURL string
	httpc      *http.Client
}

// NewClient returns a Client for the given incoming-webhook URL. If httpc
// is nil a default http.Client is used; callers SHOULD pass one with a
// timeout, but the primary deadline mechanism is the ctx passed to Send.
func NewClient(webhookURL string, httpc *http.Client) *Client {
	if httpc == nil {
		httpc = &http.Client{}
	}
	return &Client{webhookURL: webhookURL, httpc: httpc}
}

// Message is one Synology Chat post. Text is sent VERBATIM —
// internal/notify.Drain passes the outbox entry's already-redacted body
// straight through, and this package must never re-wrap, template or
// truncate it (see internal/notify.Sink's contract).
type Message struct {
	Text string
}

// wirePayload is the JSON document carried in the `payload` form field.
type wirePayload struct {
	Text string `json:"text"`
}

// envelope is Synology's uniform response shape. `success` is the
// authority — the HTTP status is 200 even for a rejected message.
type envelope struct {
	Success bool `json:"success"`
	Error   *struct {
		Code int `json:"code"`
	} `json:"error,omitempty"`
}

// Send posts one message to the webhook. Fail-closed: a transport error, a
// non-2xx status, an undecodable body, or a `success:false` envelope all
// return a non-nil error.
func (c *Client) Send(ctx context.Context, m Message) error {
	payload, err := json.Marshal(wirePayload{Text: m.Text})
	if err != nil {
		return fmt.Errorf("synology: marshal payload: %w", c.sanitizeErr(err))
	}

	form := url.Values{}
	form.Set("payload", string(payload))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.webhookURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("synology: build request: %w", c.sanitizeErr(err))
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpc.Do(req)
	if err != nil {
		return fmt.Errorf("synology: post webhook: %w", c.sanitizeErr(err))
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRespBytes))
	if err != nil {
		return fmt.Errorf("synology: read response: %w", c.sanitizeErr(err))
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("synology: post webhook: status %d: %s",
			resp.StatusCode, c.sanitize(strings.TrimSpace(string(body))))
	}

	var env envelope
	if err := json.Unmarshal(body, &env); err != nil {
		// A 200 whose body is not the envelope means we are not talking to
		// a Synology Chat webhook at all (a captive portal, a proxy error
		// page). Never treat that as delivered.
		return fmt.Errorf("synology: decode response: %w", c.sanitizeErr(err))
	}
	if !env.Success {
		code := 0
		if env.Error != nil {
			code = env.Error.Code
		}
		return fmt.Errorf("synology: webhook rejected the message (error code %d)", code)
	}
	return nil
}

// sanitize replaces the webhook URL — and, separately, its `token` query
// value — with markers wherever they appear. The token is scrubbed on its
// own as well as via the full URL because net/http sometimes reports a
// re-encoded form of the URL that will not match byte-for-byte.
func (c *Client) sanitize(s string) string {
	if c.webhookURL == "" {
		return s
	}
	out := strings.ReplaceAll(s, c.webhookURL, "[REDACTED:synology-webhook]")
	if tok := webhookToken(c.webhookURL); tok != "" {
		out = strings.ReplaceAll(out, tok, "[REDACTED:synology-token]")
	}
	return out
}

// sanitizeErr wraps err so its Error() text has the webhook URL and token
// scrubbed, keeping the original reachable through errors.Is / errors.As.
func (c *Client) sanitizeErr(err error) error {
	if err == nil {
		return err
	}
	scrubbed := c.sanitize(err.Error())
	if scrubbed == err.Error() {
		return err
	}
	return &sanitizedError{msg: scrubbed, err: err}
}

// webhookToken extracts the `token` query value from a webhook URL, or ""
// if the URL does not parse or carries no token. Synology wraps the token
// in literal double quotes in the URL it hands out; those are trimmed so
// the bare secret is scrubbed too.
func webhookToken(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.Trim(u.Query().Get("token"), `"`)
}

// sanitizedError carries a scrubbed message while keeping the original
// error reachable through errors.Is / errors.As.
type sanitizedError struct {
	msg string
	err error
}

func (e *sanitizedError) Error() string { return e.msg }
func (e *sanitizedError) Unwrap() error { return e.err }
