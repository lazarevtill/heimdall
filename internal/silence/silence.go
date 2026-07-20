// Package silence is a thin stdlib-net/http client for Alertmanager's v2
// silence API. It is pure transport — no policy, no state, no clock
// reads — so the notifier (S7-b) can drive it against a real httptest
// server or a fake.
package silence

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Client talks to Alertmanager's v2 silence API (typically loopback
// :9093). baseURL is the Alertmanager root; no auth (LAN-internal,
// inherited posture). Safe for use by the single notifier poller
// goroutine.
type Client struct {
	baseURL string
	httpc   *http.Client
}

// NewClient returns a Client for the given Alertmanager base URL (trailing
// slash trimmed). If httpc is nil, a default http.Client is used; callers
// SHOULD pass one with a timeout, but the primary deadline mechanism is the
// ctx passed to each call.
func NewClient(baseURL string, httpc *http.Client) *Client {
	if httpc == nil {
		httpc = &http.Client{}
	}
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		httpc:   httpc,
	}
}

// Matcher is one silence matcher (label = value equality by default).
type Matcher struct {
	Name    string `json:"name"`
	Value   string `json:"value"`
	IsRegex bool   `json:"isRegex"`
	IsEqual bool   `json:"isEqual"`
}

// Silence is a materialized Alertmanager silence. ID is set by AM on create
// and echoed back on list. StartsAt/EndsAt are RFC3339; CreatedBy/Comment
// are the provenance ("heimdall-notifier" / the mute reason+actor).
type Silence struct {
	ID        string    `json:"id,omitempty"`
	Matchers  []Matcher `json:"matchers"`
	StartsAt  string    `json:"startsAt"`
	EndsAt    string    `json:"endsAt"`
	CreatedBy string    `json:"createdBy"`
	Comment   string    `json:"comment"`
}

// createResponse is the shape of POST /api/v2/silences' reply.
type createResponse struct {
	SilenceID string `json:"silenceID"`
}

// Create POSTs /api/v2/silences and returns the assigned silence ID.
// Fail-closed on transport error, non-2xx status, or a decode failure.
func (c *Client) Create(ctx context.Context, s Silence) (id string, err error) {
	payload, err := json.Marshal(s)
	if err != nil {
		return "", fmt.Errorf("silence: create: marshal request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v2/silences", bytes.NewReader(payload))
	if err != nil {
		return "", fmt.Errorf("silence: create: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	var cr createResponse
	if err := c.do(req, &cr); err != nil {
		return "", fmt.Errorf("silence: create: %w", err)
	}
	return cr.SilenceID, nil
}

// gettableSilenceStatus is the nested status object on a GettableSilence.
type gettableSilenceStatus struct {
	State string `json:"state"` // active|pending|expired
}

// gettableSilence is the read-side shape of one entry in GET
// /api/v2/silences' array response.
type gettableSilence struct {
	ID        string                `json:"id"`
	Matchers  []Matcher             `json:"matchers"`
	StartsAt  string                `json:"startsAt"`
	EndsAt    string                `json:"endsAt"`
	CreatedBy string                `json:"createdBy"`
	Comment   string                `json:"comment"`
	Status    gettableSilenceStatus `json:"status"`
}

// List GETs /api/v2/silences and returns active+pending+expired silences
// as-is (the caller filters by whatever state it needs — this client
// applies no policy). Fail-closed on transport error, non-2xx status, or a
// decode failure.
func (c *Client) List(ctx context.Context) ([]Silence, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v2/silences", nil)
	if err != nil {
		return nil, fmt.Errorf("silence: list: build request: %w", err)
	}
	var gs []gettableSilence
	if err := c.do(req, &gs); err != nil {
		return nil, fmt.Errorf("silence: list: %w", err)
	}
	out := make([]Silence, 0, len(gs))
	for _, g := range gs {
		out = append(out, Silence{
			ID:        g.ID,
			Matchers:  g.Matchers,
			StartsAt:  g.StartsAt,
			EndsAt:    g.EndsAt,
			CreatedBy: g.CreatedBy,
			Comment:   g.Comment,
		})
	}
	return out, nil
}

// Delete DELETEs /api/v2/silence/{id} (expires the silence). Fail-closed on
// transport error or non-2xx status.
func (c *Client) Delete(ctx context.Context, id string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+"/api/v2/silence/"+url.PathEscape(id), nil)
	if err != nil {
		return fmt.Errorf("silence: delete %s: build request: %w", id, err)
	}
	if err := c.do(req, nil); err != nil {
		return fmt.Errorf("silence: delete %s: %w", id, err)
	}
	return nil
}

// do executes req and, on a 2xx response, decodes the JSON body into out
// (skipped if out is nil). Fail-closed: a transport error, a non-2xx status
// (error carries the truncated response body), or a decode failure all
// return a non-nil error — never a silent success.
func (c *Client) do(req *http.Request, out any) error {
	resp, err := c.httpc.Do(req)
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
