package analyst

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/lazarevtill/heimdall/internal/contract"
)

// postBody is the exact wire shape POSTed to the bridge's /hypothesis
// endpoint. S6 (the bridge) consumes this shape verbatim and is the
// authority on delivery/re-redaction from here on:
//
//	{
//	  "schema_version": 1,
//	  "run_id": "<the analyst run's RunID>",
//	  "hypothesis": { <contract.HypothesisFinding, incl. the wrapper's fingerprint> }
//	}
type postBody struct {
	SchemaVersion int                        `json:"schema_version"`
	RunID         string                     `json:"run_id"`
	Hypothesis    contract.HypothesisFinding `json:"hypothesis"`
}

// bridgeReply is the part of the bridge's /hypothesis response the poster
// needs (cmd/heimdall-bridge hypResponse: {"enqueued","deduped","suppressed","ticketed"}).
// Pointers, so a reply that does not SAY what happened is distinguishable
// from one that says "no". Fields the bridge adds later are ignored.
type bridgeReply struct {
	Enqueued   *bool `json:"enqueued"`
	Deduped    *bool `json:"deduped"`
	Suppressed *bool `json:"suppressed"`
}

// maxReplyBytes bounds how much of the bridge's reply is read.
const maxReplyBytes = 4096

// HTTPPoster POSTs one vetted hypothesis to the bridge's /hypothesis
// endpoint as JSON and reads back what the bridge did with it. The bridge
// re-redacts and owns delivery/ticketing from there; this type's only job
// is getting the already-vetted document there and reporting the outcome
// honestly.
type HTTPPoster struct {
	url   string
	httpc *http.Client
	token string // bridge bearer token; "" sends no Authorization header
}

// NewHTTPPoster returns an HTTPPoster that POSTs to url (e.g.
// "http://host:port/hypothesis"). If httpc is nil, a default http.Client is
// used; callers SHOULD pass one with a timeout, but the primary deadline
// mechanism is the ctx passed to Post. A non-empty token is sent as
// "Authorization: Bearer <token>" on every POST; it is never written into
// an error.
func NewHTTPPoster(url string, httpc *http.Client, token string) *HTTPPoster {
	if httpc == nil {
		httpc = &http.Client{}
	}
	return &HTTPPoster{url: url, httpc: httpc, token: token}
}

// Post sends h (with runID) to the bridge and reports its outcome: a 2xx
// whose body says enqueued (a NEW message), deduped (the bridge already
// held this hyp_fp) or suppressed (an operator's hypothesis mute held it
// back). Anything else — a transport error, a non-2xx status, a
// body that does not decode or reports neither outcome — is an error, so an
// unreadable reply is never counted as a delivery. The caller (Run) treats
// a Post failure as count-and-continue, never as a reason to re-run the
// gates or lose the already-persisted run.
func (p *HTTPPoster) Post(ctx context.Context, runID string, h contract.HypothesisFinding) (Delivery, error) {
	payload, err := json.Marshal(postBody{SchemaVersion: 1, RunID: runID, Hypothesis: h})
	if err != nil {
		return 0, fmt.Errorf("analyst: poster marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.url, bytes.NewReader(payload))
	if err != nil {
		return 0, fmt.Errorf("analyst: poster build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if p.token != "" {
		req.Header.Set("Authorization", "Bearer "+p.token)
	}
	resp, err := p.httpc.Do(req)
	if err != nil {
		return 0, fmt.Errorf("analyst: poster post: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxReplyBytes))
	if err != nil {
		return 0, fmt.Errorf("analyst: poster read reply: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, fmt.Errorf("analyst: poster unexpected status %d", resp.StatusCode)
	}
	var reply bridgeReply
	if err := json.Unmarshal(body, &reply); err != nil {
		return 0, fmt.Errorf("analyst: poster decode reply: %w", err)
	}
	switch {
	case reply.Enqueued != nil && *reply.Enqueued:
		return DeliveryEnqueued, nil
	case reply.Deduped != nil && *reply.Deduped:
		return DeliveryDeduped, nil
	case reply.Suppressed != nil && *reply.Suppressed:
		return DeliverySuppressed, nil
	}
	return 0, errors.New("analyst: poster: bridge reply reports none of enqueued, deduped or suppressed")
}
