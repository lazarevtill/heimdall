package analyst

import (
	"bytes"
	"context"
	"encoding/json"
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

// HTTPPoster POSTs one vetted hypothesis to the bridge's /hypothesis
// endpoint as JSON: a fire-and-verify POST where any 2xx status means
// accepted. The bridge re-redacts and owns delivery/ticketing from there;
// this type's only job is getting the already-vetted document there.
type HTTPPoster struct {
	url   string
	httpc *http.Client
}

// NewHTTPPoster returns an HTTPPoster that POSTs to url (e.g.
// "http://host:port/hypothesis"). If httpc is nil, a default http.Client is
// used; callers SHOULD pass one with a timeout, but the primary deadline
// mechanism is the ctx passed to Post.
func NewHTTPPoster(url string, httpc *http.Client) *HTTPPoster {
	if httpc == nil {
		httpc = &http.Client{}
	}
	return &HTTPPoster{url: url, httpc: httpc}
}

// Post sends h (with runID) to the bridge. Any transport error or non-2xx
// status is returned as an error; the caller (Run) treats a Post failure as
// log-and-continue, never as a reason to re-run the gates or lose the
// already-persisted run.
func (p *HTTPPoster) Post(ctx context.Context, runID string, h contract.HypothesisFinding) error {
	payload, err := json.Marshal(postBody{SchemaVersion: 1, RunID: runID, Hypothesis: h})
	if err != nil {
		return fmt.Errorf("analyst: poster marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("analyst: poster build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.httpc.Do(req)
	if err != nil {
		return fmt.Errorf("analyst: poster post: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("analyst: poster unexpected status %d", resp.StatusCode)
	}
	return nil
}
