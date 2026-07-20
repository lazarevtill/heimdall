package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"
)

// TestLiveOrnith is the REAL Ornith (llama.cpp) proof. It is compiled (not
// build-tagged) so it never rots, but SKIPS unless HEIMDALL_LLM_LIVE_URL is
// set — this keeps `make ci` fully hermetic (no real infra string is ever
// hardcoded in this package). The controller runs this against the real
// endpoint after review.
func TestLiveOrnith(t *testing.T) {
	url := os.Getenv("HEIMDALL_LLM_LIVE_URL")
	if url == "" {
		t.Skip("set HEIMDALL_LLM_LIVE_URL to run the live llama.cpp test")
	}

	c := NewClient(url, &http.Client{})

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	if err := c.Health(ctx); err != nil {
		t.Fatalf("Health: %v", err)
	}

	schema := json.RawMessage(`{"type":"object","properties":{"color":{"type":"string"},"count":{"type":"integer"}},"required":["color","count"],"additionalProperties":false}`)
	req := Request{
		System:     "You are a strict JSON generator. Respond only via the provided schema.",
		User:       "Pick any color and any count and respond via the schema.",
		SchemaName: "color_count",
		Schema:     schema,
	}

	res, err := c.Analyze(ctx, req)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	var got struct {
		Color string      `json:"color"`
		Count json.Number `json:"count"`
	}
	if err := json.Unmarshal(res.Content, &got); err != nil {
		t.Fatalf("unmarshal live Content %q: %v", res.Content, err)
	}
	if got.Color == "" {
		t.Errorf("live response color is empty; Content=%q", res.Content)
	}
	if _, err := got.Count.Int64(); err != nil {
		t.Errorf("live response count is not a number: %v; Content=%q", err, res.Content)
	}
}
