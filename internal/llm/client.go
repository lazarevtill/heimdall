package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/lazarevtill/heimdall/internal/contract"
)

// Client is a llama.cpp OpenAI-compatible client. Construct with NewClient;
// it is safe for sequential use by one analyst process (no shared mutable
// state beyond the http.Client).
type Client struct {
	baseURL string
	httpc   *http.Client
}

// NewClient returns a Client for the given base URL (e.g. "http://host:8082",
// no trailing slash required — normalize it). If httpc is nil, a default
// http.Client is used; callers SHOULD pass one with a timeout, but the primary
// deadline mechanism is the ctx passed to each call.
func NewClient(baseURL string, httpc *http.Client) *Client {
	if httpc == nil {
		httpc = &http.Client{}
	}
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		httpc:   httpc,
	}
}

// healthResponse is the minimal shape of GET /health.
type healthResponse struct {
	Status string `json:"status"`
}

// Health probes GET {base}/health and returns nil iff the server answers 200
// with a body whose "status" field == "ok". Any transport error, non-200, or
// non-ok status is returned as an error — the analyst uses this as a hard gate
// (a dead/mis-answering LLM must be VISIBLE, never silently skipped).
func (c *Client) Health(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/health", nil)
	if err != nil {
		return fmt.Errorf("llm health request: %w", err)
	}
	resp, err := c.httpc.Do(req)
	if err != nil {
		return fmt.Errorf("llm health: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("llm health: unexpected status %d", resp.StatusCode)
	}
	var hr healthResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&hr); err != nil {
		return fmt.Errorf("llm health: decode response: %w", err)
	}
	if hr.Status != "ok" {
		return fmt.Errorf("llm health: unexpected status field %q", hr.Status)
	}
	return nil
}

// Request is one strict-json_schema completion. System is static instructions
// (not redacted). User is the payload (the redacted digest) — redacted AGAIN
// here, defense-in-depth, callsite #5. SchemaName/Schema are the strict
// json_schema forwarded verbatim. MaxTokens>0 caps the completion (0 = omit).
type Request struct {
	System     string
	User       string
	SchemaName string          // response_format.json_schema.name (^[a-z0-9_-]+$ recommended)
	Schema     json.RawMessage // response_format.json_schema.schema — the JSON Schema object
	MaxTokens  int
}

// Result is a successful completion.
type Result struct {
	Content           []byte // choices[0].message.content raw bytes — caller unmarshals against Schema
	PromptTokens      int
	CompletionTokens  int
	RedactionFailures int // # of user-content redaction failures (feeds heimdall_redaction_failures_total)
}

// chatMessage is one entry in the request's "messages" array.
type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// jsonSchemaFormat is response_format for {"type":"json_schema",...}.
type jsonSchemaFormat struct {
	Name   string          `json:"name"`
	Strict bool            `json:"strict"`
	Schema json.RawMessage `json:"schema"`
}

// responseFormat wraps jsonSchemaFormat in the OpenAI-compatible envelope.
type responseFormat struct {
	Type       string           `json:"type"`
	JSONSchema jsonSchemaFormat `json:"json_schema"`
}

// chatRequest is the body posted to /v1/chat/completions. Temperature is a
// plain (never omitempty) field: the server must always see an explicit 0.
type chatRequest struct {
	Messages       []chatMessage  `json:"messages"`
	Temperature    float64        `json:"temperature"`
	ResponseFormat responseFormat `json:"response_format"`
	MaxTokens      int            `json:"max_tokens,omitempty"`
}

// chatResponse is the minimal shape of the /v1/chat/completions reply we
// consume — only the fields Analyze needs are decoded.
type chatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
}

// Analyze performs one strict-json_schema chat completion at temperature 0.
// It redacts req.User via contract.EvidenceOrWithheld before sending (counting
// failures into Result.RedactionFailures — a redaction FAILURE withholds that
// content but the request STILL proceeds with the withheld sentinel, matching
// the content-fail-closed/signal-fail-open rule: we never send unredacted
// evidence, but a redactor bug does not silently skip the analysis).
//
// Fail-closed: a transport error, non-200 status, an empty choices array, a
// missing/empty message.content, or a body that does not decode all return a
// non-nil error and a zero Result — never a partial or fabricated answer. The
// returned Content is NOT validated against Schema here (the server enforces
// the schema; the caller unmarshals+validates semantically).
func (c *Client) Analyze(ctx context.Context, req Request) (Result, error) {
	user, failed := contract.EvidenceOrWithheld(req.User)
	redactionFailures := 0
	if failed {
		redactionFailures = 1
	}

	body := chatRequest{
		Messages: []chatMessage{
			{Role: "system", Content: req.System},
			{Role: "user", Content: user},
		},
		Temperature: 0,
		ResponseFormat: responseFormat{
			Type: "json_schema",
			JSONSchema: jsonSchemaFormat{
				Name:   req.SchemaName,
				Strict: true,
				Schema: req.Schema,
			},
		},
	}
	if req.MaxTokens > 0 {
		body.MaxTokens = req.MaxTokens
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return Result{}, fmt.Errorf("llm analyze: marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/chat/completions", bytes.NewReader(payload))
	if err != nil {
		return Result{}, fmt.Errorf("llm analyze: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpc.Do(httpReq)
	if err != nil {
		return Result{}, fmt.Errorf("llm analyze: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return Result{}, fmt.Errorf("llm analyze: unexpected status %d", resp.StatusCode)
	}

	var cr chatResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&cr); err != nil {
		return Result{}, fmt.Errorf("llm analyze: decode response: %w", err)
	}
	if len(cr.Choices) == 0 {
		return Result{}, fmt.Errorf("llm analyze: empty choices array")
	}
	content := cr.Choices[0].Message.Content
	if content == "" {
		return Result{}, fmt.Errorf("llm analyze: empty message content")
	}

	return Result{
		Content:           []byte(content),
		PromptTokens:      cr.Usage.PromptTokens,
		CompletionTokens:  cr.Usage.CompletionTokens,
		RedactionFailures: redactionFailures,
	}, nil
}
