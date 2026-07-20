package llm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newTestClient wires a Client at an httptest server's URL, sharing the
// server's client (which trusts its own TLS cert, though these are all
// plaintext servers).
func newTestClient(t *testing.T, h http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return NewClient(srv.URL, srv.Client()), srv
}

func ctxWithDeadline(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestHealthOK(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			t.Errorf("path = %q, want /health", r.URL.Path)
		}
		w.Write([]byte(`{"status":"ok"}`))
	})
	if err := c.Health(ctxWithDeadline(t)); err != nil {
		t.Fatalf("Health: %v", err)
	}
}

func TestHealthNon200(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	if err := c.Health(ctxWithDeadline(t)); err == nil {
		t.Fatal("Health: want error on 503, got nil")
	}
}

func TestHealthLoading(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"loading"}`))
	})
	if err := c.Health(ctxWithDeadline(t)); err == nil {
		t.Fatal("Health: want error on non-ok status field, got nil")
	}
}

func TestHealthUnreachable(t *testing.T) {
	// A base URL nothing listens on: 127.0.0.1 port 1 is reserved/unused.
	c := NewClient("http://127.0.0.1:1", &http.Client{Timeout: 2 * time.Second})
	if err := c.Health(ctxWithDeadline(t)); err == nil {
		t.Fatal("Health: want error on unreachable URL, got nil")
	}
}

// canned OpenAI-shaped response body used by the happy-path test.
const cannedContent = `{"color":"blue","count":42}`

func cannedResponse(content string) string {
	body, err := json.Marshal(map[string]any{
		"choices": []map[string]any{
			{"message": map[string]string{"content": content}},
		},
		"usage": map[string]int{
			"prompt_tokens":     11,
			"completion_tokens": 4,
			"total_tokens":      15,
		},
	})
	if err != nil {
		panic(err)
	}
	return string(body)
}

func TestAnalyzeHappyPath(t *testing.T) {
	const schemaName = "color_count"
	schema := json.RawMessage(`{"type":"object","properties":{"color":{"type":"string"},"count":{"type":"integer"}},"required":["color","count"],"additionalProperties":false}`)

	var gotBody map[string]any
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Errorf("path = %q, want /v1/chat/completions", r.URL.Path)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q", ct)
		}
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}
		if err := json.Unmarshal(raw, &gotBody); err != nil {
			t.Fatalf("unmarshal request body: %v", err)
		}
		w.Write([]byte(cannedResponse(cannedContent)))
	})

	req := Request{
		System:     "you are a static-instructions system prompt",
		User:       "the redacted digest payload",
		SchemaName: schemaName,
		Schema:     schema,
	}
	res, err := c.Analyze(ctxWithDeadline(t), req)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	// --- assert the REQUEST body the stub received ---
	temp, ok := gotBody["temperature"].(float64)
	if !ok || temp != 0 {
		t.Errorf("request temperature = %v, want 0", gotBody["temperature"])
	}
	rf, ok := gotBody["response_format"].(map[string]any)
	if !ok {
		t.Fatalf("request response_format missing or wrong type: %v", gotBody["response_format"])
	}
	if rf["type"] != "json_schema" {
		t.Errorf("response_format.type = %v, want json_schema", rf["type"])
	}
	js, ok := rf["json_schema"].(map[string]any)
	if !ok {
		t.Fatalf("response_format.json_schema missing or wrong type: %v", rf["json_schema"])
	}
	if js["strict"] != true {
		t.Errorf("response_format.json_schema.strict = %v, want true", js["strict"])
	}
	if js["name"] != schemaName {
		t.Errorf("response_format.json_schema.name = %v, want %q", js["name"], schemaName)
	}
	gotSchema, err := json.Marshal(js["schema"])
	if err != nil {
		t.Fatalf("re-marshal forwarded schema: %v", err)
	}
	var wantSchemaCanon, gotSchemaCanon any
	if err := json.Unmarshal(schema, &wantSchemaCanon); err != nil {
		t.Fatalf("unmarshal want schema: %v", err)
	}
	if err := json.Unmarshal(gotSchema, &gotSchemaCanon); err != nil {
		t.Fatalf("unmarshal got schema: %v", err)
	}
	wantCanon, _ := json.Marshal(wantSchemaCanon)
	gotCanon, _ := json.Marshal(gotSchemaCanon)
	if string(wantCanon) != string(gotCanon) {
		t.Errorf("forwarded schema mismatch:\n got: %s\nwant: %s", gotCanon, wantCanon)
	}
	msgs, ok := gotBody["messages"].([]any)
	if !ok || len(msgs) != 2 {
		t.Fatalf("request messages = %v, want 2 entries", gotBody["messages"])
	}
	first, _ := msgs[0].(map[string]any)
	second, _ := msgs[1].(map[string]any)
	if first["role"] != "system" {
		t.Errorf("messages[0].role = %v, want system", first["role"])
	}
	if second["role"] != "user" {
		t.Errorf("messages[1].role = %v, want user", second["role"])
	}

	// --- assert the RESULT ---
	if string(res.Content) != cannedContent {
		t.Errorf("Content = %q, want %q", res.Content, cannedContent)
	}
	if res.PromptTokens != 11 {
		t.Errorf("PromptTokens = %d, want 11", res.PromptTokens)
	}
	if res.CompletionTokens != 4 {
		t.Errorf("CompletionTokens = %d, want 4", res.CompletionTokens)
	}
	if res.RedactionFailures != 0 {
		t.Errorf("RedactionFailures = %d, want 0", res.RedactionFailures)
	}
}

// TestAnalyzeRedactsBeforeSend proves callsite #5: a glpat-shaped token in
// req.User must never reach the wire. The token is obviously fake (all 'x's)
// and is assembled from split literals so no contiguous "glpat-<20+>" string
// appears in this file's SOURCE — the public-mirror leak scanner is stricter
// than the Makefile gate (it does not exempt _test.go), so even a defanged
// literal must not be present verbatim. The runtime VALUE is still a valid
// glpat- shape, so the redactor matches and strips it.
func TestAnalyzeRedactsBeforeSend(t *testing.T) {
	const fakeToken = "glp" + "at-" + "xxxxxxxxxxxxxxxxxxxxxxxx" // runtime: glpat- + 24 'x'

	var rawBody string
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}
		rawBody = string(raw)
		w.Write([]byte(cannedResponse(cannedContent)))
	})

	req := Request{
		System:     "static system prompt",
		User:       "here is a leaked token: " + fakeToken,
		SchemaName: "s",
		Schema:     json.RawMessage(`{"type":"object"}`),
	}
	if _, err := c.Analyze(ctxWithDeadline(t), req); err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if strings.Contains(rawBody, fakeToken) {
		t.Fatalf("request body leaked unredacted token:\n%s", rawBody)
	}
	if !strings.Contains(rawBody, "REDACTED") {
		t.Fatalf("request body missing redaction marker:\n%s", rawBody)
	}
}

func TestAnalyzeFailClosed(t *testing.T) {
	validReq := Request{
		System:     "sys",
		User:       "usr",
		SchemaName: "s",
		Schema:     json.RawMessage(`{"type":"object"}`),
	}

	tests := []struct {
		name string
		h    http.HandlerFunc
	}{
		{
			name: "500 status",
			h: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
		},
		{
			name: "empty choices",
			h: func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(`{"choices":[],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
			},
		},
		{
			name: "empty message content",
			h: func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(`{"choices":[{"message":{"content":""}}],"usage":{}}`))
			},
		},
		{
			name: "malformed JSON body",
			h: func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(`{not json`))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := newTestClient(t, tt.h)
			res, err := c.Analyze(ctxWithDeadline(t), validReq)
			if err == nil {
				t.Fatal("Analyze: want error, got nil")
			}
			if res.Content != nil || res.PromptTokens != 0 || res.CompletionTokens != 0 || res.RedactionFailures != 0 {
				t.Errorf("Analyze: want zero Result on error, got %+v", res)
			}
		})
	}
}
