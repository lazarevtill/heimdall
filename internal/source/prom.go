package source

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/lazarevtill/heimdall/internal/contract"
)

// PromSource queries a Prometheus-compatible instant-query API.
type PromSource struct {
	base      string
	client    *http.Client
	timeout   time.Duration // per-attempt budget
	baseDelay time.Duration
	jitter    func() float64
}

func NewProm(baseURL string, client *http.Client) *PromSource {
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	return &PromSource{
		base:      strings.TrimRight(baseURL, "/"),
		client:    client,
		timeout:   15 * time.Second,
		baseDelay: 250 * time.Millisecond,
		jitter:    rand.Float64,
	}
}

func (s *PromSource) ID() string { return "prometheus" }

func (s *PromSource) Query(ctx context.Context, q Query) (Signal, error) {
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			if err := sleepCtx(ctx, retryDelay(attempt-1, s.baseDelay, s.jitter)); err != nil {
				lastErr = err
				break
			}
		}
		sig, status, err := s.once(ctx, q)
		if err == nil {
			sig.Attempts = attempt + 1
			return sig, nil
		}
		lastErr = err
		if !retryableStatus(status) {
			break
		}
	}
	wrapped := fmt.Errorf("prometheus query %q: %w", q.ID, lastErr)
	return Signal{QueryID: q.ID, State: contract.StateUnknown, Err: wrapped.Error()}, wrapped
}

type promResponse struct {
	Status string `json:"status"`
	Data   struct {
		Result []promResult `json:"result"`
	} `json:"data"`
}

type promResult struct {
	Metric map[string]string  `json:"metric"`
	Value  [2]json.RawMessage `json:"value"` // [unix_ts, "value-string"]
}

func (r promResult) value() (float64, error) {
	var s string
	if err := json.Unmarshal(r.Value[1], &s); err != nil {
		return 0, fmt.Errorf("sample value: %w", err)
	}
	return strconv.ParseFloat(s, 64)
}

// once returns status 0 for transport-level failures.
func (s *PromSource) once(ctx context.Context, q Query) (Signal, int, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	u := s.base + "/api/v1/query?query=" + url.QueryEscape(q.Expr)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return Signal{}, 0, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return Signal{}, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return Signal{}, resp.StatusCode, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	var pr promResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&pr); err != nil {
		return Signal{}, resp.StatusCode, fmt.Errorf("decode response: %w", err)
	}
	if pr.Status != "success" {
		return Signal{}, resp.StatusCode, fmt.Errorf("prometheus reported status %q", pr.Status)
	}
	sig := Signal{QueryID: q.ID, State: contract.StateOK}
	for _, r := range pr.Data.Result {
		v, err := r.value()
		if err != nil {
			return Signal{}, resp.StatusCode, err
		}
		sig.Samples = append(sig.Samples, Sample{Labels: r.Metric, Value: v})
	}
	return sig, http.StatusOK, nil
}
