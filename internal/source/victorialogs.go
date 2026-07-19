package source

import (
	"bufio"
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

// VLSource queries a VictoriaLogs LogsQL endpoint
// (POST /select/logsql/query), which streams one JSON object per result row
// (newline-delimited JSON), not a single JSON document.
//
// Convention (caller's responsibility): the LogsQL expr aliases the numeric
// metric of interest to a field named "_hv", e.g.:
//
//	... | stats by (hostname) count() as _hv
//
// For each row, "_hv" becomes the Sample.Value; every OTHER field becomes a
// string Sample.Labels entry (numbers/bools are stringified). A row missing
// "_hv" or with an unparseable "_hv" is a malformed response and fails
// closed (Unknown), never silently dropped or coerced to 0. The time range
// is carried inside the expr itself via "_time:" filters — this source does
// not add start/end params.
type VLSource struct {
	base      string
	username  string
	password  string
	client    *http.Client
	timeout   time.Duration // per-attempt budget
	baseDelay time.Duration
	jitter    func() float64
}

func NewVictoriaLogs(baseURL, username, password string, client *http.Client) *VLSource {
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	return &VLSource{
		base:      strings.TrimRight(baseURL, "/"),
		username:  username,
		password:  password,
		client:    client,
		timeout:   15 * time.Second,
		baseDelay: 250 * time.Millisecond,
		jitter:    rand.Float64,
	}
}

func (s *VLSource) ID() string { return "victorialogs" }

func (s *VLSource) Query(ctx context.Context, q Query) (Signal, error) {
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
	wrapped := fmt.Errorf("victorialogs query %q: %w", q.ID, lastErr)
	return Signal{QueryID: q.ID, State: contract.StateUnknown, Err: wrapped.Error()}, wrapped
}

// vlValueField is the row field the caller aliases the numeric metric to.
const vlValueField = "_hv"

// once returns status 0 for transport-level failures.
func (s *VLSource) once(ctx context.Context, q Query) (Signal, int, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	form := "query=" + url.QueryEscape(q.Expr)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.base+"/select/logsql/query", strings.NewReader(form))
	if err != nil {
		return Signal{}, 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if s.username != "" {
		req.SetBasicAuth(s.username, s.password)
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

	sig := Signal{QueryID: q.ID, State: contract.StateOK}
	limited := io.LimitReader(resp.Body, 8<<20)
	scanner := bufio.NewScanner(limited)
	scanner.Buffer(make([]byte, 0, 64*1024), 8<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var row map[string]json.RawMessage
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			return Signal{}, resp.StatusCode, fmt.Errorf("decode row: %w", err)
		}
		raw, ok := row[vlValueField]
		if !ok {
			return Signal{}, resp.StatusCode, fmt.Errorf("row missing %q field", vlValueField)
		}
		v, err := parseVLValue(raw)
		if err != nil {
			return Signal{}, resp.StatusCode, fmt.Errorf("%s field: %w", vlValueField, err)
		}
		labels := make(map[string]string, len(row)-1)
		for k, rawV := range row {
			if k == vlValueField {
				continue
			}
			labels[k] = stringifyVLField(rawV)
		}
		sig.Samples = append(sig.Samples, Sample{Labels: labels, Value: v})
	}
	if err := scanner.Err(); err != nil {
		return Signal{}, resp.StatusCode, fmt.Errorf("read response: %w", err)
	}
	return sig, http.StatusOK, nil
}

// parseVLValue accepts _hv encoded as a JSON number or a quoted numeric
// string (VictoriaLogs commonly quotes stats output); anything else fails
// closed.
func parseVLValue(raw json.RawMessage) (float64, error) {
	var f float64
	if err := json.Unmarshal(raw, &f); err == nil {
		return f, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		v, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return 0, fmt.Errorf("parse %q as float: %w", s, err)
		}
		return v, nil
	}
	return 0, fmt.Errorf("unsupported value encoding: %s", raw)
}

// stringifyVLField renders any other row field as a Label string.
// Deterministic: JSON strings are unquoted, everything else (numbers,
// bools, null) keeps its raw JSON text.
func stringifyVLField(raw json.RawMessage) string {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	return strings.TrimSpace(string(raw))
}
