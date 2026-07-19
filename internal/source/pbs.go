package source

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"strings"
	"time"

	"github.com/lazarevtill/heimdall/internal/contract"
)

// PBSSource queries the Proxmox Backup Server admin API. It is the
// dead-man-check PRIMARY source: "no recent successful snapshot" is what
// the detector treats as a firing dead-man condition.
type PBSSource struct {
	base       string
	authHeader string
	client     *http.Client
	timeout    time.Duration // per-attempt budget
	baseDelay  time.Duration
	jitter     func() float64
}

// NewPBS builds a PBSSource pinned to caPEM: PBS commonly serves a
// self-signed (or private-CA-signed) certificate, so we pin the issuing CA
// and verify against it — InsecureSkipVerify is never set, on either the
// built-in client or a caller-supplied one.
//
// If client is nil, NewPBS builds one whose Transport trusts ONLY caPEM.
// If client is non-nil (e.g. in tests, an httptest server's own client),
// it is used as-is; the caller is then responsible for that client's own
// trust configuration. Either way, caPEM is always validated up front, so a
// garbage CA is rejected regardless of whether client is supplied.
func NewPBS(baseURL, tokenID, tokenSecret string, caPEM []byte, client *http.Client) (*PBSSource, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("pbs: invalid CA PEM")
	}
	if client == nil {
		client = &http.Client{
			Timeout: 20 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: pool},
			},
		}
	}
	return &PBSSource{
		base:       strings.TrimRight(baseURL, "/"),
		authHeader: "PBSAPIToken " + tokenID + ":" + tokenSecret,
		client:     client,
		timeout:    15 * time.Second,
		baseDelay:  250 * time.Millisecond,
		jitter:     rand.Float64,
	}, nil
}

func (s *PBSSource) ID() string { return "pbs" }

func (s *PBSSource) Query(ctx context.Context, q Query) (Signal, error) {
	spec, err := parsePBSExpr(q.Expr)
	if err != nil {
		wrapped := fmt.Errorf("pbs query %q: %w", q.ID, err)
		return Signal{QueryID: q.ID, State: contract.StateUnknown, Err: wrapped.Error()}, wrapped
	}

	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			if err := sleepCtx(ctx, retryDelay(attempt-1, s.baseDelay, s.jitter)); err != nil {
				lastErr = err
				break
			}
		}
		sig, status, err := s.once(ctx, q, spec)
		if err == nil {
			sig.Attempts = attempt + 1
			return sig, nil
		}
		lastErr = err
		if !retryableStatus(status) {
			break
		}
	}
	wrapped := fmt.Errorf("pbs query %q: %w", q.ID, lastErr)
	return Signal{QueryID: q.ID, State: contract.StateUnknown, Err: wrapped.Error()}, wrapped
}

// pbsSpec is the parsed form of the compact "key=val;key=val" Query.Expr.
type pbsSpec struct {
	datastore string
	mode      string // "snapshots" (default) or "gc"
	typ       string // optional vm|ct filter
	id        string // optional backup-id filter
}

// parsePBSExpr parses "key=val;key=val". datastore is required; any
// malformed segment, unknown key, or missing datastore fails closed
// (returned as an error, never silently defaulted) — a bad manifest expr
// must never be treated as ok.
func parsePBSExpr(expr string) (pbsSpec, error) {
	spec := pbsSpec{mode: "snapshots"}
	for _, part := range strings.Split(expr, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			return pbsSpec{}, fmt.Errorf("malformed spec segment %q", part)
		}
		key, val := strings.TrimSpace(kv[0]), strings.TrimSpace(kv[1])
		switch key {
		case "datastore":
			spec.datastore = val
		case "mode":
			if val != "snapshots" && val != "gc" {
				return pbsSpec{}, fmt.Errorf("unknown mode %q", val)
			}
			spec.mode = val
		case "type":
			spec.typ = val
		case "id":
			spec.id = val
		default:
			return pbsSpec{}, fmt.Errorf("unknown key %q", key)
		}
	}
	if spec.datastore == "" {
		return pbsSpec{}, fmt.Errorf("missing required key %q", "datastore")
	}
	return spec, nil
}

type pbsSnapshot struct {
	BackupID   string `json:"backup-id"`
	BackupType string `json:"backup-type"`
	BackupTime int64  `json:"backup-time"`
}

type pbsSnapshotsResponse struct {
	Data []pbsSnapshot `json:"data"`
}

type pbsGCResponse struct {
	Data json.RawMessage `json:"data"`
}

// pbsGCData covers the fields we understand from a GC status/report
// response. The shape of this endpoint is not fully pinned down; we only
// ever read a recognized last-run timestamp field and otherwise report an
// empty (still StateOK) result rather than guess.
type pbsGCData struct {
	LastRunEndtime int64 `json:"last-run-endtime"`
}

// once returns status 0 for transport-level failures.
func (s *PBSSource) once(ctx context.Context, q Query, spec pbsSpec) (Signal, int, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	var path string
	if spec.mode == "gc" {
		path = fmt.Sprintf("/api2/json/admin/datastore/%s/gc", spec.datastore)
	} else {
		path = fmt.Sprintf("/api2/json/admin/datastore/%s/snapshots", spec.datastore)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.base+path, nil)
	if err != nil {
		return Signal{}, 0, err
	}
	req.Header.Set("Authorization", s.authHeader)
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
	if spec.mode == "gc" {
		var pr pbsGCResponse
		if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&pr); err != nil {
			return Signal{}, resp.StatusCode, fmt.Errorf("decode response: %w", err)
		}
		if len(pr.Data) > 0 && string(pr.Data) != "null" {
			var d pbsGCData
			if err := json.Unmarshal(pr.Data, &d); err != nil {
				return Signal{}, resp.StatusCode, fmt.Errorf("decode gc data: %w", err)
			}
			if d.LastRunEndtime > 0 {
				sig.Samples = append(sig.Samples, Sample{
					Labels: map[string]string{"datastore": spec.datastore},
					Value:  float64(d.LastRunEndtime),
				})
			}
		}
		return sig, http.StatusOK, nil
	}

	var pr pbsSnapshotsResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&pr); err != nil {
		return Signal{}, resp.StatusCode, fmt.Errorf("decode response: %w", err)
	}
	var newest int64
	found := false
	for _, snap := range pr.Data {
		if spec.typ != "" && snap.BackupType != spec.typ {
			continue
		}
		if spec.id != "" && snap.BackupID != spec.id {
			continue
		}
		if !found || snap.BackupTime > newest {
			newest = snap.BackupTime
			found = true
		}
	}
	if found {
		sig.Samples = append(sig.Samples, Sample{
			Labels: map[string]string{"datastore": spec.datastore},
			Value:  float64(newest),
		})
	}
	return sig, http.StatusOK, nil
}
