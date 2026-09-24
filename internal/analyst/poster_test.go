package analyst_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/lazarevtill/heimdall/internal/analyst"
	"github.com/lazarevtill/heimdall/internal/contract"
)

// The bridge answers /hypothesis with {"enqueued","deduped","suppressed",
// "ticketed"} (cmd/heimdall-bridge hypResponse). The poster reports which of
// the three outcomes happened; anything it cannot read as one of them is an
// error, so an unreadable reply is never counted as a delivery.
func TestHTTPPosterReadsTheBridgeReply(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		body    string
		want    analyst.Delivery
		wantErr bool
	}{
		{"new enqueue", 200, `{"enqueued":true,"deduped":false,"ticketed":false}`, analyst.DeliveryEnqueued, false},
		{"bridge already held it", 200, `{"enqueued":false,"deduped":true,"ticketed":true}`, analyst.DeliveryDeduped, false},
		{"an operator muted it", 200, `{"enqueued":false,"deduped":false,"suppressed":true,"ticketed":false}`, analyst.DeliverySuppressed, false},
		{"extra fields are tolerated", 200, `{"enqueued":true,"deduped":false,"ticketed":false,"added_later":1}`, analyst.DeliveryEnqueued, false},
		{"any 2xx is accepted", 202, `{"enqueued":true,"deduped":false}`, analyst.DeliveryEnqueued, false},
		{"neither outcome", 200, `{"enqueued":false,"deduped":false,"ticketed":false}`, 0, true},
		{"empty object", 200, `{}`, 0, true},
		{"empty body", 200, ``, 0, true},
		{"not JSON", 200, `ok`, 0, true},
		{"server error", 500, `{"enqueued":true}`, 0, true},
		{"unauthorized", 401, `unauthorized`, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.status)
				io.WriteString(w, tt.body)
			}))
			defer srv.Close()
			got, err := analyst.NewHTTPPoster(srv.URL+"/hypothesis", srv.Client(), "").
				Post(context.Background(), "run-1", validFinding("row-1"))
			if (err != nil) != tt.wantErr {
				t.Fatalf("Post error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("Post delivery = %v, want %v", got, tt.want)
			}
		})
	}
}

// The bridge authenticates /hypothesis with a bearer token. The poster sends
// it only when one is configured, and never lets it into an error string
// (errors are logged; a log line is an egress).
func TestHTTPPosterBearerToken(t *testing.T) {
	const token = "t0k3n-for-the-bridge-only"
	tests := []struct {
		name       string
		token      string
		wantHeader string
	}{
		{"token configured", token, "Bearer " + token},
		{"no token configured", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotHeader string
			var gotBody map[string]any
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotHeader = r.Header.Get("Authorization")
				raw, _ := io.ReadAll(r.Body)
				_ = json.Unmarshal(raw, &gotBody)
				w.WriteHeader(http.StatusUnauthorized) // so the error path is exercised too
			}))
			defer srv.Close()

			_, err := analyst.NewHTTPPoster(srv.URL+"/hypothesis", srv.Client(), tt.token).
				Post(context.Background(), "run-1", validFinding("row-1"))
			if err == nil {
				t.Fatal("Post: want an error for a 401, got nil")
			}
			if diff := cmp.Diff(tt.wantHeader, gotHeader); diff != "" {
				t.Errorf("Authorization header (-want +got):\n%s", diff)
			}
			if strings.Contains(err.Error(), token) {
				t.Errorf("Post error leaked the bridge token: %v", err)
			}
			if gotBody["run_id"] != "run-1" || gotBody["schema_version"] != float64(1) {
				t.Errorf("request body = %v, want schema_version 1 and run_id run-1", gotBody)
			}
		})
	}
}

// Post's contract with Run: the hypothesis on the wire is the vetted one,
// fingerprint included.
func TestHTTPPosterSendsTheHypothesis(t *testing.T) {
	h := validFinding("row-1")
	h.Fingerprint = contract.HypFingerprint(h.EvidenceRows)
	var got struct {
		Hypothesis contract.HypothesisFinding `json:"hypothesis"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", ct)
		}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &got)
		io.WriteString(w, `{"enqueued":true,"deduped":false,"ticketed":false}`)
	}))
	defer srv.Close()
	if _, err := analyst.NewHTTPPoster(srv.URL, srv.Client(), "").Post(context.Background(), "run-1", h); err != nil {
		t.Fatalf("Post: %v", err)
	}
	if diff := cmp.Diff(h, got.Hypothesis); diff != "" {
		t.Errorf("hypothesis on the wire (-want +got):\n%s", diff)
	}
}
