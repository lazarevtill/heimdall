package source

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/lazarevtill/heimdall/internal/contract"
)

const vectorBody = `{"status":"success","data":{"resultType":"vector","result":[
  {"metric":{"backup_id":"vm-100"},"value":[1752900000,"1752896400"]},
  {"metric":{"backup_id":"vm-101"},"value":[1752900000,"1752893000"]}]}}`

// newTestProm zeroes BOTH baseDelay and jitter: retryDelay treats d<=0 as
// the 8s ceiling before jitter, so zeroing only baseDelay would silently
// sleep 8s per retry.
func newTestProm(t *testing.T, h http.HandlerFunc) *PromSource {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	s := NewProm(srv.URL, srv.Client())
	s.baseDelay = 0
	s.jitter = func() float64 { return 0 }
	return s
}

func TestPromQueryOK(t *testing.T) {
	s := newTestProm(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/query" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Write([]byte(vectorBody))
	})
	sig, err := s.Query(context.Background(), Query{ID: "q1", Expr: "up"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	want := Signal{QueryID: "q1", State: contract.StateOK, Attempts: 1, Samples: []Sample{
		{Labels: map[string]string{"backup_id": "vm-100"}, Value: 1752896400},
		{Labels: map[string]string{"backup_id": "vm-101"}, Value: 1752893000},
	}}
	if diff := cmp.Diff(want, sig); diff != "" {
		t.Errorf("Signal mismatch (-want +got):\n%s", diff)
	}
}

func TestPromRetriesThenSucceeds(t *testing.T) {
	var calls atomic.Int64
	s := newTestProm(t, func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Write([]byte(vectorBody))
	})
	sig, err := s.Query(context.Background(), Query{ID: "q1", Expr: "up"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if sig.Attempts != 2 || calls.Load() != 2 {
		t.Errorf("attempts = %d, calls = %d, want 2/2", sig.Attempts, calls.Load())
	}
}

// The core trust invariant at the source layer: every failure mode returns
// State=Unknown and a non-nil error — never a silent ok.
func TestPromFailureMatrixIsNeverSilentOK(t *testing.T) {
	cases := []struct {
		name      string
		handler   http.HandlerFunc
		wantCalls int64
	}{
		{"persistent 500 retried 3x", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}, 3},
		{"429 retried 3x", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusTooManyRequests)
		}, 3},
		{"404 fails fast", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}, 1},
		{"garbage body fails fast", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("<html>not prometheus</html>"))
		}, 1},
		{"prometheus error status fails fast", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"error","error":"bad query"}`))
		}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int64
			s := newTestProm(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				tc.handler(w, r)
			})
			sig, err := s.Query(context.Background(), Query{ID: "q1", Expr: "up"})
			if err == nil {
				t.Fatal("want error, got nil")
			}
			if sig.State != contract.StateUnknown {
				t.Errorf("State = %v, want StateUnknown (never a silent ok)", sig.State)
			}
			if calls.Load() != tc.wantCalls {
				t.Errorf("calls = %d, want %d", calls.Load(), tc.wantCalls)
			}
		})
	}
}

func TestPromTimeoutIsUnknown(t *testing.T) {
	s := newTestProm(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.Write([]byte(vectorBody))
	})
	s.timeout = 20 * time.Millisecond
	sig, err := s.Query(context.Background(), Query{ID: "q1", Expr: "up"})
	if err == nil {
		t.Fatal("want timeout error, got nil")
	}
	if sig.State != contract.StateUnknown {
		t.Errorf("State = %v, want StateUnknown", sig.State)
	}
	if sig.Err == "" {
		t.Error("Signal.Err should describe the failure")
	}
}
