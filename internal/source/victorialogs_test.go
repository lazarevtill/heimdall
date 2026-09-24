package source

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/lazarevtill/heimdall/internal/contract"
)

// newTestVL zeroes BOTH baseDelay and jitter: retryDelay treats d<=0 as the
// 8s ceiling before jitter, so zeroing only baseDelay would silently sleep
// 8s per retry (see backoff.go).
func newTestVL(t *testing.T, username, password string, h http.HandlerFunc) *VLSource {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	s := NewVictoriaLogs(srv.URL, username, password, srv.Client())
	s.baseDelay = 0
	s.jitter = func() float64 { return 0 }
	return s
}

func TestVLQueryOK(t *testing.T) {
	const ndjson = `{"_hv":"3","hostname":"host-a","level":5}
{"_hv":7,"hostname":"host-b"}
`
	s := newTestVL(t, "", "", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/select/logsql/query" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
			t.Errorf("content-type = %q", ct)
		}
		w.Write([]byte(ndjson))
	})
	sig, err := s.Query(context.Background(), Query{ID: "q1", Expr: "* | stats count() as _hv"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	want := Signal{QueryID: "q1", State: contract.StateOK, Attempts: 1, Samples: []Sample{
		{Labels: map[string]string{"hostname": "host-a", "level": "5"}, Value: 3},
		{Labels: map[string]string{"hostname": "host-b"}, Value: 7},
	}}
	if diff := cmp.Diff(want, sig); diff != "" {
		t.Errorf("Signal mismatch (-want +got):\n%s", diff)
	}
}

func TestVLBasicAuthSent(t *testing.T) {
	var gotUser, gotPass string
	var gotOK bool
	s := newTestVL(t, "vluser", "vlpass", func(w http.ResponseWriter, r *http.Request) {
		gotUser, gotPass, gotOK = r.BasicAuth()
		w.Write([]byte(""))
	})
	if _, err := s.Query(context.Background(), Query{ID: "q1", Expr: "*"}); err != nil {
		t.Fatalf("Query: %v", err)
	}
	if !gotOK || gotUser != "vluser" || gotPass != "vlpass" {
		t.Errorf("basic auth = (%q,%q,%v), want (vluser,vlpass,true)", gotUser, gotPass, gotOK)
	}
}

func TestVLNoBasicAuthWhenUsernameEmpty(t *testing.T) {
	var gotOK bool
	s := newTestVL(t, "", "", func(w http.ResponseWriter, r *http.Request) {
		_, _, gotOK = r.BasicAuth()
		w.Write([]byte(""))
	})
	if _, err := s.Query(context.Background(), Query{ID: "q1", Expr: "*"}); err != nil {
		t.Fatalf("Query: %v", err)
	}
	if gotOK {
		t.Error("expected no Authorization header when username is empty")
	}
}

func TestVLEmptyBodyIsOKWithNoSamples(t *testing.T) {
	s := newTestVL(t, "", "", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(""))
	})
	sig, err := s.Query(context.Background(), Query{ID: "q1", Expr: "*"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	want := Signal{QueryID: "q1", State: contract.StateOK, Attempts: 1}
	if diff := cmp.Diff(want, sig); diff != "" {
		t.Errorf("Signal mismatch (-want +got):\n%s", diff)
	}
}

// The core trust invariant at the source layer: every failure mode returns
// State=Unknown and a non-nil error — never a silent ok.
func TestVLFailureMatrixIsNeverSilentOK(t *testing.T) {
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
		{"401 fails fast", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}, 1},
		{"malformed json line fails fast", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("not json at all\n"))
		}, 1},
		{"missing _hv field fails fast", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"hostname":"host-a"}` + "\n"))
		}, 1},
		{"unparseable _hv field fails fast", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"_hv":"not-a-number","hostname":"host-a"}` + "\n"))
		}, 1},
		// json.Unmarshal(null, &float64) is a silent no-op, which used to
		// coerce a null _hv to 0 — exactly the "calm" reading this source
		// promises never to invent.
		{"null _hv fails fast", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"_hv":null,"hostname":"host-a"}` + "\n"))
		}, 1},
		{"NaN string _hv fails fast", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"_hv":"NaN","hostname":"host-a"}` + "\n"))
		}, 1},
		{"Inf string _hv fails fast", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"_hv":"+Inf","hostname":"host-a"}` + "\n"))
		}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int64
			s := newTestVL(t, "", "", func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				tc.handler(w, r)
			})
			sig, err := s.Query(context.Background(), Query{ID: "q1", Expr: "*"})
			if err == nil {
				t.Fatal("want error, got nil")
			}
			if sig.State != contract.StateUnknown {
				t.Errorf("State = %v, want StateUnknown (never a silent ok)", sig.State)
			}
			if sig.Err == "" {
				t.Error("Signal.Err should describe the failure")
			}
			if calls.Load() != tc.wantCalls {
				t.Errorf("calls = %d, want %d", calls.Load(), tc.wantCalls)
			}
		})
	}
}

// A body larger than the read cap must fail closed even when the cap lands
// exactly on a row boundary. A bare LimitReader returns a clean EOF there, so
// every row before the cut parses and the query used to read as a complete,
// OK answer with rows silently missing (and a missing row can be the max).
func TestVLOversizedBodyIsUnknownEvenOnRowBoundary(t *testing.T) {
	const row = `{"_hv":1,"a":1}` + "\n" // 16 bytes
	cases := []struct {
		name    string
		rows    int
		maxBody int64
		wantErr bool
	}{
		{"exactly at cap is complete", 4, 64, false},
		{"one row over, cut on a row boundary", 5, 64, true},
		{"cut mid-row", 5, 70, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestVL(t, "", "", func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(strings.Repeat(row, tc.rows)))
			})
			s.maxBody = tc.maxBody
			sig, err := s.Query(context.Background(), Query{ID: "q1", Expr: "*"})
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr && sig.State != contract.StateUnknown {
				t.Errorf("State = %v, want StateUnknown (a truncated answer is not an answer)", sig.State)
			}
			if !tc.wantErr && len(sig.Samples) != tc.rows {
				t.Errorf("samples = %d, want %d", len(sig.Samples), tc.rows)
			}
		})
	}
}

func TestVLRetriesThenSucceeds(t *testing.T) {
	var calls atomic.Int64
	s := newTestVL(t, "", "", func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Write([]byte(`{"_hv":1,"k":"v"}` + "\n"))
	})
	sig, err := s.Query(context.Background(), Query{ID: "q1", Expr: "*"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if sig.Attempts != 2 || calls.Load() != 2 {
		t.Errorf("attempts = %d, calls = %d, want 2/2", sig.Attempts, calls.Load())
	}
}
