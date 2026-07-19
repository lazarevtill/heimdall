package source

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/lazarevtill/heimdall/internal/contract"
)

// defanged, obviously-fake token — never a real PBS credential.
const testTokenID = "user@pbs!tok"
const testTokenSecret = "AAAA-BBBB-EXAMPLE"

func serverCAPEM(srv *httptest.Server) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
}

// garbageCAPEM is a syntactically valid PEM CERTIFICATE block for a freshly
// generated, unrelated self-signed cert — NOT the test server's cert, and
// NOT derived from it. httptest.NewTLSServer reuses a single fixed built-in
// certificate across every server instance in this Go toolchain, so a
// second httptest server would (surprisingly) hand back the SAME cert;
// generating our own key/cert from scratch is what actually guarantees a
// mismatched CA, proving there is no insecure fallback.
func garbageCAPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	// Fixed validity window (no time.Now(): ADR-G10 bans it even in test
	// helpers) comfortably straddling any plausible test run.
	notBefore := time.Unix(1577836800, 0).UTC() // 2020-01-01
	notAfter := time.Unix(4102444800, 0).UTC()  // 2100-01-01
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "heimdall-test-garbage-ca"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create garbage cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func newTestPBS(t *testing.T, h http.HandlerFunc) (*PBSSource, *httptest.Server) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	s, err := NewPBS(srv.URL, testTokenID, testTokenSecret, serverCAPEM(srv), srv.Client())
	if err != nil {
		t.Fatalf("NewPBS: %v", err)
	}
	s.baseDelay = 0
	s.jitter = func() float64 { return 0 }
	return s, srv
}

const snapshotsBody = `{"data":[
  {"backup-id":"100","backup-type":"vm","backup-time":1752893000},
  {"backup-id":"100","backup-type":"vm","backup-time":1752896400},
  {"backup-id":"200","backup-type":"ct","backup-time":1752890000}]}`

func TestPBSSnapshotsNewestBackupTime(t *testing.T) {
	s, _ := newTestPBS(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api2/json/admin/datastore/store1/snapshots" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Write([]byte(snapshotsBody))
	})
	sig, err := s.Query(context.Background(), Query{ID: "q1", Expr: "datastore=store1"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	want := Signal{QueryID: "q1", State: contract.StateOK, Attempts: 1, Samples: []Sample{
		{Labels: map[string]string{"datastore": "store1"}, Value: 1752896400},
	}}
	if diff := cmp.Diff(want, sig); diff != "" {
		t.Errorf("Signal mismatch (-want +got):\n%s", diff)
	}
}

func TestPBSSnapshotsFilteredByTypeAndID(t *testing.T) {
	s, _ := newTestPBS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(snapshotsBody))
	})
	sig, err := s.Query(context.Background(), Query{ID: "q1", Expr: "datastore=store1;type=ct;id=200"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	want := Signal{QueryID: "q1", State: contract.StateOK, Attempts: 1, Samples: []Sample{
		{Labels: map[string]string{"datastore": "store1"}, Value: 1752890000},
	}}
	if diff := cmp.Diff(want, sig); diff != "" {
		t.Errorf("Signal mismatch (-want +got):\n%s", diff)
	}
}

func TestPBSNoMatchIsOKWithEmptySamples(t *testing.T) {
	s, _ := newTestPBS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(snapshotsBody))
	})
	sig, err := s.Query(context.Background(), Query{ID: "q1", Expr: "datastore=store1;type=ct;id=does-not-exist"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	want := Signal{QueryID: "q1", State: contract.StateOK, Attempts: 1}
	if diff := cmp.Diff(want, sig); diff != "" {
		t.Errorf("Signal mismatch (-want +got):\n%s", diff)
	}
}

func TestPBSGCNewestRunTime(t *testing.T) {
	s, _ := newTestPBS(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api2/json/admin/datastore/store1/gc" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Write([]byte(`{"data":{"upid":"UPID:example","last-run-endtime":1752899000}}`))
	})
	sig, err := s.Query(context.Background(), Query{ID: "q1", Expr: "datastore=store1;mode=gc"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	want := Signal{QueryID: "q1", State: contract.StateOK, Attempts: 1, Samples: []Sample{
		{Labels: map[string]string{"datastore": "store1"}, Value: 1752899000},
	}}
	if diff := cmp.Diff(want, sig); diff != "" {
		t.Errorf("Signal mismatch (-want +got):\n%s", diff)
	}
}

func TestPBSGCNullDataIsOKWithEmptySamples(t *testing.T) {
	s, _ := newTestPBS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"data":null}`))
	})
	sig, err := s.Query(context.Background(), Query{ID: "q1", Expr: "datastore=store1;mode=gc"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	want := Signal{QueryID: "q1", State: contract.StateOK, Attempts: 1}
	if diff := cmp.Diff(want, sig); diff != "" {
		t.Errorf("Signal mismatch (-want +got):\n%s", diff)
	}
}

func TestPBSAuthHeaderSent(t *testing.T) {
	var got string
	s, _ := newTestPBS(t, func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
		w.Write([]byte(`{"data":[]}`))
	})
	if _, err := s.Query(context.Background(), Query{ID: "q1", Expr: "datastore=store1"}); err != nil {
		t.Fatalf("Query: %v", err)
	}
	want := "PBSAPIToken " + testTokenID + ":" + testTokenSecret
	if got != want {
		t.Errorf("Authorization header = %q, want %q", got, want)
	}
}

func TestPBSMalformedExprIsUnknownFailClosed(t *testing.T) {
	cases := []string{
		"",                            // no datastore at all
		"mode=snapshots",              // missing required datastore key
		"datastore",                   // no '=' separator
		"datastore=store1;mode=bogus", // unknown mode value
		"datastore=store1;wat=1",      // unknown key
	}
	// A source pointed at an unreachable address: if parsing fails closed
	// as it should, the handler must never even be dialed.
	s, err := NewPBS("https://127.0.0.1:1", testTokenID, testTokenSecret, garbageCAPEM(t), nil)
	if err != nil {
		t.Fatalf("NewPBS: %v", err)
	}
	for _, expr := range cases {
		t.Run(expr, func(t *testing.T) {
			sig, err := s.Query(context.Background(), Query{ID: "q1", Expr: expr})
			if err == nil {
				t.Fatal("want error, got nil")
			}
			if sig.State != contract.StateUnknown {
				t.Errorf("State = %v, want StateUnknown", sig.State)
			}
			if sig.Err == "" {
				t.Error("Signal.Err should describe the failure")
			}
		})
	}
}

// The core trust invariant at the source layer: every failure mode returns
// State=Unknown and a non-nil error — never a silent ok.
func TestPBSFailureMatrixIsNeverSilentOK(t *testing.T) {
	cases := []struct {
		name      string
		handler   http.HandlerFunc
		wantCalls int64
	}{
		{"persistent 500 retried 3x", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}, 3},
		{"401 fails fast", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}, 1},
		{"garbage body fails fast", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("<html>not pbs</html>"))
		}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int64
			s, _ := newTestPBS(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				tc.handler(w, r)
			})
			sig, err := s.Query(context.Background(), Query{ID: "q1", Expr: "datastore=store1"})
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

func TestNewPBSInvalidCAPEMErrors(t *testing.T) {
	_, err := NewPBS("https://example.invalid", testTokenID, testTokenSecret, []byte("not a pem cert"), nil)
	if err == nil {
		t.Fatal("want error for invalid CA PEM, got nil")
	}
}

// Proves the pinned-CA success path end to end: NewPBS builds its OWN
// http.Client (client=nil) whose Transport trusts ONLY the CA pool derived
// from caPEM, and a request against the httptest TLS server (signed by
// that same cert) succeeds.
func TestPBSPinnedCASucceedsWithNilClient(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"data":[]}`))
	}))
	defer srv.Close()

	s, err := NewPBS(srv.URL, testTokenID, testTokenSecret, serverCAPEM(srv), nil)
	if err != nil {
		t.Fatalf("NewPBS: %v", err)
	}
	s.baseDelay = 0
	s.jitter = func() float64 { return 0 }

	sig, err := s.Query(context.Background(), Query{ID: "q1", Expr: "datastore=store1"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if sig.State != contract.StateOK {
		t.Errorf("State = %v, want StateOK", sig.State)
	}
}

// Proves there is NO insecure fallback: pinning to a CA that did NOT sign
// the server's certificate must fail TLS verification, never silently
// succeed or silently skip verification.
func TestPBSWrongCAFailsVerification(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"data":[]}`))
	}))
	defer srv.Close()

	s, err := NewPBS(srv.URL, testTokenID, testTokenSecret, garbageCAPEM(t), nil)
	if err != nil {
		t.Fatalf("NewPBS: %v", err)
	}
	s.baseDelay = 0
	s.jitter = func() float64 { return 0 }

	sig, err := s.Query(context.Background(), Query{ID: "q1", Expr: "datastore=store1"})
	if err == nil {
		t.Fatal("want TLS verification error, got nil")
	}
	if sig.State != contract.StateUnknown {
		t.Errorf("State = %v, want StateUnknown", sig.State)
	}
	if sig.Err == "" {
		t.Error("Signal.Err should describe the failure")
	}
}
