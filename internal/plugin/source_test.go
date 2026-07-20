package plugin

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/lazarevtill/heimdall/internal/contract"
	"github.com/lazarevtill/heimdall/internal/source"
)

// testSourceManifest returns a valid source-kind manifest for id, declaring
// the same HEIMDALL_PLUGIN_SECRET credential the real reference plugin (and
// the badsrc fixture, which doesn't care) declare.
func testSourceManifest(id string) Manifest {
	return Manifest{
		PluginAPI: PluginAPIVersion,
		ID:        id,
		Kind:      KindSource,
		Version:   "0.1.0-test",
		Capabilities: Capabilities{
			Credential: "HEIMDALL_PLUGIN_SECRET",
		},
		Budgets: Budgets{
			DeadlineSeconds: 5,
			MaxOutputBytes:  1 << 20,
		},
	}
}

// --- NewSourcePlugin ---------------------------------------------------

func TestNewSourcePluginRejectsDetectorKind(t *testing.T) {
	m := testSourceManifest("refsrc")
	m.Kind = KindDetector
	m.Capabilities = Capabilities{} // detector + credential is independently invalid; keep this test isolated to the kind check
	_, err := NewSourcePlugin(m, refsrcPath, "")
	if err == nil {
		t.Fatal("NewSourcePlugin: want error for kind=detector, got nil")
	}
	if !errors.Is(err, ErrInvalid) {
		t.Errorf("NewSourcePlugin error = %v, want wrapping ErrInvalid", err)
	}
}

func TestNewSourcePluginRejectsInvalidManifest(t *testing.T) {
	m := testSourceManifest("refsrc")
	m.PluginAPI = 999 // ABI mismatch
	_, err := NewSourcePlugin(m, refsrcPath, "")
	if err == nil {
		t.Fatal("NewSourcePlugin: want error for invalid manifest, got nil")
	}
	if !errors.Is(err, ErrInvalid) {
		t.Errorf("NewSourcePlugin error = %v, want wrapping ErrInvalid", err)
	}
}

func TestNewSourcePluginID(t *testing.T) {
	m := testSourceManifest("refsrc")
	sp, err := NewSourcePlugin(m, refsrcPath, "")
	if err != nil {
		t.Fatalf("NewSourcePlugin: %v", err)
	}
	if got := sp.ID(); got != "refsrc" {
		t.Errorf("ID() = %q, want %q", got, "refsrc")
	}
}

// --- happy path against the REAL compiled reference plugin -------------

// TestSourcePluginQueryHappyPathCredentialPresent drives the real compiled
// plugins/source-reference subprocess through the whole real path (adapter
// -> plugin.Run -> subprocess) with a non-empty secret, asserting: the ABI
// round-trips, the deterministic sample value matches the documented
// rune-count function, and the capability-scoped credential actually
// reached the child (cred:"present").
func TestSourcePluginQueryHappyPathCredentialPresent(t *testing.T) {
	m := testSourceManifest("refsrc")
	sp, err := NewSourcePlugin(m, refsrcPath, "s3cr3t-fake")
	if err != nil {
		t.Fatalf("NewSourcePlugin: %v", err)
	}
	q := source.Query{ID: "exp-1", Expr: "up"}
	sig, err := sp.Query(context.Background(), q)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if sig.QueryID != q.ID {
		t.Errorf("QueryID = %q, want %q", sig.QueryID, q.ID)
	}
	if sig.State != contract.StateOK {
		t.Errorf("State = %v, want StateOK", sig.State)
	}
	if len(sig.Samples) != 1 {
		t.Fatalf("len(Samples) = %d, want exactly 1", len(sig.Samples))
	}
	wantValue := float64(len([]rune(q.Expr)))
	if sig.Samples[0].Value != wantValue {
		t.Errorf("Samples[0].Value = %v, want %v (rune count of %q)", sig.Samples[0].Value, wantValue, q.Expr)
	}
	if got := sig.Samples[0].Labels["cred"]; got != "present" {
		t.Errorf(`Samples[0].Labels["cred"] = %q, want "present"`, got)
	}
	if got := sig.Samples[0].Labels["query_id"]; got != q.ID {
		t.Errorf(`Samples[0].Labels["query_id"] = %q, want %q`, got, q.ID)
	}
}

// TestSourcePluginQueryHappyPathCredentialAbsent is the same real-subprocess
// path with an empty secret: the reference plugin must observe no non-empty
// HEIMDALL_PLUGIN_SECRET and report cred:"absent".
func TestSourcePluginQueryHappyPathCredentialAbsent(t *testing.T) {
	m := testSourceManifest("refsrc")
	sp, err := NewSourcePlugin(m, refsrcPath, "")
	if err != nil {
		t.Fatalf("NewSourcePlugin: %v", err)
	}
	q := source.Query{ID: "exp-2", Expr: "vector(1)"}
	sig, err := sp.Query(context.Background(), q)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(sig.Samples) != 1 {
		t.Fatalf("len(Samples) = %d, want exactly 1", len(sig.Samples))
	}
	if got := sig.Samples[0].Labels["cred"]; got != "absent" {
		t.Errorf(`Samples[0].Labels["cred"] = %q, want "absent"`, got)
	}
}

// --- fail-closed decodes, driven by the REAL badsrc misbehaving subprocess

func TestSourcePluginQueryWrongPluginAPIIsUnknownWithErr(t *testing.T) {
	m := testSourceManifest("badsrc")
	m.Capabilities = Capabilities{} // badsrc needs no credential
	sp, err := NewSourcePlugin(m, badsrcPath, "")
	if err != nil {
		t.Fatalf("NewSourcePlugin: %v", err)
	}
	sig, err := sp.Query(context.Background(), source.Query{ID: "q1", Expr: "badabi:x"})
	if err == nil {
		t.Fatal("Query: want error for a plugin_api mismatch, got nil")
	}
	if sig.State != contract.StateUnknown {
		t.Errorf("State = %v, want StateUnknown", sig.State)
	}
	if sig.Err == "" {
		t.Error("Signal.Err = \"\", want a non-empty reason")
	}
}

func TestSourcePluginQueryMissingQueryIDIsUnknownWithErr(t *testing.T) {
	m := testSourceManifest("badsrc")
	m.Capabilities = Capabilities{}
	sp, err := NewSourcePlugin(m, badsrcPath, "")
	if err != nil {
		t.Fatalf("NewSourcePlugin: %v", err)
	}
	sig, err := sp.Query(context.Background(), source.Query{ID: "q1", Expr: "noquery:x"})
	if err == nil {
		t.Fatal("Query: want error when the plugin drops the asked query_id, got nil")
	}
	if sig.State != contract.StateUnknown {
		t.Errorf("State = %v, want StateUnknown", sig.State)
	}
}

// TestSourcePluginQueryUnrecognizedStateDegradesWithoutError documents the
// deliberate split: an unrecognized state string is a legitimate (if
// garbled) answer from a plugin that ran cleanly and answered the query we
// asked about — unlike an ABI mismatch or a dropped query_id, it is NOT an
// envelope-level failure, so Query degrades the Signal to StateUnknown
// (carrying the raw string in Err) but returns a nil error, exactly as it
// would for a plugin that legitimately reported "unknown".
func TestSourcePluginQueryUnrecognizedStateDegradesWithoutError(t *testing.T) {
	m := testSourceManifest("badsrc")
	m.Capabilities = Capabilities{}
	sp, err := NewSourcePlugin(m, badsrcPath, "")
	if err != nil {
		t.Fatalf("NewSourcePlugin: %v", err)
	}
	sig, err := sp.Query(context.Background(), source.Query{ID: "q1", Expr: "badstate:x"})
	if err != nil {
		t.Fatalf("Query: want nil error for an unrecognized-but-present state, got %v", err)
	}
	if sig.State != contract.StateUnknown {
		t.Errorf("State = %v, want StateUnknown", sig.State)
	}
	if !strings.Contains(sig.Err, "spooky-unrecognized-state") {
		t.Errorf("Signal.Err = %q, want it to carry the raw unrecognized state string", sig.Err)
	}
}

func TestSourcePluginQueryNonZeroExitIsUnknownWithErrNonZeroExit(t *testing.T) {
	m := testSourceManifest("badsrc")
	m.Capabilities = Capabilities{}
	sp, err := NewSourcePlugin(m, badsrcPath, "")
	if err != nil {
		t.Fatalf("NewSourcePlugin: %v", err)
	}
	sig, err := sp.Query(context.Background(), source.Query{ID: "q1", Expr: "crash:x"})
	if err == nil {
		t.Fatal("Query: want error for a non-zero exit, got nil")
	}
	if !errors.Is(err, ErrNonZeroExit) {
		t.Errorf("Query error = %v, want wrapping ErrNonZeroExit", err)
	}
	if sig.State != contract.StateUnknown {
		t.Errorf("State = %v, want StateUnknown", sig.State)
	}
}

func TestSourcePluginQueryMalformedJSONIsUnknownWithErr(t *testing.T) {
	m := testSourceManifest("badsrc")
	m.Capabilities = Capabilities{}
	sp, err := NewSourcePlugin(m, badsrcPath, "")
	if err != nil {
		t.Fatalf("NewSourcePlugin: %v", err)
	}
	sig, err := sp.Query(context.Background(), source.Query{ID: "q1", Expr: "malformed:x"})
	if err == nil {
		t.Fatal("Query: want error for malformed JSON stdout, got nil")
	}
	if sig.State != contract.StateUnknown {
		t.Errorf("State = %v, want StateUnknown", sig.State)
	}
}
