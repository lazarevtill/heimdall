package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

// helperplugPath is the path to the compiled testdata/helperplug fixture,
// built once in TestMain. Using a real subprocess (not a mock) is the point
// of this package's tests: Run's scrubbed-env, deadline, and output-cap
// guarantees only mean something against an actual OS process.
var helperplugPath string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "heimdall-plugin-test-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "helperplug: mkdtemp:", err)
		os.Exit(1)
	}
	helperplugPath = filepath.Join(dir, "helperplug")
	if runtime.GOOS == "windows" {
		helperplugPath += ".exe"
	}
	build := exec.Command("go", "build", "-o", helperplugPath, "./testdata/helperplug")
	build.Stdout = os.Stderr
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "helperplug: build failed:", err)
		os.RemoveAll(dir)
		os.Exit(1)
	}

	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func testManifest(kind Kind, deadlineSeconds, maxOutputBytes int) Manifest {
	return Manifest{
		PluginAPI: PluginAPIVersion,
		ID:        "refplug",
		Kind:      kind,
		Version:   "0.1.0-fixture",
		Budgets: Budgets{
			DeadlineSeconds: deadlineSeconds,
			MaxOutputBytes:  maxOutputBytes,
		},
	}
}

func stdinMode(mode string) []byte {
	b, err := json.Marshal(map[string]string{"mode": mode})
	if err != nil {
		panic(err)
	}
	return b
}

// 1. round-trip: mode echo => Run returns the canned bytes, nil error.
func TestRunEchoRoundTrip(t *testing.T) {
	m := testManifest(KindDetector, 5, 1<<20)
	out, err := Run(context.Background(), m, RunOptions{ExePath: helperplugPath}, stdinMode("echo"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	const want = `{"canned":"heimdall-refplug-fixture"}`
	if string(out) != want {
		t.Errorf("stdout = %q, want %q", out, want)
	}
}

// 2. deadline kill: mode slow with deadline_seconds:1 => Run returns a
// deadline-flavored error promptly (well under the 10s sleep), meaning the
// process-group kill fired instead of the child lingering.
func TestRunDeadlineKill(t *testing.T) {
	m := testManifest(KindDetector, 1, 1<<20)

	type result struct {
		out []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		out, err := Run(context.Background(), m, RunOptions{ExePath: helperplugPath}, stdinMode("slow"))
		done <- result{out, err}
	}()

	select {
	case r := <-done:
		if r.err == nil {
			t.Fatalf("Run: want a deadline error, got nil (out=%q)", r.out)
		}
		if !errors.Is(r.err, ErrDeadlineExceeded) {
			t.Errorf("Run error = %v, want wrapping ErrDeadlineExceeded", r.err)
		}
		if len(r.out) != 0 {
			t.Errorf("stdout = %q, want discarded (empty) on deadline kill", r.out)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return within 5s of a 1s deadline — process-group kill likely did not fire (child sleeps 10s)")
	}
}

// 3. output-cap kill: mode flood with a small max_output_bytes => error,
// returned stdout is discarded (nil/empty).
func TestRunOutputCapKill(t *testing.T) {
	m := testManifest(KindDetector, 5, 4096) // fixture floods 64MB
	out, err := Run(context.Background(), m, RunOptions{ExePath: helperplugPath}, stdinMode("flood"))
	if err == nil {
		t.Fatalf("Run: want an output-cap error, got nil (out=%d bytes)", len(out))
	}
	if !errors.Is(err, ErrOutputTooLarge) {
		t.Errorf("Run error = %v, want wrapping ErrOutputTooLarge", err)
	}
	if len(out) != 0 {
		t.Errorf("stdout = %d bytes, want discarded (empty)", len(out))
	}
}

// 4. non-zero exit: mode crash => error whose text carries the child's
// stderr line.
func TestRunCrashNonZeroExit(t *testing.T) {
	m := testManifest(KindDetector, 5, 1<<20)
	out, err := Run(context.Background(), m, RunOptions{ExePath: helperplugPath}, stdinMode("crash"))
	if err == nil {
		t.Fatalf("Run: want an error, got nil (out=%q)", out)
	}
	if !errors.Is(err, ErrNonZeroExit) {
		t.Errorf("Run error = %v, want wrapping ErrNonZeroExit", err)
	}
	const wantStderr = "helperplug: simulated crash"
	if !strings.Contains(err.Error(), wantStderr) {
		t.Errorf("Run error = %v, want it to contain child stderr %q", err, wantStderr)
	}
	if len(out) != 0 {
		t.Errorf("stdout = %q, want discarded (empty) on crash", out)
	}
}

// 5a. scrubbed env + capability-scoped credential: mode leakenv with a
// SOURCE manifest declaring Capabilities.Credential => the emitted environ
// contains exactly that one var with that value and nothing else.
func TestRunScrubbedEnvSourceCredentialInjected(t *testing.T) {
	m := testManifest(KindSource, 5, 1<<20)
	m.Capabilities.Credential = "HEIMDALL_PLUGIN_SECRET"
	out, err := Run(context.Background(), m, RunOptions{ExePath: helperplugPath, Secret: "s3cr3t-fake"}, stdinMode("leakenv"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var environ []string
	if err := json.Unmarshal(out, &environ); err != nil {
		t.Fatalf("unmarshal child environ: %v (out=%q)", err, out)
	}
	want := []string{"HEIMDALL_PLUGIN_SECRET=s3cr3t-fake"}
	if diff := cmp.Diff(want, environ); diff != "" {
		t.Errorf("child environ mismatch (-want +got):\n%s", diff)
	}
}

// 5b. same mode with a DETECTOR manifest (no credential) => the emitted
// environ is empty.
func TestRunScrubbedEnvDetectorEmpty(t *testing.T) {
	m := testManifest(KindDetector, 5, 1<<20)
	out, err := Run(context.Background(), m, RunOptions{ExePath: helperplugPath}, stdinMode("leakenv"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var environ []string
	if err := json.Unmarshal(out, &environ); err != nil {
		t.Fatalf("unmarshal child environ: %v (out=%q)", err, out)
	}
	if len(environ) != 0 {
		t.Errorf("child environ = %v, want empty (scrubbed)", environ)
	}
}

// Sanity: Run refuses to even start when the manifest itself is invalid.
func TestRunRejectsInvalidManifest(t *testing.T) {
	m := testManifest(KindDetector, 5, 1<<20)
	m.Capabilities.Credential = "SHOULD_NOT_BE_HERE" // detector + credential is invalid
	_, err := Run(context.Background(), m, RunOptions{ExePath: helperplugPath}, stdinMode("echo"))
	if err == nil {
		t.Fatal("Run: want error for invalid manifest, got nil")
	}
	if !errors.Is(err, ErrInvalid) {
		t.Errorf("Run error = %v, want wrapping ErrInvalid", err)
	}
}

// Sanity: a missing/non-executable binary fails to start, fail-closed.
func TestRunMissingBinary(t *testing.T) {
	m := testManifest(KindDetector, 5, 1<<20)
	_, err := Run(context.Background(), m, RunOptions{ExePath: filepath.Join(t.TempDir(), "does-not-exist")}, stdinMode("echo"))
	if err == nil {
		t.Fatal("Run: want error for a missing binary, got nil")
	}
	if !errors.Is(err, ErrStartFailed) {
		t.Errorf("Run error = %v, want wrapping ErrStartFailed", err)
	}
}
