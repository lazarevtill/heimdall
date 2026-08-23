package main

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestActionSetNamesAreSorted(t *testing.T) {
	set := ActionSet{
		"force-drain":  {Name: "force-drain"},
		"rerun-detect": {Name: "rerun-detect"},
		"a-first":      {Name: "a-first"},
	}
	got := set.Names()
	want := []string{"a-first", "force-drain", "rerun-detect"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Names() = %v, want %v", got, want)
		}
	}
}

func TestExecRunnerRunsConfiguredArgv(t *testing.T) {
	res, err := ExecRunner{}.Run(context.Background(), Action{
		Name: "echo", Argv: []string{"/bin/sh", "-c", "printf hello"}, Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Output != "hello" {
		t.Errorf("Output = %q, want %q", res.Output, "hello")
	}
	if res.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0", res.ExitCode)
	}
}

func TestExecRunnerReportsExitCode(t *testing.T) {
	res, err := ExecRunner{}.Run(context.Background(), Action{
		Name: "fail", Argv: []string{"/bin/sh", "-c", "echo nope >&2; exit 3"}, Timeout: 5 * time.Second,
	})
	if err == nil {
		t.Fatal("want an error for a non-zero exit")
	}
	if res.ExitCode != 3 {
		t.Errorf("ExitCode = %d, want 3", res.ExitCode)
	}
	// stderr is folded into the captured output for diagnostics.
	if !strings.Contains(res.Output, "nope") {
		t.Errorf("Output = %q, want it to carry stderr", res.Output)
	}
}

func TestExecRunnerUnconfiguredActionIsRefused(t *testing.T) {
	_, err := ExecRunner{}.Run(context.Background(), Action{Name: "empty"})
	if !errors.Is(err, ErrActionNotConfigured) {
		t.Fatalf("want ErrActionNotConfigured, got %v", err)
	}
}

func TestExecRunnerEnforcesTheDeadline(t *testing.T) {
	start := time.Now()
	res, err := ExecRunner{}.Run(context.Background(), Action{
		Name: "sleeper", Argv: []string{"/bin/sh", "-c", "sleep 30"}, Timeout: 300 * time.Millisecond,
	})
	if err == nil {
		t.Fatal("want a timeout error")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("error = %q, want it to name the timeout", err)
	}
	if res.ExitCode != -1 {
		t.Errorf("ExitCode = %d, want -1 for a killed action", res.ExitCode)
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Errorf("the deadline was not enforced: took %s", elapsed)
	}
}

// The console's environment holds the UI bearer token and, when routing is
// configured, sink credentials. An operator action has no business seeing
// any of it.
func TestExecRunnerScrubsTheEnvironment(t *testing.T) {
	t.Setenv("HEIMDALL_UI_TOKEN", "super-secret-token-value")
	res, err := ExecRunner{}.Run(context.Background(), Action{
		Name: "env", Argv: []string{"/bin/sh", "-c", "env"}, Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if strings.Contains(res.Output, "super-secret-token-value") {
		t.Fatalf("the action inherited the console's environment:\n%s", res.Output)
	}
	if strings.Contains(res.Output, "HEIMDALL_UI_TOKEN") {
		t.Fatalf("the action saw a HEIMDALL_ var name:\n%s", res.Output)
	}
}

func TestExecRunnerCapsOutput(t *testing.T) {
	res, err := ExecRunner{}.Run(context.Background(), Action{
		Name: "flood",
		// Emit well over the cap.
		Argv:    []string{"/bin/sh", "-c", "i=0; while [ $i -lt 2000 ]; do echo aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; i=$((i+1)); done"},
		Timeout: 20 * time.Second,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Output) > maxActionOutputBytes+64 {
		t.Errorf("output not capped: %d bytes", len(res.Output))
	}
	if !strings.Contains(res.Output, "truncated") {
		t.Error("a capped output should say so")
	}
}

// A forking action must not outlive its deadline. `sh -c` backgrounding a
// long sleep is exactly the systemctl-hands-off-to-systemd shape.
func TestExecRunnerKillsTheProcessGroup(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	start := time.Now()
	_, err := ExecRunner{}.Run(context.Background(), Action{
		Name:    "forker",
		Argv:    []string{"/bin/sh", "-c", "sleep 30 & wait"},
		Timeout: 300 * time.Millisecond,
	})
	if err == nil {
		t.Fatal("want a timeout error")
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Errorf("a forked child outlived the deadline: took %s", elapsed)
	}
}

func TestExecRunnerHonoursCallerCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := ExecRunner{}.Run(ctx, Action{
		Name: "cancelled", Argv: []string{"/bin/sh", "-c", "sleep 5"}, Timeout: 10 * time.Second,
	})
	if err == nil {
		t.Fatal("want an error for an already-cancelled context")
	}
}
