package plugin

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"time"
)

// stderrCapBytes bounds the diagnostic stderr capture. Its only purpose is
// to appear in an error message, so it stays small and is never subject to
// the fail-closed kill that MaxOutputBytes triggers on stdout.
const stderrCapBytes = 4 << 10

// RunOptions carries the per-invocation inputs the host needs beyond the
// manifest. Secret is the credential VALUE (read by the caller from its
// LoadCredential/env-file — the host never reads files or env for secrets);
// it is injected into the child's env under manifest.Capabilities.Credential
// ONLY when that field is set and kind==source. Empty Secret with a declared
// Credential name is allowed (injects an empty var) — validation of secret
// presence is the caller's job, not the host's.
type RunOptions struct {
	ExePath string // absolute path to the plugin executable
	Secret  string // the one credential value, or "" (see above)
}

// ErrDeadlineExceeded is returned by Run when the context or the plugin's
// own budget deadline elapsed before the child exited. The child and its
// entire process group were killed; stdout so far is discarded.
var ErrDeadlineExceeded = errors.New("plugin: run deadline exceeded")

// ErrOutputTooLarge is returned by Run when the child's stdout exceeded
// budgets.max_output_bytes. The child and its process group were killed;
// stdout is discarded whole (never partially returned).
var ErrOutputTooLarge = errors.New("plugin: stdout exceeded max_output_bytes cap")

// ErrNonZeroExit is returned by Run when the child ran to completion within
// budget but exited with a non-zero status. The child's captured stderr (up
// to stderrCapBytes) is folded into the wrapping error for diagnostics.
var ErrNonZeroExit = errors.New("plugin: child exited non-zero")

// ErrStartFailed is returned by Run when the child process could not be
// started at all (missing or non-executable binary, pipe setup failure).
var ErrStartFailed = errors.New("plugin: failed to start child process")

// Run executes the plugin as a subprocess: it writes stdin to the child's
// stdin, waits up to min(ctx deadline, budget.DeadlineSeconds) for it to
// exit, and returns the child's stdout (capped at budget.MaxOutputBytes).
//
// Fail-closed guarantees (every one returns a non-nil error, stdout
// discarded):
//   - manifest.Validate() fails
//   - exec fails to start (missing/non-executable binary)
//   - the child exits non-zero
//   - the deadline elapses (the child AND its process group are killed)
//   - stdout exceeds budget.MaxOutputBytes (child killed, output discarded)
//
// Environment is SCRUBBED: the child inherits NOTHING from the host env. The
// child's env is exactly: nothing, plus (iff kind==source and
// Capabilities.Credential != "") one var "<Credential>=<Secret>". No PATH,
// no HOME, no inherited secrets. (Go's exec.Cmd does not leak parent fds
// beyond the pipes we set, and we set Stdin/Stdout/Stderr explicitly.)
//
// stderr is captured (also capped) and, on a non-zero exit or signal, folded
// into the returned error for diagnostics — but NEVER into the returned
// stdout.
//
// Run does NOT validate that stdout is well-formed JSON or that its
// plugin_api matches — that is the ABI-decode step, done by the typed
// decode helpers (DecodeSignalSet in S3-b) so the host stays kind-agnostic.
// Run's contract is purely: "ran to a clean exit within budget, here are the
// <=cap bytes it wrote."
func Run(ctx context.Context, m Manifest, opts RunOptions, stdin []byte) (stdout []byte, err error) {
	if err := m.Validate(); err != nil {
		return nil, fmt.Errorf("plugin: run %s: invalid manifest: %w", m.ID, err)
	}

	budget := time.Duration(m.Budgets.DeadlineSeconds) * time.Second
	runCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	cmd := exec.CommandContext(runCtx, opts.ExePath)
	setupProcessGroup(cmd)
	// Override the default cancel-on-ctx-done behavior (which only kills the
	// direct child) with a process-GROUP kill, so a plugin that forks cannot
	// outlive the deadline.
	cmd.Cancel = func() error { return killProcessGroup(cmd) }

	if m.Kind == KindSource && m.Capabilities.Credential != "" {
		cmd.Env = []string{m.Capabilities.Credential + "=" + opts.Secret}
	} else {
		cmd.Env = []string{}
	}
	cmd.Stdin = bytes.NewReader(stdin)

	stdoutPipe, perr := cmd.StdoutPipe()
	if perr != nil {
		return nil, fmt.Errorf("plugin: run %s: %w: stdout pipe: %v", m.ID, ErrStartFailed, perr)
	}
	stderrPipe, perr := cmd.StderrPipe()
	if perr != nil {
		return nil, fmt.Errorf("plugin: run %s: %w: stderr pipe: %v", m.ID, ErrStartFailed, perr)
	}

	if serr := cmd.Start(); serr != nil {
		return nil, fmt.Errorf("plugin: run %s: %w: %v", m.ID, ErrStartFailed, serr)
	}

	var killOnce sync.Once
	kill := func() { killOnce.Do(func() { _ = killProcessGroup(cmd) }) }

	var wg sync.WaitGroup
	var stdoutRes cappedResult
	var stderrBuf []byte
	wg.Add(2)
	go func() {
		defer wg.Done()
		stdoutRes = readCapped(stdoutPipe, m.Budgets.MaxOutputBytes, kill)
	}()
	go func() {
		defer wg.Done()
		stderrBuf = readTruncated(stderrPipe, stderrCapBytes)
	}()
	wg.Wait()

	waitErr := cmd.Wait()

	switch {
	case stdoutRes.overflow:
		return nil, fmt.Errorf("plugin: run %s: %w (cap %d bytes)", m.ID, ErrOutputTooLarge, m.Budgets.MaxOutputBytes)
	case runCtx.Err() != nil:
		return nil, fmt.Errorf("plugin: run %s: %w: %v", m.ID, ErrDeadlineExceeded, runCtx.Err())
	case waitErr != nil:
		return nil, fmt.Errorf("plugin: run %s: %w: %v: stderr: %s", m.ID, ErrNonZeroExit, waitErr, stderrBuf)
	}
	return stdoutRes.data, nil
}

// cappedResult is the outcome of a capped stdout read.
type cappedResult struct {
	data     []byte
	overflow bool
}

// readCapped reads r to EOF or until more than limit bytes have arrived,
// whichever comes first. On overflow it calls kill (idempotent) so the
// child cannot keep producing output forever, drains and discards the rest
// of r so the child is never left blocked on a full pipe, and reports
// overflow=true with nil data — S3-a's contract is that an oversized output
// is discarded WHOLE, never partially returned.
func readCapped(r io.Reader, limit int, kill func()) cappedResult {
	buf := make([]byte, 0, limit+1)
	chunk := make([]byte, 32*1024)
	for {
		n, err := r.Read(chunk)
		if n > 0 {
			if len(buf) <= limit {
				want := n
				if room := limit + 1 - len(buf); room < want {
					want = room
				}
				buf = append(buf, chunk[:want]...)
			}
			if len(buf) > limit {
				kill()
				_, _ = io.Copy(io.Discard, r)
				return cappedResult{overflow: true}
			}
		}
		if err != nil {
			break
		}
	}
	return cappedResult{data: buf}
}

// readTruncated reads r to EOF, retaining at most the first limit bytes.
// Unlike readCapped it never kills the child and never stops early — its
// only purpose is a small diagnostic stderr sample, not enforcement.
func readTruncated(r io.Reader, limit int) []byte {
	buf := make([]byte, 0, limit)
	chunk := make([]byte, 4096)
	for {
		n, err := r.Read(chunk)
		if n > 0 && len(buf) < limit {
			want := n
			if room := limit - len(buf); room < want {
				want = room
			}
			buf = append(buf, chunk[:want]...)
		}
		if err != nil {
			break
		}
	}
	return buf
}
