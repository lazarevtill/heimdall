package plugin

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// stderrCapBytes bounds the diagnostic stderr capture. Its only purpose is
// to appear in an error message, so it stays small and is never subject to
// the fail-closed kill that MaxOutputBytes triggers on stdout.
const stderrCapBytes = 4 << 10

// waitDelay bounds cmd.Wait once the deadline has fired or the child has
// exited: it waits at most this long more for the goroutine feeding the
// child's stdin, then closes the pipes and returns. Without it, a descendant
// that escaped the process group and holds stdin open (never reading it)
// could keep Wait — and so Run — blocked long after the deadline.
const waitDelay = 2 * time.Second

// scrubbedSecret is what replaces the injected credential's exact value
// wherever plugin-authored text (stderr, a per-query err, a quoted state
// string) is carried into an error. The redaction library only recognises
// secret SHAPES; a plugin credential can have any shape, but the host knows
// its exact value, so it removes that value itself — the same stance the
// in-process transports take for their own credentials.
const scrubbedSecret = "[REDACTED:plugin-credential]"

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
//   - the deadline elapses (the child AND its process group are killed) —
//     and the deadline holds even when a descendant has escaped the process
//     group and still holds stdout/stderr open: the host closes its own read
//     ends at the deadline instead of waiting for that descendant's exit
//   - stdout exceeds budget.MaxOutputBytes (child killed, output discarded)
//   - reading stdout fails for any reason other than EOF
//
// Environment is SCRUBBED: the child inherits NOTHING from the host env. The
// child's env is exactly: nothing, plus (iff kind==source and
// Capabilities.Credential != "") one var "<Credential>=<Secret>". No PATH,
// no HOME, no inherited secrets. (Go's exec.Cmd does not leak parent fds
// beyond the pipes we set, and we set Stdin/Stdout/Stderr explicitly.)
//
// stderr is captured (also capped) and, on a non-zero exit or signal, folded
// into the returned error for diagnostics — but NEVER into the returned
// stdout. When opts.Secret is non-empty, its exact value is scrubbed out of
// that stderr text before it goes anywhere (see scrubbedSecret).
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
	cmd.WaitDelay = waitDelay

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
		// Capture len(secret) bytes past the cap, so a credential that
		// straddles the cap is scrubbed whole BEFORE the text is cut —
		// cutting first would leave its head behind, unrecognisable.
		stderrBuf = readTruncated(stderrPipe, stderrCapBytes+len(opts.Secret))
	}()

	// The readers finish at EOF, i.e. when EVERY holder of the pipes' write
	// ends has closed them. The process-group kill reaches the child and
	// anything it forked in place — but not a descendant that left the group
	// (setsid, a double fork), which may hold stdout open for as long as it
	// likes. Waiting for EOF would then mean waiting for that descendant, not
	// for the deadline. So at the deadline the host closes its own read
	// ends, which ends both reads at once, whoever still holds the other end.
	readersDone := make(chan struct{})
	go func() {
		select {
		case <-runCtx.Done():
			_ = stdoutPipe.Close()
			_ = stderrPipe.Close()
		case <-readersDone:
		}
	}()
	wg.Wait()
	close(readersDone)

	waitErr := cmd.Wait()

	switch {
	case stdoutRes.overflow:
		return nil, fmt.Errorf("plugin: run %s: %w (cap %d bytes)", m.ID, ErrOutputTooLarge, m.Budgets.MaxOutputBytes)
	case runCtx.Err() != nil:
		return nil, fmt.Errorf("plugin: run %s: %w: %v", m.ID, ErrDeadlineExceeded, runCtx.Err())
	case waitErr != nil:
		stderrText := scrubSecret(string(stderrBuf), opts.Secret)
		if len(stderrText) > stderrCapBytes {
			stderrText = stderrText[:stderrCapBytes]
		}
		return nil, fmt.Errorf("plugin: run %s: %w: %v: stderr: %s", m.ID, ErrNonZeroExit, waitErr, stderrText)
	case stdoutRes.err != nil:
		// A read that ended in anything but EOF: whatever arrived is not
		// known to be the whole output, and partial output is never
		// returned.
		return nil, fmt.Errorf("plugin: run %s: read stdout: %v", m.ID, stdoutRes.err)
	}
	return stdoutRes.data, nil
}

// scrubSecret replaces every occurrence of the injected credential's exact
// value in s with scrubbedSecret. An empty secret scrubs nothing (there is
// nothing to find, and ReplaceAll with an empty old string would insert the
// marker between every byte).
func scrubSecret(s, secret string) string {
	if secret == "" {
		return s
	}
	return strings.ReplaceAll(s, secret, scrubbedSecret)
}

// cappedResult is the outcome of a capped stdout read.
type cappedResult struct {
	data     []byte
	overflow bool
	err      error // a read failure other than EOF; data is then untrustworthy
}

// readCapped reads r to EOF or until more than limit bytes have arrived,
// whichever comes first. It reads through a limit+1 window into a buffer
// that grows with what actually arrives: memory tracks the output, never the
// declared cap, so a generous budget costs nothing until a plugin uses it.
// On overflow it calls kill (idempotent) so the child cannot keep producing
// output forever, drains and discards the rest of r so the child is never
// left blocked on a full pipe, and reports overflow=true with nil data —
// S3-a's contract is that an oversized output is discarded WHOLE, never
// partially returned.
func readCapped(r io.Reader, limit int, kill func()) cappedResult {
	var buf bytes.Buffer
	n, err := buf.ReadFrom(io.LimitReader(r, int64(limit)+1))
	if n > int64(limit) {
		kill()
		_, _ = io.Copy(io.Discard, r)
		return cappedResult{overflow: true}
	}
	if err != nil {
		return cappedResult{err: err}
	}
	return cappedResult{data: buf.Bytes()}
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
