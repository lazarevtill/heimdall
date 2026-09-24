package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// Operator actions that run a local command — "re-run detect", "force
// drain". This is the console's only path to process control, and it is
// built to be boring on purpose.
//
// THE INJECTION ARGUMENT. Nothing from an HTTP request ever reaches a
// command. An action is selected by NAME from a fixed, config-declared map;
// the argv was parsed at boot from configuration and is never assembled
// from, appended to, or templated with request data. A request can only
// choose among argvs the operator already wrote down, so there is no input
// for a shell to mis-parse — which is why no shell is involved either
// (exec.CommandContext, never `sh -c`).
//
// DISABLED BY DEFAULT. An action with no configured command does not exist:
// the endpoint answers 501 and the button is not rendered. A web-facing
// daemon that can run commands is a real surface, so it is opt-in, per
// action, with the exact argv written out by the operator.

// ErrActionNotConfigured is returned when a named action has no command.
var ErrActionNotConfigured = errors.New("action not configured")

// maxActionOutputBytes bounds captured output, for diagnostics only. A
// command that floods stdout must not put that flood in a log line, an HTTP
// response — or the console's memory: the cap is applied AS the output
// arrives (cappedBuffer), not after the whole flood has been buffered.
const maxActionOutputBytes = 4 << 10

// actionWaitDelay bounds how long Run waits for the command's output pipes to
// close once the command has exited or its context is done. Without it,
// exec reads until EOF, and EOF never comes while any descendant that
// escaped the process group (a daemonising child, `setsid`) still holds the
// pipe: the handler would block past every deadline and the operator would
// see a dead connection.
const actionWaitDelay = 2 * time.Second

// Action is one operator-invocable command.
type Action struct {
	// Name is the URL-safe identifier ("rerun-detect", "force-drain").
	Name string
	// Label is what the button says.
	Label string
	// Argv is the fixed command, argv[0] plus arguments, parsed from config
	// at boot. Never derived from a request.
	Argv []string
	// Timeout bounds the run.
	Timeout time.Duration
}

// ActionSet is the configured actions, keyed by name.
type ActionSet map[string]Action

// Names returns the configured action names in a stable order.
func (a ActionSet) Names() []string {
	out := make([]string, 0, len(a))
	for n := range a {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// ActionResult reports one run.
type ActionResult struct {
	Name     string
	ExitCode int
	Output   string
	Duration time.Duration
}

// Runner executes an action. It is an interface so the server's tests drive
// a fake and never fork a real process.
type Runner interface {
	Run(ctx context.Context, a Action) (ActionResult, error)
}

// ExecRunner runs actions as real subprocesses.
type ExecRunner struct{}

// Run executes a.Argv with a hard deadline and a bounded output capture.
//
// The child is started in its own process group and the GROUP is killed on
// timeout, so a command that forks (systemctl handing off to systemd is the
// normal case) cannot leave a child running past the deadline. This mirrors
// internal/plugin's host discipline for exactly the same reason.
func (ExecRunner) Run(ctx context.Context, a Action) (ActionResult, error) {
	if len(a.Argv) == 0 {
		return ActionResult{Name: a.Name}, fmt.Errorf("action %q: %w", a.Name, ErrActionNotConfigured)
	}

	timeout := a.Timeout
	if timeout <= 0 {
		timeout = defaultActionTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, a.Argv[0], a.Argv[1:]...)
	// Empty, not inherited: the console's environment may hold the UI token
	// and sink credentials, and an operator action has no business seeing
	// them. Same stance as the plugin host's scrubbed env.
	cmd.Env = []string{}
	setProcessGroup(cmd)
	cmd.Cancel = func() error { return killProcessGroup(cmd) }
	cmd.WaitDelay = actionWaitDelay

	// One writer for both streams: exec then runs a single copy goroutine,
	// so cappedBuffer needs no lock.
	capture := &cappedBuffer{limit: maxActionOutputBytes}
	cmd.Stdout = capture
	cmd.Stderr = capture

	start := time.Now()
	err := cmd.Run()
	elapsed := time.Since(start)

	out := capture.buf.String()
	if capture.truncated {
		out += "\n… output truncated"
	}
	res := ActionResult{
		Name:     a.Name,
		Output:   strings.TrimSpace(out),
		Duration: elapsed,
	}

	if ctx.Err() == context.DeadlineExceeded {
		res.ExitCode = -1
		return res, fmt.Errorf("action %q: timed out after %s", a.Name, timeout)
	}
	if errors.Is(err, exec.ErrWaitDelay) {
		// The command itself exited 0; something it started kept the output
		// pipe open past actionWaitDelay. That is a success whose captured
		// output may be incomplete — reporting it as a failure would tell
		// the operator an action failed that did not.
		res.Output = strings.TrimSpace(res.Output + "\n(a background process kept the output open; output may be incomplete)")
		return res, nil
	}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			res.ExitCode = ee.ExitCode()
			return res, fmt.Errorf("action %q: exit %d", a.Name, res.ExitCode)
		}
		res.ExitCode = -1
		return res, fmt.Errorf("action %q: %w", a.Name, err)
	}
	return res, nil
}

// cappedBuffer keeps the first limit bytes written to it and discards the
// rest, while reporting every write as complete. Discarding rather than
// failing matters: a short write would reach the child as EPIPE/SIGPIPE and
// change the command's own outcome merely because it was chatty.
type cappedBuffer struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	room := c.limit - c.buf.Len()
	switch {
	case len(p) <= room:
		c.buf.Write(p)
	case room > 0:
		c.buf.Write(p[:room])
		c.truncated = true
	default:
		c.truncated = c.truncated || len(p) > 0
	}
	return len(p), nil
}

// defaultActionTimeout bounds an action that declares none.
const defaultActionTimeout = 30 * time.Second

// actionWriteHeadroom is kept between the longest permitted action and the
// server's write deadline. That deadline runs from when the request's
// headers were read, and a timed-out action still costs the kill, up to
// actionWaitDelay for its pipes, and the redirect write. An action allowed
// the FULL write timeout therefore always lost its response exactly when it
// timed out — the one run whose outcome the operator most needs to see.
const actionWriteHeadroom = 5 * time.Second

// actionTimeoutLimit is the EXCLUSIVE ceiling for a configured action
// timeout. At or past it the command still completes in its own process
// group, but the response carrying its result may be cut — so the operator
// sees a dead connection and cannot tell whether the action ran. Refused at
// boot rather than shipped as that ambiguity.
const actionTimeoutLimit = writeTimeout - actionWriteHeadroom
