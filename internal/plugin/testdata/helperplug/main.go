// Command helperplug is a stdlib-only fixture used by internal/plugin's
// tests to drive Run against a REAL subprocess (not a mock). Its mode is
// carried in stdin JSON, not env or args, mirroring the real ABI: plugins
// are configured via stdin, and the host's env is scrubbed anyway.
//
// This file lives under testdata/ so the go tool never builds, vets, or
// tests it as part of the module; internal/plugin's TestMain compiles it
// on demand to a temp path.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"
)

type request struct {
	Mode    string `json:"mode"`
	N       int    `json:"n,omitempty"`       // mode bytes: how many bytes to write
	PIDFile string `json:"pidfile,omitempty"` // modes escape*: where to record the escapee's pid
}

// sleeperArg is argv[1] for the re-executed escapee: a descendant that has
// left the plugin's process group (and session) and simply holds the
// inherited stdout open for a long time.
const sleeperArg = "sleeper"

func main() {
	if len(os.Args) > 1 && os.Args[1] == sleeperArg {
		time.Sleep(30 * time.Second)
		return
	}
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "helperplug: read stdin:", err)
		os.Exit(2)
	}
	var req request
	if err := json.Unmarshal(raw, &req); err != nil {
		fmt.Fprintln(os.Stderr, "helperplug: parse stdin:", err)
		os.Exit(2)
	}

	switch req.Mode {
	case "echo":
		os.Stdout.Write([]byte(`{"canned":"heimdall-refplug-fixture"}`))
	case "slow":
		time.Sleep(10 * time.Second)
		os.Stdout.Write([]byte(`{"should":"never appear"}`))
	case "flood":
		chunk := make([]byte, 64*1024)
		for i := range chunk {
			chunk[i] = 'x'
		}
		// Write far more than any reasonable test cap; Run is expected to
		// kill this process before the loop finishes.
		for i := 0; i < 1024; i++ {
			if _, err := os.Stdout.Write(chunk); err != nil {
				return
			}
		}
	case "bytes":
		os.Stdout.Write(bytes.Repeat([]byte{'x'}, req.N))
	case "crash":
		fmt.Fprintln(os.Stderr, "helperplug: simulated crash")
		os.Exit(1)
	case "leaksecret":
		// A plugin that prints its own credential while failing — the
		// kind of "auth failed for key ..." line a real client emits.
		fmt.Fprintln(os.Stderr, "helperplug: auth failed with key", os.Getenv("HEIMDALL_PLUGIN_SECRET"))
		os.Exit(1)
	case "escape", "escape-hang":
		// Start a descendant in a NEW SESSION (so outside the process
		// group the host kills) that inherits stdout and holds it open,
		// then either exit cleanly with valid output or hang.
		pid, err := startEscapee()
		if err != nil {
			fmt.Fprintln(os.Stderr, "helperplug: setsid unavailable:", err)
			os.Exit(3)
		}
		if err := os.WriteFile(req.PIDFile, []byte(strconv.Itoa(pid)), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "helperplug: write pidfile:", err)
			os.Exit(2)
		}
		if req.Mode == "escape-hang" {
			time.Sleep(10 * time.Second)
		}
		os.Stdout.Write([]byte(`{"canned":"heimdall-refplug-fixture"}`))
	case "leakenv":
		env := os.Environ()
		out, err := json.Marshal(env)
		if err != nil {
			fmt.Fprintln(os.Stderr, "helperplug: marshal environ:", err)
			os.Exit(2)
		}
		os.Stdout.Write(out)
	default:
		fmt.Fprintln(os.Stderr, "helperplug: unknown mode", req.Mode)
		os.Exit(2)
	}
}
