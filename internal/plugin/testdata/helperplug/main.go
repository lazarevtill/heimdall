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
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"
)

type request struct {
	Mode string `json:"mode"`
}

func main() {
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
	case "crash":
		fmt.Fprintln(os.Stderr, "helperplug: simulated crash")
		os.Exit(1)
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
