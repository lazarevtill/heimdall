//go:build !unix

package main

import "os/exec"

// setProcessGroup is a no-op on non-unix platforms: there is no portable
// process-group primitive, so Run falls back to killing the process leader
// only (see killProcessGroup).
func setProcessGroup(cmd *exec.Cmd) {}

// killProcessGroup falls back to killing just the process leader.
func killProcessGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	return cmd.Process.Kill()
}
