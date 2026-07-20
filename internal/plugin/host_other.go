//go:build !unix

package plugin

import "os/exec"

// setupProcessGroup is a no-op on non-unix platforms: there is no portable
// process-group primitive here, so Run falls back to killing the process
// leader only (see killProcessGroup).
func setupProcessGroup(cmd *exec.Cmd) {}

// killProcessGroup falls back to killing just the process leader on
// non-unix platforms.
func killProcessGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	return cmd.Process.Kill()
}
