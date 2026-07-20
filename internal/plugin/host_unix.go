//go:build unix

package plugin

import (
	"os/exec"
	"syscall"
)

// setupProcessGroup makes the child the leader of its own process group so
// killProcessGroup can later kill it and every descendant it forked as one
// unit — a plugin that forks cannot outlive Run's deadline or output cap.
func setupProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// killProcessGroup sends SIGKILL to the negative pgid, i.e. the whole
// process group rooted at cmd's process, not just the process leader.
func killProcessGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}
