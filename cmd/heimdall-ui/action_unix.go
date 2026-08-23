//go:build unix

package main

import (
	"os/exec"
	"syscall"
)

// setProcessGroup makes the child the leader of its own process group so
// killProcessGroup can kill it and every descendant as one unit. An action
// that forks — `systemctl start`, which hands off to systemd, is the normal
// case — cannot outlive the deadline. Same discipline as internal/plugin's
// host, for the same reason.
func setProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// killProcessGroup sends SIGKILL to the negative pgid, i.e. the whole group
// rooted at cmd's process, not just the leader.
func killProcessGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
		return cmd.Process.Kill()
	}
	return nil
}
