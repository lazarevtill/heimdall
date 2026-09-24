//go:build unix

package main

import (
	"os"
	"syscall"
)

// startEscapee re-executes this binary as a sleeper in a new session: it
// shares no process group with the plugin, so a process-group kill cannot
// reach it, and it inherits (and holds open) the plugin's stdout.
func startEscapee() (int, error) {
	self, err := os.Executable()
	if err != nil {
		return 0, err
	}
	p, err := os.StartProcess(self, []string{self, sleeperArg}, &os.ProcAttr{
		Files: []*os.File{nil, os.Stdout, os.Stderr},
		Sys:   &syscall.SysProcAttr{Setsid: true},
	})
	if err != nil {
		return 0, err
	}
	pid := p.Pid // read before Release, which resets it
	return pid, p.Release()
}
