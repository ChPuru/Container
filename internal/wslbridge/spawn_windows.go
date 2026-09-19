//go:build windows

package wslbridge

import (
	"os/exec"
	"syscall"
)

// createNoWindow is CREATE_NO_WINDOW: the child gets no console of its own.
// Without it every relay and keep-alive restart flashes a console window when
// hull.exe was started from Explorer or from a GUI terminal host.
const createNoWindow = 0x08000000

// hideWindow keeps a spawned wsl.exe from opening a console window.
func hideWindow(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.HideWindow = true
	cmd.SysProcAttr.CreationFlags |= createNoWindow
}
