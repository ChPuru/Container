//go:build !windows

package wslbridge

import "os/exec"

// hideWindow is a no-op off Windows, where there is no console window to hide.
// It exists so the spawning code is shared rather than duplicated per platform.
func hideWindow(cmd *exec.Cmd) { _ = cmd }
