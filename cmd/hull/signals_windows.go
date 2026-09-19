//go:build windows

package main

import (
	"os"
	"syscall"
)

// interruptSignals are the signals that should unwind one of the hidden
// plumbing processes.
//
// Windows delivers Ctrl-C and Ctrl-Break as os.Interrupt and has no SIGHUP or
// SIGQUIT, so the set is deliberately smaller than the Unix one rather than
// referring to signals the runtime will never raise.
func interruptSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM}
}
