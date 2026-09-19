//go:build !windows

package main

import (
	"os"

	"golang.org/x/sys/unix"
)

// interruptSignals are the signals that should unwind one of the hidden
// plumbing processes.
//
// SIGHUP is included because the relay's usual death is its terminal or its
// parent going away, and it must tear its streams down rather than linger
// inside the distro holding connections open.
func interruptSignals() []os.Signal {
	return []os.Signal{unix.SIGINT, unix.SIGTERM, unix.SIGHUP}
}
