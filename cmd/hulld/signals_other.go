//go:build !linux

package main

import (
	"os"
	"syscall"
)

// shutdownSignals are the signals that start a graceful drain on a platform
// that is not Linux. hulld only runs for real inside the engine distro; this
// exists so the package still builds and vets everywhere.
func shutdownSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM}
}
