package main

import (
	"os"

	"golang.org/x/sys/unix"
)

// shutdownSignals are the signals that start a graceful drain.
//
// SIGTERM is what a supervisor sends, SIGINT what a person sends from a
// terminal, and SIGHUP is what WSL delivers when the distro's session goes
// away — which happens routinely, so treating it as a crash would make the
// daemon look unreliable when it is merely being shut down.
func shutdownSignals() []os.Signal {
	return []os.Signal{unix.SIGTERM, unix.SIGINT, unix.SIGHUP}
}
