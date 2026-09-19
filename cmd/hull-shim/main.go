// Command hull-shim supervises exactly one hull container.
//
// It is never run by hand. hulld spawns it double-forked and setsid'd, hands
// it its configuration on file descriptor 3 and reads one line of readiness
// from file descriptor 4; from then on it is reparented to PID 1 and talks to
// the daemon only over <containerDir>/shim.sock.
//
// Everything the container cannot afford to lose lives here: its init's pidfd,
// its pty master, its json-file log writer and its exit status. Kill hulld and
// the container keeps running; restart hulld and it reconnects to this process
// and picks up exactly where it left off.
//
// All the logic is in internal/shim, which is where its tests live too.
package main

import (
	"os"

	"github.com/rahuldhali/hull/internal/shim"
)

func main() {
	os.Exit(shim.Main())
}
