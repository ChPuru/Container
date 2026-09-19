//go:build !linux

package shim

import (
	"context"
	"fmt"
	"os"
	"runtime"
)

// errNotLinux explains why the supervising half of this package does nothing
// off Linux: it rests on pidfds, PR_SET_CHILD_SUBREAPER and the OCI
// console-socket protocol, none of which exist elsewhere. Only the protocol,
// the client and the state files are portable, which is enough for the parts
// of hull that cross-compile.
func errNotLinux(what string) error {
	return fmt.Errorf("shim: %s is only supported on linux, not %s", what, runtime.GOOS)
}

// Spawn is Linux-only. See the Linux implementation for the contract.
func Spawn(ctx context.Context, shimBinary string, cfg Config) (*Client, error) {
	return nil, errNotLinux("spawning a container shim")
}

// Supervise is Linux-only. See the Linux implementation for the contract.
func Supervise(ctx context.Context, cfg Config, ready *os.File) error {
	return errNotLinux("supervising a container")
}

// Run is Linux-only. See the Linux implementation for the contract.
func Run(ctx context.Context) error {
	return errNotLinux("running the container shim")
}

// Main is Linux-only. It reports a non-zero exit code everywhere else.
func Main() int {
	_, _ = fmt.Fprintln(os.Stderr, errNotLinux("hull-shim"))
	return 2
}
