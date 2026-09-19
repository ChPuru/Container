//go:build !linux

// Command hull-init is the in-container stage of hull's native runtime. It is
// Linux-only by nature - it exists to drive namespaces, pivot_root, capability
// sets and seccomp - so on every other platform it is a stub that says so
// rather than a package that fails to build.
package main

import (
	"fmt"
	"os"
	"runtime"
)

func main() {
	fmt.Fprintf(os.Stderr,
		"hull-init runs inside a Linux container; there is nothing for it to do on %s/%s\n",
		runtime.GOOS, runtime.GOARCH)
	os.Exit(1)
}
