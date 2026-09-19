//go:build !linux

package seccompprof

// kernelVersion cannot be determined off Linux. LoadProfile therefore keeps
// any rule carrying a minKernel condition rather than dropping it: the only
// caller on a non-Linux build is the CLI validating a profile the user passed
// to --security-opt, and dropping rules there would make the CLI disagree
// with the daemon about what the profile contains.
func kernelVersion() (int, int, bool) { return 0, 0, false }
