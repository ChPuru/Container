//go:build !linux

package logbuf

// newChangeWatcher falls back to timed polling off Linux, where hull never
// tails a container log from disk anyway.
func newChangeWatcher(path string) changeWatcher { return pollWatcher{} }
