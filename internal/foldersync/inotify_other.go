//go:build !linux

package foldersync

import "fmt"

// newTreeWatcher has nothing to open anywhere but Linux. The hull CLI is built
// for windows/amd64 and links this package for "hull sync", so the package has
// to compile there; what it cannot do there is watch, and Run says so by
// falling back to polling both sides rather than failing.
func newTreeWatcher(root string, ig *Ignorer) (treeWatcher, error) {
	return nil, fmt.Errorf("%w: inotify is Linux-only, so %s must be polled", ErrUnsupported, root)
}
