package foldersync

import "context"

// watchResult is what one wait on the volume-side watcher produced.
type watchResult struct {
	// changed is true when at least one interesting event arrived.
	changed bool

	// overflow is true when the kernel dropped events. The queue is gone and
	// cannot be replayed, so the only honest recovery is a full scan.
	overflow bool

	// paths lists the relative paths the events named, best effort. It is
	// advisory - a reconciliation pass never trusts it - and exists so the
	// caller can say what woke it.
	paths []string
}

// treeWatcher is the volume-side change source: inotify on Linux, nothing
// anywhere else. It is an interface so that the Run loop, the overflow
// handling and the tests are all platform-independent, and so that a build for
// GOOS=windows - which the hull CLI needs - still compiles.
type treeWatcher interface {
	// wait blocks until something happens under the watched tree, the context
	// is done, or the watch fails.
	wait(ctx context.Context) (watchResult, error)

	// rearm re-adds watches across the whole tree. It is what the syncer does
	// after an overflow, when directories may have been created while the
	// queue was being dropped and their watches never added.
	rearm() error

	// watchCount reports how many directories are currently watched.
	watchCount() int

	// close releases the watch descriptors.
	close() error
}
