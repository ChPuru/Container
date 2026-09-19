package fsutil

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// fsyncDir opens dir read-only and fsyncs it, which is what persists a rename
// across a crash or a hard VM stop.
func fsyncDir(dir string) error {
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return &os.PathError{Op: "open", Path: dir, Err: err}
	}
	defer unix.Close(fd)
	if err := unix.Fsync(fd); err != nil {
		return fmt.Errorf("fsync %s: %w", dir, err)
	}
	return nil
}
