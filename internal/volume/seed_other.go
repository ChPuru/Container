//go:build !linux

package volume

import (
	"fmt"

	"github.com/ChPuru/hull/internal/fsutil"
)

// copyImageContent is Linux-only: seeding a volume from image content needs
// fd-relative openat, mknodat and symlinkat, and only the engine — which runs
// exclusively inside the WSL distro — ever performs it. The Windows CLI links
// this stub so the parsing half of the package still builds there.
func copyImageContent(dest, rootfs, rel string) (bool, error) {
	return false, fmt.Errorf("volume: seed %s from %s/%s: %w", dest, rootfs, rel, fsutil.ErrUnsupported)
}
