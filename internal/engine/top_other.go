//go:build !linux

package engine

import (
	"context"
	"fmt"
	"runtime"
)

// Top is Linux-only: it reads the container's cgroup and the host's /proc,
// neither of which exists elsewhere. This build exists so the cross-compiled
// hull CLI can link the package.
func (e *Engine) Top(ctx context.Context, idOrName, psArgs string) (TopResult, error) {
	return TopResult{}, fmt.Errorf("%w: reading a container's process table needs a Linux /proc, not %s",
		ErrUnsupported, runtime.GOOS)
}
