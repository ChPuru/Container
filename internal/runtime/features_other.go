//go:build !linux

package runtime

import (
	"context"
	"fmt"
	"runtime"
)

// ProbeFeatures reports no kernel facilities off Linux. hull's containers only
// ever run inside the WSL engine distro; the Windows CLI links this so it can
// render a runtime's self-description without pretending to have probed a
// kernel it cannot see.
func ProbeFeatures(ctx context.Context) (Features, error) {
	if err := ctx.Err(); err != nil {
		return Features{}, err
	}
	return Features{
		Kernel: runtime.GOOS + "/" + runtime.GOARCH,
		Warnings: []string{fmt.Sprintf(
			"hull is running on %s; container features can only be probed inside the Linux engine distro",
			runtime.GOOS)},
	}, nil
}
