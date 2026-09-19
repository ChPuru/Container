//go:build !windows

package client

import (
	"context"
	"fmt"
	"net"
)

// dialNamedPipe reports that Windows named pipes do not exist on this OS.
//
// The Linux build of hull talks to the engine over its unix socket — either
// its own, or the /mnt/wsl bind a sibling distro sees — so an npipe://
// address here is a configuration mistake worth naming rather than a case to
// paper over: WSL's AF_UNIX interop does not bridge the two.
func dialNamedPipe(_ context.Context, name string) (net.Conn, error) {
	return nil, fmt.Errorf("client: %s is a Windows named pipe and cannot be dialled from this OS; use unix://%s instead", name, SharedUnixSocket)
}
