//go:build !windows

package wslbridge

import (
	"context"
	"fmt"
	"net"
)

// listenPipe reports that named pipes do not exist off Windows.
func listenPipe(cfg PipeConfig) (net.Listener, error) {
	return nil, fmt.Errorf("wslbridge: cannot serve %s: %w", cfg.Name, ErrUnsupportedPlatform)
}

// CurrentUserSID reports that there are no Windows SIDs off Windows.
func CurrentUserSID() (string, error) {
	return "", ErrUnsupportedPlatform
}

// DialPipe reports that named pipes do not exist off Windows.
func DialPipe(ctx context.Context, name string) (net.Conn, error) {
	_ = ctx
	return nil, fmt.Errorf("wslbridge: cannot dial %s: %w", name, ErrUnsupportedPlatform)
}
