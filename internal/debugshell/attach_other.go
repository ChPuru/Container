//go:build !linux

package debugshell

import "context"

// This file keeps the package's entry point present on every GOOS so the
// Windows build of the hull CLI links, while making it impossible to pretend a
// debug shell works anywhere but Linux. The option handling, the toolbox
// installer and the container lookup are all portable and live in
// debugshell.go; only the part that needs setns(2) is refused here.

// Attach reports that a debug shell needs Linux namespaces.
//
// There is nothing to attach to off Linux: containers live inside the WSL
// engine distro, so the Windows CLI asks the daemon to run the session and
// relays the bytes rather than joining anything itself. Options are still
// validated first, so a bad flag is reported as a bad flag rather than as a
// platform error.
func Attach(ctx context.Context, opts Options) error {
	if _, err := opts.normalize(); err != nil {
		return err
	}
	return ErrUnsupportedPlatform
}
