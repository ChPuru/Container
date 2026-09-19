//go:build linux

package initspec

import (
	"fmt"

	"github.com/rahuldhali/hull/internal/oci/runtimespec"
)

// The runtime spec's linux.devices list holds the devices a caller asked for *in
// addition* to a standard set every container gets. Creating only what the bundle
// lists leaves /dev empty, which breaks in a way that looks unrelated: masking a path
// needs /dev/null to bind over it, so the first symptom is
// "open /dev/null to mask a file: no such file or directory" rather than anything
// about devices.
//
// These are the defaults the spec names, with the major/minor numbers Linux has used
// for them since forever. /dev/console is deliberately absent: it is set up from the
// pty when the container has a terminal, and fabricating it here would defeat the
// fstat check that guards against the /dev/console symlink-swap CVEs.

func devMode(m uint32) *uint32 { return &m }

var defaultDevices = []runtimespec.LinuxDevice{
	{Path: "/dev/null", Type: "c", Major: 1, Minor: 3, FileMode: devMode(0o666)},
	{Path: "/dev/zero", Type: "c", Major: 1, Minor: 5, FileMode: devMode(0o666)},
	{Path: "/dev/full", Type: "c", Major: 1, Minor: 7, FileMode: devMode(0o666)},
	{Path: "/dev/random", Type: "c", Major: 1, Minor: 8, FileMode: devMode(0o666)},
	{Path: "/dev/urandom", Type: "c", Major: 1, Minor: 9, FileMode: devMode(0o666)},
	{Path: "/dev/tty", Type: "c", Major: 5, Minor: 0, FileMode: devMode(0o666)},
}

// SetupDefaultDevices creates the standard device nodes in the container's /dev.
//
// A device the caller has already listed in linux.devices is skipped, so an
// explicit entry always wins over the default. Everything else goes through
// setupDevice, which prefers mknod and falls back to a bind of the host's node
// when CAP_MKNOD is not held - the normal case inside a user namespace, where
// a rootless container would otherwise get an empty /dev.
//
// The fallback is deliberately not open-coded here: setupDevice verifies by
// fstat that the host node really is the character device with the major and
// minor the bundle named before it is bound, and that check is the whole
// defence against an image that has substituted something else for /dev/null
// (CVE-2025-31133).
func SetupDefaultDevices(rootFD int, requested []runtimespec.LinuxDevice) error {
	listed := make(map[string]bool, len(requested))
	for _, d := range requested {
		listed[d.Path] = true
	}
	for _, d := range defaultDevices {
		if listed[d.Path] {
			continue
		}
		if err := setupDevice(rootFD, d); err != nil {
			return fmt.Errorf("initspec: create default device %s: %w", d.Path, err)
		}
	}
	return nil
}
