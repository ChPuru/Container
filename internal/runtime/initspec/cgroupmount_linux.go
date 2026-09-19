//go:build linux

package initspec

import (
	"fmt"
	"os"
	"strings"

	"github.com/rahuldhali/hull/internal/oci/runtimespec"
	"golang.org/x/sys/unix"
)

// The OCI runtime spec asks for the cgroup filesystem with a mount whose type is
// literally "cgroup":
//
//	{"destination": "/sys/fs/cgroup", "type": "cgroup", "source": "cgroup",
//	 "options": ["nosuid", "noexec", "nodev", "relatime", "ro"]}
//
// That is what runc, crun and hull's own bundle generator all emit, and taking it at
// face value does not work. `mount -t cgroup` without a controller name is meaningless
// on a v1 hierarchy and simply fails, and on a v2 host the filesystem is called
// "cgroup2". Every real runtime therefore treats the entry as a *request* and decides
// what to actually mount from the host's layout.
//
// Measured on the WSL 5.15 kernel this engine targets, inside a fresh mount namespace:
//
//	mount -t cgroup2 none <dir>           works, even with hybrid v1+v2 cgroups
//	mount -t cgroup  none <dir>           fails: "none already mounted on /dev"
//	mount --rbind /sys/fs/cgroup <dir>    works
//
// So: prefer cgroup2, fall back to a read-only recursive bind of whatever the host has.
// The bind is also the only correct answer inside a user namespace, where mounting a
// fresh cgroup filesystem is not permitted regardless of the host's layout.

// hostCgroupRoot is where the host keeps its cgroup hierarchy. It is a variable so
// tests can point it somewhere harmless.
var hostCgroupRoot = "/sys/fs/cgroup"

// isCgroupMount reports whether m is the spec's request for the cgroup filesystem.
func isCgroupMount(m *runtimespec.Mount) bool {
	return m.Type == "cgroup"
}

// resolveCgroupMount turns the spec's "cgroup" request into the mounts this host can
// actually satisfy, newest-preferred first. Each candidate is tried in order and the
// first that succeeds wins, so a host that has moved to pure cgroup v2 gets a real
// cgroup2 filesystem while an older or namespaced one still gets a usable view.
func resolveCgroupMount(m *runtimespec.Mount, userNS bool) []runtimespec.Mount {
	// Keep the caller's flags (ro, nosuid, noexec, nodev, relatime) on every candidate;
	// only the filesystem type and source change.
	opts := append([]string(nil), m.Options...)

	bind := runtimespec.Mount{
		Destination: m.Destination,
		Type:        "none",
		Source:      hostCgroupRoot,
		Options:     append(append([]string(nil), opts...), "rbind"),
	}

	// In a user namespace a fresh cgroup2 mount is refused, so do not even try: going
	// straight to the bind avoids a confusing EPERM in the logs.
	if userNS || !cgroup2Available() {
		return []runtimespec.Mount{bind}
	}

	unified := runtimespec.Mount{
		Destination: m.Destination,
		Type:        "cgroup2",
		Source:      "cgroup",
		Options:     opts,
	}
	return []runtimespec.Mount{unified, bind}
}

// cgroup2Available reports whether the kernel knows the cgroup2 filesystem at all.
// A kernel built without it cannot mount one no matter how the host is configured.
func cgroup2Available() bool {
	b, err := os.ReadFile("/proc/filesystems")
	if err != nil {
		// Assume yes and let the mount attempt decide; the bind fallback covers us.
		return true
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasSuffix(strings.TrimSpace(line), "cgroup2") {
			return true
		}
	}
	return false
}

// mountCgroup satisfies the spec's cgroup request, trying each resolved candidate until
// one sticks. It returns the error from the LAST attempt, annotated with what else was
// tried, so a failure says something actionable instead of repeating one syscall's errno.
func mountCgroup(rootFD int, m *runtimespec.Mount, feat StageFeatures, userNS bool) error {
	candidates := resolveCgroupMount(m, userNS)
	var attempts []string
	var lastErr error
	for i := range candidates {
		c := candidates[i]
		if err := mountOne(rootFD, &c, feat); err != nil {
			attempts = append(attempts, fmt.Sprintf("%s: %v", describeCandidate(c), err))
			lastErr = err
			continue
		}
		return nil
	}
	return fmt.Errorf("could not provide %s (tried %s): %w",
		m.Destination, strings.Join(attempts, "; "), lastErr)
}

func describeCandidate(m runtimespec.Mount) string {
	if m.Type == "none" {
		return "rbind " + m.Source
	}
	return "mount -t " + m.Type
}

// inUserNamespace reports whether this process is in a user namespace other than the
// initial one, which is the case whenever the container was asked for one. The initial
// namespace maps the full uid range starting at 0; anything narrower is a child.
func inUserNamespace() bool {
	b, err := os.ReadFile("/proc/self/uid_map")
	if err != nil {
		return false
	}
	var containerID, hostID, size uint64
	if _, err := fmt.Sscanf(strings.TrimSpace(string(b)), "%d %d %d", &containerID, &hostID, &size); err != nil {
		return false
	}
	return !(containerID == 0 && hostID == 0 && size >= uint64(^uint32(0)))
}

var _ = unix.MS_BIND // keep the unix import meaningful if the helpers above change
