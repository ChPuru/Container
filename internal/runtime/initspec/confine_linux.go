package initspec

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/ChPuru/hull/internal/oci/runtimespec"
)

// Confine applies everything that turns the calling process into the confined
// container process, in the one order that is actually safe:
//
//	rlimits, umask, oom_score_adj   - cheap, reversible, no ordering hazard
//	cwd                             - resolved inside the container root
//	capability bounding set         - needs CAP_SETPCAP, so before the uid drop
//	PR_SET_KEEPCAPS                 - so the permitted set survives setresuid
//	setgroups, setresgid, setresuid - groups first, then gid, then uid
//	effective/permitted/inheritable/ambient capabilities
//	no_new_privs                    - ALWAYS before seccomp
//	seccomp                         - last, so nothing after it needs a syscall
//	                                  the filter might deny
//
// The no_new_privs-before-seccomp order is not a style choice. A seccomp
// filter installed without it can be escaped through any setuid binary the
// container can reach, which turns a hardening measure into a lie.
//
// Confine never returns after installing seccomp without having installed it
// successfully: a failure here fails the container start.
func Confine(e *Exec) error {
	if err := ApplyRlimits(e.Process.Rlimits); err != nil {
		return err
	}
	if e.Process.User.Umask != nil {
		unix.Umask(int(*e.Process.User.Umask & 0o7777))
	}
	if e.Process.OOMScoreAdj != nil {
		if err := SetOOMScoreAdj(*e.Process.OOMScoreAdj); err != nil {
			return err
		}
	}
	if err := ChdirInRoot(e.Process.Cwd); err != nil {
		return err
	}
	if err := ApplyBoundingSet(e.Process.Capabilities); err != nil {
		return err
	}
	if err := SetKeepCaps(true); err != nil {
		return err
	}
	if err := DropPrivileges(e.Process.User); err != nil {
		return err
	}
	if err := SetKeepCaps(false); err != nil {
		return err
	}
	if err := ApplyCapSets(e.Process.Capabilities); err != nil {
		return err
	}
	// no_new_privs is set unconditionally, not only when the spec asks for
	// it: hull will not run a container that can regain privilege through a
	// setuid binary, and the seccomp filter below depends on it.
	if err := SetNoNewPrivs(); err != nil {
		return err
	}
	if e.Seccomp != nil {
		prog, err := CompileSeccomp(e.Seccomp)
		if err != nil {
			return err
		}
		if !e.Features.SeccompSpecAllow {
			prog.Flags &^= FilterFlagSpecAllow
		} else {
			prog.Flags |= FilterFlagSpecAllow
		}
		if err := prog.Install(); err != nil {
			return err
		}
	}
	return nil
}

// ApplyRlimits sets every rlimit the spec names. An unknown name is an error
// rather than a silent skip: a container told it has a limit it does not have
// is worse than one that fails to start.
func ApplyRlimits(limits []runtimespec.POSIXRlimit) error {
	for _, l := range limits {
		res, ok := RlimitNumber(l.Type)
		if !ok {
			return fmt.Errorf("initspec: unknown rlimit %q (known: %s)",
				l.Type, strings.Join(RlimitNames(), ", "))
		}
		rl := unix.Rlimit{Cur: l.Soft, Max: l.Hard}
		if err := unix.Setrlimit(res, &rl); err != nil {
			return fmt.Errorf("initspec: setrlimit(%s, soft=%d hard=%d): %w", l.Type, l.Soft, l.Hard, err)
		}
	}
	return nil
}

// SetOOMScoreAdj writes /proc/self/oom_score_adj. A container asking to be a
// worse OOM candidate than the daemon needs privilege it may not have, so a
// refusal is reported rather than swallowed.
func SetOOMScoreAdj(v int) error {
	if v < -1000 || v > 1000 {
		return fmt.Errorf("initspec: oomScoreAdj %d is outside the kernel range -1000..1000", v)
	}
	if err := os.WriteFile("/proc/self/oom_score_adj", []byte(strconv.Itoa(v)), 0o644); err != nil {
		return fmt.Errorf("initspec: write oom_score_adj=%d: %w", v, err)
	}
	return nil
}

// ChdirInRoot changes to cwd, which must already be inside the container root
// because this runs after pivot_root. The directory is opened first and
// entered by descriptor, so a symlink swapped in between the lookup and the
// chdir cannot redirect it.
func ChdirInRoot(cwd string) error {
	if cwd == "" {
		cwd = "/"
	}
	rootFD, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("initspec: open container root: %w", err)
	}
	defer unix.Close(rootFD)
	fd, err := OpenInRoot(rootFD, cwd, unix.O_PATH|unix.O_DIRECTORY, 0)
	if err != nil {
		return fmt.Errorf("initspec: container working directory %q: %w", cwd, err)
	}
	defer unix.Close(fd)
	if err := unix.Fchdir(fd); err != nil {
		return fmt.Errorf("initspec: chdir to %q: %w", cwd, err)
	}
	return nil
}

// LookupInPath resolves an executable name the way execvp would, but using
// only the container's own filesystem - which, by the time this runs, is the
// only filesystem the process can see.
func LookupInPath(name string, env []string) (string, error) {
	if strings.Contains(name, "/") {
		if err := unix.Access(name, unix.X_OK); err != nil {
			return "", fmt.Errorf("initspec: %q is not executable: %w", name, err)
		}
		return name, nil
	}
	path := "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	for _, kv := range env {
		if strings.HasPrefix(kv, "PATH=") {
			path = strings.TrimPrefix(kv, "PATH=")
			break
		}
	}
	var tried []string
	for _, dir := range strings.Split(path, ":") {
		if dir == "" {
			dir = "."
		}
		cand := dir + "/" + name
		if err := unix.Access(cand, unix.X_OK); err == nil {
			return cand, nil
		}
		tried = append(tried, cand)
	}
	return "", fmt.Errorf("initspec: executable %q not found in the container (looked in %s)",
		name, strings.Join(tried, ", "))
}
