package seccompprof

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/rahuldhali/hull/internal/capabilities"
	"github.com/rahuldhali/hull/internal/oci/runtimespec"
)

// SecurityOptions is the parsed form of a container's --security-opt list.
//
// NoNewPrivileges defaults to true. This is the one place hull deliberately
// departs from the lizzie.io "containers from scratch" reference the native
// runtime is otherwise modelled on: that walkthrough explicitly clears
// no_new_privs before loading its seccomp filter, which makes the filter
// bypassable through any setuid binary in the image. A seccomp filter without
// no_new_privs is not a hardening measure, it is decoration. hull sets
// PR_SET_NO_NEW_PRIVS first and only clears it when the user asks for that in
// so many words.
type SecurityOptions struct {
	// Seccomp is the profile to install, or nil to use hull's default.
	Seccomp *runtimespec.LinuxSeccomp

	// SeccompUnconfined means the user asked for no filter at all.
	// Seccomp is nil in that case too, so the two fields must be read
	// together: nil+false means "default profile", nil+true means "none".
	SeccompUnconfined bool

	// NoNewPrivileges is PR_SET_NO_NEW_PRIVS. Default true.
	NoNewPrivileges bool

	// AppArmor is the requested profile name. The WSL kernels hull targets
	// have no AppArmor, so the runtime reports a clear error rather than
	// ignoring a non-empty value here.
	AppArmor string

	// MaskedPathsUnconfined is `systempaths=unconfined`: do not mask or set
	// read-only the usual /proc and /sys paths.
	MaskedPathsUnconfined bool

	// SELinuxLabels holds the raw `label=...` values, in order. hull does not
	// implement SELinux; the runtime rejects a non-empty list rather than
	// pretending the labels were applied.
	SELinuxLabels []string
}

// DefaultSecurityOptions returns the options a container gets when the user
// passes no --security-opt at all: hull's default seccomp profile and
// no_new_privs on.
func DefaultSecurityOptions() SecurityOptions {
	return SecurityOptions{NoNewPrivileges: true}
}

// ParseSecurityOpt parses a container's --security-opt list.
//
// Recognised forms:
//
//	seccomp=unconfined          no filter at all
//	seccomp=/path/to/prof.json  a Docker-format profile on disk
//	seccomp={"defaultAction"..} a Docker-format profile inline
//	seccomp:<value>             the colon spelling of any of the above
//	no-new-privileges           set PR_SET_NO_NEW_PRIVS (the default)
//	no-new-privileges=false     clear it; see SecurityOptions
//	apparmor=<profile>          AppArmor profile name
//	label=<k>:<v>               SELinux label component, recorded verbatim
//	systempaths=unconfined      do not mask /proc and /sys paths
//
// An unrecognised option is an error. Silently ignoring a security option the
// user asked for is how a container ends up less confined than its operator
// believes.
//
// Profiles are resolved against the default capability set. A caller that
// already knows the container's capabilities should re-resolve an inline or
// on-disk profile with LoadProfile.
func ParseSecurityOpt(opts []string) (SecurityOptions, error) {
	out := DefaultSecurityOptions()

	for _, raw := range opts {
		opt := strings.TrimSpace(raw)
		if opt == "" {
			continue
		}

		key, value, hasValue := splitSecurityOpt(opt)
		key = strings.ToLower(key)

		switch key {
		case "seccomp":
			if !hasValue {
				return out, fmt.Errorf("seccompprof: security-opt %q: seccomp needs a value (unconfined, a path, or inline JSON)", raw)
			}
			if strings.EqualFold(strings.TrimSpace(value), "unconfined") {
				out.SeccompUnconfined = true
				out.Seccomp = nil
				continue
			}
			prof, err := loadSeccompValue(value)
			if err != nil {
				return out, fmt.Errorf("seccompprof: security-opt %q: %w", raw, err)
			}
			out.SeccompUnconfined = false
			out.Seccomp = prof

		case "no-new-privileges":
			if !hasValue {
				// Bare `no-new-privileges` means "turn it on", which is
				// already the default; accept it so Docker command lines
				// carry over unchanged.
				out.NoNewPrivileges = true
				continue
			}
			b, err := strconv.ParseBool(strings.TrimSpace(value))
			if err != nil {
				return out, fmt.Errorf("seccompprof: security-opt %q: no-new-privileges wants true or false: %w", raw, err)
			}
			out.NoNewPrivileges = b

		case "apparmor":
			if !hasValue {
				return out, fmt.Errorf("seccompprof: security-opt %q: apparmor needs a profile name", raw)
			}
			out.AppArmor = strings.TrimSpace(value)

		case "label":
			if !hasValue {
				return out, fmt.Errorf("seccompprof: security-opt %q: label needs a value", raw)
			}
			out.SELinuxLabels = append(out.SELinuxLabels, strings.TrimSpace(value))

		case "systempaths":
			if !strings.EqualFold(strings.TrimSpace(value), "unconfined") {
				return out, fmt.Errorf("seccompprof: security-opt %q: systempaths only accepts \"unconfined\"", raw)
			}
			out.MaskedPathsUnconfined = true

		default:
			return out, fmt.Errorf("seccompprof: unknown security-opt %q", raw)
		}
	}

	return out, nil
}

// splitSecurityOpt splits an option on the first "=", falling back to the
// first ":" so that Docker's `label:user:USER` spelling works. The value of a
// label keeps everything after the first separator, so `label=user:USER`
// yields "user:USER".
func splitSecurityOpt(opt string) (key, value string, hasValue bool) {
	if i := strings.Index(opt, "="); i >= 0 {
		return opt[:i], opt[i+1:], true
	}
	if i := strings.Index(opt, ":"); i >= 0 {
		return opt[:i], opt[i+1:], true
	}
	return opt, "", false
}

// loadSeccompValue interprets a seccomp= value that is not "unconfined": JSON
// when it starts with a brace, otherwise a path on disk.
func loadSeccompValue(value string) (*runtimespec.LinuxSeccomp, error) {
	v := strings.TrimSpace(value)
	if strings.HasPrefix(v, "{") {
		prof, err := LoadProfile([]byte(v), capabilities.Default())
		if err != nil {
			return nil, fmt.Errorf("inline seccomp profile: %w", err)
		}
		return prof, nil
	}
	return Load(v)
}

// Resolve turns parsed options and a capability set into the profile the
// runtime should actually install: nil for an unconfined or privileged
// container, the user's profile when they supplied one, otherwise hull's
// capability-aware default.
func (o SecurityOptions) Resolve(caps []string, privileged bool) *runtimespec.LinuxSeccomp {
	if o.SeccompUnconfined || privileged {
		return Unconfined()
	}
	if o.Seccomp != nil {
		return o.Seccomp
	}
	return ForCapabilities(caps, false)
}
