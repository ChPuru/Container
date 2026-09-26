// Package initspec is the wire contract between hull's native container
// runtime (which runs on the host, in the daemon) and the hull-init binary
// (the only hull code that ever runs inside a container).
//
// Everything the container stage needs travels as JSON over a SOCK_SEQPACKET
// socketpair, never through argv or the environment, so no secret is visible
// in /proc/<pid>/cmdline to anything that can read it.
//
// The package deliberately keeps its dependency set to the standard library,
// golang.org/x/sys/unix and internal/oci/runtimespec: hull-init links it, and
// hull-init must stay small enough to be worth sealing into a memfd.
package initspec

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ChPuru/hull/internal/oci/runtimespec"
)

// Stage names select which half of hull-init runs. The stage arrives as the
// single flag --hull-stage=<name>; anything else (including no flag at all)
// means the binary is the container's PID 1 and runs the reaper.
const (
	// StageInit is the post-clone container stage: it does the namespace,
	// mount, pivot_root, capability, seccomp and privilege-drop work and
	// then execs the container entrypoint.
	StageInit = "init"
	// StageSetns joins an existing container's namespaces from a pidfd and
	// forks the StageExec stage inside them.
	StageSetns = "setns"
	// StageExec is the confinement-only stage: it applies the process
	// limits, credentials, capabilities, no_new_privs and seccomp, then
	// execs. It is what StageSetns forks.
	StageExec = "exec"
	// StagePID1 is the container's own init: reap, forward signals, relay
	// the child's exit status.
	StagePID1 = "pid1"
)

// StageFlagPrefix is the argv prefix hull-init parses to find its stage.
const StageFlagPrefix = "--hull-stage="

// ArgvName is the argv[0] hull's runtime gives hull-init. It is cosmetic: the
// stage is always taken from the flag, never from argv[0], so a container that
// rewrites its own argv cannot talk hull-init into a different stage.
const ArgvName = "hull-init"

// Well-known file descriptor numbers the runtime hands to hull-init. Anything
// above FDLast is closed with close_range(2) before the container entrypoint
// is exec'd (CVE-2024-21626).
const (
	// FDSync is the SOCK_SEQPACKET socket carrying the handshake.
	FDSync = 3
	// FDStart is the read end of the start pipe. A single byte on it means
	// the host called Start and the entrypoint may be exec'd.
	FDStart = 4
	// FDConsole is the pty peer when the process has a terminal, or is
	// closed when it does not.
	FDConsole = 5
	// FDSelf is the sealed memfd holding hull-init itself, passed so the
	// setns stage can re-exec hull-init without ever touching
	// /proc/self/exe (CVE-2019-5736).
	FDSelf = 6
	// FDTarget is the pidfd of the container init process, passed to the
	// setns stage.
	FDTarget = 7
	// FDLast is the highest descriptor hull-init may inherit.
	FDLast = FDTarget
)

// StageFromArgs returns the stage named by --hull-stage= in args, or StagePID1
// when the flag is absent. Only the first occurrence is honoured.
func StageFromArgs(args []string) (string, error) {
	for _, a := range args {
		if !strings.HasPrefix(a, StageFlagPrefix) {
			continue
		}
		s := strings.TrimPrefix(a, StageFlagPrefix)
		switch s {
		case StageInit, StageSetns, StageExec, StagePID1:
			return s, nil
		default:
			return "", fmt.Errorf("initspec: unknown stage %q", s)
		}
	}
	return StagePID1, nil
}

// MsgType names one handshake message.
type MsgType string

// Handshake messages. The runtime speaks first with MsgConfig; receiving it
// also tells the container stage that the parent has finished writing
// /proc/<pid>/uid_map and gid_map, so it is safe to proceed.
const (
	// MsgConfig carries the whole container configuration, host to child.
	MsgConfig MsgType = "config"
	// MsgReady is sent by the child once every irreversible step short of
	// execve has succeeded.
	MsgReady MsgType = "ready"
	// MsgError is sent by the child when a step failed; Err explains it.
	MsgError MsgType = "error"
)

// Message is one frame on the handshake socket. Frames are datagrams on a
// SOCK_SEQPACKET socket, so a short read never splices two messages together.
type Message struct {
	Type MsgType `json:"t"`
	Err  string  `json:"err,omitempty"`
	Pid  int     `json:"pid,omitempty"`
	Cfg  *Config `json:"cfg,omitempty"`
	Exec *Exec   `json:"exec,omitempty"`
}

// Encode marshals the message. It is a method so both sides agree on the
// framing without duplicating the json call.
func (m *Message) Encode() ([]byte, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("initspec: encode %s message: %w", m.Type, err)
	}
	return b, nil
}

// DecodeMessage parses one handshake frame.
func DecodeMessage(b []byte) (*Message, error) {
	var m Message
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("initspec: decode message (%d bytes): %w", len(b), err)
	}
	if m.Type == "" {
		return nil, fmt.Errorf("initspec: message has no type")
	}
	return &m, nil
}

// MaxMessage is the largest handshake frame either side will accept. A
// SOCK_SEQPACKET socket on Linux has a much larger default buffer than this,
// and no legitimate container config comes close.
const MaxMessage = 1 << 20

// Config is everything the container stage needs. It is derived from the
// bundle config.json by the runtime, never read from inside the container.
type Config struct {
	// ID is the container id, used only in error messages.
	ID string `json:"id"`

	// Rootfs is the absolute host path of the container root filesystem.
	// It is a path the daemon owns; every path under it is resolved
	// fd-relative because the container may control its contents.
	Rootfs string `json:"rootfs"`
	// RootfsReadonly remounts the root read-only as the last mount step.
	RootfsReadonly bool `json:"rootfsReadonly,omitempty"`
	// RootfsPropagation is the propagation mode applied to the new root
	// (private, slave, shared or unbindable, optionally r-prefixed).
	RootfsPropagation string `json:"rootfsPropagation,omitempty"`
	// NoPivotRoot falls back to chroot when pivot_root is impossible. It is
	// strictly less safe and the runtime never sets it by default.
	NoPivotRoot bool `json:"noPivotRoot,omitempty"`

	// Hostname and Domainname are applied when a UTS namespace was created.
	Hostname   string `json:"hostname,omitempty"`
	Domainname string `json:"domainname,omitempty"`

	// Mounts are the bundle mounts, in order.
	Mounts []runtimespec.Mount `json:"mounts,omitempty"`
	// Devices are the device nodes to materialise under /dev.
	Devices []runtimespec.LinuxDevice `json:"devices,omitempty"`
	// MaskedPaths are covered with /dev/null (files) or an empty read-only
	// tmpfs (directories).
	MaskedPaths []string `json:"maskedPaths,omitempty"`
	// ReadonlyPaths are bind-mounted onto themselves and remounted ro.
	ReadonlyPaths []string `json:"readonlyPaths,omitempty"`
	// Sysctl entries are written through the host /proc before pivot_root,
	// so they land in the namespaces the child has just entered.
	Sysctl map[string]string `json:"sysctl,omitempty"`

	// NamespacePaths maps a namespace type to an existing namespace file to
	// join instead of creating a fresh one. The pid and user types are
	// rejected: a Go process cannot usefully join either.
	NamespacePaths map[string]string `json:"namespacePaths,omitempty"`
	// UserNS records that the child was cloned into a user namespace whose
	// mappings the parent has already written.
	UserNS bool `json:"userns,omitempty"`

	// Exec is the process to run once the container is built.
	Exec Exec `json:"exec"`

	// Init reports that the entrypoint should be wrapped by the hull-init
	// PID 1 reaper (HostConfig.Init).
	Init bool `json:"init,omitempty"`

	// Features tells the stage which kernel facilities the host probed as
	// present, so the stage never has to guess.
	Features StageFeatures `json:"features"`
}

// Exec is one process to run: the OCI process block plus the terminal wiring.
type Exec struct {
	// Process is the runtime-spec process description.
	Process runtimespec.Process `json:"process"`
	// Terminal means FDConsole holds the pty peer to install as the
	// controlling terminal and as stdio.
	Terminal bool `json:"terminal,omitempty"`
	// Seccomp is the filter to compile and install last.
	Seccomp *runtimespec.LinuxSeccomp `json:"seccomp,omitempty"`
	// CgroupPath is the absolute cgroup v2 directory the exec'd process
	// must join, or empty when the parent has already placed it.
	CgroupPath string `json:"cgroupPath,omitempty"`
	// Features mirrors Config.Features for the standalone exec stage.
	Features StageFeatures `json:"features"`
}

// StageFeatures is the subset of the host kernel feature probe that changes
// what the container stage does. Nothing here is probed inside the container:
// a container must never be able to influence which code path the stage takes.
type StageFeatures struct {
	// MountAPI enables fsopen/fsconfig/fsmount/move_mount instead of
	// mount(2).
	MountAPI bool `json:"mountApi,omitempty"`
	// Openat2 enables openat2 with RESOLVE_IN_ROOT|RESOLVE_NO_MAGICLINKS
	// for in-container path resolution instead of the fd-relative walk.
	Openat2 bool `json:"openat2,omitempty"`
	// CloseRange enables close_range(2) rather than a readdir of
	// /proc/self/fd.
	CloseRange bool `json:"closeRange,omitempty"`
	// SeccompSpecAllow adds SECCOMP_FILTER_FLAG_SPEC_ALLOW to the filter.
	SeccompSpecAllow bool `json:"seccompSpecAllow,omitempty"`
}

// Validate rejects a configuration the stage cannot safely act on. It runs on
// both sides: the runtime will not send an invalid config and the stage will
// not act on one.
func (c *Config) Validate() error {
	if c.Rootfs == "" {
		return fmt.Errorf("initspec: config has no rootfs")
	}
	if !strings.HasPrefix(c.Rootfs, "/") {
		return fmt.Errorf("initspec: rootfs %q is not absolute", c.Rootfs)
	}
	for ns, p := range c.NamespacePaths {
		switch ns {
		case "pid", "user":
			return fmt.Errorf("initspec: joining an existing %s namespace by path is not supported "+
				"(a multi-threaded process cannot setns into it); create the namespace instead", ns)
		case "mount", "network", "ipc", "uts", "cgroup", "time":
		default:
			return fmt.Errorf("initspec: unknown namespace type %q", ns)
		}
		if !strings.HasPrefix(p, "/") {
			return fmt.Errorf("initspec: namespace path %q for %s is not absolute", p, ns)
		}
	}
	return c.Exec.Validate()
}

// Validate rejects an exec request the stage cannot act on.
func (e *Exec) Validate() error {
	if len(e.Process.Args) == 0 {
		return fmt.Errorf("initspec: process has no args")
	}
	if e.Process.Cwd != "" && !strings.HasPrefix(e.Process.Cwd, "/") {
		return fmt.Errorf("initspec: process cwd %q is not absolute", e.Process.Cwd)
	}
	return nil
}
