package hostinfo

import (
	"fmt"
	"strings"
)

// Free-space thresholds for the data-root check.
const (
	// MinFreeBytes is the floor below which hull refuses to be useful.
	MinFreeBytes uint64 = 5 << 30
	// ComfortableFreeBytes is the floor below which hull warns.
	ComfortableFreeBytes uint64 = 20 << 30
)

// buildChecks derives the check list from the already-populated fact sections.
// It is pure: given the same Report fields it always produces the same checks,
// which is what makes the doctor output testable without a host.
func buildChecks(r *Report) []Check {
	var checks []Check
	add := func(c Check) { checks = append(checks, c) }

	add(kernelCheck(r.Kernel))
	add(cgroupCheck(r.Cgroups))
	for _, w := range r.Cgroups.Warnings {
		add(Check{
			Name:   "cgroup hierarchy",
			Detail: w,
			Remedy: "See 'hull doctor' cgroup remedy above; hull cannot enforce resource limits without delegated v2 controllers.",
			Status: StatusWarn,
		})
	}
	add(overlayCheck(r.Overlay, r.Kernel))
	add(usernsCheck(r.Namespaces))
	add(seccompCheck(r.Security))
	add(dataRootCheck(r.Storage))
	add(freeSpaceCheck(r.Storage))
	add(ipForwardCheck(r.Network))
	add(bridgeVethCheck(r.Network))
	add(netfilterCheck(r.Network))
	add(forwardPolicyCheck(r.Network))
	add(psiCheck(r.Cgroups, r.Kernel))
	add(landlockCheck(r.Security))
	add(dtypeCheck(r.Storage))

	sortChecks(checks)
	return checks
}

func kernelCheck(k KernelInfo) Check {
	c := Check{Name: "kernel version", Detail: fmt.Sprintf("%s (parsed %d.%d)", or(k.Release, "unknown"), k.Major, k.Minor)}
	switch {
	case k.Major == 0:
		c.Status = StatusFail
		c.Detail = "could not parse the kernel release"
		c.Remedy = "hull needs a Linux kernel of at least 5.10. Report this kernel release upstream."
	case !k.AtLeast(5, 10):
		c.Status = StatusFail
		c.Remedy = "hull requires kernel 5.10 or newer for openat2, cgroup.kill and the fd-based mount API. Run 'wsl --update' on Windows, then 'wsl --shutdown'."
	case k.AtLeast(6, 6):
		c.Status = StatusOK
	default:
		c.Status = StatusWarn
		c.Remedy = "kernel 5.15 works but lacks PSI, idmapped overlay layers (5.19), MOVE_MOUNT_BENEATH (6.5) and lowerdir+ (6.7), and ships hybrid cgroups. Run 'wsl --update' on Windows for the 6.6 kernel, then 'wsl --shutdown'."
	}
	return c
}

func cgroupCheck(cg CgroupInfo) Check {
	c := Check{Name: "cgroup v2 delegated"}
	remedy := "Run 'wsl --update' on Windows for a 6.x kernel with pure cgroup v2, or add kernelCommandLine = cgroup_no_v1=all under [wsl2] in %USERPROFILE%\\.wslconfig, then 'wsl --shutdown'."
	switch {
	case cg.Mode == "none" || cg.UnifiedRoot == "":
		c.Status = StatusFail
		c.Detail = "no cgroup2 filesystem is mounted"
		c.Remedy = remedy
	case len(cg.Controllers) == 0:
		c.Status = StatusFail
		c.Detail = fmt.Sprintf("%s cgroups: %s has an empty cgroup.controllers, so no v2 controller is delegated", cg.Mode, cg.UnifiedRoot)
		c.Remedy = remedy
	case !cg.Delegated:
		c.Status = StatusFail
		c.Detail = fmt.Sprintf("%s cgroups at %s is missing controllers: %s", cg.Mode, cg.UnifiedRoot, strings.Join(cg.MissingControllers(), ", "))
		c.Remedy = remedy
	case cg.Mode == "hybrid":
		c.Status = StatusWarn
		c.Detail = fmt.Sprintf("hybrid v1+v2 at %s with controllers: %s", cg.UnifiedRoot, strings.Join(cg.Controllers, " "))
		c.Remedy = "v2 controllers are delegated but v1 hierarchies are still mounted; some tools will disagree about limits. " + remedy
	default:
		c.Status = StatusOK
		c.Detail = fmt.Sprintf("unified v2 at %s with controllers: %s", cg.UnifiedRoot, strings.Join(cg.Controllers, " "))
	}
	return c
}

func overlayCheck(o OverlayInfo, k KernelInfo) Check {
	c := Check{Name: "overlayfs"}
	switch {
	case !o.Supported:
		c.Status = StatusFail
		c.Detail = "overlay is absent from /proc/filesystems"
		c.Remedy = "hull's snapshotter needs overlayfs. Load it with 'modprobe overlay', or use a kernel built with CONFIG_OVERLAY_FS=y ('wsl --update')."
	case o.MountTested && !o.MountOK:
		c.Status = StatusFail
		c.Detail = "a live overlay mount failed: " + o.MountError
		c.Remedy = "Check that hull's data root is on ext4 or btrfs (overlay refuses 9p/virtiofs upper layers) and that the kernel allows the mount."
	case o.MountTested && o.MountOK:
		c.Status = StatusOK
		c.Detail = fmt.Sprintf("live mount succeeded; redirect_dir=%s metacopy=%s index=%s", or(o.Redirect, "?"), or(o.Metacopy, "?"), or(o.Index, "?"))
	default:
		c.Status = StatusWarn
		c.Detail = fmt.Sprintf("overlay is present but was not test-mounted (needs root); redirect_dir=%s metacopy=%s index=%s", or(o.Redirect, "?"), or(o.Metacopy, "?"), or(o.Index, "?"))
		c.Remedy = "Re-run 'hull doctor' as root inside the engine distro to exercise a real overlay mount."
	}
	if c.Status == StatusOK && !k.AtLeast(5, 19) {
		c.Detail += "; no idmapped layers (needs 5.19)"
	}
	return c
}

func usernsCheck(n NamespaceInfo) Check {
	c := Check{Name: "user namespaces"}
	switch {
	case !n.User:
		c.Status = StatusFail
		c.Detail = "/proc/self/ns/user is absent"
		c.Remedy = "hull isolates containers with a user namespace by default. Build or install a kernel with CONFIG_USER_NS=y ('wsl --update')."
	case n.MaxUserNamespaces == 0:
		c.Status = StatusFail
		c.Detail = "/proc/sys/user/max_user_namespaces is 0"
		c.Remedy = "Run 'sysctl -w user.max_user_namespaces=31286' and persist it in /etc/sysctl.d/99-hull.conf."
	case n.UsernsCloneSysctl && !n.UnprivilegedUsernsClone:
		c.Status = StatusFail
		c.Detail = "kernel.unprivileged_userns_clone is 0"
		c.Remedy = "Run 'sysctl -w kernel.unprivileged_userns_clone=1' and persist it in /etc/sysctl.d/99-hull.conf."
	case n.SubuidRange == "" || n.SubgidRange == "":
		c.Status = StatusWarn
		c.Detail = "user namespaces work, but this user has no /etc/subuid or /etc/subgid range"
		c.Remedy = "Add a 65536-wide range, e.g. 'usermod --add-subuids 100000-165535 --add-subgids 100000-165535 $USER'. Without it hull falls back to host uids."
	default:
		c.Status = StatusOK
		c.Detail = fmt.Sprintf("available; subuid %s, subgid %s, max %d", n.SubuidRange, n.SubgidRange, n.MaxUserNamespaces)
	}
	return c
}

func seccompCheck(s SecurityInfo) Check {
	c := Check{Name: "seccomp"}
	switch {
	case !s.Seccomp:
		c.Status = StatusFail
		c.Detail = "CONFIG_SECCOMP is not enabled and /proc/sys/kernel/seccomp/actions_avail is absent"
		c.Remedy = "hull applies a syscall allowlist to every container. Install a kernel with CONFIG_SECCOMP_FILTER=y ('wsl --update'), or run with --security-opt seccomp=unconfined at your own risk."
	case len(s.SeccompActions) == 0:
		c.Status = StatusWarn
		c.Detail = "seccomp is compiled in but actions_avail could not be read"
		c.Remedy = "Check that /proc/sys/kernel/seccomp/actions_avail is readable; hull needs SCMP_ACT_ERRNO at minimum."
	case !containsStr(s.SeccompActions, "errno"):
		c.Status = StatusFail
		c.Detail = "seccomp cannot return errno: " + strings.Join(s.SeccompActions, " ")
		c.Remedy = "hull's default profile denies syscalls with ERRNO. This kernel cannot express that; use --security-opt seccomp=unconfined or update the kernel."
	default:
		c.Status = StatusOK
		c.Detail = "actions: " + strings.Join(s.SeccompActions, " ")
	}
	return c
}

func dataRootCheck(st StorageInfo) Check {
	c := Check{Name: "data root filesystem", Detail: fmt.Sprintf("%s is %s", or(st.Probed, st.DataRoot), or(st.FSType, "an unknown filesystem"))}
	if st.OnDrvFs {
		c.Status = StatusFail
		c.Remedy = "hull's data root is on a Windows drive share. Image and container I/O will be roughly 7x slower for writes and 60x slower for metadata. Move HULL_DATA_ROOT onto the distro's own ext4 disk."
		return c
	}
	if st.FSType == "" {
		c.Status = StatusSkip
		c.Detail = "could not identify the filesystem behind " + st.DataRoot
		c.Remedy = "Check that " + st.DataRoot + " or one of its parents exists and is readable."
		return c
	}
	c.Status = StatusOK
	return c
}

func freeSpaceCheck(st StorageInfo) Check {
	c := Check{Name: "free space", Detail: fmt.Sprintf("%s free of %s on %s", humanBytes(st.FreeBytes), humanBytes(st.TotalBytes), or(st.Probed, st.DataRoot))}
	switch {
	case st.TotalBytes == 0:
		c.Status = StatusSkip
		c.Detail = "could not statfs " + st.DataRoot
		c.Remedy = "Check that " + st.DataRoot + " or one of its parents exists and is readable."
	case st.FreeBytes < MinFreeBytes:
		c.Status = StatusFail
		c.Remedy = fmt.Sprintf("hull needs at least %s free to pull and extract images. Free space, or run 'hull system prune'.", humanBytes(MinFreeBytes))
	case st.FreeBytes < ComfortableFreeBytes:
		c.Status = StatusWarn
		c.Remedy = fmt.Sprintf("Under %s free: a couple of large images will exhaust the disk. Consider 'hull system prune' or growing the WSL virtual disk.", humanBytes(ComfortableFreeBytes))
	default:
		c.Status = StatusOK
	}
	return c
}

func dtypeCheck(st StorageInfo) Check {
	c := Check{Name: "d_type support", Detail: fmt.Sprintf("readdir on %s returns d_type: %s", or(st.Probed, st.DataRoot), yesno(st.SupportsDType))}
	if st.SupportsDType {
		c.Status = StatusOK
		return c
	}
	if st.TotalBytes == 0 {
		c.Status = StatusSkip
		c.Detail = "not probed"
		return c
	}
	c.Status = StatusFail
	c.Remedy = "overlayfs refuses an upper layer whose filesystem does not report d_type. Move HULL_DATA_ROOT onto ext4 (mkfs.ext4 defaults are fine) or btrfs."
	return c
}

func ipForwardCheck(n NetworkInfo) Check {
	c := Check{Name: "ip_forward"}
	if n.IPForward {
		c.Status = StatusOK
		c.Detail = "net.ipv4.ip_forward = 1"
		return c
	}
	c.Status = StatusFail
	c.Detail = "net.ipv4.ip_forward = 0"
	c.Remedy = "Containers on a hull bridge cannot reach the outside world. Run 'sysctl -w net.ipv4.ip_forward=1' and persist it in /etc/sysctl.d/99-hull.conf."
	return c
}

func bridgeVethCheck(n NetworkInfo) Check {
	c := Check{Name: "bridge + veth"}
	var missing []string
	if !n.BridgeModule {
		missing = append(missing, "bridge")
	}
	if !n.VethModule {
		missing = append(missing, "veth")
	}
	if len(missing) == 0 {
		c.Status = StatusOK
		c.Detail = "both drivers are available"
		return c
	}
	c.Status = StatusFail
	c.Detail = "missing kernel driver(s): " + strings.Join(missing, ", ")
	c.Remedy = fmt.Sprintf("hull's bridge network needs both. Try 'modprobe %s'. If modprobe fails the WSL kernel lacks them; run 'wsl --update' or build a kernel with CONFIG_BRIDGE=y and CONFIG_VETH=y.", strings.Join(missing, " "))
	return c
}

func netfilterCheck(n NetworkInfo) Check {
	c := Check{Name: "netfilter backend"}
	switch {
	case n.NftBinary != "" && n.NftablesModule:
		c.Status = StatusOK
		c.Detail = "nftables via " + n.NftBinary
	case n.IptablesBinary != "":
		c.Status = StatusWarn
		c.Detail = "no usable nftables backend; falling back to iptables at " + n.IptablesBinary
		c.Remedy = "Install nftables ('apt install nftables') so hull can own its own table instead of appending to shared iptables chains."
	default:
		c.Status = StatusFail
		c.Detail = "neither nft nor iptables is installed"
		c.Remedy = "hull needs one of them to NAT and filter container traffic. Run 'apt install nftables' (preferred) or 'apt install iptables'."
	}
	return c
}

func forwardPolicyCheck(n NetworkInfo) Check {
	c := Check{Name: "FORWARD policy"}
	switch {
	case n.ForwardPolicy == "":
		c.Status = StatusSkip
		c.Detail = "no iptables or nft binary available to read the filter FORWARD policy"
		c.Remedy = "Install nftables or iptables so 'hull doctor' can verify that forwarded container traffic is not dropped."
	case n.DockerForwardPolicyDrop:
		c.Status = StatusWarn
		c.Detail = fmt.Sprintf("filter FORWARD policy is DROP (reported by %s)%s", n.ForwardPolicySource, dockerSuffix(n.DockerPresent))
		c.Remedy = "hull inserts an explicit ACCEPT for its bridge; if container networking still fails, check 'iptables -S FORWARD'"
	default:
		c.Status = StatusOK
		c.Detail = fmt.Sprintf("filter FORWARD policy is %s (reported by %s)", n.ForwardPolicy, n.ForwardPolicySource)
	}
	return c
}

func dockerSuffix(present bool) string {
	if present {
		return "; Docker Desktop shares this VM and installs that policy"
	}
	return ""
}

func psiCheck(cg CgroupInfo, k KernelInfo) Check {
	c := Check{Name: "pressure stall info"}
	if cg.PSI {
		c.Status = StatusOK
		c.Detail = "/proc/pressure is present"
		return c
	}
	c.Status = StatusWarn
	c.Detail = fmt.Sprintf("/proc/pressure is absent (CONFIG_PSI unset on kernel %s)", or(k.Release, "unknown"))
	c.Remedy = "pressure metrics need a 6.x WSL kernel"
	return c
}

func landlockCheck(s SecurityInfo) Check {
	c := Check{Name: "landlock"}
	switch {
	case s.Landlock >= 1:
		c.Status = StatusOK
		c.Detail = fmt.Sprintf("ABI %d", s.Landlock)
	case s.AppArmor || s.SELinux:
		c.Status = StatusWarn
		c.Detail = "Landlock is unavailable; another LSM is active"
		c.Remedy = "hull's extra filesystem confinement is disabled. Containers still get seccomp, capabilities and namespaces."
	default:
		c.Status = StatusWarn
		c.Detail = "Landlock is unavailable and no other LSM is active"
		c.Remedy = "hull's extra filesystem confinement is disabled; containers rely on seccomp, capabilities and namespaces alone. A 5.13+ kernel with CONFIG_SECURITY_LANDLOCK=y restores it."
	}
	return c
}

func containsStr(v []string, want string) bool {
	for _, s := range v {
		if s == want {
			return true
		}
	}
	return false
}
