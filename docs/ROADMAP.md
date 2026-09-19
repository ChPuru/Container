# hull roadmap

Derived from the 2026-09-13 research sweep's 58-item feature inventory, ordered so that each
milestone is independently useful rather than a step toward a distant payoff.

Effort: **S** ≈ a day, **M** ≈ a few days, **L** ≈ a week or two, **XL** ≈ longer.

---

## M0 — it runs a container (the floor)

Everything here is required before anything else means anything.

| Feature | Effort | Notes |
|---|---|---|
| WSL/kernel doctor and feature probe | S | `hull doctor`; every later feature probes rather than assumes |
| Dedicated engine WSL distro and supervisor | S | Alpine, `wsl --import`, `hull-boot` |
| OCI distribution pull client | L | registry v2, token auth, manifest lists, rate-limit awareness |
| Content-addressed blob store and safe layer applier | L | digest verification, whiteouts, path-traversal defence |
| Overlayfs snapshotter keyed by ChainID | M | short link names to stay inside the one-page mount option limit |
| OCI bundle generation with a pluggable runtime | M | entrypoint/cmd/env/user/mount fidelity |
| Namespace creation with correct user-namespace ownership | M | parent writes uid_map; `setgroups` denied first |
| Hardened rootfs pivot and OCI default mounts | L | fd-based mount API, `openat2`, no `/proc/self/exe` re-exec |
| Capabilities, `no_new_privs` and a seccomp allowlist | M | NNP **before** the filter, unlike the reference implementations |
| cgroup v2 resource driver | M | degrades loudly on a hybrid-cgroup host |
| Process spec: user, env, workdir, rlimits, entrypoint/cmd | S | |
| Runtime self-protection | S | memfd-sealed init binary, fd sanitisation |
| Per-container supervisor shim | M | survives a daemon restart; owns pidfd, pty, logs |
| Minimal PID 1 init (`--init`) | S | zombie reaping, signal forwarding |
| TTY allocation and attach streams | M | console socket, `SCM_RIGHTS`, detach keys |
| Lifecycle, persistent state and crash-safe cleanup | M | atomic writes, recovery on start |
| Bridge networking with IPAM and nftables NAT | L | own `inet hull` table; iptables FORWARD shim for Docker Desktop |

## M1 — it replaces Docker Desktop for a normal day

| Feature | Effort | Notes |
|---|---|---|
| Docker Engine API subset (tiered) | XL | ping, version, info, containers, images, networks, volumes, exec, events, stats, archive |
| Windows client bridge | L | named pipe ↔ long-lived `wsl.exe` stdio relay |
| Engine distro lifecycle: keep-alive and on-demand start | M | WSL kills the distro ~15 s after the last Windows client exits |
| Windows-reachable port publishing | M | a real root-netns listener per port, because DNAT alone is invisible to WSL's relay |
| Embedded DNS, network aliases, `host-gateway` | M | own wire-format implementation; NXDOMAIN done properly for musl |
| Subnet-conflict-aware IPAM | S | avoids the WSL NAT subnet and Docker's pools |
| Exec into running containers | M | `setns` via the separate init binary, not `/proc/self/exe` |
| Volumes and Windows bind-path translation | M | including image-volume seeding, the classic omission |
| Registry credentials, login and push | M | `credsStore: desktop.exe` handled, with a graceful fallback |
| Image builds via bundled BuildKit | M | `/grpc` and `/session` endpoints so buildx works |
| Healthchecks, restart policies and events | M | |
| Compose via the stock `docker compose` | M | falls out of API compat; needs a conformance pass |
| Image management and interchange | S | `save`, `load`, `tag`, `history`, `prune` |
| Stats, log following, archive copy | M | |
| Compatibility conformance harness | M | run early, not last — it is what keeps M1 honest |

## M2 — the reasons to prefer it

| Feature | Effort | Notes |
|---|---|---|
| User namespaces by default with idmapped layers | L | needs kernel ≥ 5.19 for idmapped overlay; degrade with a clear warning |
| Scale-to-zero idle engine | M | freeze + daemon exit; the thing Resource Saver does not do |
| Zero-config `*.localhost` domains with local HTTPS | M | built-in reverse proxy and a local CA |
| TUI dashboard | M | containers, logs, stats, events in one screen |
| PSI pressure alerts and per-project budgets | M | needs a 6.x WSL kernel; absent on 5.15 |
| btrfs snapshots, branching and time-travel diffs | M | reflink where available, hardlink otherwise |
| Debug shell for distroless images | S | `hull debug` |
| Environment lockfile pinned to digests | S | `hull.lock` |
| Rate-limit-aware Docker Hub pulling | S | reads `RateLimit-*`, suggests `hull login` before it bites |
| Windows-folder sync for hot reload | L | Windows-side edits raise no inotify events under 9p |
| Tiered isolation: gVisor and microVM | L | `/dev/kvm` is present on this host |
| Agent sandbox mode | M | a locked-down profile for running untrusted code |
| Trace/explain mode | S | `--explain` |

## M3 — later

Native Dockerfile builder (XL) · rootless mode (L) · CRIU checkpoint/restore (L) ·
composefs/EROFS dedup store (XL) · lazy pulling (XL) · signature verification policy (M) ·
GPU passthrough via `/dev/dxg` (M) · IPv6 dual-stack (M) · native compose front end with
`develop.watch` (M) · declarative autostart services (S) · a WSLC backend adapter (XL) ·
a custom VMM outside WSL via WHP/HCS (XL) · CNI 1.1 shim and live migration (XL).

---

## Risks being actively managed

1. **Docker Engine API long tail** — hijacked attach/exec framing, filters, error shapes,
   BuildKit's `/grpc` and `/session`. Mitigated by building the conformance harness in M1
   rather than at the end.
2. **Escapes from a hand-written root runtime** — every recent runc CVE came from path-based
   operations on an attacker-controlled rootfs. Mitigated by `openat2`, the fd-based mount API,
   a sealed-memfd init binary, user namespaces by default, `test/cve/` regression tests, and
   keeping `crun` as the default until the native runtime passes them.
3. **The host platform moves under us** — WSL 2.4 → 2.7 changes the kernel, removes cgroup v1
   and adds new networking modes. Mitigated by probing every feature and degrading loudly.
4. **Windows reachability** depends on the WSL networking mode. Mitigated by always opening a
   real root-netns listener per published port.
5. **Coexistence with Docker Desktop** in one VM: `FORWARD DROP`, a contested pipe name,
   global `.wslconfig`. Mitigated by a separate pipe, a separate subnet pool and an explicit
   iptables ACCEPT for hull's bridge.
6. **`wslc` may make basic parity worthless** — Microsoft's WSL Containers reaches GA in late
   2026. hull differentiates on Docker API compatibility and developer experience, neither of
   which `wslc` has.
