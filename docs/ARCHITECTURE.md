# hull — architecture

`hull` is a personal container engine for Windows 11 + WSL2, built to replace Docker
Desktop as a daily driver. It speaks the Docker Engine API so the stock `docker` CLI,
`docker compose`, VS Code Dev Containers and Testcontainers work against it unchanged,
and it also ships its own `hull` CLI and TUI.

## Topology (architecture A: daemon in a dedicated WSL distro + Windows byte relay)

```
Windows                                  WSL2 VM (one kernel, shared by all distros)
────────────────────────────────         ─────────────────────────────────────────────
hull.exe  (CLI + TUI)                    hull-engine distro (Alpine, wsl --import)
   │                                        │
   ├── \\.\pipe\hull_engine  ◄──── relay ──►├── hulld  (daemon, Go)
   │   (named pipe, Docker API)             │     ├── Docker API server (unix socket
   │                                        │     │   + /mnt/wsl/hull/hull.sock + TCP)
   └── keep-alive agent                     │     ├── image store (content + snapshots)
       (long-lived wsl.exe, stops           │     ├── nftables table `hull`
        the distro from being torn down)    │     ├── embedded DNS (per-bridge :53)
                                            │     ├── port proxies (userland, so WSL
                                            │     │   NAT localhost relay sees a
                                            │     │   LISTEN socket in the root netns)
                                            │     └── event bus
                                            └── per-container shim (hull-shim)
                                                  holds pidfd + pty + log writer
```

Why a userland port proxy and not pure DNAT: WSL NAT-mode localhost forwarding polls
`sock_diag` for TCP sockets in `LISTEN` state in the **root** network namespace and
relays only those. A port published solely with nftables DNAT has no such socket and is
invisible from Windows. hull therefore always opens a real listening socket in the root
netns for every published port, and uses DNAT only for LAN-facing traffic.

## Disk layout (inside the engine distro)

```
/var/lib/hull/
  content/blobs/sha256/<hex>        content-addressed blob store (immutable)
  content/ingest/<random>           in-progress writes, fsync+rename into blobs
  images/images.json                image index (digest -> types.Image)
  snapshots/<chainid>/fs            extracted layer (the `lower` for the next one)
  snapshots/<chainid>/.complete     commit marker; absent means partial, re-extract
  containers/<id>/upper             overlay upperdir
  containers/<id>/work              overlay workdir
  containers/<id>/merged            overlay mountpoint == container rootfs
  containers/<id>/config.json       OCI runtime-spec bundle config
  containers/<id>/state.json        types.Container, written atomically
  containers/<id>/<id>-json.log     json-file log driver output
  containers/<id>/shim.sock         shim control socket
  volumes/<name>/_data              named volume data
  networks/networks.json            network index
  run/hull.sock                     Docker API + hull API unix socket
  run/hull.pid
```

`/mnt/wsl/hull/hull.sock` is a bind of `run/hull.sock` into the shared `/mnt/wsl`
tmpfs so other distros (your Ubuntu) can talk to the engine without the Windows relay.

## Package map and ownership

Each package owns one subsystem. Packages may only import packages *below* them.

| Layer | Package | Responsibility |
|---|---|---|
| 0 | `internal/types` | domain model; imports nothing but stdlib |
| 0 | `internal/version` | build identity, API version constants |
| 1 | `internal/oci/imagespec` | OCI image-spec v1.1.1 media types + structs |
| 1 | `internal/oci/runtimespec` | OCI runtime-spec v1.2 `config.json` structs |
| 1 | `internal/content` | content-addressed blob store, digest verification, GC roots |
| 1 | `internal/layer` | tar layer applier: whiteouts, opaque dirs, path-traversal safety |
| 1 | `internal/cgroups` | cgroup v2 driver: create, apply `types.Resources`, read stats, freeze, kill |
| 1 | `internal/hostinfo` | kernel/WSL/cgroup/overlay/seccomp feature probe (`hull doctor`) |
| 1 | `internal/seccompprof` | default seccomp allowlist as `runtimespec.LinuxSeccomp` |
| 1 | `internal/logbuf` | json-file log writer + tailer with follow and rotation |
| 2 | `internal/oci/registry` | distribution-spec v1.1.1 client: auth, manifests, blobs, push |
| 2 | `internal/snapshot` | overlayfs snapshotter keyed by ChainID; prepare/commit/mount/remove |
| 2 | `internal/runtime` | OCI bundle generation + native runtime (namespaces, pivot_root) and crun driver |
| 2 | `internal/network` | bridge, IPAM, veth, nftables, embedded DNS, userland port proxy |
| 2 | `internal/state` | crash-safe container/network/volume state store with file locks |
| 3 | `internal/engine` | lifecycle orchestration, event bus, healthchecks, restart policy, stats |
| 4 | `internal/api` | Docker Engine API v1.43 HTTP server (hijack, streams, filters, errors) |
| 4 | `internal/client` | Go client for the engine, used by CLI and TUI |
| 4 | `internal/tui` | terminal dashboard |
| 4 | `internal/wslbridge` | Windows named-pipe <-> WSL relay and keep-alive agent |
| 5 | `cmd/hulld` | daemon entrypoint (linux) |
| 5 | `cmd/hull` | CLI entrypoint (linux + windows) |

## Target platform reality (verified on this host, 2026-09-13/19)

- WSL **2.4.13**, kernel **5.15.167.4**, cgroups **hybrid v1 + v2 with no v2
  controllers delegated**. `hull doctor` must detect this and tell the user to run
  `wsl --update`, or set `kernelCommandLine = cgroup_no_v1=all` in `.wslconfig`.
  Every cgroup write must therefore be *feature-probed*, never assumed.
- Kernel 5.15 **has**: clone3, `CLONE_INTO_CGROUP`, pidfd + `setns(pidfd)`,
  `cgroup.kill`, the new mount API (`fsopen`/`fsmount`/`move_mount`),
  `mount_setattr` idmap for ext4/btrfs, rootless overlay, unprivileged whiteout
  mknod, `openat2`, seccomp, Landlock ABI 1, user namespaces, `/dev/kvm`.
- Kernel 5.15 **lacks**: idmapped *overlay* layers (5.19), idmapped tmpfs (6.3),
  `lowerdir+` (6.7), `MOVE_MOUNT_BENEATH` (6.5), **PSI** (`CONFIG_PSI` unset),
  newer Landlock ABIs, AppArmor.
- Overlay must always be mounted with `redirect_dir=off,metacopy=off,index=off`
  explicitly, because the newer WSL 6.6 kernel config turns redirect-always-follow on.
  The legacy mount option string is limited to one page, so use short symlinked
  layer names (`/var/lib/hull/l/<n>`) rather than full ChainID paths.
- Docker Desktop runs in the same VM and installs an **iptables FORWARD DROP**
  policy. An accept in hull's nftables chain does **not** override it, so hull must
  also insert an accept rule in the iptables filter FORWARD chain for its bridge.
- All distros share one network namespace root, one netfilter ruleset and one port
  space. hull must default to a subnet pool that avoids both the WSL NAT subnet and
  Docker's pools (172.17–172.31/16, 192.168.0.0/16 in /20s). Default: `10.66.0.0/16`
  carved into /24s.
- WSL terminates the engine distro when its Windows-side clients exit (~15s). A
  long-lived `wsl.exe` keep-alive agent on Windows is mandatory.
- Windows AF_UNIX interop into WSL2 does not work. hvsock needs the VM's runtime ID,
  which is undiscoverable without admin. hull's default transport is therefore a
  **long-lived `wsl.exe --exec` stdio relay** (with `WSL_UTF8=1`), with an optional
  TCP-on-loopback transport guarded by a shared secret.

### Validated on this host (2026-09-19)

The three load-bearing kernel paths were exercised directly on WSL 2.4.13 / kernel 5.15.167.4
before the engine was written, so the design is not resting on assumptions:

- **Runtime** — a hand-written OCI bundle over a static-busybox rootfs runs under `crun 1.14.1`:
  it pivots into the new root, sees its own PID namespace, and exits 0. The fallback runtime the
  design depends on is real and works here.
- **Overlayfs** — a two-lower stack mounts with
  `redirect_dir=off,metacopy=off,index=off`, upper-layer precedence resolves correctly, a new
  file lands in `upperdir`, and a deletion materialises as a **character device whiteout**
  (`c---------`), which is exactly the form `internal/layer`'s `Diff` has to convert into
  `.wh.<name>`.
- **Networking** — a bridge plus a veth pair with one end moved into a fresh network namespace
  passes traffic to the gateway, and an `inet` nftables table can be created and dropped cleanly.
- **cgroups** — `/sys/fs/cgroup/cgroup.controllers` is **empty**, confirming the hybrid-cgroup
  problem. Resource limits will not work until `wsl --update` or `cgroup_no_v1=all`, and
  `hull doctor` must say so rather than failing at `run` time.
- **Registry** — the full Docker Hub flow works from this network over IPv4: an unauthenticated
  manifest request returns `401` with a parseable `WWW-Authenticate`, the token dance succeeds,
  and `library/alpine:3.20` comes back as an `application/vnd.oci.image.index.v1+json` with 16
  platform entries, from which the linux/amd64 manifest, its 612-byte config and its single
  3.6 MB gzip layer resolve cleanly. The client must dispatch on `Content-Type`, not on what it
  asked for in `Accept`.
  **Rate limit, resolved:** the research recorded a conflict between Docker's docs (100 pulls per
  6 hours) and an observed header. The live header on this host is `ratelimit-limit: 100;w=3600`
  — **100 per hour**, not per 6 hours. Read the header; do not hard-code the documented number.
- **Windows transport** — a long-lived `wsl.exe -d Ubuntu -u root --exec /bin/cat` child carried
  200 consecutive 70-byte frames with zero corruption and shut down cleanly, with `WSL_UTF8=1`
  set. The stdio relay is a sound default transport, which matters because hvsock needs the VM's
  runtime ID and there is no supported way to discover it.
- Docker Desktop was not running, so the iptables `FORWARD` policy was `ACCEPT`. The explicit
  ACCEPT rule for hull's bridge is still required, because the policy flips to `DROP` the moment
  Docker Desktop starts.
- A backgrounded `wsl.exe` whose Windows parent exits is torn down within seconds — observed
  while bootstrapping the toolchain. This is the same lifecycle rule that forces the Windows
  keep-alive agent, and it is not theoretical.

## Security posture

Every recent runc breakout came from path-based operations against an attacker-
controlled rootfs. hull's native runtime must:

1. Resolve every in-container path with `openat2(RESOLVE_IN_ROOT|RESOLVE_NO_MAGICLINKS)`
   or fd-relative `openat` walks — never `filepath.Join` + `os.Open` on a container path.
2. Use the fd-based mount API (`fsopen`/`fsmount`/`move_mount`/`open_tree`) where the
   kernel supports it, falling back to `mount(2)` with pre-opened fds.
3. `pivot_root` into an fd-opened new root, then `umount2(MNT_DETACH)` the old root.
4. Never re-exec `/proc/self/exe` into the container (CVE-2019-5736). The init stage is
   a separate static binary bind-mounted read-only at `/.hull-init` from a memfd.
5. Set `no_new_privs = 1` **before** applying seccomp, unlike the lizzie.io reference
   which explicitly disables it.
6. Close all inherited fds above stderr before exec (CVE-2024-21626).
7. Re-open `/dev/null` and `/dev/console` by fd, verifying with `fstat` that the target
   is the expected device (CVE-2025-31133 / 52565 / 52881).
8. Default to a user namespace with a 65536-uid mapping, and fall back to host uids with
   a loud warning only when the kernel refuses.
9. `crun` remains available as `--runtime crun` and is the documented fallback until the
   native runtime passes the CVE regression suite in `test/cve/`.

## Differentiators (why this is not just a Docker clone)

1. **Scale-to-zero engine** — the daemon freezes idle containers with `cgroup.freeze`
   and exits when nothing has run for N minutes, releasing the distro so WSL reclaims
   the VM memory. Docker Desktop's Resource Saver does not reduce memory on WSL.
2. **Snapshots and time-travel** — `hull snapshot <ctr>` commits the overlay upperdir as
   a named checkpoint; `hull revert`, `hull branch` and `hull diff` operate on them.
3. **User namespaces on by default** with per-container uid ranges.
4. **`*.localhost` routing** — every container with a published HTTP port is reachable
   at `<name>.localhost` through a built-in reverse proxy, with a local CA for HTTPS.
5. **Environment lockfile** — `hull.lock` pins every image to a digest so a project
   rebuilds byte-identically.
6. **`hull doctor`** — a first-class, honest environment report.
7. **TUI dashboard** — containers, logs, stats and events in one screen.
8. **Trace mode** — `hull run --explain` prints every syscall-level step the engine
   takes, so it is a teaching tool as well as an engine.

## Build and test

```bash
make build      # builds bin/hulld and bin/hull (linux/amd64) inside WSL
make windows    # cross-compiles bin/hull.exe (windows/amd64)
make test       # go test ./...
make e2e        # integration tests; needs root inside the engine distro
make distro     # builds the Alpine engine distro tarball in dist/
```
