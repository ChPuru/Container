# hull

A container engine built from scratch, to replace Docker Desktop on Windows 11 + WSL2.

`hull` runs OCI images the way Docker does — it speaks the Docker Engine API, so the stock
`docker` CLI, `docker compose`, VS Code Dev Containers and Testcontainers work against it
unchanged — and it ships its own CLI and TUI on top. The engine is written in Go and the
container internals (namespaces, cgroups, rootfs, layer store, networking) are implemented
directly against the kernel rather than delegated to containerd or runc.

> Status: **under active construction.** The subsystems land package by package; see
> [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the design and `hull doctor` for what your
> machine actually supports.

## Why not just use Docker Desktop

Four things it does badly on Windows, and what hull does instead.

| | Docker Desktop | hull |
|---|---|---|
| **Idle cost** | Resource Saver pauses the engine but does *not* return memory to Windows on WSL | scale-to-zero: idle containers are frozen with `cgroup.freeze` and the daemon exits, letting WSL reclaim the VM |
| **Snapshots** | `docker commit` produces a new image and nothing else | `hull snapshot` / `revert` / `branch` / `diff` on a live container's overlay upper layer, near-free via reflinks |
| **Isolation** | user namespaces are opt-in and awkward | user namespaces on by default with per-container uid ranges; `crun` available as a safety net while hull's own runtime earns trust |
| **Reaching a container** | port publishing breaks in mirrored and Consomme networking modes | every published port gets a real listening socket in the root netns — the only thing WSL's localhost relay actually forwards — plus DNAT for LAN traffic |

Plus: `*.localhost` routing with local HTTPS, an environment lockfile that pins every image to a
digest, a TUI dashboard, a `--explain` mode that narrates every kernel step it takes, and a
`hull doctor` that tells you the truth about your machine instead of failing mysteriously.

## Install

```powershell
# from a WSL shell, build everything
make build && make windows && make distro

# from Windows PowerShell, register the engine distro
.\scripts\install.ps1
```

Then either use hull's own CLI:

```
hull doctor
hull run --rm alpine echo hello
hull ps
hull ui
```

…or point the Docker CLI at it:

```powershell
$env:DOCKER_HOST = "npipe:////./pipe/hull_engine"
docker run --rm alpine echo hello
docker compose up
```

Docker Desktop can stay installed and running. hull uses its own WSL distro, its own named pipe,
its own subnet pool (`10.66.0.0/16`) and its own data root, so the two do not collide.

## Layout

```
cmd/hulld          the daemon (runs inside the engine distro)
cmd/hull           the CLI and TUI (builds for both linux and windows)
cmd/hull-init      the in-container PID 1 / namespace-entry stage
cmd/hull-shim      the per-container supervisor
internal/          one package per subsystem — see docs/ARCHITECTURE.md for the layering
distro/            the Alpine engine distro's rootfs overlay
scripts/           build-distro.sh, install.ps1, wslgo.sh
test/              integration and CVE-regression suites (build tag: e2e)
```

## Building

The code is Linux code; build it inside WSL. From Windows, `scripts/wslgo.sh` proxies a command
into the Ubuntu dev distro with Go on `PATH`:

```bash
./scripts/wslgo.sh 'make build'
./scripts/wslgo.sh 'go test ./...'
```

Requirements inside the dev distro: Go 1.26+, `nftables`, `iproute2`, `iptables`, and `crun` if
you want the fallback runtime. The engine distro ships its own copies.

## Credits

The kernel primitives were learned from the usual suspects — lizzie.io's *Linux containers in 500
lines of C*, Julian Friedman's InfoQ Go article, Liz Rice's *containers from scratch*,
rubber-docker and bocker. hull is not a port of any of them: all five predate cgroup v2, the OCI
distribution API and every runc CVE of the last five years, and
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) records where their approaches are unsafe today.

## License

MIT
