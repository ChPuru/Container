# hull CLI

Two surfaces, one engine.

- **`hull …`** — hull's own CLI. Docker's verbs where they are good, hull's where they are better.
- **The Docker Engine API** on `\\.\pipe\hull_engine` (Windows) and `/var/lib/hull/run/hull.sock`
  (Linux), so `docker`, `docker compose`, Dev Containers and Testcontainers work unchanged.

`hull` accepts the Docker flag spellings everywhere they exist, so muscle memory transfers. Where
hull adds something Docker has no equivalent for, the flag is prefixed to make that obvious.

## Containers

```
hull run [opts] IMAGE [CMD...]      create and start
hull create [opts] IMAGE [CMD...]   create without starting
hull start [-a] [-i] CTR...
hull stop [-t N] CTR...             stop signal, then SIGKILL after the timeout
hull restart [-t N] CTR...
hull kill [-s SIG] CTR...
hull pause CTR... / hull unpause CTR...
hull rm [-f] [-v] CTR...
hull ps [-a] [-q] [--filter K=V] [--format ...]
hull inspect [--format ...] OBJ...
hull logs [-f] [--tail N] [--since T] [--until T] [-t] CTR
hull exec [-it] [-u USER] [-w DIR] [-e K=V] CTR CMD...
hull attach [--detach-keys K] CTR
hull top CTR [ps-opts]
hull stats [--no-stream] [CTR...]
hull port CTR [PORT[/PROTO]]
hull rename CTR NAME
hull update [--memory ...] [--cpus ...] CTR...
hull wait CTR...
hull cp SRC DST                     container:path or host path, either direction
hull diff CTR                       filesystem changes against the image
hull commit [-m MSG] CTR [REPO:TAG]
hull export CTR > rootfs.tar
hull prune [--all] [--volumes]
```

Key `run` flags: `-d --rm -i -t --name --hostname -e --env-file -w -u -v --mount --tmpfs
-p --publish-all --network --network-alias --dns --add-host --restart --memory --memory-swap
--cpus --cpu-shares --cpuset-cpus --pids-limit --ulimit --cap-add --cap-drop --privileged
--security-opt --read-only --init --device --sysctl --label --health-cmd --stop-signal
--stop-timeout --pull --platform --runtime`.

hull-only `run` flags:

| Flag | What it does |
|---|---|
| `--explain` | narrates every kernel step — namespaces created, mounts made, cgroup writes, seccomp install — as it happens. A teaching mode and a debugging mode. |
| `--isolation=userns\|host\|gvisor` | picks the isolation tier per container instead of per daemon |
| `--budget=mem=2G,cpu=2` | a soft budget: hull warns via PSI pressure instead of OOM-killing outright |
| `--idle-freeze=5m` | freeze this container when it has had no activity for the given time |

## Images

```
hull pull [--platform P] REF
hull push REF
hull images [-a] [-q] [--filter K=V]
hull image inspect REF
hull rmi [-f] REF...
hull tag SRC TARGET
hull save REF... > img.tar   /   hull load < img.tar
hull login [-u USER] [--password-stdin] [REGISTRY]
hull logout [REGISTRY]
hull history REF
hull build [-t TAG] [-f FILE] [--build-arg K=V] PATH
```

## Networks and volumes

```
hull network create [--subnet CIDR] [--gateway IP] [-d bridge] NAME
hull network ls / inspect / rm / connect / disconnect / prune
hull volume create [--label K=V] [NAME]
hull volume ls / inspect / rm / prune
```

## hull's own verbs

```
hull doctor [--json]              what this machine supports, and the exact fix for what it does not
hull ui                           the TUI dashboard: containers, logs, stats, events
hull events [--filter K=V]        the live event stream

hull snapshot CTR NAME            checkpoint a running container's writable layer
hull snapshot ls CTR
hull revert CTR NAME              roll the writable layer back to a checkpoint
hull branch CTR NAME NEW-CTR      start a new container from a checkpoint
hull snapshot diff CTR A B        what changed between two checkpoints

hull lock [--update]              write hull.lock, pinning every image in the project to a digest
hull sync PATH                    two-way sync a Windows folder into a volume, with real inotify
hull debug CTR                    attach a busybox toolbox to a distroless container's namespaces
hull engine status|start|stop|restart|logs
hull engine gc [--dry-run]        reclaim unreferenced blobs and snapshots
```

## Output

Every listing command supports `--format` with Go template syntax and `--format json` for a JSON
array. `-q` prints bare IDs. hull detects a non-TTY stdout and drops colour and progress bars, so
piping into `jq` or a script is always safe.

## Environment

| Variable | Meaning |
|---|---|
| `HULL_HOST` | where to reach the engine; defaults to the named pipe on Windows and the unix socket on Linux |
| `HULL_DATA_ROOT` | the engine's data directory (default `/var/lib/hull`) |
| `HULL_DISTRO` | which WSL distro holds the engine (default `hull-engine`) |
| `HULL_RUNTIME` | `hull` (native) or `crun` |
| `DOCKER_HOST` | honoured too, so `hull` works as a drop-in in scripts that already set it |
