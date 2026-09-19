# Integration notes

Things found by actually running the code, that no unit test caught. Each one is either fixed
or has a named owner.

## 1. `ociVersion` must be negotiated, not asserted — FIXED

`internal/oci/runtimespec.Version` is `"1.2.0"`, the current OCI runtime-spec release. Handing
that to `crun 1.14.1` (what Ubuntu 24.04 ships) fails with a bare `unknown version specified`
and no clue as to which field it disliked. crun's own `crun spec` emits `"1.0.0"`.

Downgrading the generated `config.json` to `"1.0.2"` made the exact same bundle run perfectly —
so the version string was the *only* incompatibility, not any field hull emits.

The runtime tells us what it wants, if we ask. `crun features` returns:

```json
{ "ociVersionMin": "1.0.0", "ociVersionMax": "1.1.0+dev", ... }
```

**Fix:** `bundle.Options.SpecVersion` selects the version, and each driver reports its accepted
range through `RuntimeFeatures.OCIVersions` — the crun driver parses it from `crun features`
(stripping a `+dev` suffix) and falls back to `1.0.2` when the subcommand is missing, as it is
on older runc. The engine takes the lower of hull's version and the driver's maximum. hull still
*models* 1.2.0; it just writes whatever the installed runtime will read.

This matters beyond crun: runc, youki and gVisor all have their own floors, and a user with an
older runtime on `PATH` would otherwise hit an unreadable error on their very first `hull run`.

## 1b. `type: "cgroup"` is a request, not an instruction — FIXED

The native runtime reaches the in-container init stage and then dies:

```
hull-init: initspec: mount /sys/fs/cgroup: mount(cgroup, type cgroup, ...): operation not permitted
```

hull's bundle is not wrong here — it emits exactly the mount crun's own `crun spec` emits, which
is what the OCI spec says:

```json
{"destination": "/sys/fs/cgroup", "type": "cgroup", "source": "cgroup",
 "options": ["nosuid", "noexec", "nodev", "relatime", "ro"]}
```

The mistake is taking it literally. Every real runtime special-cases `type: "cgroup"` and decides
what to actually mount from the host's cgroup mode:

- **unified host** → `mount -t cgroup2`, or bind the delegated subtree when the container has no
  cgroup namespace
- **hybrid or legacy host** (this one) → bind the host's `/sys/fs/cgroup` read-only, or mount each
  v1 controller individually; a fresh `mount -t cgroup` from an unprivileged mount namespace is
  `EPERM` and always will be
- **inside a user namespace** → always a read-only bind, never a fresh filesystem

Probed directly on this host, so the fix is not guesswork:

| Attempt (in a fresh mount namespace) | Result |
|---|---|
| `mount -t cgroup2 none <dir>` with a cgroup namespace | **works** — even here, on the hybrid host |
| `mount -t cgroup none <dir>` (no controller named) | fails — `none already mounted on /dev` |
| `mount --rbind /sys/fs/cgroup <dir>` then remount `ro` | **works** |

So the rule is simple and has no host-dependent branch on this machine: **never issue
`mount -t cgroup`.** Mount `cgroup2` when the container has a cgroup namespace, and fall back to
a read-only recursive bind of the host's `/sys/fs/cgroup` when it does not, or when the container
runs in a user namespace.

Fixed in `internal/runtime/initspec/cgroupmount_linux.go`: the init stage now resolves the
request into candidates and takes the first that mounts.

## 1c. Nobody was creating the default devices — FIXED

With the cgroup mount working, the next failure was
`open /dev/null to mask a file: no such file or directory`, which says nothing about the actual
problem. `linux.devices` in the spec is the list of devices a caller wants *in addition to* a
standard set, and `SetupDevices` was creating only what the bundle listed — so `/dev` was empty,
and masking a path (which binds `/dev/null` over it) was the first thing to notice.

Fixed in `internal/runtime/initspec/defaultdev_linux.go`: `/dev/{null,zero,full,random,urandom,tty}`
are created before the caller's own devices, with an explicit entry always winning.
`/dev/console` is deliberately not in the set — it comes from the pty, and fabricating it here
would defeat the `fstat` check guarding the console symlink-swap CVEs.

**Result:** hull's native runtime now runs containers with the same posture as the crun path —
`pid=1`, `CapEff a80425fb`, `NoNewPrivs 1`, `Seccomp 2`, a real cgroup2 filesystem inside,
`mount` refused by hull's own hand-compiled cBPF filter, and `/proc/kcore` masked to zero bytes.

## 2. `error obtaining VCS status: exit status 128` — FIXED

Building any `cmd/` package inside WSL as root fails, because git refuses a repo owned by the
Windows user. The message never mentions git or ownership.

**Fix:** `git config --global --add safe.directory /mnt/d/container` in the dev distro. The
engine distro is unaffected (it builds nothing). `-buildvcs=false` also works but loses the
embedded revision, which `hull version` should report.

## 3. Overlay mounts outlive a crashing process

A scratch harness that called `os.Exit` skipped its deferred `Unmount`, leaving the overlay
mounted; the next run then failed with `EBUSY` on cleanup and `ENOENT` on the merged dir.

This is exactly the daemon-crash case, so it is not just a test artifact: the snapshotter
records mounts in `mounts.json` and reconciles them on startup, and `engine.New`'s recovery pass
must call that reconciliation **before** it touches any container directory. Verified behaviour
to preserve: `umount -l` (lazy) succeeds where a plain `umount` returns `EBUSY`.

## 4. cgroup v2 warnings surface at the right layer

`bundle.Generate` returns warnings rather than failing when resource limits are requested on a
host with no delegated cgroup v2 controllers, and the text names both remedies. That is the
correct behaviour — a container that runs without its memory cap is better than one that refuses
to start — but the engine must propagate those warnings into the API response and the CLI, or
the user silently gets unlimited containers. Owner: `internal/engine` + `internal/api`.

## 5. The differentiators are built but not yet wired — OPEN

Each differentiator is a self-contained package with its own tests, deliberately not reaching
into the engine. That leaves a short, specific wiring list, recorded here so it does not get
lost between phases.

**`internal/idle` (scale-to-zero)** — the engine already has every field the `idle.Source`
interface wants:

| `idle.Snapshot` field | engine source |
|---|---|
| `Attached` | `ctrState.attachments` |
| `CGroupPath` | `e.cgroupPath(id)` |
| `Freeze` / `Thaw` / `Frozen` | `cgroups.Manager` |

`engine.Config.IdleFreeze` / `IdleExit` map straight onto `idle.Config.FreezeAfter` / `ExitAfter`.
Beyond that:

- **`internal/network`'s port proxy must call `ThawFor(ctx, id)` before dialling the container**,
  and `TouchWith(id, idle.ReasonPort)` as bytes move. The proxies are built from `startProxy`
  with only `IP:port` today, so the additive change is an optional hook field the engine fills in.
  Without this, a frozen container's published port hangs instead of waking it.
- The API layer calls `ClientConnected`/`ClientDisconnected`, `Touch(id)` on container-scoped
  requests, and must report a frozen container as **paused**, never as exited.
- `hull run --idle-freeze=5m` calls `SetFreezeAfter(id, d)`; a negative duration pins a container
  permanently awake.
- **The daemon must persist which containers *it* froze and call `Reclaim(ids...)` on recovery.**
  Without that, a freeze that outlived the daemon is indistinguishable from a user's `hull pause`,
  and the watcher will correctly refuse to undo it — leaving the container stuck.
- `Config.OnEvent` → the event bus, `Config.OnIdle` → the daemon's shutdown path,
  `Config.Logger` → the engine's `*slog.Logger`.

Deliberately not done: memory pressure as an activity signal (PSI is absent on the 5.15 WSL
kernel), and measuring what a freeze actually returns to Windows — that belongs in an e2e test
against a real distro.

**`internal/localproxy`** — `hull doctor` should probe whether `<name>.localhost` resolves on
this machine. Chrome and Edge resolve it internally; curl and PowerShell do not, because Windows'
resolver has no special case for it the way systemd-resolved does. The remedy is the hosts file
or the `127.0.0.1` + `Host:` header route.

## 6. `hull doctor --json` buries its answer under the kernel config

The JSON report embeds all 1499 `CONFIG_*` options from `/proc/config.gz`, so the fields anyone
actually wants are thousands of lines down. The data is genuinely useful in a bug report, but it
should not be the default: gate `Report.Kernel.Config` behind a `--verbose` flag, or move it to
a sibling `hull doctor --kconfig`. Owner: `internal/cli`, with a marshalling tweak in
`internal/hostinfo`.

## 7. A bridge with no endpoints reports `NO-CARRIER`

`hull0` shows operstate `DOWN` with the `UP` flag set until the first veth is attached. That is
normal Linux behaviour, but `hull doctor` and the TUI must not report it as a fault.
