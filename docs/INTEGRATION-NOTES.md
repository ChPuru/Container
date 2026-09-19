# Integration notes

Things found by actually running the code, that no unit test caught. Each one is either fixed
or has a named owner.

## 1. `ociVersion` must be negotiated, not asserted — FIXED

`internal/oci/runtimespec.Version` is `"1.2.0"`, the current OCI runtime-spec release. Handing
that to `crun 1.14.1` (what Ubuntu 24.04 ships) fails with a bare `unknown version specified`
and no clue as to which field it disliked. crun's own `crun spec` emits `"1.0.0"`.

Downgrading the generated `config.json` to `"1.0.2"` made the exact same bundle run perfectly —
so the version string was the *only* incompatibility, not any field hull emits.

**Fix:** `bundle.Options.SpecVersion` selects the version, and each runtime driver reports the
highest it accepts through `Features()`. The engine asks the driver and passes it down. hull
still *models* 1.2.0; it just writes whatever the installed runtime will read.

This matters beyond crun: runc, youki and gVisor all have their own floors, and a user with an
older runtime on `PATH` would otherwise hit an unreadable error on their very first `hull run`.

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

## 5. A bridge with no endpoints reports `NO-CARRIER`

`hull0` shows operstate `DOWN` with the `UP` flag set until the first veth is attached. That is
normal Linux behaviour, but `hull doctor` and the TUI must not report it as a fault.
