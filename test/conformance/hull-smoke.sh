#!/usr/bin/env bash
# hull-smoke.sh — exercise hull's own CLI, including the verbs Docker has no equivalent for.
#
# smoke.sh proves hull is compatible. This proves hull is worth using.
#
#   ./test/conformance/hull-smoke.sh
#
# Exit code is the number of failed checks.

set -uo pipefail

HULL="${HULL:-hull}"
PREFIX="hullown-$$"
FAILED=0
PASSED=0

green() { printf '\033[32m%s\033[0m\n' "$*"; }
red()   { printf '\033[31m%s\033[0m\n' "$*"; }
head2() { printf '\n\033[1m── %s\033[0m\n' "$*"; }

check() {
    local name="$1"; shift
    if "$@" >/tmp/$PREFIX.out 2>&1; then
        green "  pass  $name"; PASSED=$((PASSED+1))
    else
        red   "  FAIL  $name"; sed 's/^/        /' /tmp/$PREFIX.out | head -6; FAILED=$((FAILED+1))
    fi
}

check_out() {
    local name="$1" want="$2"; shift 2
    local got; got="$("$@" 2>&1)"
    if [[ "$got" == *"$want"* ]]; then
        green "  pass  $name"; PASSED=$((PASSED+1))
    else
        red   "  FAIL  $name — wanted '$want', got:"; echo "$got" | sed 's/^/        /' | head -6
        FAILED=$((FAILED+1))
    fi
}

cleanup() {
    $HULL rm -f "$PREFIX-a" "$PREFIX-b" "$PREFIX-branch" >/dev/null 2>&1
    $HULL volume rm "$PREFIX-vol" >/dev/null 2>&1
    $HULL network rm "$PREFIX-net" >/dev/null 2>&1
    rm -f /tmp/$PREFIX.out /tmp/$PREFIX.lock
}
trap cleanup EXIT

head2 "doctor"
# doctor exits non-zero when a check fails, which is correct on a machine that has not had
# 'wsl --update' run. What matters is that it produces a report and names remedies.
$HULL doctor >/tmp/$PREFIX.doctor 2>&1
check_out "doctor reports on cgroups"  "cgroup"     cat /tmp/$PREFIX.doctor
check_out "doctor names a remedy"      "wsl --update" cat /tmp/$PREFIX.doctor
check     "doctor --json is valid json" bash -c "$HULL doctor --json 2>/dev/null | python3 -m json.tool >/dev/null"

head2 "basics"
check_out "version"        "hull"        $HULL version
check     "info"                         $HULL info
check     "pull"                         $HULL pull alpine:3.20
check_out "run prints stdout" "hello"    $HULL run --rm alpine:3.20 echo hello
check     "run detached"                 $HULL run -d --name "$PREFIX-a" alpine:3.20 sleep 300
check_out "ps shows it"  "$PREFIX-a"     $HULL ps
check_out "exec"         "inside"        $HULL exec "$PREFIX-a" echo inside
check     "logs"                         $HULL logs "$PREFIX-a"
check     "stats one-shot"               $HULL stats --no-stream "$PREFIX-a"
check     "inspect"                      $HULL inspect "$PREFIX-a"

head2 "formatting and quiet output"
check_out "ps -q is bare ids"  ""        bash -c "$HULL ps -q | grep -qE '^[0-9a-f]{12}'"
check     "ps --format json parses"      bash -c "$HULL ps --format json | python3 -m json.tool >/dev/null"
check_out "ps --format template" "$PREFIX-a" bash -c "$HULL ps --format '{{.Names}}'"
check_out "images lists alpine" "alpine" $HULL images

head2 "snapshots and time travel — hull's own"
check     "write a file, then snapshot"  bash -c "
    $HULL exec $PREFIX-a sh -c 'echo v1 > /marker' &&
    $HULL snapshot $PREFIX-a v1"
check_out "snapshot ls shows it" "v1"    $HULL snapshot ls "$PREFIX-a"
check     "change the file, snapshot again" bash -c "
    $HULL exec $PREFIX-a sh -c 'echo v2 > /marker' &&
    $HULL snapshot $PREFIX-a v2"
check_out "snapshot diff names the change" "marker" $HULL snapshot diff "$PREFIX-a" v1 v2
check_out "revert restores v1"  "v1"     bash -c "
    $HULL stop -t 2 $PREFIX-a >/dev/null &&
    $HULL revert $PREFIX-a v1 &&
    $HULL start $PREFIX-a >/dev/null &&
    $HULL exec $PREFIX-a cat /marker"
check     "branch makes a new container" bash -c "
    $HULL branch $PREFIX-a v2 $PREFIX-branch"
check_out "the branch has v2"   "v2"     bash -c "
    $HULL start $PREFIX-branch >/dev/null && $HULL exec $PREFIX-branch cat /marker"

head2 "lockfile"
check     "lock writes hull.lock"        bash -c "cd /tmp && $HULL lock --update >/dev/null && test -f hull.lock"
check_out "lock pins a digest" "sha256:" bash -c "cat /tmp/hull.lock 2>/dev/null"

head2 "explain mode"
check_out "explain narrates namespaces" "namespace" bash -c "
    $HULL run --rm --explain alpine:3.20 true 2>&1"
check_out "explain narrates seccomp"    "seccomp"   bash -c "
    $HULL run --rm --explain alpine:3.20 true 2>&1"

head2 "networks and volumes"
check     "network create"               $HULL network create "$PREFIX-net"
check     "volume create"                $HULL volume create "$PREFIX-vol"
check_out "volume round trip" "kept"     bash -c "
    $HULL run --rm -v $PREFIX-vol:/d alpine:3.20 sh -c 'echo kept > /d/f' &&
    $HULL run --rm -v $PREFIX-vol:/d alpine:3.20 cat /d/f"

head2 "engine control"
check     "engine status"                $HULL engine status
check     "engine gc --dry-run"          $HULL engine gc --dry-run

printf '\n'
if [ "$FAILED" -eq 0 ]; then
    green "all $PASSED checks passed"
else
    red "$FAILED failed, $PASSED passed"
fi
exit "$FAILED"
