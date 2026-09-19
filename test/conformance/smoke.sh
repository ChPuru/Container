#!/usr/bin/env bash
# smoke.sh — point the real docker CLI at hull and make it do a normal day's work.
#
# This is the test that matters. Unit tests prove the pieces are right; this proves that a
# client which knows nothing about hull cannot tell the difference.
#
#   DOCKER_HOST=unix:///var/lib/hull/run/hull.sock ./test/conformance/smoke.sh
#
# Exit code is the number of failed checks.

set -uo pipefail

: "${DOCKER_HOST:=unix:///var/lib/hull/run/hull.sock}"
export DOCKER_HOST
DOCKER="${DOCKER:-docker}"
PREFIX="hullsmoke-$$"
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
    # check_out <name> <expected substring> <cmd...>
    local name="$1" want="$2"; shift 2
    local got
    got="$("$@" 2>&1)"
    if [[ "$got" == *"$want"* ]]; then
        green "  pass  $name"; PASSED=$((PASSED+1))
    else
        red   "  FAIL  $name — wanted '$want', got:"; echo "$got" | sed 's/^/        /' | head -6
        FAILED=$((FAILED+1))
    fi
}

cleanup() {
    $DOCKER rm -f "$PREFIX-a" "$PREFIX-b" "$PREFIX-web" >/dev/null 2>&1
    $DOCKER network rm "$PREFIX-net" >/dev/null 2>&1
    $DOCKER volume rm "$PREFIX-vol" >/dev/null 2>&1
    rm -f /tmp/$PREFIX.out /tmp/$PREFIX.tar
}
trap cleanup EXIT

head2 "daemon"
check_out "docker version reaches the engine" "Server" $DOCKER version
check     "docker info"                        $DOCKER info

head2 "images"
check     "pull alpine"                        $DOCKER pull -q alpine:3.20
check_out "image appears in ls"  "alpine"      $DOCKER images alpine:3.20
check     "inspect image"                      $DOCKER image inspect alpine:3.20
check     "tag"                                $DOCKER tag alpine:3.20 "$PREFIX:tagged"
check     "history"                            $DOCKER history alpine:3.20

head2 "run and exit codes"
check_out "stdout is captured"  "hello"        $DOCKER run --rm --name "$PREFIX-a" alpine:3.20 echo hello
check_out "exit code propagates" "42"          bash -c "$DOCKER run --rm alpine:3.20 sh -c 'exit 42' >/dev/null 2>&1; echo \$?"
check_out "env is set"          "VAL"          $DOCKER run --rm -e K=VAL alpine:3.20 sh -c 'echo $K'
check_out "workdir applies"     "/tmp"         $DOCKER run --rm -w /tmp alpine:3.20 pwd
check_out "hostname applies"    "smokehost"    $DOCKER run --rm --hostname smokehost alpine:3.20 hostname
check_out "entrypoint override" "over"         $DOCKER run --rm --entrypoint echo alpine:3.20 over

head2 "lifecycle"
check     "run detached"                       $DOCKER run -d --name "$PREFIX-b" alpine:3.20 sleep 300
check_out "ps shows it"         "$PREFIX-b"    $DOCKER ps
check_out "inspect name has the leading slash" "/$PREFIX-b" $DOCKER inspect -f '{{.Name}}' "$PREFIX-b"
check_out "state is running"    "true"         $DOCKER inspect -f '{{.State.Running}}' "$PREFIX-b"
check_out "exec works"          "execok"       $DOCKER exec "$PREFIX-b" echo execok
check     "top"                                $DOCKER top "$PREFIX-b"
check     "stats one-shot"                     $DOCKER stats --no-stream "$PREFIX-b"
check     "pause"                              $DOCKER pause "$PREFIX-b"
check_out "paused state"        "paused"       $DOCKER inspect -f '{{.State.Status}}' "$PREFIX-b"
check     "unpause"                            $DOCKER unpause "$PREFIX-b"
check     "restart"                            $DOCKER restart -t 2 "$PREFIX-b"
check     "stop"                               $DOCKER stop -t 2 "$PREFIX-b"
check_out "exited state"        "exited"       $DOCKER inspect -f '{{.State.Status}}' "$PREFIX-b"
check     "rm"                                 $DOCKER rm "$PREFIX-b"

head2 "logs"
$DOCKER run -d --name "$PREFIX-b" alpine:3.20 sh -c 'for i in 1 2 3 4 5; do echo line$i; sleep 0.1; done; sleep 30' >/dev/null
sleep 2
check_out "logs captured"       "line3"        $DOCKER logs "$PREFIX-b"
check_out "logs --tail"         "line5"        $DOCKER logs --tail 1 "$PREFIX-b"
check     "logs with timestamps"               $DOCKER logs -t "$PREFIX-b"
$DOCKER rm -f "$PREFIX-b" >/dev/null 2>&1

head2 "filesystem"
check     "cp out of a container"              bash -c "$DOCKER run -d --name $PREFIX-b alpine:3.20 sleep 60 >/dev/null && $DOCKER cp $PREFIX-b:/etc/hostname /tmp/$PREFIX.out"
check     "cp into a container"                $DOCKER cp /etc/hosts "$PREFIX-b:/tmp/hosts"
check_out "the copied file is there" "hosts"   $DOCKER exec "$PREFIX-b" ls /tmp
check     "diff"                               $DOCKER diff "$PREFIX-b"
check     "export"                             bash -c "$DOCKER export $PREFIX-b > /tmp/$PREFIX.tar"
check     "commit"                             $DOCKER commit "$PREFIX-b" "$PREFIX:committed"
$DOCKER rm -f "$PREFIX-b" >/dev/null 2>&1

head2 "volumes"
check     "volume create"                      $DOCKER volume create "$PREFIX-vol"
check_out "write then read through a volume" "persisted" bash -c "
    $DOCKER run --rm -v $PREFIX-vol:/data alpine:3.20 sh -c 'echo persisted > /data/f' &&
    $DOCKER run --rm -v $PREFIX-vol:/data alpine:3.20 cat /data/f"
check     "volume ls"                          $DOCKER volume ls
check     "volume inspect"                     $DOCKER volume inspect "$PREFIX-vol"

head2 "networking"
check     "network create"                     $DOCKER network create "$PREFIX-net"
check     "network inspect"                    $DOCKER network inspect "$PREFIX-net"
check_out "container reaches the internet" "0" bash -c "
    $DOCKER run --rm alpine:3.20 sh -c 'ping -c1 -W3 1.1.1.1 >/dev/null 2>&1; echo \$?'"
check_out "dns resolves by container name" "alive" bash -c "
    $DOCKER run -d --name $PREFIX-a --network $PREFIX-net alpine:3.20 sleep 60 >/dev/null &&
    $DOCKER run --rm --network $PREFIX-net alpine:3.20 sh -c 'getent hosts $PREFIX-a >/dev/null && echo alive'"
check     "published port is reachable from the host" bash -c "
    $DOCKER run -d --name $PREFIX-web -p 18080:80 alpine:3.20 sh -c 'while :; do printf \"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok\" | nc -l -p 80; done' >/dev/null
    sleep 2
    curl -sf --max-time 5 http://127.0.0.1:18080/ | grep -q ok"

head2 "resources"
check_out "memory limit is applied" "268435456" $DOCKER run --rm --memory 256m alpine:3.20 cat /sys/fs/cgroup/memory.max
check_out "pids limit is applied"   "42"        $DOCKER run --rm --pids-limit 42 alpine:3.20 cat /sys/fs/cgroup/pids.max
check     "cpu limit is accepted"               $DOCKER run --rm --cpus 0.5 alpine:3.20 true

head2 "isolation"
check_out "pid namespace is separate"  "1"      $DOCKER run --rm alpine:3.20 sh -c 'echo $$'
check_out "root filesystem is the image" "alpine" bash -c "$DOCKER run --rm alpine:3.20 cat /etc/os-release | head -1"
check_out "read-only rootfs is enforced" "fail" bash -c "
    $DOCKER run --rm --read-only alpine:3.20 sh -c 'touch /x 2>/dev/null || echo fail'"
check_out "dropped caps really are dropped" "fail" bash -c "
    $DOCKER run --rm --cap-drop NET_RAW alpine:3.20 sh -c 'ping -c1 -W1 127.0.0.1 >/dev/null 2>&1 || echo fail'"

head2 "errors"
check_out "missing container 404s clearly" "No such container" bash -c "$DOCKER inspect $PREFIX-nope 2>&1"
check_out "duplicate name conflicts"       "already in use"     bash -c "
    $DOCKER run -d --name $PREFIX-b alpine:3.20 sleep 30 >/dev/null
    $DOCKER run -d --name $PREFIX-b alpine:3.20 sleep 30 2>&1"

head2 "events"
check     "events replays from a past time"     bash -c "timeout 5 $DOCKER events --since 5m --until 1s >/dev/null"

printf '\n'
if [ "$FAILED" -eq 0 ]; then
    green "all $PASSED checks passed"
else
    red "$FAILED failed, $PASSED passed"
fi
exit "$FAILED"
