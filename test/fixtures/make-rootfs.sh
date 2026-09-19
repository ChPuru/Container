#!/usr/bin/env bash
# make-rootfs.sh — build a tiny busybox rootfs for the runtime tests.
#
# The end-to-end runtime tests need something to pivot_root into. Pulling a real image would
# make them depend on a registry, the network and the whole image stack, which is exactly what
# they are not trying to test. A static busybox plus a handful of directories is enough.
#
#   ./test/fixtures/make-rootfs.sh [dest]      # default: test/fixtures/rootfs
#
# Needs a static busybox. On Debian/Ubuntu: apt-get install busybox-static.
set -euo pipefail

DEST="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/rootfs}"

BUSYBOX=""
for cand in /bin/busybox /usr/bin/busybox /sbin/busybox; do
    # Only a *static* busybox works: the rootfs has no loader and no libc.
    if [ -x "$cand" ] && ! ldd "$cand" >/dev/null 2>&1; then BUSYBOX="$cand"; break; fi
done
if [ -z "$BUSYBOX" ]; then
    echo "error: no static busybox found. Install it with:" >&2
    echo "  apt-get install -y busybox-static   # Debian/Ubuntu" >&2
    echo "  apk add busybox-static              # Alpine" >&2
    exit 1
fi

rm -rf "$DEST"
mkdir -p "$DEST"/{bin,sbin,etc,proc,sys,dev,dev/pts,dev/shm,tmp,var,root,usr/bin,usr/sbin,run}
chmod 1777 "$DEST/tmp"

cp "$BUSYBOX" "$DEST/bin/busybox"
chmod 0755 "$DEST/bin/busybox"

# Every applet busybox knows about, as a symlink, so tests can call `sh`, `echo`, `ls`, `true`…
( cd "$DEST/bin" && for applet in $(./busybox --list); do
      [ "$applet" = busybox ] || ln -sf busybox "$applet"
  done )
ln -sf ../bin/busybox "$DEST/sbin/init"

cat > "$DEST/etc/passwd" <<'EOF'
root:x:0:0:root:/root:/bin/sh
daemon:x:1:1:daemon:/usr/sbin:/bin/false
nobody:x:65534:65534:nobody:/nonexistent:/bin/false
tester:x:1000:1000:tester:/home/tester:/bin/sh
EOF

cat > "$DEST/etc/group" <<'EOF'
root:x:0:
daemon:x:1:
tty:x:5:
nogroup:x:65534:
tester:x:1000:
extra:x:1001:tester
EOF

cat > "$DEST/etc/os-release" <<'EOF'
NAME="hull-test"
ID=hulltest
PRETTY_NAME="hull test rootfs"
EOF

printf 'hull-test\n'                       > "$DEST/etc/hostname"
printf '127.0.0.1 localhost\n::1 localhost\n' > "$DEST/etc/hosts"
printf 'nameserver 127.0.0.11\n'           > "$DEST/etc/resolv.conf"
mkdir -p "$DEST/home/tester" && chmod 0755 "$DEST/home/tester"

# A marker the tests can assert on to prove they are really inside the new root and not the host.
printf 'hull-test-rootfs\n' > "$DEST/.hull-marker"

echo "rootfs ready at $DEST ($(du -sh "$DEST" | cut -f1))"
echo "try it:  chroot $DEST /bin/sh -c 'cat /.hull-marker'"
