#!/usr/bin/env bash
# Build the hull-engine WSL distro tarball.
#
# The engine does not live in your Ubuntu. It gets its own minimal Alpine distro so it is
# reproducible, so it can force its own settings, and so nothing it does can break your dev
# environment. This script produces dist/hull-engine.tar.gz, which install.ps1 feeds to
# `wsl --import`.
#
# Run it inside a Linux environment with curl and tar (the Ubuntu dev distro is fine):
#   ./scripts/build-distro.sh
set -euo pipefail

ALPINE_VERSION="${ALPINE_VERSION:-3.22}"
ALPINE_PATCH="${ALPINE_PATCH:-3.22.2}"
ARCH="${ARCH:-x86_64}"
MIRROR="${MIRROR:-https://dl-cdn.alpinelinux.org/alpine}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT/bin"
DIST="$ROOT/dist"
WORK="$DIST/rootfs"

log() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

for b in hulld hull hull-init hull-shim; do
  [ -x "$BIN/$b" ] || die "missing $BIN/$b — run 'make build' first"
done

mkdir -p "$DIST"
rm -rf "$WORK"
mkdir -p "$WORK"

TARBALL="alpine-minirootfs-${ALPINE_PATCH}-${ARCH}.tar.gz"
CACHE="$DIST/$TARBALL"
if [ ! -f "$CACHE" ]; then
  log "fetching Alpine ${ALPINE_PATCH} minirootfs"
  # -4 is deliberate: WSL's NAT has no IPv6, and AAAA-only resolution hangs for 10s per try.
  curl -4 -fsSL --retry 3 -o "$CACHE" \
    "$MIRROR/v${ALPINE_VERSION}/releases/${ARCH}/${TARBALL}"
fi

log "unpacking rootfs"
tar -C "$WORK" -xzf "$CACHE"

log "installing hull binaries"
install -D -m 0755 "$BIN/hulld"     "$WORK/usr/local/bin/hulld"
install -D -m 0755 "$BIN/hull"      "$WORK/usr/local/bin/hull"
install -D -m 0755 "$BIN/hull-init" "$WORK/usr/local/lib/hull/hull-init"
install -D -m 0755 "$BIN/hull-shim" "$WORK/usr/local/lib/hull/hull-shim"

log "installing distro configuration"
cp -a "$ROOT/distro/rootfs/." "$WORK/"
chmod 0755 "$WORK/usr/local/bin/hull-boot" "$WORK/etc/init.d/hulld" 2>/dev/null || true

# Packages the engine genuinely needs at runtime. crun is the safety-net runtime the user chose;
# nftables and iproute2 back the network manager; ca-certificates is needed for registry TLS.
log "staging package install list"
cat > "$WORK/etc/apk/world" <<'PKGS'
alpine-baselayout
alpine-keys
apk-tools
busybox
busybox-openrc
ca-certificates
crun
iproute2
iptables
musl
nftables
openrc
tzdata
PKGS

mkdir -p "$WORK/var/lib/hull" "$WORK/run/hull" "$WORK/mnt/wsl"
chmod 0700 "$WORK/var/lib/hull"

log "packing dist/hull-engine.tar.gz"
# --numeric-owner matters: wsl --import preserves uids, and Alpine expects root:root as 0:0.
tar -C "$WORK" --numeric-owner -czf "$DIST/hull-engine.tar.gz" .

rm -rf "$WORK"
log "done: $DIST/hull-engine.tar.gz ($(du -h "$DIST/hull-engine.tar.gz" | cut -f1))"
log "install it from Windows PowerShell with: .\\scripts\\install.ps1"
