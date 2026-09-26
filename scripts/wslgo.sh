#!/usr/bin/env bash
# Run a Go/make command inside the WSL dev distro, from Windows git-bash.
#   scripts/wslgo.sh go build ./...
#   scripts/wslgo.sh make build
# HULL_DEV_DISTRO picks the distro (default: Ubuntu).
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && (pwd -W 2>/dev/null || pwd))"
exec "C:/Windows/System32/wsl.exe" -d "${HULL_DEV_DISTRO:-Ubuntu}" -u root -e bash -lc \
    "export PATH=/usr/local/go/bin:\$PATH; cd \"\$(wslpath -a '$root')\" && $*"
