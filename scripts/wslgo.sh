#!/usr/bin/env bash
# Run a Go/make command inside the Ubuntu WSL distro, from Windows git-bash.
#   scripts/wslgo.sh go build ./...
#   scripts/wslgo.sh make build
set -euo pipefail
exec "C:/Windows/System32/wsl.exe" -d Ubuntu -u root -e bash -lc "export PATH=/usr/local/go/bin:\$PATH; cd /mnt/d/container && $*"
