# install.ps1 — register the hull-engine WSL distro and put hull.exe on PATH.
#
#   .\scripts\install.ps1                 install or upgrade
#   .\scripts\install.ps1 -Uninstall      remove the distro and the shim
#
# This never touches Docker Desktop. hull uses its own distro, its own named pipe, its own
# subnet pool and its own data, so the two run side by side.

[CmdletBinding()]
param(
    [string]$DistroName = 'hull-engine',
    [string]$InstallRoot = "$env:LOCALAPPDATA\hull",
    [string]$Tarball,
    [switch]$Uninstall,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot

function Info($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Warn($m) { Write-Host "warning: $m" -ForegroundColor Yellow }
function Die($m)  { Write-Host "error: $m" -ForegroundColor Red; exit 1 }

function Get-Distros {
    # wsl.exe writes UTF-16LE unless WSL_UTF8 is set, which mangles every string comparison.
    $env:WSL_UTF8 = '1'
    (& wsl.exe --list --quiet) | ForEach-Object { $_.Trim() } | Where-Object { $_ }
}

if ($Uninstall) {
    Info "unregistering $DistroName"
    if ((Get-Distros) -contains $DistroName) {
        & wsl.exe --terminate $DistroName 2>$null | Out-Null
        & wsl.exe --unregister $DistroName
    } else {
        Warn "$DistroName is not registered"
    }
    if (Test-Path $InstallRoot) { Remove-Item -Recurse -Force $InstallRoot }
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $binDir = Join-Path $InstallRoot 'bin'
    if ($userPath -and $userPath.Contains($binDir)) {
        $cleaned = ($userPath -split ';' | Where-Object { $_ -ne $binDir }) -join ';'
        [Environment]::SetEnvironmentVariable('Path', $cleaned, 'User')
        Info "removed $binDir from PATH"
    }
    Info 'hull removed.'
    exit 0
}

# --- preflight ---------------------------------------------------------------------
Info 'checking WSL'
$env:WSL_UTF8 = '1'
$wslVersion = (& wsl.exe --version) -join "`n"
if ($LASTEXITCODE -ne 0) { Die "WSL is not installed. Run 'wsl --install' first." }

if ($wslVersion -match 'WSL version:\s*([\d.]+)') {
    $v = [version]$Matches[1]
    Write-Host "    WSL $v"
    if ($v -lt [version]'2.5.1') {
        Warn @"
WSL $v still mounts cgroup v1, so hull cannot delegate cgroup v2 controllers and
resource limits (--memory, --cpus) will not work.

  Fix it with:   wsl --update
  Or, to stay on this version, add to $env:USERPROFILE\.wslconfig under [wsl2]:
                 kernelCommandLine = cgroup_no_v1=all
  then:          wsl --shutdown

'hull doctor' will tell you exactly what is missing after install.
"@
    }
}

if (-not $Tarball) { $Tarball = Join-Path $repo 'dist\hull-engine.tar.gz' }
if (-not (Test-Path $Tarball)) {
    Die "no distro tarball at $Tarball — build it first with 'make build && make distro' inside WSL"
}

# --- install -----------------------------------------------------------------------
$distroDir = Join-Path $InstallRoot 'distro'
$binDir    = Join-Path $InstallRoot 'bin'
New-Item -ItemType Directory -Force -Path $distroDir, $binDir | Out-Null

if ((Get-Distros) -contains $DistroName) {
    if (-not $Force) {
        Die "$DistroName is already registered. Re-run with -Force to replace it (this deletes every container and image it holds)."
    }
    Info "replacing the existing $DistroName"
    & wsl.exe --terminate $DistroName 2>$null | Out-Null
    & wsl.exe --unregister $DistroName
}

Info "importing $DistroName from $(Split-Path -Leaf $Tarball)"
& wsl.exe --import $DistroName $distroDir $Tarball --version 2
if ($LASTEXITCODE -ne 0) { Die 'wsl --import failed' }

Info 'installing Alpine packages inside the engine'
& wsl.exe -d $DistroName -u root -e /bin/sh -c 'apk update >/dev/null 2>&1 && apk add --no-cache $(cat /etc/apk/world | tr "\n" " ") >/dev/null 2>&1; crun --version | head -1'
if ($LASTEXITCODE -ne 0) {
    Warn 'package install failed (no network in the distro?). hull will run with its native runtime only; crun will be unavailable as a fallback.'
}

$hullExe = Join-Path $repo 'bin\hull.exe'
if (Test-Path $hullExe) {
    Copy-Item $hullExe (Join-Path $binDir 'hull.exe') -Force
    Info "installed hull.exe to $binDir"
} else {
    Warn "no bin\hull.exe — build it inside WSL with 'make windows'"
}

$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (-not $userPath) { $userPath = '' }
if (-not ($userPath -split ';' | Where-Object { $_ -eq $binDir })) {
    [Environment]::SetEnvironmentVariable('Path', "$userPath;$binDir".Trim(';'), 'User')
    Info "added $binDir to your PATH (restart your terminal to pick it up)"
}

# --- start -------------------------------------------------------------------------
Info 'starting the engine'
& wsl.exe -d $DistroName -u root -e /bin/sh -c '/usr/local/bin/hull-boot >/dev/null 2>&1 &' | Out-Null
Start-Sleep -Seconds 2

Info 'engine status'
& wsl.exe -d $DistroName -u root -e /bin/sh -c 'test -S /run/hull/hull.sock && echo "  socket: up" || echo "  socket: NOT up — see /var/log/hull-boot.log"'

Write-Host ''
Write-Host 'hull is installed.' -ForegroundColor Green
Write-Host ''
Write-Host '  hull doctor          check what this machine supports'
Write-Host '  hull run alpine echo hi'
Write-Host '  hull ui              the dashboard'
Write-Host ''
Write-Host 'To point the stock docker CLI at hull instead of Docker Desktop:'
Write-Host '  $env:DOCKER_HOST = "npipe:////./pipe/hull_engine"' -ForegroundColor DarkGray
Write-Host ''
