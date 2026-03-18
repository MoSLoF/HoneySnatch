#!/usr/bin/env pwsh
<#
.SYNOPSIS
    honeysnatch — HackberryPi CM5 Pre-Flight Setup
    Run this on iHBV-TUF (Windows) to prepare a HackberryPi CM5
    before first boot / first connect.

.DESCRIPTION
    Covers:
      1. Verify SSH connectivity to the device
      2. Push the honeysnatch repo to the device
      3. Transfer deploy script and requirements files
      4. Optionally launch the deploy script over SSH
      5. Wire in the FHS MCP server endpoint for remote ops

.NOTES
    Prerequisites on iHBV-TUF:
      - OpenSSH client (ships with Windows 10+)
      - Git for Windows
      - The HackberryPi must be on the same LAN (or USB-OTG network)

.PARAMETER DeviceHost
    Hostname or IP of the HackberryPi. Default: hackberrypi.local

.PARAMETER DeviceUser
    SSH username. Default: kali (Kali default) or pi (Pi OS default)

.PARAMETER RepoPath
    Local path to the honeysnatch repo. Default: H:\Development\Projects\honeysnatch

.PARAMETER Deploy
    If set, automatically runs deploy-hackberrypi.sh on the device after push.

.PARAMETER SkipHostap
    Pass --skip-hostap to the deploy script (no isolation testing).

.EXAMPLE
    .\Prepare-HackberryPi.ps1
    .\Prepare-HackberryPi.ps1 -DeviceHost 192.168.1.42 -Deploy
    .\Prepare-HackberryPi.ps1 -DeviceHost hackberrypi.local -Deploy -SkipHostap
#>
[CmdletBinding()]
param(
    [string] $DeviceHost  = "hackberrypi.local",
    [string] $DeviceUser  = "kali",
    [string] $RepoPath    = "H:\Development\Projects\honeysnatch",
    [switch] $Deploy,
    [switch] $SkipHostap,
    [switch] $DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Write-Step  { param([string]$msg) Write-Host "  [>>] $msg" -ForegroundColor Cyan }
function Write-Ok    { param([string]$msg) Write-Host "  [OK] $msg" -ForegroundColor Green }
function Write-Warn  { param([string]$msg) Write-Host "  [!!] $msg" -ForegroundColor Yellow }
function Write-Fail  { param([string]$msg) Write-Host "  [XX] $msg" -ForegroundColor Red }

function Invoke-SSH {
    param([string]$Cmd, [switch]$AllowFail)
    $full = "ssh -o StrictHostKeyChecking=accept-new ${DeviceUser}@${DeviceHost} '$Cmd'"
    Write-Verbose "SSH: $Cmd"
    if ($DryRun) { Write-Host "  [DRY] $full" -ForegroundColor DarkYellow; return }
    $result = ssh -o StrictHostKeyChecking=accept-new "${DeviceUser}@${DeviceHost}" "$Cmd" 2>&1
    if ($LASTEXITCODE -ne 0 -and -not $AllowFail) {
        throw "SSH command failed ($LASTEXITCODE): $Cmd`n$result"
    }
    return $result
}

function Invoke-SCP {
    param([string]$LocalPath, [string]$RemotePath)
    if ($DryRun) {
        Write-Host "  [DRY] scp -r '$LocalPath' '${DeviceUser}@${DeviceHost}:${RemotePath}'" -ForegroundColor DarkYellow
        return
    }
    scp -r -o StrictHostKeyChecking=accept-new $LocalPath "${DeviceUser}@${DeviceHost}:${RemotePath}"
    if ($LASTEXITCODE -ne 0) { throw "SCP failed: $LocalPath -> $RemotePath" }
}

# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "  ╔═════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║  honeysnatch — HackberryPi CM5 Pre-Flight Setup  ║" -ForegroundColor Cyan
Write-Host "  ╚═════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Target : ${DeviceUser}@${DeviceHost}" -ForegroundColor White
Write-Host "  Repo   : ${RepoPath}" -ForegroundColor White
Write-Host "  Deploy : $($Deploy.IsPresent)" -ForegroundColor White
if ($DryRun) { Write-Warn "DRY RUN — no commands will execute" }
Write-Host ""

# ---------------------------------------------------------------------------
# Step 1 — Verify repo exists locally
# ---------------------------------------------------------------------------
Write-Step "Step 1 — Checking local repo"
if (-not (Test-Path "$RepoPath\pyproject.toml")) {
    throw "Repo not found at: $RepoPath`nSet -RepoPath to the honeysnatch directory."
}
Write-Ok "Repo found: $RepoPath"

# ---------------------------------------------------------------------------
# Step 2 — Test SSH connectivity
# ---------------------------------------------------------------------------
Write-Step "Step 2 — Testing SSH connectivity to ${DeviceHost}"
try {
    $uname = Invoke-SSH "uname -m"
    if ($uname -notmatch "aarch64") {
        Write-Warn "Expected aarch64 but got: $uname"
    } else {
        Write-Ok "Connected — arch: $uname"
    }
} catch {
    Write-Fail "Cannot reach ${DeviceUser}@${DeviceHost}"
    Write-Host ""
    Write-Host "  Troubleshooting:" -ForegroundColor Yellow
    Write-Host "    1. Ensure HackberryPi is powered on and on the same LAN" -ForegroundColor Yellow
    Write-Host "    2. Try by IP instead of hostname: -DeviceHost 192.168.x.x" -ForegroundColor Yellow
    Write-Host "    3. On the HackberryPi: sudo systemctl enable --now ssh" -ForegroundColor Yellow
    Write-Host "    4. For USB-OTG: the CM5 USB-C port must be in gadget mode" -ForegroundColor Yellow
    throw
}

# ---------------------------------------------------------------------------
# Step 3 — Check / install rsync on device
# ---------------------------------------------------------------------------
Write-Step "Step 3 — Ensuring rsync is available on device"
$rsyncCheck = Invoke-SSH "which rsync 2>/dev/null || echo MISSING" -AllowFail
if ($rsyncCheck -match "MISSING") {
    Write-Step "  Installing rsync on device..."
    Invoke-SSH "sudo apt-get install -y --no-install-recommends rsync"
    Write-Ok "rsync installed"
} else {
    Write-Ok "rsync present: $rsyncCheck"
}

# ---------------------------------------------------------------------------
# Step 4 — Push repo to device
# ---------------------------------------------------------------------------
Write-Step "Step 4 — Pushing repo to device"

$RemoteRepoDir = "/home/${DeviceUser}/honeysnatch"
Invoke-SSH "mkdir -p $RemoteRepoDir"

# Files/dirs to exclude from transfer (local dev artefacts, Windows paths)
$ExcludeArgs = @(
    "--exclude=.git"
    "--exclude=.venv"
    "--exclude=__pycache__"
    "--exclude=*.pyc"
    "--exclude=*.pyo"
    "--exclude=.mypy_cache"
    "--exclude=.ruff_cache"
    "--exclude=dist"
    "--exclude=build"
    "--exclude=*.egg-info"
)

if ($DryRun) {
    Write-Host "  [DRY] rsync -avz $ExcludeArgs '${RepoPath}/' '${DeviceUser}@${DeviceHost}:${RemoteRepoDir}/'" -ForegroundColor DarkYellow
} else {
    # Convert Windows path to rsync-compatible format
    $LocalPath = $RepoPath.Replace('\', '/').Replace('H:', '/h')
    # Use forward slash at end to sync contents into the remote dir
    $rsyncCmd = @("rsync", "-avz", "--progress") + $ExcludeArgs + @("${RepoPath}/", "${DeviceUser}@${DeviceHost}:${RemoteRepoDir}/")
    Write-Verbose "rsync: $rsyncCmd"
    & rsync -avz --progress @ExcludeArgs "${RepoPath}/" "${DeviceUser}@${DeviceHost}:${RemoteRepoDir}/"
    if ($LASTEXITCODE -ne 0) { throw "rsync failed" }
}
Write-Ok "Repo synced to ${DeviceHost}:${RemoteRepoDir}"

# ---------------------------------------------------------------------------
# Step 5 — Make deploy script executable
# ---------------------------------------------------------------------------
Write-Step "Step 5 — Setting permissions on deploy script"
Invoke-SSH "chmod +x ${RemoteRepoDir}/deploy-hackberrypi.sh"
Write-Ok "deploy-hackberrypi.sh is executable"

# ---------------------------------------------------------------------------
# Step 6 — Check WiFi adapters on device
# ---------------------------------------------------------------------------
Write-Step "Step 6 — Checking WiFi interfaces on device"
$ifaces = Invoke-SSH "iw dev 2>/dev/null | grep Interface" -AllowFail
if ($ifaces) {
    Write-Ok "Wireless interfaces detected:"
    $ifaces -split "`n" | ForEach-Object { Write-Host "    $_" -ForegroundColor White }
} else {
    Write-Warn "No wireless interfaces found via 'iw dev'"
    Write-Warn "On-board CM5 WiFi may need rfkill unblocked:"
    Write-Warn "  sudo rfkill unblock wifi"
}

# Check for external USB adapter (needed for monitor mode)
$lsusb = Invoke-SSH "lsusb 2>/dev/null" -AllowFail
$monAdapters = @("Realtek", "Ralink", "MediaTek", "ALFA", "Atheros")
$found = $false
foreach ($vendor in $monAdapters) {
    if ($lsusb -match $vendor) {
        Write-Ok "  External USB WiFi adapter detected: $vendor"
        $found = $true
    }
}
if (-not $found) {
    Write-Warn "No external USB WiFi adapter detected"
    Write-Warn "Plug in an Alfa AWUS036ACH or similar before running fhs scan"
}

# ---------------------------------------------------------------------------
# Step 7 — Disk space check
# ---------------------------------------------------------------------------
Write-Step "Step 7 — Checking disk space on device"
$df = Invoke-SSH "df -h / | tail -1" -AllowFail
Write-Ok "Root filesystem: $df"
$avail = Invoke-SSH "df / | tail -1 | awk '{print \$4}'" -AllowFail
$availMB = [int]$avail / 1024
if ($availMB -lt 2048) {
    Write-Warn "Low disk space (${availMB} MB available). Recommend at least 2 GB free."
    Write-Warn "Consider booting from NVMe SSD instead of microSD."
} else {
    Write-Ok "Disk space OK: ${availMB} MB available"
}

# ---------------------------------------------------------------------------
# Step 8 — Run deploy script (if requested)
# ---------------------------------------------------------------------------
if ($Deploy) {
    Write-Step "Step 8 — Running deploy-hackberrypi.sh on device"
    Write-Warn "This will take ~5-10 minutes (apt + hostap build on CM5)"
    Write-Host ""

    $deployFlags = ""
    if ($SkipHostap) { $deployFlags += " --skip-hostap" }

    $deployCmd = "cd ${RemoteRepoDir} && sudo bash deploy-hackberrypi.sh${deployFlags} 2>&1 | tee /tmp/fhs-deploy.log"

    if ($DryRun) {
        Write-Host "  [DRY] ssh ${DeviceUser}@${DeviceHost} '$deployCmd'" -ForegroundColor DarkYellow
    } else {
        # Use SSH with tty allocation so we see live output
        ssh -t "${DeviceUser}@${DeviceHost}" "$deployCmd"
        if ($LASTEXITCODE -eq 0) {
            Write-Ok "Deploy script completed successfully"
        } else {
            Write-Warn "Deploy script returned non-zero exit code — check /tmp/fhs-deploy.log on device"
        }
    }
} else {
    Write-Step "Step 8 — Deploy script ready (skipped — use -Deploy to run automatically)"
    Write-Host ""
    Write-Host "  To deploy manually, SSH into the device and run:" -ForegroundColor Cyan
    Write-Host "    cd ~/honeysnatch" -ForegroundColor White
    Write-Host "    sudo bash deploy-hackberrypi.sh" -ForegroundColor White
    Write-Host "    sudo bash deploy-hackberrypi.sh --gui         # + Qt display config" -ForegroundColor White
    Write-Host "    sudo bash deploy-hackberrypi.sh --skip-hostap # Skip isolation build" -ForegroundColor White
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "  ╔═════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "  ║  Pre-Flight Complete — Quick Reference                 ║" -ForegroundColor Green
Write-Host "  ╚═════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "  SSH into device:    ssh ${DeviceUser}@${DeviceHost}" -ForegroundColor White
Write-Host "  Repo on device:     ~/honeysnatch" -ForegroundColor White
Write-Host "  Deploy log:         /tmp/fhs-deploy.log" -ForegroundColor White
Write-Host ""
Write-Host "  After deploy, on device:" -ForegroundColor Cyan
Write-Host "    source ~/honeysnatch/.venv/bin/activate" -ForegroundColor White
Write-Host "    fhs info" -ForegroundColor White
Write-Host "    fhs isolation run-all -i wlan0 -j wlan1 --simulate" -ForegroundColor White
Write-Host ""
Write-Host "  Sync changes from iHBV-TUF at any time:" -ForegroundColor Cyan
Write-Host "    .\Prepare-HackberryPi.ps1 -DeviceHost ${DeviceHost} --skip-apt --skip-hostap" -ForegroundColor White
Write-Host ""
