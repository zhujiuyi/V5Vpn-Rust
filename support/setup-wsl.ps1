#Requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$HostOnly
)

$ErrorActionPreference = 'Stop'
if (Get-Variable -Name PSNativeCommandUseErrorActionPreference -ErrorAction SilentlyContinue) {
    $PSNativeCommandUseErrorActionPreference = $false
}

$distribution = 'V5VPN-NC'
$wslCommand = Join-Path $env:SystemRoot 'System32\wsl.exe'
$ownerIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$ownerPrincipal = [Security.Principal.WindowsPrincipal]::new($ownerIdentity)
$elevated = $ownerPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not (Test-Path -LiteralPath $wslCommand -PathType Leaf)) {
    throw 'This Windows version does not expose wsl.exe. Install a Windows version with WSL 2 support.'
}

function Test-WslHost {
    & $wslCommand --status 2>$null | Out-Null
    return ($LASTEXITCODE -eq 0)
}

function Initialize-WslHost {
    if (Test-WslHost) { return }

    if (-not $elevated) {
        throw 'Windows requires an Administrator PowerShell session to install WSL. Run this script there with -HostOnly, then rerun without -HostOnly under your normal V5VPN Windows account.'
    }

    Write-Host 'Installing the Microsoft WSL runtime and platform features.'
    & $wslCommand --install --no-distribution --web-download
    $installCode = $LASTEXITCODE
    if ($installCode -eq 3010) {
        throw 'Windows enabled WSL and requires a restart. Save your work, restart Windows, and rerun this script. No restart was started by this script.'
    }
    if ($installCode -ne 0) {
        throw ('The Microsoft WSL installer exited with code {0}. Review the installer message above.' -f $installCode)
    }
    if (-not (Test-WslHost)) {
        throw 'The WSL runtime is not ready after installation. Complete any pending Windows restart before running this script again.'
    }
}

function Get-NcRegistration {
    $registrationRoot = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss'
    if (-not (Test-Path -LiteralPath $registrationRoot)) { return }

    Get-ChildItem -LiteralPath $registrationRoot | ForEach-Object {
        $registration = Get-ItemProperty -LiteralPath $_.PSPath
        if ($registration.DistributionName -eq $distribution) { $registration }
    }
}

function Install-NcDistribution([string]$installPath, [string]$stampPath) {
    $architecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    $ubuntuImages = @{
        X64   = @('ubuntu-noble-wsl-amd64-24.04lts.rootfs.tar.gz', '2a790896740b14d637dbdc583cce1ba081ac53b9e9cdb46dc09a2f73abbd9934')
        Arm64 = @('ubuntu-noble-wsl-arm64-24.04lts.rootfs.tar.gz', 'e113b8c49af3ab49b992b8e29550fc921e689f211abc338176f8243786173a32')
    }
    if (-not $ubuntuImages.ContainsKey($architecture)) {
        throw ('No Ubuntu WSL image is configured for {0}.' -f $architecture)
    }
    if ((Test-Path -LiteralPath $installPath) -and @(Get-ChildItem -LiteralPath $installPath -Force).Count -gt 0) {
        throw 'The dedicated import directory already contains files. The installer will not overwrite them.'
    }

    $archiveName, $expectedSha256 = $ubuntuImages[$architecture]
    # The pinned digests come from Canonical's release directory SHA256SUMS.
    $imageUrl = 'https://cloud-images.ubuntu.com/wsl/releases/24.04/current/' + $archiveName
    $archive = Join-Path $dataRoot ('download-' + [guid]::NewGuid().ToString('N') + '.tar.gz')
    try {
        Write-Host 'Downloading the official Ubuntu 24.04 LTS WSL image.'
        Invoke-WebRequest -Uri $imageUrl -OutFile $archive -UseBasicParsing -TimeoutSec 900
        $actualSha256 = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash
        if ($actualSha256 -ne $expectedSha256) {
            throw 'The Ubuntu WSL image did not match the pinned SHA-256 digest.'
        }

        New-Item -ItemType Directory -Path $installPath -Force | Out-Null
        [IO.File]::WriteAllText($stampPath, 'V5VPN-NC ubuntu-24.04 v1')
        & $wslCommand --import $distribution $installPath $archive --version 2
        if ($LASTEXITCODE -ne 0) {
            throw ('Importing {0} as WSL 2 failed with code {1}. The existing files were retained.' -f $distribution, $LASTEXITCODE)
        }
    }
    finally {
        if (Test-Path -LiteralPath $archive) { Remove-Item -LiteralPath $archive -Force }
    }
}

function Install-NcTools {
    $installScript = @'
set -eu
export DEBIAN_FRONTEND=noninteractive

policy=/usr/sbin/policy-rc.d
policy_marker='# V5VPN-NC provisioning only'
if [ ! -e "$policy" ] && [ ! -L "$policy" ]; then
    # Package setup must not start a second, default IPsec service.
    ( set -C; printf '#!/bin/sh\n%s\nexit 101\n' "$policy_marker" > "$policy" )
fi
if [ -f "$policy" ] && [ ! -L "$policy" ] && grep -Fxq "$policy_marker" "$policy"; then
    trap 'if [ -f "$policy" ] && [ ! -L "$policy" ] && grep -Fxq "$policy_marker" "$policy"; then rm -f -- "$policy"; fi' EXIT
    chmod 0755 "$policy"
fi

dpkg --configure -a
apt-get update
apt-get install -y --no-install-recommends \
    strongswan-charon strongswan-swanctl libstrongswan-standard-plugins \
    iproute2 iptables socat util-linux python3

# Clean up default IPsec services if an earlier package setup installed them.
if [ -d /run/systemd/system ]; then
    for unit in strongswan.service strongswan-starter.service; do
        if systemctl cat "$unit" >/dev/null 2>&1; then
            systemctl disable --now "$unit"
        fi
    done
fi

test -x /usr/lib/ipsec/charon
for plugin in kernel-netlink socket-default vici aes gmp hmac sha1; do
    test -f "/usr/lib/ipsec/plugins/libstrongswan-$plugin.so"
done
for tool in swanctl ip iptables socat flock python3; do
    command -v "$tool" >/dev/null
done
install -d -m 0755 /etc/v5vpn-nc
touch /etc/v5vpn-nc/managed-ubuntu-24.04-v1
dpkg-query -W strongswan-charon strongswan-swanctl
'@

    Write-Host 'Preparing strongSwan and route tooling in V5VPN-NC.'
    # The script is ASCII. Remove PowerShell's CRLF on the Linux side.
    $installScript | & $wslCommand --distribution $distribution --user root --exec /bin/sh -c "tr -d '\015' | /bin/sh -s"
    if ($LASTEXITCODE -ne 0) {
        throw ('Preparing the dedicated WSL distribution failed with code {0}.' -f $LASTEXITCODE)
    }
}

Initialize-WslHost
if ($HostOnly) {
    Write-Host 'The Microsoft WSL runtime is ready. Run this script without -HostOnly under your normal V5VPN Windows account.'
    return
}

$dataRoot = Join-Path $env:LOCALAPPDATA 'V5VPN Desktop\WSL'
$installDirectory = Join-Path $dataRoot $distribution
$ownershipStamp = Join-Path $dataRoot 'managed-ubuntu-24.04-v1'
$mutex = [Threading.Mutex]::new($false, ('Local\V5VPN-NC-bootstrap-' + $ownerIdentity.User.Value))
$acquired = $false
try {
    try { $acquired = $mutex.WaitOne(0) }
    catch [Threading.AbandonedMutexException] { $acquired = $true }
    if (-not $acquired) { throw 'Another V5VPN-NC setup process is running.' }

    New-Item -ItemType Directory -Path $dataRoot -Force | Out-Null
    $registered = Get-NcRegistration
    if (-not $registered) {
        Install-NcDistribution $installDirectory $ownershipStamp
        $registered = Get-NcRegistration
    }

    if (-not $registered -or @($registered).Count -ne 1 -or $registered.Version -ne 2) {
        throw 'The dedicated V5VPN-NC distribution was not found as WSL 2 for this Windows account.'
    }
    $registeredPath = [IO.Path]::GetFullPath(($registered.BasePath -replace '^\\\\\?\\', '')).TrimEnd('\')
    $expectedPath = [IO.Path]::GetFullPath($installDirectory).TrimEnd('\')
    if ($registeredPath -ne $expectedPath -or -not (Test-Path -LiteralPath $ownershipStamp -PathType Leaf)) {
        throw 'The existing V5VPN-NC distribution was not installed by this script. It was left untouched.'
    }
    if ([IO.File]::ReadAllText($ownershipStamp) -ne 'V5VPN-NC ubuntu-24.04 v1') {
        throw 'The existing V5VPN-NC installer marker does not match. The distribution was left untouched.'
    }

    Install-NcTools
    Write-Host 'V5VPN-NC (WSL 2) is ready. The VPN client starts the dedicated charon daemon during an NC session.'
}
finally {
    if ($acquired) { $mutex.ReleaseMutex() }
    $mutex.Dispose()
}
