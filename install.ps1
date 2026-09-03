#Requires -Version 7.0

[CmdletBinding()]
param(
    [ValidateSet("wgprobe", "nordprobe", "all")]
    [string]$Bin = "all",
    [string]$Version = "",
    [string]$To = "",
    [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$repository = "scotthaleen/wgprobe"

function Show-Usage {
    @"
Install wgprobe release binaries on 64-bit Windows.

Usage: install.ps1 [-Bin wgprobe|nordprobe|all] [-Version VERSION] [-To DIRECTORY]

Defaults:
  -Bin all
  -Version latest
  -To `$env:LOCALAPPDATA\Programs\wgprobe\bin
"@
}

function Fail([string]$Message) {
    [Console]::Error.WriteLine("install.ps1: $Message")
    exit 1
}

function Test-ReleaseVersion([string]$Value) {
    return $Value -match '^\d+\.\d+\.\d+$'
}

if ($Help) {
    Show-Usage
    exit 0
}

if (-not [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
    [System.Runtime.InteropServices.OSPlatform]::Windows
)) {
    Fail "the installer supports Windows only"
}
if ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne
    [System.Runtime.InteropServices.Architecture]::X64) {
    Fail "the installer supports x86-64 Windows only"
}

if ($Version) {
    $releaseTag = if ($Version.StartsWith("v")) { $Version } else { "v$Version" }
    $Version = $releaseTag.Substring(1)
    if (-not (Test-ReleaseVersion $Version)) {
        Fail "invalid release version: $releaseTag"
    }
}

if (-not $To) {
    if (-not $env:LOCALAPPDATA) {
        Fail "LOCALAPPDATA is not set; provide an installation directory with -To"
    }
    $To = Join-Path $env:LOCALAPPDATA "Programs\wgprobe\bin"
}

if (-not $Version) {
    $latest = Invoke-WebRequest -Uri "https://github.com/$repository/releases/latest" -Method Head
    $releaseTag = Split-Path $latest.BaseResponse.RequestMessage.RequestUri.AbsolutePath -Leaf
    $Version = if ($releaseTag.StartsWith("v")) { $releaseTag.Substring(1) } else { "" }
    if (-not (Test-ReleaseVersion $Version)) {
        Fail "invalid latest release version: $releaseTag"
    }
}

$platform = "windows-x86_64"
$baseUrl = "https://github.com/$repository/releases/download/$releaseTag"
$temporary = Join-Path ([System.IO.Path]::GetTempPath()) ("wgprobe-" + [guid]::NewGuid())
$binaries = if ($Bin -eq "all") { @("wgprobe", "nordprobe") } else { @($Bin) }

New-Item -ItemType Directory -Path $temporary | Out-Null
try {
    $checksums = Join-Path $temporary "SHA256SUMS"
    Invoke-WebRequest -Uri "$baseUrl/SHA256SUMS" -OutFile $checksums
    $checksumLines = Get-Content -LiteralPath $checksums

    foreach ($binary in $binaries) {
        $package = "$binary-$Version-$platform"
        $asset = "$package.zip"
        $archive = Join-Path $temporary $asset
        Invoke-WebRequest -Uri "$baseUrl/$asset" -OutFile $archive

        $expected = $null
        foreach ($line in $checksumLines) {
            if ($line -match '^([0-9a-fA-F]{64})\s+\*?(.+)$' -and $Matches[2] -eq $asset) {
                $expected = $Matches[1]
                break
            }
        }
        if (-not $expected) {
            Fail "checksum not found for $asset"
        }
        $actual = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash
        if ($actual -ne $expected) {
            Fail "checksum mismatch for $asset"
        }

        Expand-Archive -LiteralPath $archive -DestinationPath $temporary
        $executable = Join-Path $temporary "$package\$binary.exe"
        & $executable --version
        if ($LASTEXITCODE -ne 0) {
            Fail "$binary failed after extraction"
        }
    }

    New-Item -ItemType Directory -Force -Path $To | Out-Null
    foreach ($binary in $binaries) {
        $package = "$binary-$Version-$platform"
        $source = Join-Path $temporary "$package\$binary.exe"
        $destination = Join-Path $To "$binary.exe"
        Copy-Item -LiteralPath $source -Destination $destination -Force
        Write-Output "installed $binary $Version to $destination"
    }
}
finally {
    if (Test-Path -LiteralPath $temporary) {
        Remove-Item -LiteralPath $temporary -Recurse -Force
    }
}

$pathEntries = $env:PATH -split [System.IO.Path]::PathSeparator
if ($To -notin $pathEntries) {
    [Console]::Error.WriteLine("add $To to your user PATH to run the installed binaries")
}
