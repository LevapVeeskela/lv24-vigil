#Requires -Version 5.1
<#
.SYNOPSIS
Publish the Vigil npm packages and configure GitHub Actions Trusted Publishing.

.DESCRIPTION
Run this once after `npm login --auth-type=web` (or with -Otp). It publishes the
six platform packages first, then the `lv24-vigil` launcher, skipping versions
that already exist on npm. Then it configures Trusted Publishing for every
package against .github/workflows/npm-publish.yml.

.PARAMETER Otp
Current 6-digit npm one-time password. Omit it when the npm session already
allows publishing without a prompt (for example a 2FA-bypass automation token).

.PARAMETER Version
Version to publish. Defaults to the latest GitHub release tag (without `v`).

.PARAMETER SkipPublish
Only configure Trusted Publishing; do not publish.

.EXAMPLE
.\scripts\npm-publish-and-trust.ps1 -Version 0.1.3 -Otp 123456
#>
[CmdletBinding()]
param(
    [string]$Otp = '',
    [string]$Version = '',
    [switch]$SkipPublish
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$Repo = 'LevapVeeskela/lv24-vigil'
$Workflow = 'npm-publish.yml'
$MainPackage = 'lv24-vigil'
$PlatformPackages = @(
    '@lv24/vigil-win32-x64',
    '@lv24/vigil-win32-arm64',
    '@lv24/vigil-darwin-x64',
    '@lv24/vigil-darwin-arm64',
    '@lv24/vigil-linux-x64',
    '@lv24/vigil-linux-arm64'
)

if (-not $Version) {
    $tag = (& gh release view --repo $Repo --json tagName --jq '.tagName').Trim()
    if ($LASTEXITCODE -ne 0 -or -not $tag) {
        throw 'Could not read the latest release tag. Pass -Version explicitly.'
    }
    $Version = $tag.TrimStart('v')
}
$Version = $Version.TrimStart('v')

if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
    throw 'npm is not on PATH.'
}
if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    throw 'gh is not on PATH.'
}

$otpArgs = @()
if (-not $Otp -and -not $SkipPublish) {
    $Otp = (Read-Host -Prompt 'npm one-time password (6 digits)').Trim()
}
if ($Otp) {
    $otpArgs = @("--otp=$Otp")
}

function Test-Published([string]$Name, [string]$Ver) {
    & npm view "$Name@$Ver" version *> $null
    return $LASTEXITCODE -eq 0
}

if (-not $SkipPublish) {
    $dist = Join-Path $Root 'dist'
    if (-not (Test-Path (Join-Path $dist "checksums.txt"))) {
        Write-Host "Downloading release assets for v$Version..."
        New-Item -ItemType Directory -Force $dist | Out-Null
        & gh release download "v$Version" --repo $Repo --dir $dist
        if ($LASTEXITCODE -ne 0) { throw "gh release download v$Version failed" }
    }
    Write-Host "Building npm packages for $Version..."
    & node npm/build.mjs --version $Version --dist $dist --out npm-out
    if ($LASTEXITCODE -ne 0) { throw 'npm/build.mjs failed' }

    foreach ($pkg in $PlatformPackages) {
        if (Test-Published $pkg $Version) {
            Write-Host "$pkg@$Version already published; skipping"
            continue
        }
        $dir = Join-Path $Root "npm-out\$pkg"
        Write-Host "Publishing $pkg@$Version..."
        & npm publish $dir --access public @otpArgs
        if ($LASTEXITCODE -ne 0) { throw "npm publish $pkg failed" }
    }

    if (Test-Published $MainPackage $Version) {
        Write-Host "$MainPackage@$Version already published; skipping"
    } else {
        Write-Host "Publishing $MainPackage@$Version..."
        & npm publish (Join-Path $Root 'npm-out\lv24-vigil') --access public @otpArgs
        if ($LASTEXITCODE -ne 0) { throw "npm publish $MainPackage failed" }
    }
}

$all = @($MainPackage) + $PlatformPackages
foreach ($pkg in $all) {
    Write-Host "Configuring Trusted Publishing for $pkg..."
    & npm trust github $pkg --file $Workflow --repo $Repo --allow-publish -y @otpArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "npm trust failed for $pkg (exit $LASTEXITCODE); rerun with a fresh -Otp."
    }
}

Write-Host ''
Write-Host 'Trusted Publishing state:'
foreach ($pkg in $all) {
    Write-Host "--- $pkg ---"
    & npm trust list $pkg @otpArgs
}
