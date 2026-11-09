#Requires -Version 5.1
<#
Interactive npm publish + Trusted Publishing for Vigil.
Run this in a real PowerShell window: npm prints an auth URL and waits for
ENTER, then the browser approval completes the operation. The script logs every
step to %TEMP%\vigil-npm-interactive.log.
#>
$ErrorActionPreference = 'Continue'
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$Version = '0.1.3'
$Repo = 'LevapVeeskela/lv24-vigil'
$Workflow = 'npm-publish.yml'
$Log = Join-Path $env:TEMP 'vigil-npm-interactive.log'

Start-Transcript -Path $Log -Force | Out-Null

function Write-Step([string]$Message) {
    Write-Host ''
    Write-Host "=== $Message ===" -ForegroundColor Cyan
}

function Test-Published([string]$Name) {
    & npm view "$Name@$Version" version *> $null
    return $LASTEXITCODE -eq 0
}

$platform = @(
    '@lv24/vigil-win32-x64',
    '@lv24/vigil-win32-arm64',
    '@lv24/vigil-darwin-x64',
    '@lv24/vigil-darwin-arm64',
    '@lv24/vigil-linux-x64',
    '@lv24/vigil-linux-arm64'
)

Write-Host 'Vigil npm publish (interactive).' -ForegroundColor Green
Write-Host 'For every package: press ENTER, then approve the login in the browser.' -ForegroundColor Yellow
Write-Host "Log: $Log"
Write-Host ''

foreach ($pkg in $platform) {
    if (Test-Published $pkg) {
        Write-Host "$pkg@$Version already published; skipping." -ForegroundColor DarkGray
        continue
    }
    Write-Step "Publishing $pkg@$Version"
    & npm publish (Join-Path $Root "npm-out\$pkg") --access public
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FAILED: $pkg (exit $LASTEXITCODE). Rerun this script; published packages are skipped." -ForegroundColor Red
        Read-Host 'Press Enter to continue with the next package'
    }
}

if (-not (Test-Published 'lv24-vigil')) {
    Write-Step "Publishing lv24-vigil@$Version"
    & npm publish (Join-Path $Root 'npm-out\lv24-vigil') --access public
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FAILED: lv24-vigil (exit $LASTEXITCODE)." -ForegroundColor Red
        Read-Host 'Press Enter to continue to Trusted Publishing'
    }
} else {
    Write-Host "lv24-vigil@$Version already published; skipping." -ForegroundColor DarkGray
}

Write-Host ''
Write-Host 'Now configuring Trusted Publishing for all packages.' -ForegroundColor Green
Write-Host 'Each command may open the browser again; approve it.' -ForegroundColor Yellow

$all = @('lv24-vigil') + $platform
foreach ($pkg in $all) {
    Write-Step "Trusted Publishing: $pkg"
    & npm trust github $pkg --file $Workflow --repo $Repo --allow-publish -y
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FAILED: trust $pkg (exit $LASTEXITCODE)." -ForegroundColor Red
    }
}

Write-Host ''
Write-Host '=== Trust list ===' -ForegroundColor Green
foreach ($pkg in $all) {
    Write-Host "--- $pkg ---" -ForegroundColor Cyan
    & npm trust list $pkg
}

Write-Host ''
Write-Host 'Done. The full log is in:' $Log -ForegroundColor Green
Stop-Transcript | Out-Null
Read-Host 'Press Enter to close this window'
