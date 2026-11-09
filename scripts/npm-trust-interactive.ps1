#Requires -Version 5.1
# Configure Trusted Publishing for the remaining Vigil npm packages.
# Run in a real PowerShell window; approve each browser prompt.
$ErrorActionPreference = 'Continue'
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$Repo = 'LevapVeeskela/lv24-vigil'
$Workflow = 'npm-publish.yml'
$Log = Join-Path $env:TEMP 'vigil-npm-trust.log'
Start-Transcript -Path $Log -Force | Out-Null

$packages = @(
    'lv24-vigil',
    '@lv24/vigil-win32-arm64',
    '@lv24/vigil-darwin-x64',
    '@lv24/vigil-darwin-arm64',
    '@lv24/vigil-linux-x64',
    '@lv24/vigil-linux-arm64'
)

Write-Host 'Trusted Publishing for the remaining Vigil packages.' -ForegroundColor Green
Write-Host 'For each package: press ENTER, then approve in the browser.' -ForegroundColor Yellow
Write-Host "Log: $Log"
Write-Host ''

foreach ($pkg in $packages) {
    Write-Host ''
    Write-Host "=== $pkg ===" -ForegroundColor Cyan
    & npm trust github $pkg --file $Workflow --repo $Repo --allow-publish -y
    $code = $LASTEXITCODE
    Write-Host "Exit: $code" -ForegroundColor $(if ($code -eq 0) { 'Green' } else { 'Red' })
    if ($code -ne 0) {
        Read-Host 'Press Enter to continue with the next package'
    }
}

Write-Host ''
Write-Host 'Finished. Check the result in the npm package settings.' -ForegroundColor Green
Stop-Transcript | Out-Null
Read-Host 'Press Enter to close this window'
