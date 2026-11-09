#Requires -Version 5.1
<#
.SYNOPSIS
Installs the Vigil security auditor on Windows.

.DESCRIPTION
Downloads vigil.exe from a GitHub release, verifies its SHA-256 checksum from
checksums.txt, installs it atomically, and optionally adds the install
directory to the user PATH. The previous binary is kept as vigil.exe.previous.

The installer never requires administrator rights, never asks for or stores
secrets, and never runs a downloaded script.

.PARAMETER Version
Release version to install (for example 1.2.3 or v1.2.3) or latest (default).

.PARAMETER Dir
Install directory. Defaults to %LOCALAPPDATA%\Programs\vigil.

.PARAMETER Repo
GitHub repository in owner/name form.

.PARAMETER NoPath
Do not add the install directory to the user PATH.

.PARAMETER Force
Reinstall even when the selected version is already installed.

.PARAMETER Uninstall
Remove vigil.exe and its leftovers from -Dir and remove the PATH entry this
installer added. Keeps .vigil.yaml and scan history. Requires -Yes when input
is not interactive.

.PARAMETER Yes
Non-interactive: skip the uninstall confirmation.

.EXAMPLE
.\install.ps1

.EXAMPLE
.\install.ps1 -Version v1.2.3 -Dir "$env:USERPROFILE\bin"

.EXAMPLE
.\install.ps1 -Uninstall -Yes
#>
[CmdletBinding()]
param(
    [string]$Version = 'latest',

    [string]$Dir,

    [string]$Repo = 'LevapVeeskela/lv24-vigil',

    [switch]$NoPath,

    [switch]$Force,

    [switch]$Uninstall,

    [switch]$Yes
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
}
catch {
    # Older hosts keep their configured protocol.
}

$script:Headers = @{
    'User-Agent' = 'lv24-vigil-installer'
    'Accept'     = 'application/vnd.github+json'
}
if ($env:GITHUB_TOKEN) {
    if ($env:GITHUB_TOKEN -match '\s') {
        throw 'GITHUB_TOKEN must not contain whitespace.'
    }
    $script:Headers['Authorization'] = "Bearer $($env:GITHUB_TOKEN)"
}

$script:StageRoot = Join-Path $env:TEMP ('lv24-vigil-install-' + [Guid]::NewGuid().ToString('N'))
$script:CreatedStageRoot = $false

function Write-Step {
    param([Parameter(Mandatory = $true)][string]$Text)
    Write-Host "==> $Text"
}

function Write-Note {
    param([Parameter(Mandatory = $true)][string]$Text)
    Write-Host "    $Text"
}

function Get-PlatformArchitecture {
    $architecture = $env:PROCESSOR_ARCHITECTURE
    if ($env:PROCESSOR_ARCHITEW6432) {
        $architecture = $env:PROCESSOR_ARCHITEW6432
    }
    switch ($architecture.ToUpperInvariant()) {
        'AMD64' { return 'amd64' }
        'ARM64' { return 'arm64' }
        default { throw "Unsupported Windows architecture: $architecture. Releases cover amd64 and arm64." }
    }
}

function Invoke-Download {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $true)][string]$Destination
    )
    if (-not $Uri.StartsWith('https://', [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing non-HTTPS download URL: $Uri"
    }
    Invoke-WebRequest -Uri $Uri -OutFile $Destination -Headers $script:Headers -UseBasicParsing
}

function Get-Release {
    param([Parameter(Mandatory = $true)][string]$ReleaseVersion)

    if (-not $ReleaseVersion -or $ReleaseVersion -eq 'latest') {
        $uri = "https://api.github.com/repos/$Repo/releases/latest"
    }
    else {
        $tag = $ReleaseVersion
        if (-not $tag.StartsWith('v')) {
            $tag = 'v' + $tag
        }
        $uri = "https://api.github.com/repos/$Repo/releases/tags/$tag"
    }

    try {
        $release = Invoke-RestMethod -Uri $uri -Headers $script:Headers -Method Get
    }
    catch {
        throw "Could not read release '$ReleaseVersion' from $Repo. $($_.Exception.Message)"
    }
    if (-not $release) {
        throw "Release '$ReleaseVersion' was not found in $Repo."
    }
    if ($release.draft) {
        throw "Release $($release.tag_name) is still a draft and cannot be installed."
    }
    return $release
}

function Get-ChecksumFromFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$FileName
    )
    foreach ($line in Get-Content -LiteralPath $Path -Encoding UTF8) {
        $trimmed = $line.Trim()
        if (-not $trimmed -or $trimmed.StartsWith('#')) {
            continue
        }
        $parts = $trimmed -split '\s+', 2
        if ($parts.Count -ne 2) {
            continue
        }
        $name = $parts[1].TrimStart('*')
        if ($name -eq $FileName -and $parts[0] -match '^[0-9a-fA-F]{64}$') {
            return $parts[0].ToLowerInvariant()
        }
    }
    return ''
}

function Assert-FileChecksum {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Expected
    )
    if (-not $Expected) {
        throw 'No SHA-256 checksum is available for the selected binary.'
    }
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $Expected.ToLowerInvariant()) {
        throw "SHA-256 mismatch: got $actual, expected $($Expected.ToLowerInvariant())."
    }
}

function Get-InstalledVersion {
    # Returns the version named by "vigil version" (first line), or '' when unavailable.
    param([Parameter(Mandatory = $true)][string]$Exe)
    if (-not (Test-Path -LiteralPath $Exe)) {
        return ''
    }
    try {
        $line = @(& $Exe version 2>$null) | Select-Object -First 1
    }
    catch {
        return ''
    }
    if ($LASTEXITCODE -ne 0 -or -not $line) {
        return ''
    }
    if ([string]$line -match '^vigil\s+v?([0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?)') {
        return $Matches[1]
    }
    return ''
}

function Test-InstalledVersion {
    param(
        [Parameter(Mandatory = $true)][string]$Exe,
        [Parameter(Mandatory = $true)][string]$Wanted
    )
    $installed = Get-InstalledVersion -Exe $Exe
    if (-not $installed) {
        return $false
    }
    return ($installed -eq $Wanted.TrimStart('v'))
}

function Install-VigilBinary {
    param(
        [Parameter(Mandatory = $true)][string]$TargetDir,
        [Parameter(Mandatory = $true)][string]$Architecture
    )

    if (-not (Test-Path -LiteralPath $script:StageRoot)) {
        New-Item -ItemType Directory -Path $script:StageRoot -Force | Out-Null
        $script:CreatedStageRoot = $true
    }

    Write-Step "Looking up release ($Version)"
    $release = Get-Release -ReleaseVersion $Version
    $tag = [string]$release.tag_name
    if (-not $tag) {
        throw 'The GitHub response did not contain a release tag.'
    }
    $versionNumber = $tag.TrimStart('v')
    if ($versionNumber -notmatch '^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$') {
        throw "Unexpected release tag from GitHub: $tag"
    }

    $exe = Join-Path $TargetDir 'vigil.exe'
    if (-not $Force -and (Test-InstalledVersion -Exe $exe -Wanted $versionNumber)) {
        Write-Step "vigil $versionNumber is already installed at $exe (download skipped; use -Force to reinstall)"
        return [pscustomobject]@{ Path = $exe; Version = $versionNumber }
    }

    $assetName = "vigil_${versionNumber}_windows_${Architecture}.exe"
    $base = "https://github.com/$Repo/releases/download/$tag"
    $checksumsPath = Join-Path $script:StageRoot 'checksums.txt'

    Write-Step 'Downloading checksums.txt'
    Invoke-Download -Uri "$base/checksums.txt" -Destination $checksumsPath
    $expected = Get-ChecksumFromFile -Path $checksumsPath -FileName $assetName
    if (-not $expected) {
        throw "checksums.txt has no entry for $assetName; refusing to install."
    }

    $downloadPath = Join-Path $script:StageRoot $assetName
    Write-Step "Downloading vigil $versionNumber for windows/$Architecture"
    Invoke-Download -Uri "$base/$assetName" -Destination $downloadPath
    Assert-FileChecksum -Path $downloadPath -Expected $expected
    Write-Note "checksum verified: $expected"

    if (-not (Test-Path -LiteralPath $TargetDir)) {
        New-Item -ItemType Directory -Path $TargetDir -Force | Out-Null
    }
    $staged = Join-Path $TargetDir 'vigil.exe.new'
    Copy-Item -LiteralPath $downloadPath -Destination $staged -Force
    if (Test-Path -LiteralPath $exe) {
        Copy-Item -LiteralPath $exe -Destination (Join-Path $TargetDir 'vigil.exe.previous') -Force
    }
    try {
        Move-Item -LiteralPath $staged -Destination $exe -Force
    }
    catch {
        Remove-Item -LiteralPath $staged -Force -ErrorAction SilentlyContinue
        throw "Could not replace $exe. Stop any running vigil process and retry. $($_.Exception.Message)"
    }
    Write-Note "installed: $exe"

    return [pscustomobject]@{ Path = $exe; Version = $versionNumber }
}

function Add-UserPath {
    param([Parameter(Mandatory = $true)][string]$Directory)
    $current = [Environment]::GetEnvironmentVariable('Path', 'User')
    if ($null -eq $current) {
        $current = ''
    }
    $entries = @($current -split ';' | Where-Object { $_ })
    $present = $false
    foreach ($entry in $entries) {
        if ($entry.TrimEnd('\') -ieq $Directory.TrimEnd('\')) {
            $present = $true
            break
        }
    }
    $added = $false
    if (-not $present) {
        $updated = (($entries + $Directory.TrimEnd('\')) -join ';')
        [Environment]::SetEnvironmentVariable('Path', $updated, 'User')
        Write-Step "Added $Directory to the user PATH (open a new terminal to pick it up)"
        $added = $true
    }
    $env:Path = $Directory + ';' + $env:Path
    return $added
}

function Remove-UserPath {
    # Removes only the exact Directory entry from the user PATH.
    param([Parameter(Mandatory = $true)][string]$Directory)
    $current = [Environment]::GetEnvironmentVariable('Path', 'User')
    if ([string]::IsNullOrEmpty($current)) {
        return $false
    }
    $target = $Directory.TrimEnd('\')
    $kept = @()
    $removed = $false
    foreach ($entry in ($current -split ';')) {
        if ($entry -and $entry.TrimEnd('\') -ieq $target) {
            $removed = $true
            continue
        }
        $kept += $entry
    }
    if ($removed) {
        [Environment]::SetEnvironmentVariable('Path', ($kept -join ';'), 'User')
    }
    return $removed
}

function Invoke-Uninstall {
    $dir = [IO.Path]::GetFullPath($Dir)
    $targets = New-Object System.Collections.Generic.List[string]
    foreach ($name in @('vigil.exe', 'vigil.exe.previous', 'vigil.exe.new')) {
        $candidate = Join-Path $dir $name
        if (Test-Path -LiteralPath $candidate) {
            $targets.Add($candidate)
        }
    }
    if (Test-Path -LiteralPath $dir) {
        foreach ($item in @(Get-ChildItem -LiteralPath $dir -Force -File)) {
            if (($item.Name -like '.vigil*-old-*') -or ($item.Name -like '.vigil*-new-*') -or ($item.Name -like '.vigil.install.*')) {
                $targets.Add($item.FullName)
            }
        }
    }
    $markerPath = Join-Path $dir '.path-added'
    $pathAdded = Test-Path -LiteralPath $markerPath

    if ($targets.Count -eq 0 -and -not $pathAdded) {
        Write-Step "Uninstall: nothing to remove in $dir"
        return
    }

    Write-Step "Uninstalling vigil from $dir"
    foreach ($path in $targets) {
        Write-Note "will remove: $path"
    }
    if ($pathAdded) {
        if ($NoPath) {
            Write-Note 'user PATH is left unchanged (-NoPath)'
        }
        else {
            Write-Note "will remove $dir from the user PATH (the installer added it)"
        }
    }

    if (-not $Yes) {
        if ([Console]::IsInputRedirected) {
            Write-Host 'Uninstall needs confirmation: rerun with -Yes when input is not interactive.' -ForegroundColor Red
            exit 2
        }
        $answer = [string](Read-Host 'Remove the items listed above? [y/N]')
        if ($answer.Trim() -notmatch '^(y|yes)$') {
            Write-Step 'Uninstall cancelled; nothing was removed.'
            exit 1
        }
    }

    foreach ($path in $targets) {
        Remove-Item -LiteralPath $path -Force
        Write-Note "removed: $path"
    }
    if ($pathAdded -and -not $NoPath) {
        if (Remove-UserPath -Directory $dir) {
            Write-Note "removed $dir from the user PATH"
        }
        else {
            Write-Note 'the user PATH had no entry for this directory'
        }
        Remove-Item -LiteralPath $markerPath -Force
    }

    Write-Host ''
    Write-Step 'Kept (never removed by the uninstaller)'
    Write-Note '.vigil.yaml and scan history (default %USERPROFILE%\.local\share\vigil or .vigil\)'
    Write-Note 'Open a new terminal to refresh PATH.'
}

try {
    if (-not $Dir) {
        $localAppData = $env:LOCALAPPDATA
        if (-not $localAppData) {
            $localAppData = Join-Path $env:USERPROFILE 'AppData\Local'
        }
        $Dir = Join-Path $localAppData 'Programs\vigil'
    }
    $Dir = [IO.Path]::GetFullPath($Dir)

    if ($Uninstall) {
        Invoke-Uninstall
        exit 0
    }

    $architecture = Get-PlatformArchitecture
    if (-not (Test-Path -LiteralPath $Dir)) {
        New-Item -ItemType Directory -Path $Dir -Force | Out-Null
    }

    $result = Install-VigilBinary -TargetDir $Dir -Architecture $architecture

    if (-not $NoPath) {
        if (Add-UserPath -Directory $Dir) {
            # Marks the PATH entry as installer-owned so -Uninstall removes only that.
            [IO.File]::WriteAllText((Join-Path $Dir '.path-added'), "added by install.ps1`r`n", (New-Object System.Text.UTF8Encoding($false)))
        }
    }

    Write-Step 'Verifying the installed binary'
    $versionLine = ''
    try {
        $versionLine = [string](@(& $result.Path version 2>$null) | Select-Object -First 1)
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "vigil version exited with code $LASTEXITCODE."
        }
    }
    catch {
        Write-Warning "Could not run vigil version: $($_.Exception.Message)"
    }

    Write-Host ''
    Write-Step 'Install complete'
    Write-Note "binary:  $($result.Path)"
    Write-Note "version: $($result.Version)"
    if ($versionLine) {
        Write-Note "binary check: $versionLine"
    }
    if (-not $NoPath) {
        Write-Note 'Open a new terminal so PATH picks up the install directory.'
    }
    Write-Note "Next: vigil scan ."
    Write-Note "      vigil init"
    Write-Note "      vigil mcp   # MCP server over stdio"
    Write-Note 'No secrets were stored. Keep tokens and .env values out of scanned repositories.'
    exit 0
}
catch {
    Write-Host "Install failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
finally {
    if ($script:CreatedStageRoot -and (Test-Path -LiteralPath $script:StageRoot)) {
        Remove-Item -LiteralPath $script:StageRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
