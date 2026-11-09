#Requires -Version 5.1
<#
.SYNOPSIS
Local fallback release for Vigil when GitHub Actions is unavailable.

.DESCRIPTION
Cross-compiles the six release targets with `go build`, writes checksums.txt,
creates a GitHub release with `gh`, uploads missing assets, then builds and
publishes the npm packages. The script is idempotent: an existing release is
reused, assets already present are skipped, and npm versions already published
are skipped by npm/publish.sh.

.PARAMETER Version
Release version without the v prefix (1.2.3) or with it (v1.2.3).

.PARAMETER Notes
Release notes. Defaults to "Vigil <version>".

.PARAMETER Repo
GitHub repository in owner/name form.

.PARAMETER SkipNpm
Build the GitHub release but do not build or publish npm packages.

.EXAMPLE
.\scripts\release.ps1 -Version 1.2.3

.EXAMPLE
.\scripts\release.ps1 -Version v1.2.3 -Notes "Fixes SARIF output"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Version,

    [string]$Notes = '',

    [string]$Repo = 'LevapVeeskela/lv24-vigil',

    [switch]$SkipNpm
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$Version = $Version.Trim()
if ($Version.StartsWith('v')) {
    $Version = $Version.Substring(1)
}
if ($Version -notmatch '^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$') {
    throw "Version must look like 1.2.3 or 1.2.3-beta.1 (got '$Version')."
}
$Tag = "v$Version"

foreach ($tool in @('go', 'gh', 'git')) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        throw "$tool is required but was not found on PATH."
    }
}
& gh auth status *> $null
if ($LASTEXITCODE -ne 0) {
    throw 'gh is not authenticated; run gh auth login first.'
}

$Commit = (& git rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or -not $Commit) {
    throw 'Could not resolve HEAD; run this script inside the git repository.'
}
$Date = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")
$Dist = Join-Path $Root 'dist'
$notesFile = Join-Path $env:TEMP ('vigil-release-notes-' + [Guid]::NewGuid().ToString('N') + '.txt')

$targets = @(
    [pscustomobject]@{ Goos = 'windows'; Goarch = 'amd64'; Ext = '.exe' },
    [pscustomobject]@{ Goos = 'windows'; Goarch = 'arm64'; Ext = '.exe' },
    [pscustomobject]@{ Goos = 'darwin'; Goarch = 'amd64'; Ext = '' },
    [pscustomobject]@{ Goos = 'darwin'; Goarch = 'arm64'; Ext = '' },
    [pscustomobject]@{ Goos = 'linux'; Goarch = 'amd64'; Ext = '' },
    [pscustomobject]@{ Goos = 'linux'; Goarch = 'arm64'; Ext = '' }
)

function Write-Step {
    param([Parameter(Mandatory = $true)][string]$Text)
    Write-Host "==> $Text"
}

function Write-Note {
    param([Parameter(Mandatory = $true)][string]$Text)
    Write-Host "    $Text"
}

try {
    if (Test-Path -LiteralPath $Dist) {
        Remove-Item -LiteralPath $Dist -Recurse -Force
    }
    New-Item -ItemType Directory -Path $Dist -Force | Out-Null

    $ldflags = "-s -w " +
        "-X github.com/levapveeskela/lv24-vigil/internal/version.Version=$Version " +
        "-X github.com/levapveeskela/lv24-vigil/internal/version.Commit=$Commit " +
        "-X github.com/levapveeskela/lv24-vigil/internal/version.Date=$Date"

    $env:CGO_ENABLED = '0'
    foreach ($target in $targets) {
        $name = "vigil_${Version}_$($target.Goos)_$($target.Goarch)$($target.Ext)"
        $out = Join-Path $Dist $name
        Write-Step "Building $name"
        $env:GOOS = $target.Goos
        $env:GOARCH = $target.Goarch
        & go build -trimpath -ldflags $ldflags -o $out ./cmd/vigil
        if ($LASTEXITCODE -ne 0) {
            throw "go build failed for $($target.Goos)/$($target.Goarch)."
        }
    }

    Write-Step 'Writing checksums.txt'
    $names = @($targets | ForEach-Object {
            "vigil_${Version}_$($_.Goos)_$($_.Goarch)$($_.Ext)"
        } | Sort-Object)
    $checksumLines = foreach ($name in $names) {
        $hash = (Get-FileHash -LiteralPath (Join-Path $Dist $name) -Algorithm SHA256).Hash.ToLowerInvariant()
        "$hash  $name"
    }
    # LF line endings keep `sha256sum -c checksums.txt` working on Linux even
    # when the release is cut from Windows.
    [IO.File]::WriteAllText(
        (Join-Path $Dist 'checksums.txt'),
        (($checksumLines -join "`n") + "`n"),
        (New-Object System.Text.UTF8Encoding($false))
    )

    $assetFiles = @(Get-ChildItem -LiteralPath $Dist -File | Where-Object {
            $_.Name -eq 'checksums.txt' -or $_.Name -like 'vigil_*'
        })
    if ($assetFiles.Count -ne ($targets.Count + 1)) {
        throw "Expected $($targets.Count + 1) release assets in $Dist, found $($assetFiles.Count)."
    }

    $notesText = if ($Notes) { $Notes } else { "Vigil $Version" }
    [IO.File]::WriteAllText($notesFile, $notesText + [Environment]::NewLine, (New-Object System.Text.UTF8Encoding($false)))

    $releaseExists = $false
    & gh release view $Tag --repo $Repo *> $null
    if ($LASTEXITCODE -eq 0) {
        $releaseExists = $true
        Write-Step "Release $Tag already exists; uploading missing assets"
    }
    else {
        Write-Step "Creating release $Tag"
        $tagExists = $false
        & git ls-remote --exit-code --tags origin "refs/tags/$Tag" *> $null
        if ($LASTEXITCODE -eq 0) {
            $tagExists = $true
        }
        $createArgs = @(
            'release', 'create', $Tag,
            '--repo', $Repo,
            '--title', "Vigil $Version",
            '--notes-file', $notesFile
        )
        if (-not $tagExists) {
            $createArgs += @('--target', $Commit)
        }
        if ($Version.Contains('-')) {
            $createArgs += '--prerelease'
        }
        & gh @createArgs
        if ($LASTEXITCODE -ne 0) {
            throw "gh release create failed for $Tag."
        }
    }

    $existing = @()
    if ($releaseExists) {
        $existing = @(& gh release view $Tag --repo $Repo --json assets --jq '.assets[].name')
        if ($LASTEXITCODE -ne 0) {
            throw "Could not list assets of release $Tag."
        }
    }

    foreach ($asset in $assetFiles) {
        if ($existing -contains $asset.Name) {
            Write-Note "skip existing asset $($asset.Name)"
            continue
        }
        Write-Step "Uploading $($asset.Name)"
        & gh release upload $Tag $asset.FullName --repo $Repo
        if ($LASTEXITCODE -ne 0) {
            throw "gh release upload failed for $($asset.Name)."
        }
    }

    if ($SkipNpm) {
        Write-Step 'npm build/publish skipped (-SkipNpm)'
    }
    else {
        Write-Step 'Building npm packages'
        & node npm/build.mjs --version $Version --dist dist --out npm-out
        if ($LASTEXITCODE -ne 0) {
            throw 'node npm/build.mjs failed.'
        }

        $bash = Get-Command bash -ErrorAction SilentlyContinue
        if ($bash) {
            Write-Step 'Publishing npm packages'
            & bash npm/publish.sh $Version npm-out
            if ($LASTEXITCODE -ne 0) {
                throw 'npm/publish.sh failed.'
            }
        }
        else {
            Write-Warning "bash was not found; publish manually with: npm/publish.sh $Version npm-out"
        }
    }

    Write-Host ''
    Write-Step 'Release complete'
    Write-Note "tag:     $Tag"
    Write-Note "commit:  $Commit"
    Write-Note "assets:  $Dist"
    Write-Note "release: https://github.com/$Repo/releases/tag/$Tag"
}
finally {
    if (Test-Path -LiteralPath $notesFile) {
        Remove-Item -LiteralPath $notesFile -Force -ErrorAction SilentlyContinue
    }
}
