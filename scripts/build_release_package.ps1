param(
    [string]$OutDir = "dist",
    [switch]$SkipDockerBuild,
    [switch]$SaveDockerImage
)

$ErrorActionPreference = "Stop"

$commitSha = (git rev-parse HEAD).Trim()
$shortSha = (git rev-parse --short=12 HEAD).Trim()
$versionLine = Select-String -Path "pyproject.toml" -Pattern '^version = "([^"]+)"' | Select-Object -First 1
if ($null -eq $versionLine) {
    throw "Could not determine project version from pyproject.toml"
}
$version = $versionLine.Matches[0].Groups[1].Value
$imageTag = "aethelgard:${version}-${shortSha}"
$releaseName = "aethelgard-${version}-${shortSha}"
$releaseRoot = Join-Path $OutDir $releaseName

if (Test-Path $releaseRoot) {
    Remove-Item -LiteralPath $releaseRoot -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $releaseRoot | Out-Null

$excludedPathPrefixes = @(
    "reports/",
    "dist/",
    "docs/research/",
    ".git/",
    ".venv/",
    ".venv-fresh/",
    "venv/",
    "env/"
)
$excludedSuffixes = @(".db", ".sqlite", ".sqlite3", ".log")
$trackedFiles = git ls-files
foreach ($file in $trackedFiles) {
    $normalized = $file.Replace("\", "/")
    if (($excludedPathPrefixes | Where-Object { $normalized.StartsWith($_) }).Count -gt 0) {
        continue
    }
    if (($excludedSuffixes | Where-Object { $normalized.EndsWith($_) }).Count -gt 0) {
        continue
    }
    if ($normalized -eq ".env" -or $normalized.StartsWith(".env.")) {
        continue
    }
    $target = Join-Path $releaseRoot $file
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $target) | Out-Null
    Copy-Item -LiteralPath $file -Destination $target
}

$metadata = [ordered]@{
    package = $releaseName
    version = $version
    commit = $commitSha
    docker_image_tag = $imageTag
    vm_required = $false
    excludes = @("reports", "dist", "docs/research", ".git", ".env", ".venv", "logs", "db")
}
$metadata | ConvertTo-Json -Depth 4 | Set-Content -Encoding UTF8 -Path (Join-Path $releaseRoot "release_manifest.json")

$zipPath = Join-Path $OutDir "${releaseName}.zip"
if (Test-Path $zipPath) {
    Remove-Item -LiteralPath $zipPath -Force
}
Compress-Archive -Path (Join-Path $releaseRoot "*") -DestinationPath $zipPath

if (-not $SkipDockerBuild) {
    docker build -t $imageTag -t "aethelgard:local" .
    if ($SaveDockerImage) {
        docker save $imageTag -o (Join-Path $OutDir "${releaseName}-docker-image.tar")
    }
}

$hashTargets = Get-ChildItem -LiteralPath $OutDir -File |
    Where-Object { $_.Name -like "${releaseName}*" -and $_.Name -ne "SHA256SUMS.txt" }
$hashLines = foreach ($item in $hashTargets) {
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $item.FullName).Hash.ToLowerInvariant()
    "$hash  $($item.Name)"
}
$hashLines | Set-Content -Encoding UTF8 -Path (Join-Path $OutDir "SHA256SUMS.txt")

Write-Host "Release package: $zipPath"
Write-Host "Docker image tag: $imageTag"
Write-Host "SHA256SUMS: $(Join-Path $OutDir 'SHA256SUMS.txt')"
