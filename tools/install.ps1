# Builds the pinned development tools into .\bin (Windows equivalent of
# tools/install.sh). See tools/README.md.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$env:GOBIN = Join-Path $root 'bin'
$env:GOFLAGS = '-mod=readonly'
Get-ChildItem -Path (Join-Path $root 'tools') -Directory | ForEach-Object {
    if (Test-Path (Join-Path $_.FullName 'go.mod')) {
        Write-Host "building $($_.Name)"
        go -C $_.FullName install tool
        if ($LASTEXITCODE -ne 0) { throw "failed to build $($_.Name)" }
    }
}
