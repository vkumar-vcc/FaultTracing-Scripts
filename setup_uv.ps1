$ErrorActionPreference = "Stop"

Set-Location $PSScriptRoot

if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    Write-Host "uv was not found. Installing uv..."
    Invoke-RestMethod https://astral.sh/uv/install.ps1 | Invoke-Expression

    $uvCandidates = @(
        "$HOME\.local\bin\uv.exe",
        "$env:USERPROFILE\.local\bin\uv.exe"
    )
    foreach ($candidate in $uvCandidates) {
        if (Test-Path $candidate) {
            $env:Path = "$(Split-Path $candidate);$env:Path"
            break
        }
    }
}

if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    throw "uv was installed but is not available on PATH. Restart PowerShell and run this script again."
}

Write-Host "Initializing Git submodules..."
git submodule update --init --recursive

Write-Host "Syncing the uv project environment..."
uv sync

Write-Host "Setup complete. Activate the environment with:"
Write-Host "  .\.venv\Scripts\Activate.ps1"
