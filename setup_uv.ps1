$ErrorActionPreference = "Stop"

Set-Location $PSScriptRoot

if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    Write-Host "uv was not found. Installing uv..."
    irm https://astral.sh/uv/install.ps1 | iex

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

Write-Host "Creating the uv virtual environment..."
uv venv .venv

Write-Host "Installing Python dependencies..."
uv pip install --python .venv\Scripts\python.exe -r download_combine_NUC_dlt\requirements.txt smbprotocol keyring

Write-Host "Setup complete. Activate the environment with:"
Write-Host "  .\.venv\Scripts\Activate.ps1"
