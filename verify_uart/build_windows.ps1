<#
.SYNOPSIS
    Builds the UART Verifier into a standalone Windows executable with PyInstaller.

.DESCRIPTION
    Creates an isolated build virtual environment, installs the runtime and build
    dependencies, and produces dist\UARTVerifier. One-dir is the default because it
    launches much faster than one-file, which unpacks to %TEMP% on every start.

.EXAMPLE
    .\build_windows.ps1
    .\build_windows.ps1 -OneFile
    .\build_windows.ps1 -Clean
#>
[CmdletBinding()]
param(
    # Produce a single self-contained .exe instead of a folder.
    [switch]$OneFile,
    # Keep a console window attached (useful for debugging).
    [switch]$Console,
    # Retained for compatibility; the build is always packaged into a ZIP.
    [switch]$Zip,
    # Remove build\, dist\ and the build venv, then exit.
    [switch]$Clean,
    [string]$Name = 'UARTVerifier',
    [string]$Entry = 'verify_uart_V2.py'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $root
try {
    $buildVenv = Join-Path $root '.buildvenv'
    $buildDir = Join-Path $root 'build'
    $distDir = Join-Path $root 'dist'

    if ($Clean) {
        foreach ($path in @($buildDir, $distDir, $buildVenv)) {
            if (Test-Path $path) {
                Write-Host "Removing $path"
                Remove-Item $path -Recurse -Force
            }
        }
        Write-Host 'Clean complete.' -ForegroundColor Green
        return
    }

    if (-not (Test-Path $Entry)) {
        throw "Entry script not found: $Entry"
    }

    $pythonCmd = Get-Command python -ErrorAction SilentlyContinue
    if (-not $pythonCmd) { throw 'python was not found on PATH.' }
    $python = $pythonCmd.Source

    if (-not (Test-Path $buildVenv)) {
        Write-Host 'Creating build virtual environment...' -ForegroundColor Cyan
        & $python -m venv $buildVenv
        if ($LASTEXITCODE -ne 0) { throw 'Failed to create the build virtual environment.' }
    }

    $venvPython = Join-Path $buildVenv 'Scripts\python.exe'

    Write-Host 'Installing build dependencies...' -ForegroundColor Cyan
    & $venvPython -m pip install --upgrade pip --quiet
    & $venvPython -m pip install --upgrade pyserial pyinstaller --quiet
    if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed.' }

    # PyInstaller only accepts .ico for the Windows executable icon.
    $iconArgs = @()
    $ico = Join-Path $root 'icon.ico'
    if (Test-Path $ico) {
        $iconArgs = @('--icon', $ico)
    }
    else {
        Write-Warning 'icon.ico not found - building without a custom icon.'
    }

    $pyiArgs = @(
        '--noconfirm'
        '--clean'
        '--name', $Name
        '--hidden-import', 'serial.tools.list_ports'
        '--collect-submodules', 'serial'
    )
    $pyiArgs += if ($OneFile) { '--onefile' } else { '--onedir' }
    $pyiArgs += if ($Console) { '--console' } else { '--windowed' }
    $pyiArgs += $iconArgs
    $pyiArgs += $Entry

    Write-Host "Building $Name ($(if ($OneFile) { 'one-file' } else { 'one-dir' }))..." -ForegroundColor Cyan
    & $venvPython -m PyInstaller @pyiArgs
    if ($LASTEXITCODE -ne 0) { throw 'PyInstaller build failed.' }

    $output = if ($OneFile) {
        Join-Path $distDir "$Name.exe"
    }
    else {
        Join-Path $distDir $Name
    }

    if (-not (Test-Path $output)) { throw "Expected build output not found: $output" }
    Write-Host "Build output: $output" -ForegroundColor Green

    $stamp = Get-Date -Format 'yyyyMMdd'
    $zipPath = Join-Path $distDir "$Name-$stamp.zip"
    if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
    Compress-Archive -Path $output -DestinationPath $zipPath
    Write-Host "Archive: $zipPath" -ForegroundColor Green
}
finally {
    Pop-Location
}
