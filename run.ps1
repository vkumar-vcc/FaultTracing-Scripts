[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$Tool,

    [Parameter(Position = 1, ValueFromRemainingArguments = $true)]
    [string[]]$Arguments
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

function Show-Usage {
    Write-Host "Usage: .\run.ps1 <tool> [arguments]"
    Write-Host ""
    Write-Host "Tools:"
    Write-Host "  confighub  ConfigHub part lookup"
    Write-Host "  can        CAN BLF/ASC decoder and signal viewer"
    Write-Host "  nuc        NUC DLT downloader"
    Write-Host "  sat        SAT readout decoder"
    Write-Host "  standby    Standby decoder"
    Write-Host ""
    Write-Host "Examples:"
    Write-Host "  .\run.ps1 confighub 32477281IMJ"
    Write-Host "  .\run.ps1 can log.blf --map can_decoder\channels.txt"
    Write-Host "  .\run.ps1 nuc --help"
    Write-Host "  .\run.ps1 standby --input-file hp_coldboot.log"
}

if (-not $Tool -or $Tool -in @("-h", "--help", "help")) {
    Show-Usage
    exit 0
}

switch ($Tool.ToLowerInvariant()) {
    "confighub" {
        uv run python confighub_lookup.py @Arguments
    }
    "can" {
        if (-not $Arguments -or $Arguments[0] -in @("-h", "--help", "help")) {
            Get-Help (Join-Path $PSScriptRoot "can_decoder\run.ps1") -Full
        }
        else {
            & (Join-Path $PSScriptRoot "can_decoder\run.ps1") @Arguments
        }
    }
    "nuc" {
        uv run python download_combine_NUC_dlt\download_combine_NUC_dlt.py @Arguments
    }
    "sat" {
        uv run python SAT_Readout_decoder\SAT_Readout_decoder.py @Arguments
    }
    "standby" {
        uv run python standby-decoder\hpa_stanby_decoder.py @Arguments
    }
    default {
        Show-Usage
        throw "Unknown tool: $Tool"
    }
}

if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}