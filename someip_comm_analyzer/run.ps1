<#
.SYNOPSIS
    SOME/IP communication analyzer (standalone, own uv environment).

.EXAMPLE
    .\run.ps1                                  # Streamlit UI
    .\run.ps1 -Port 8510
    .\run.ps1 -Cli capture.pcapng.zst -o out   # command line, writes CSVs
#>
[CmdletBinding(PositionalBinding = $false)]
param(
    [int]$Port = 8530,

    [switch]$Cli,

    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Arguments
)

$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

if ($Cli) {
    uv run python someip_comm_analyzer.py @Arguments
}
else {
    uv run streamlit run streamlit_app.py --server.port $Port
}
exit $LASTEXITCODE
