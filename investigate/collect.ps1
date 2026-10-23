# Launcher for collect.py with the repository's Python environment.
# The root-cause agent is only allowed to run this script, so keep it a thin pass-through.
$python = Join-Path $PSScriptRoot "..\.venv\Scripts\python.exe"
& $python (Join-Path $PSScriptRoot "collect.py") @args
exit $LASTEXITCODE
