[CmdletBinding()]
param(
    [string]$Distro = "Ubuntu22",
    [string]$CaddyPath = "caddy",
    [string]$Address = "http://localhost:8501",
    [string]$CanParquet,
    [string]$StopFile,
    [switch]$NoWorker
)

$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
$rootPython = Join-Path $root ".venv\Scripts\python.exe"
$canPython = Join-Path $root "can_decoder\.venv\Scripts\python.exe"
$caddy = (Get-Command $CaddyPath -ErrorAction Stop).Source
$processes = [System.Collections.Generic.List[System.Diagnostics.Process]]::new()
$wsl = $null
$oldAddress = $env:FAULT_TRACING_ADDRESS
$env:FAULT_TRACING_ADDRESS = $Address

function ConvertTo-WslPath([string]$Path) {
    $result = & wsl.exe -d $Distro --exec wslpath -a -u $Path
    if ($LASTEXITCODE -ne 0) { throw "Cannot translate WSL path: $Path" }
    return ($result -join "").Trim()
}

function Start-HostedProcess([string]$Name, [string]$Executable, [string[]]$ProcessArguments) {
    # Start-Process joins ArgumentList without quoting; quote paths with spaces explicitly.
    $quoted = $ProcessArguments | ForEach-Object {
        if ($_ -match '[\s"]') { '"' + $_.Replace('"', '\"') + '"' } else { $_ }
    }
    $process = Start-Process -FilePath $Executable -ArgumentList $quoted `
        -WorkingDirectory $root -PassThru -NoNewWindow `
        -RedirectStandardOutput (Join-Path $runDir "$Name.stdout.log") `
        -RedirectStandardError (Join-Path $runDir "$Name.stderr.log")
    $processes.Add($process)
    return $process
}

function Wait-Healthy([string]$Url, [System.Diagnostics.Process]$Process) {
    $deadline = (Get-Date).AddSeconds(90)
    while ((Get-Date) -lt $deadline) {
        if ($Process.HasExited) { throw "Server exited ($($Process.ExitCode)): $Url. See $runDir" }
        try {
            if ($StopFile -and (Test-Path -LiteralPath $StopFile)) {
                throw "The requested stop file already exists: $StopFile"
            }
            $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 2
            if ($response.StatusCode -eq 200) { return }
        }
        catch [System.Net.WebException] {
            Start-Sleep -Milliseconds 500
        }
        catch [System.Net.Http.HttpRequestException] {
            Start-Sleep -Milliseconds 500
        }
        catch [System.OperationCanceledException] {
            Start-Sleep -Milliseconds 500
        }
    }
    throw "Server did not become healthy: $Url. See $runDir"
}

$runDir = Join-Path ([System.IO.Path]::GetTempPath()) ("fault-tracing-" + [guid]::NewGuid())
$null = New-Item -ItemType Directory -Path $runDir
$wslStopFile = Join-Path $runDir "stop-wsl"

try {
    foreach ($python in @($rootPython, $canPython)) {
        if (-not (Test-Path $python)) { throw "Missing environment: $python. Run setup_uv.ps1 first." }
    }
    if ($CanParquet) {
        $CanParquet = (Resolve-Path $CanParquet).Path
    }
    foreach ($port in 8510..8515) {
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $port)
        try { $listener.Start() }
        finally { $listener.Stop() }
    }
    $wslRoot = ConvertTo-WslPath $root
    $wslStop = ConvertTo-WslPath $wslStopFile
    $wslPython = "$wslRoot/pcap_decoder/.venv/bin/python"
    & wsl.exe -d $Distro --exec $wslPython -c "import streamlit; import pandas"
    if ($LASTEXITCODE -ne 0) {
        throw "Missing PCAP WSL environment. Follow pcap_decoder\README.md (Python 3.10)."
    }
    & $rootPython -c "import streamlit, streamlit_explorer, st_aggrid, pandas"
    if ($LASTEXITCODE -ne 0) { throw "Windows dependencies missing. Run uv sync --all-packages." }
    & $canPython -c "import streamlit, pandas, plotly, pyarrow"
    if ($LASTEXITCODE -ne 0) { throw "CAN dependencies missing. Run uv sync --project can_decoder." }
    & $caddy validate --config (Join-Path $PSScriptRoot "Caddyfile") --adapter caddyfile
    if ($LASTEXITCODE -ne 0) { throw "Invalid Caddy configuration." }

    $hosted = Join-Path $root "hosted_app.py"
    foreach ($app in @(
        @{ Name = "home"; Port = 8510; Python = $rootPython },
        @{ Name = "readout"; Port = 8511; Python = $rootPython },
        @{ Name = "someip"; Port = 8513; Python = $rootPython },
        @{ Name = "can"; Port = 8514; Python = $canPython },
        @{ Name = "investigate"; Port = 8515; Python = $rootPython }
    )) {
        $arguments = @("-m", "streamlit", "run", $hosted,
            "--server.address", "127.0.0.1", "--server.port", "$($app.Port)",
            "--server.headless", "true")
        $base = ""
        if ($app.Name -ne "home") {
            $base = "/$($app.Name)"
            $arguments += @("--server.baseUrlPath", $app.Name, "--", $app.Name)
            if ($app.Name -eq "can" -and $CanParquet) { $arguments += $CanParquet }
        }
        $process = Start-HostedProcess $app.Name $app.Python $arguments
        Wait-Healthy "http://127.0.0.1:$($app.Port)$base/_stcore/health" $process
    }

    $wsl = Start-HostedProcess "pcap" "wsl.exe" @("-d", $Distro, "--cd", "$wslRoot/pcap_decoder",
        "--exec", $wslPython, "$wslRoot/hosting/wsl_host.py", $wslStop,
        "run", "$wslRoot/hosted_app.py", "--server.address", "127.0.0.1",
        "--server.port", "8512", "--server.baseUrlPath", "pcap", "--server.headless", "true",
        "--", "pcap")
    Wait-Healthy "http://127.0.0.1:8512/pcap/_stcore/health" $wsl

    if (-not $NoWorker) {
        # Runs investigations with this account's SMB keychain, az login and Copilot CLI login.
        $null = Start-HostedProcess "investigate-worker" $rootPython @((Join-Path $root "investigate\worker.py"))
    }

    $proxy = Start-HostedProcess "proxy" $caddy @("run", "--config", (Join-Path $PSScriptRoot "Caddyfile"),
        "--adapter", "caddyfile")
    Wait-Healthy "$($Address.TrimEnd('/'))/_stcore/health" $proxy
    Write-Host "Fault tracing tools: $Address"
    Write-Host "Logs: $runDir"
    Write-Host "Press Ctrl+C to stop this hosting stack. Cancel active decoding jobs first."
    while ($true) {
        if ($StopFile -and (Test-Path -LiteralPath $StopFile)) { break }
        foreach ($process in $processes) {
            if ($process.HasExited) {
                throw "Hosting process $($process.Id) exited ($($process.ExitCode)). See $runDir"
            }
        }
        Start-Sleep -Seconds 2
    }
}
finally {
    # The WSL supervisor owns and terminates its child; never terminate an entire distribution.
    $null = New-Item -ItemType File -Path $wslStopFile -Force
    if ($wsl -and -not $wsl.HasExited) { $null = $wsl.WaitForExit(15000) }
    foreach ($process in $processes) {
        if (-not $process.HasExited) { Stop-Process -Id $process.Id -ErrorAction Continue }
    }
    $env:FAULT_TRACING_ADDRESS = $oldAddress
}
