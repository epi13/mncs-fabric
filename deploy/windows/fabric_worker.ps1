# Current-user, single-instance Fabric worker entry point.
# The installer generates worker-config.json beside this file. This script
# exits after handing off the worker so Task Scheduler remains Ready; health is
# verified by process identity and port ownership.
[CmdletBinding()]
param(
    [ValidateSet("Start", "Stop", "Restart", "Status")]
    [string]$Action = "Start",
    [string]$Config = ""
)

$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($Config)) { $Config = Join-Path $PSScriptRoot "worker-config.json" }

function Write-Json([object]$Value, [int]$Code = 0) {
    $Value | ConvertTo-Json -Depth 8 -Compress
    if ($Code -ne 0) { exit $Code }
}

function Read-Config {
    if (-not (Test-Path -LiteralPath $Config)) { throw "worker configuration not found: $Config" }
    try { $value = Get-Content -Raw -LiteralPath $Config | ConvertFrom-Json }
    catch { throw "worker configuration is unreadable: $Config" }
    foreach ($name in @("worker_id", "controller_id", "root", "python", "host", "port", "stdout", "stderr")) {
        if ($null -eq $value.$name -or [string]::IsNullOrWhiteSpace([string]$value.$name)) { throw "worker configuration field missing: $name" }
    }
    return $value
}

function Get-ExpectedProcesses([object]$Settings) {
    $rootPattern = [regex]::Escape([string]$Settings.root)
    $workerPattern = [regex]::Escape("--worker-id $($Settings.worker_id)")
    $controllerPattern = [regex]::Escape("--controller-id $($Settings.controller_id)")
    $portPattern = [regex]::Escape("--port $($Settings.port)")
    @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -match "^(python|pythonw)\.exe$" -and $_.CommandLine -and
        $_.CommandLine -match "-m\s+mncs_fabric\s+worker\s+serve" -and
        $_.CommandLine -match $rootPattern -and
        $_.CommandLine -match $workerPattern -and
        $_.CommandLine -match $controllerPattern -and
        $_.CommandLine -match $portPattern
    })
}

function Get-PortOwners([int]$Port) {
    $owners = @()
    try {
        $owners = @(Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue | ForEach-Object { [int]$_.OwningProcess })
    } catch { $owners = @() }
    if ($owners.Count -eq 0) {
        $pattern = "^\s*TCP\s+\S+:$Port\s+\S+\s+LISTENING\s+(\d+)\s*$"
        $owners = @(netstat -ano 2>$null | ForEach-Object { $match = [regex]::Match($_, $pattern); if ($match.Success) { [int]$match.Groups[1].Value } })
    }
    return @($owners | Sort-Object -Unique)
}

function Get-Health([object]$Settings) {
    $processes = @(Get-ExpectedProcesses $Settings)
    $owners = @(Get-PortOwners ([int]$Settings.port))
    $expectedIds = @($processes | ForEach-Object { [int]$_.ProcessId })
    $expectedOwners = @($owners | Where-Object { $expectedIds -contains $_ })
    $unrelatedOwners = @($owners | Where-Object { -not ($expectedIds -contains $_) })
    if ($expectedOwners.Count -gt 0 -and $unrelatedOwners.Count -eq 0) { $state = "HEALTHY" }
    elseif ($unrelatedOwners.Count -gt 0) { $state = "PORT_CONFLICT" }
    elseif ($processes.Count -gt 0) { $state = "NOT_LISTENING" }
    else { $state = "STOPPED" }
    return [ordered]@{
        state = $state
        worker_id = [string]$Settings.worker_id
        controller_id = [string]$Settings.controller_id
        port = [int]$Settings.port
        process_ids = @($expectedIds)
        port_owner_ids = @($owners)
        unrelated_port_owner_ids = @($unrelatedOwners)
    }
}

function Quote-Argument([string]$Value) {
    return '"' + ($Value -replace '"', '\"') + '"'
}

function Get-WorkerArguments([object]$Settings) {
    return @(
        "-m", "mncs_fabric", "worker", "serve",
        "--worker-id", [string]$Settings.worker_id,
        "--controller-id", [string]$Settings.controller_id,
        "--bundle-root", (Join-Path $Settings.root "bundle-root"),
        "--state", (Join-Path $Settings.root "state\worker-ledger.jsonl"),
        "--trust-state", (Join-Path $Settings.root "trust\worker-trust.jsonl"),
        "--ca", (Join-Path $Settings.root "certs\ca.pem"),
        "--certificate", (Join-Path $Settings.root "certs\worker.pem"),
        "--key", (Join-Path $Settings.root "certs\worker.key"),
        "--host", [string]$Settings.host,
        "--port", [string]$Settings.port,
        "--timeout", "30",
        "--max-requests", "100000",
        "--max-concurrent-connections", "1",
        "--graceful-shutdown-timeout", "5",
        "--bundle-cache", (Join-Path $Settings.root "bundle-cache")
    )
}

function Stop-Expected([object]$Settings) {
    $health = Get-Health $Settings
    if ($health.state -eq "STOPPED") { return $health }
    if ($health.state -eq "PORT_CONFLICT") { throw "port-conflict: port $($Settings.port) is owned by unrelated PID(s) $($health.unrelated_port_owner_ids -join ', ')" }
    foreach ($process in @(Get-ExpectedProcesses $Settings | Sort-Object ProcessId -Descending)) {
        Stop-Process -Id ([int]$process.ProcessId) -Force -ErrorAction SilentlyContinue
    }
    $deadline = (Get-Date).AddSeconds(10)
    do {
        Start-Sleep -Milliseconds 250
        $health = Get-Health $Settings
    } while ($health.state -ne "STOPPED" -and (Get-Date) -lt $deadline)
    if ($health.state -ne "STOPPED") { throw "worker did not stop cleanly; state=$($health.state) pids=$($health.process_ids -join ',')" }
    return $health
}

function Start-Expected([object]$Settings) {
    $health = Get-Health $Settings
    if ($health.state -eq "HEALTHY") { $health.status = "already-running"; return $health }
    if ($health.state -eq "PORT_CONFLICT") { throw "port-conflict: port $($Settings.port) is owned by unrelated PID(s) $($health.unrelated_port_owner_ids -join ', ')" }
    if ($health.state -eq "NOT_LISTENING") { $null = Stop-Expected $Settings }

    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Settings.stdout), (Split-Path -Parent $Settings.stderr) | Out-Null
    $args = Get-WorkerArguments $Settings
    $argumentLine = ($args | ForEach-Object { Quote-Argument ([string]$_) }) -join " "
    $process = Start-Process -FilePath ([string]$Settings.python) -ArgumentList $argumentLine -WorkingDirectory ([string]$Settings.root) -RedirectStandardOutput ([string]$Settings.stdout) -RedirectStandardError ([string]$Settings.stderr) -WindowStyle Hidden -PassThru
    $statePath = Join-Path $Settings.root "state\worker-process.json"
    [ordered]@{ schema_version = "mncs-fabric.windows-worker-process.v1"; worker_id = $Settings.worker_id; controller_id = $Settings.controller_id; launcher_pid = $process.Id; started_at = (Get-Date).ToUniversalTime().ToString("o"); command = $args } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $statePath -Encoding utf8

    $deadline = (Get-Date).AddSeconds([int]$Settings.startup_timeout_seconds)
    do {
        Start-Sleep -Milliseconds 250
        $health = Get-Health $Settings
        if ($health.state -eq "PORT_CONFLICT") { throw "port-conflict: another process acquired port $($Settings.port)" }
    } while ($health.state -ne "HEALTHY" -and (Get-Date) -lt $deadline)
    if ($health.state -ne "HEALTHY") {
        $tail = ""
        if (Test-Path -LiteralPath $Settings.stderr) { $tail = (Get-Content -LiteralPath $Settings.stderr -Tail 12 | Out-String).Trim() }
        throw "worker failed to become healthy; state=$($health.state); stderr=$tail"
    }
    $health.status = "started"
    return $health
}

try {
    $settings = Read-Config
    switch ($Action) {
        "Start" { $result = Start-Expected $settings }
        "Stop" { $result = Stop-Expected $settings; $result.status = "stopped" }
        "Restart" { $null = Stop-Expected $settings; $result = Start-Expected $settings; $result.status = "restarted" }
        "Status" { $result = Get-Health $settings; $result.status = "status" }
    }
    $result.outcome = "PASS"
    Write-Json $result
} catch {
    Write-Json @{ outcome = "FAIL"; status = "failed"; state = "UNKNOWN"; error = $_.Exception.Message } 2
}

