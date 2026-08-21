# Install and operate one current-user MNCS Fabric worker on Windows.
#
# The repository copy is authoritative. It installs only the launcher,
# launcher helper, and generated worker-config.json into the worker root;
# credentials, ledgers, bundles, and caches are never replaced. The task is a
# logon/manual entry point. It does not poll or retry every minute.
[CmdletBinding()]
param(
    [ValidateSet("Install", "Start", "Stop", "Restart", "Update", "Repair", "Status", "Uninstall")]
    [string]$Action = "Install",
    [string]$WorkerId = "collamore02-windows",
    [string]$ControllerId = "epi13-local-harness",
    [string]$Root = (Join-Path $env:USERPROFILE "mncs-fabric-worker"),
    [string]$Python = (Join-Path $env:USERPROFILE "mncs-fabric-gpu\.venv\Scripts\python.exe"),
    [int]$Port = 7443,
    [string]$TaskName = "MNCS-Fabric-Worker",
    [switch]$Start
)

$ErrorActionPreference = "Stop"
if ($Start) { $Action = "Start" }

$sourceLauncher = Join-Path $PSScriptRoot "fabric_worker.ps1"
$sourceHelper = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) "scripts\windows_worker_launcher.py"
$launcherDirectory = Join-Path $Root "launcher"
$launcher = Join-Path $launcherDirectory "fabric_worker.ps1"
$helper = Join-Path $launcherDirectory "windows_worker_launcher.py"
$configPath = Join-Path $launcherDirectory "worker-config.json"

function Write-Utf8File([string]$Path, [string]$Content) {
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Content, $encoding)
}

function Get-ExistingTask([string]$Name) {
    return Get-ScheduledTask -TaskName $Name -ErrorAction SilentlyContinue
}

function Test-TaskCorrect([object]$Task, [string]$ExpectedArguments) {
    if ($null -eq $Task) { return $false }
    $actions = @($Task.Actions)
    $triggers = @($Task.Triggers)
    if ($actions.Count -ne 1 -or $actions[0].Execute -ne "powershell.exe" -or $actions[0].Arguments -ne $ExpectedArguments) { return $false }
    # Exactly one logon trigger is intentional. A time trigger with
    # Repetition.Interval is never accepted here.
    if ($triggers.Count -ne 1 -or $triggers[0].CimClass.CimClassName -ne "MSFT_TaskLogonTrigger") { return $false }
    if ($Task.Principal.LogonType -notmatch "Interactive" -or $Task.Principal.RunLevel -notmatch "Limited") { return $false }
    if ($Task.Settings.MultipleInstances -notmatch "IgnoreNew") { return $false }
    if ([int]$Task.Settings.RestartCount -ne 0) { return $false }
    return $true
}

function Ensure-Task([string]$Name, [string]$ExpectedArguments) {
    $existing = Get-ExistingTask $Name
    if (Test-TaskCorrect $existing $ExpectedArguments) { return "task-already-correct" }
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $ExpectedArguments
    $logon = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
    $settings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -ExecutionTimeLimit ([TimeSpan]::Zero) `
        -MultipleInstances IgnoreNew
    $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited
    try { Register-ScheduledTask -TaskName $Name -Action $action -Trigger $logon -Settings $settings -Principal $principal -Force | Out-Null }
    catch {
        if ($_.Exception.Message -match "Access is denied") {
            throw "access denied replacing Scheduled Task '$Name'. Run the repository installer once from an elevated PowerShell to migrate a task created by an older elevated installer; normal current-user installs do not require elevation."
        }
        throw
    }
    if ($null -eq $existing) { return "task-created" }
    return "task-updated"
}

function Remove-LegacyWatch {
    $watchName = "MNCS-Fabric-Worker-Watch"
    $watch = Get-ExistingTask $watchName
    if ($null -ne $watch) {
        try { Unregister-ScheduledTask -TaskName $watchName -Confirm:$false }
        catch {
            if ($_.Exception.Message -match "Access is denied") {
                throw "access denied removing retired Scheduled Task '$watchName'. Run the repository installer once from an elevated PowerShell to remove the legacy one-minute watch; normal current-user installs do not require elevation."
            }
            throw
        }
        return $true
    }
    return $false
}

function Assert-InstallInputs {
    if (-not (Test-Path -LiteralPath $sourceLauncher)) { throw "repository launcher missing: $sourceLauncher" }
    if (-not (Test-Path -LiteralPath $sourceHelper)) { throw "repository launcher helper missing: $sourceHelper" }
    if (-not (Test-Path -LiteralPath $Python)) { throw "Fabric Python runtime not found: $Python" }
    foreach ($name in @("certs\ca.pem", "certs\worker.pem", "certs\worker.key", "trust\worker-trust.jsonl")) {
        $path = Join-Path $Root $name
        if (-not (Test-Path -LiteralPath $path)) { throw "required worker identity file missing: $path" }
    }
}

function Read-PreviousConfig {
    if (-not (Test-Path -LiteralPath $configPath)) { return $null }
    try { return Get-Content -Raw -LiteralPath $configPath | ConvertFrom-Json }
    catch { throw "worker configuration is unreadable: $configPath" }
}

function Ensure-Deployment {
    Assert-InstallInputs
    New-Item -ItemType Directory -Force -Path $launcherDirectory, (Join-Path $Root "state\upgrade"), (Join-Path $Root "logs") | Out-Null
    $previous = Read-PreviousConfig
    $config = [ordered]@{
        schema_version = "mncs-fabric.windows-worker-install.v1"
        worker_id = $WorkerId
        controller_id = $ControllerId
        root = (Resolve-Path -LiteralPath $Root).Path
        python = (Resolve-Path -LiteralPath $Python).Path
        host = "0.0.0.0"
        port = $Port
        startup_timeout_seconds = 30
        task_name = $TaskName
        launcher = (Join-Path $launcherDirectory "fabric_worker.ps1")
        state = (Join-Path $Root "state\worker-process.json")
        stdout = (Join-Path $Root "logs\worker.stdout.log")
        stderr = (Join-Path $Root "logs\worker.stderr.log")
    }
    $configChanged = $true
    if ($null -ne $previous) {
        $differences = @("worker_id", "controller_id", "root", "python", "host", "port", "task_name") | Where-Object { [string]$previous.$_ -ne [string]$config[$_] }
        $configChanged = @($differences).Count -gt 0
    }
    Copy-Item -LiteralPath $sourceLauncher -Destination $launcher -Force
    Copy-Item -LiteralPath $sourceHelper -Destination $helper -Force
    Write-Utf8File $configPath (($config | ConvertTo-Json -Depth 4) + "`n")

    # The old deployed installer was an unversioned copy of this script. It
    # is not a supported self-update mechanism and must not remain ambiguous.
    $legacyInstaller = Join-Path $launcherDirectory "Install-FabricWorker.ps1"
    $legacyRemoved = $false
    if (Test-Path -LiteralPath $legacyInstaller) {
        Remove-Item -LiteralPath $legacyInstaller -Force
        $legacyRemoved = $true
    }

    $taskArguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$launcher`" -Action Start -Config `"$configPath`""
    $taskResult = Ensure-Task $TaskName $taskArguments
    $watchRemoved = Remove-LegacyWatch
    return [ordered]@{
        config_changed = [bool]$configChanged
        task = $taskResult
        legacy_installer_removed = $legacyRemoved
        legacy_watch_removed = $watchRemoved
        config = $configPath
        launcher = $launcher
    }
}

function Invoke-WorkerLauncher([string]$Operation) {
    if (-not (Test-Path -LiteralPath $launcher)) { throw "installed worker launcher missing: $launcher" }
    $output = & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $launcher -Action $Operation -Config $configPath
    $code = $LASTEXITCODE
    if ($code -ne 0) {
        $message = (($output | Out-String).Trim())
        if (-not $message) { $message = "worker launcher exited with code $code" }
        throw $message
    }
    $line = @($output | Where-Object { $_ -and $_.ToString().Trim() }) | Select-Object -Last 1
    if ($null -eq $line) { throw "worker launcher returned no status" }
    return ($line.ToString() | ConvertFrom-Json)
}

try {
    $result = [ordered]@{
        worker_id = $WorkerId
        controller_id = $ControllerId
        task = $TaskName
        root = $Root
        python = $Python
        privilege = "current-user-scheduled-task"
        run_level = "Limited"
        logon_type = "Interactive"
    }
    switch ($Action) {
        "Install" { $result.outcome = "installed"; $deployment = Ensure-Deployment }
        "Update" { $result.outcome = "updated"; $deployment = Ensure-Deployment }
        "Repair" { $result.outcome = "repaired"; $deployment = Ensure-Deployment; $worker = Invoke-WorkerLauncher "Start"; if ($worker.status -eq "already-running") { $result.outcome = "already-running" } }
        "Start" { $deployment = Ensure-Deployment; $worker = Invoke-WorkerLauncher "Start"; $result.outcome = [string]$worker.status }
        "Restart" { $result.outcome = "restarted"; $deployment = Ensure-Deployment; $worker = Invoke-WorkerLauncher "Restart" }
        "Stop" { $result.outcome = "stopped"; $worker = Invoke-WorkerLauncher "Stop" }
        "Status" {
            if (-not (Test-Path -LiteralPath $configPath)) {
                $result.outcome = "not-installed"
                $result.state = "NOT_INSTALLED"
            } else {
                $worker = Invoke-WorkerLauncher "Status"
                $result.outcome = "status"
            }
        }
        "Uninstall" {
            if (Test-Path -LiteralPath $configPath) { $worker = Invoke-WorkerLauncher "Stop" }
            $taskRemoved = $false
            if ($null -ne (Get-ExistingTask $TaskName)) {
                Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
                $taskRemoved = $true
            }
            $watchRemoved = Remove-LegacyWatch
            foreach ($path in @($launcher, $helper, $configPath)) {
                if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force }
            }
            $result.outcome = "uninstalled"
            $result.task_removed = $taskRemoved
            $result.watch_removed = $watchRemoved
            $result.data_preserved = $true
        }
    }
    if ($null -ne $deployment) { $result.deployment = $deployment }
    if ($null -ne $worker) { $result.worker = $worker }
    $result | ConvertTo-Json -Depth 8 -Compress
    exit 0
} catch {
    $errorMessage = $_.Exception.Message
    $errorOutcome = if ($errorMessage -match "port-conflict") { "port-conflict" } else { "failed" }
    [ordered]@{ outcome = $errorOutcome; error = $errorMessage; worker_id = $WorkerId; task = $TaskName } | ConvertTo-Json -Compress
    exit 2
}

