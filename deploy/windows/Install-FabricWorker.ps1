# Idempotent current-user Fabric worker supervisor for Windows.
# Does not require elevation. Registers a Scheduled Task that restarts on
# failure and at logon. Identity/certs/ledgers are preserved.
[CmdletBinding()]
param(
    [string]$WorkerId = "collamore02-windows",
    [string]$Root = (Join-Path $env:USERPROFILE "mncs-fabric-worker"),
    [string]$Python = (Join-Path $env:USERPROFILE "mncs-fabric-gpu\.venv\Scripts\python.exe"),
    [string]$TaskName = "MNCS-Fabric-Worker",
    [switch]$Start
)

$ErrorActionPreference = "Stop"
$launcher = Join-Path $Root "launcher\fabric_worker.ps1"
if (-not (Test-Path -LiteralPath $Python)) { throw "Fabric Python runtime not found: $Python" }
if (-not (Test-Path -LiteralPath $launcher)) { throw "Worker launcher not found: $launcher" }
foreach ($name in @("certs\ca.pem", "certs\worker.pem", "certs\worker.key", "trust\worker-trust.jsonl")) {
    $path = Join-Path $Root $name
    if (-not (Test-Path -LiteralPath $path)) { throw "required worker identity file missing: $path" }
}

New-Item -ItemType Directory -Force -Path (Join-Path $Root "state\upgrade") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $Root "logs") | Out-Null

$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -File `"$launcher`""
$logon = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $logon -Settings $settings -Principal $principal -Force | Out-Null
# Older installs created a second timer-driven watcher. Remove only that
# duplicate task; the single hidden task above remains the supervisor.
Unregister-ScheduledTask -TaskName "MNCS-Fabric-Worker-Watch" -Confirm:$false -ErrorAction SilentlyContinue

$result = [ordered]@{
    worker_id = $WorkerId
    task = $TaskName
    root = $Root
    python = $Python
    launcher = $launcher
    elevated = $false
    privilege = "current-user-scheduled-task"
    start_triggers = @("AtLogOn", "manual")
}
if ($Start) {
    Start-ScheduledTask -TaskName $TaskName
    $result.started = $true
}
$result | ConvertTo-Json -Compress
