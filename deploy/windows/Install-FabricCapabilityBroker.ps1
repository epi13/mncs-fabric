# Install the bounded Fabric capability broker as a LocalSystem Windows service.
# The broker itself accepts only versioned structured requests over a named
# pipe. This installer does not create a TCP listener or a PowerShell command
# bridge.
[CmdletBinding()]
param(
    [ValidateSet("Install", "Start", "Stop", "Restart", "Status", "Uninstall")]
    [string]$Action = "Install",
    [string]$ServiceName = "MNCS-Fabric-CapabilityBroker",
    [string]$Python = (Join-Path $env:ProgramFiles "MNCS Fabric\\venv\\Scripts\\python.exe"),
    [string]$Profile = (Join-Path $env:ProgramData "MNCS\\worker-capability.json"),
    [string]$State = (Join-Path $env:ProgramData "MNCS\\state\\capability-broker.jsonl"),
    [string]$PipeName = "\\.\pipe\mncs-fabric-capability-broker",
    [Parameter(Mandatory = $false)]
    [string]$WorkerSid = ""
)

$ErrorActionPreference = "Stop"

function Assert-SafeText([string]$Value, [string]$Name) {
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value.Contains("`0") -or $Value.Contains('"')) {
        throw "$Name is empty or contains an unsupported quote"
    }
}

function Get-ServiceObject {
    return Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
}

function Get-BinaryPath {
    Assert-SafeText $Python "Python"
    Assert-SafeText $Profile "Profile"
    Assert-SafeText $State "State"
    Assert-SafeText $PipeName "PipeName"
    if ($PipeName -notmatch '^\\\\\.\\pipe\\[A-Za-z0-9_.-]{1,128}$') { throw "PipeName is not a safe named pipe" }
    if ($WorkerSid -notmatch '^S-1-[0-9-]{3,80}$') { throw "WorkerSid must be an explicit Windows SID" }
    return ('"{0}" -m mncs_fabric.capability_broker --profile "{1}" --pipe-name "{2}" --allowed-sid "{3}" --state "{4}"' -f $Python, $Profile, $PipeName, $WorkerSid, $State)
}

function Ensure-Directories {
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Profile), (Split-Path -Parent $State) | Out-Null
}

function Install-Broker {
    if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) { throw "Python runtime not found: $Python" }
    if (-not (Test-Path -LiteralPath $Profile -PathType Leaf)) { throw "capability profile not found: $Profile" }
    Ensure-Directories
    $binaryPath = Get-BinaryPath
    $service = Get-ServiceObject
    if ($null -eq $service) {
        New-Service -Name $ServiceName -BinaryPathName $binaryPath -DisplayName "MNCS Fabric Capability Broker" -Description "Bounded structured privileged-worker capability broker" -StartupType Automatic | Out-Null
        return "service-created"
    }
    $existing = Get-CimInstance Win32_Service -Filter ("Name='{0}'" -f $ServiceName)
    if ($existing.PathName -ne $binaryPath) {
        & sc.exe config $ServiceName binPath= $binaryPath | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "unable to update capability broker service path" }
        return "service-updated"
    }
    return "service-already-correct"
}

try {
    switch ($Action) {
        "Install" { $status = Install-Broker }
        "Start" { Start-Service -Name $ServiceName; $status = "started" }
        "Stop" { Stop-Service -Name $ServiceName -Force; $status = "stopped" }
        "Restart" { Restart-Service -Name $ServiceName -Force; $status = "restarted" }
        "Status" { $status = (Get-ServiceObject).Status.ToString() }
        "Uninstall" { Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue; sc.exe delete $ServiceName | Out-Null; if ($LASTEXITCODE -ne 0) { throw "unable to remove capability broker service" }; $status = "uninstalled" }
    }
    @{ outcome = "PASS"; service = $ServiceName; status = $status; pipe = $PipeName; profile = $Profile } | ConvertTo-Json -Compress
} catch {
    @{ outcome = "FAIL"; service = $ServiceName; status = "UNKNOWN"; error = $_.Exception.Message } | ConvertTo-Json -Compress
    exit 2
}
