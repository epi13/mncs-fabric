$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
if (-not (Test-Path -LiteralPath (Join-Path $root "certs\worker.key"))) {
    $root = Join-Path $env:USERPROFILE "mncs-fabric-worker"
}
$python = Join-Path $env:USERPROFILE "mncs-fabric-gpu\.venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $python)) {
    $python = Join-Path $root ".venv\Scripts\python.exe"
}
$logDir = Join-Path $root "logs"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$transcript = Join-Path $logDir "supervisor.log"
function Write-Supervisor([string]$Message) {
    Add-Content -LiteralPath $transcript -Value ("{0} {1}" -f (Get-Date -Format o), $Message)
}

if (-not (Test-Path -LiteralPath $python)) { throw "Fabric Python runtime not found: $python" }
$gitCmd = "C:\Program Files\Git\cmd"
if (Test-Path -LiteralPath $gitCmd) { $env:Path = "$gitCmd;$env:Path" }

$arguments = @(
    "-m", "mncs_fabric", "worker", "serve",
    "--worker-id", "collamore02-windows",
    "--controller-id", "epi13-local-harness",
    "--bundle-root", (Join-Path $root "bundle-root"),
    "--state", (Join-Path $root "state\worker-ledger.jsonl"),
    "--trust-state", (Join-Path $root "trust\worker-trust.jsonl"),
    "--ca", (Join-Path $root "certs\ca.pem"),
    "--certificate", (Join-Path $root "certs\worker.pem"),
    "--key", (Join-Path $root "certs\worker.key"),
    "--host", "0.0.0.0",
    "--port", "7443",
    "--timeout", "30",
    "--max-requests", "100000",
    "--max-concurrent-connections", "1",
    "--graceful-shutdown-timeout", "5",
    "--bundle-cache", (Join-Path $root "bundle-cache")
)
Write-Supervisor "starting $($arguments -join ' ')"
& $python @arguments
$code = $LASTEXITCODE
Write-Supervisor "exit $code"
exit $code
