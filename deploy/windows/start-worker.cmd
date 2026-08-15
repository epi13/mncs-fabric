@echo off
setlocal
set ROOT=C:\Users\epicu\mncs-fabric-worker
set PYTHON=C:\Users\epicu\mncs-fabric-gpu\.venv\Scripts\python.exe
set PYTHONPATH=%ROOT%\src
set PATH=C:\Program Files\Git\cmd;%PATH%
if not exist "%ROOT%\logs" mkdir "%ROOT%\logs"
start "MNCS-Fabric-Worker" /B "%PYTHON%" -m mncs_fabric worker serve --worker-id collamore02-windows --controller-id epi13-local-harness --bundle-root "%ROOT%\bundle-root" --state "%ROOT%\state\worker-ledger.jsonl" --trust-state "%ROOT%\trust\worker-trust.jsonl" --ca "%ROOT%\certs\ca.pem" --certificate "%ROOT%\certs\worker.pem" --key "%ROOT%\certs\worker.key" --host 0.0.0.0 --port 7443 --timeout 30 --max-requests 100000 --max-concurrent-connections 1 --graceful-shutdown-timeout 5 --bundle-cache "%ROOT%\bundle-cache" >> "%ROOT%\logs\worker.stdout.log" 2>> "%ROOT%\logs\worker.stderr.log"
exit /b 0
