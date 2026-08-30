#!/usr/bin/env bash
# Idempotent update for a direct-endpoint systemd-user worker that already has
# identity material under $HOME/mncs-fabric-worker/current.
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "usage: $0 WORKER_ID FABRIC_SOURCE" >&2
  exit 2
fi

worker_id=$1
fabric_source=$2
root=${MNCS_FABRIC_WORKER_ROOT:-"$HOME/mncs-fabric-worker/current"}
venv="$root/venv"
unit_root="$HOME/.config/systemd/user"

if [[ ! -d $fabric_source || ! -f $fabric_source/pyproject.toml ]]; then
  echo "Fabric source must be an explicit local checkout or release directory" >&2
  exit 2
fi
if [[ ! -x $venv/bin/python ]]; then
  echo "worker venv is missing: $venv" >&2
  exit 2
fi
if [[ ! -f $root/certs/worker.key ]]; then
  echo "worker identity is missing under $root/certs" >&2
  exit 2
fi

"$venv/bin/python" -m pip install --disable-pip-version-check --upgrade "$fabric_source"
if [[ -f $fabric_source/deploy/systemd/mncs-fabric-worker-upgrade.service ]]; then
  mkdir -p "$unit_root"
  install -m 0644 "$fabric_source/deploy/systemd/mncs-fabric-worker-upgrade.service" \
    "$unit_root/mncs-fabric-worker-upgrade.service"
  systemctl --user daemon-reload
fi
systemctl --user restart mncs-fabric-worker.service
"$venv/bin/python" -c "import mncs_fabric; print(mncs_fabric.__version__)"
systemctl --user --no-pager --lines=8 status mncs-fabric-worker.service
