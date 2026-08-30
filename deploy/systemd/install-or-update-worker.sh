#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 || $# -gt 3 ]]; then
  echo "usage: $0 WORKER_ID FABRIC_SOURCE [STATE_ROOT]" >&2
  exit 2
fi

worker_id=$1
fabric_source=$2
state_root=${3:-"$HOME/.local/state/mncs-fabric/workers/$worker_id"}

if [[ ! $worker_id =~ ^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$ ]]; then
  echo "worker identity is invalid" >&2
  exit 2
fi
if [[ ! -d $fabric_source || ! -f $fabric_source/pyproject.toml ]]; then
  echo "Fabric source must be an explicit local checkout or release directory" >&2
  exit 2
fi
if [[ ! -f $state_root/installation.json || ! -f $state_root/worker.env ]]; then
  echo "run 'mncs-fabric worker activate' before installing the service" >&2
  exit 2
fi
if grep -qx 'MNCS_FABRIC_CONTAINMENT_MODE=required' "$state_root/worker.env" \
  && ! command -v bwrap >/dev/null 2>&1; then
  echo "required worker containment needs bubblewrap (Fedora: sudo dnf install bubblewrap)" >&2
  exit 1
fi

install_root="$HOME/.local/share/mncs-fabric"
venv="$install_root/venv"
unit_root="$HOME/.config/systemd/user"
config_root="$HOME/.config/mncs-fabric/workers"
mkdir -p -m 700 "$install_root" "$config_root"
mkdir -p "$unit_root"

if [[ ! -x $venv/bin/python ]]; then
  python3 -m venv "$venv"
fi
"$venv/bin/python" -m pip install --disable-pip-version-check --upgrade "$fabric_source"
if fabric_revision=$(git -C "$fabric_source" rev-parse --verify HEAD 2>/dev/null); then
  printf '%s\n' "$fabric_revision" > "$install_root/fabric-revision.txt"
  chmod 0600 "$install_root/fabric-revision.txt"
else
  rm -f "$install_root/fabric-revision.txt"
fi
install -m 0644 "$fabric_source/deploy/systemd/mncs-fabric-worker-rendezvous@.service" \
  "$unit_root/mncs-fabric-worker-rendezvous@.service"
install -m 0600 "$state_root/worker.env" "$config_root/$worker_id.env"

systemctl --user daemon-reload
systemctl --user enable --now "mncs-fabric-worker-rendezvous@$worker_id.service"
systemctl --user restart "mncs-fabric-worker-rendezvous@$worker_id.service"
systemctl --user --no-pager status "mncs-fabric-worker-rendezvous@$worker_id.service"
