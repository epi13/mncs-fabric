#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 FABRIC_SOURCE" >&2
  exit 2
fi

fabric_source=$1
if [[ ! -d $fabric_source || ! -f $fabric_source/pyproject.toml ]]; then
  echo "Fabric source must be an explicit local checkout or release directory" >&2
  exit 2
fi

install_root="$HOME/.local/share/mncs-fabric"
venv="$install_root/venv"
unit_root="$HOME/.config/systemd/user"
config_root="$HOME/.config/mncs-fabric"
state_root="$HOME/.local/state/mncs-fabric"
mkdir -p -m 700 "$install_root" "$config_root" "$state_root"
mkdir -p "$unit_root"

if [[ ! -x $venv/bin/python ]]; then
  python3 -m venv "$venv"
fi
"$venv/bin/python" -m pip install --disable-pip-version-check --upgrade "$fabric_source"
install -m 0644 "$fabric_source/deploy/systemd/mncs-fabric-controller.service" \
  "$unit_root/mncs-fabric-controller.service"
if [[ ! -f $config_root/controller.env ]]; then
  install -m 0600 \
    "$fabric_source/deploy/systemd/mncs-fabric-controller.env.example" \
    "$config_root/controller.env"
fi

systemctl --user daemon-reload
systemctl --user enable --now mncs-fabric-controller.service
systemctl --user restart mncs-fabric-controller.service
systemctl --user --no-pager status mncs-fabric-controller.service
