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

# Keep the deployed source identity aligned with the installed checkout.  The
# package version is intentionally not sufficient here because same-version
# fixes can otherwise leave the controller reporting an older implementation.
if fabric_revision=$(git -C "$fabric_source" rev-parse --verify HEAD 2>/dev/null); then
  printf '%s\n' "$fabric_revision" > "$install_root/fabric-revision.txt"
  chmod 0600 "$install_root/fabric-revision.txt"
else
  rm -f "$install_root/fabric-revision.txt"
fi

install -m 0644 "$fabric_source/deploy/systemd/mncs-fabric-controller.service" \
  "$unit_root/mncs-fabric-controller.service"
if [[ ! -f $config_root/controller.env ]]; then
  install -m 0600 \
    "$fabric_source/deploy/systemd/mncs-fabric-controller.env.example" \
    "$config_root/controller.env"
fi

# The source-commit override is installer-owned provenance, not operator
# rendezvous configuration. Refresh only that key so a preserved env file
# cannot pin the service to an older same-version checkout.
if [[ -n ${fabric_revision:-} ]]; then
  if grep -q '^MNCS_FABRIC_SOURCE_COMMIT=' "$config_root/controller.env"; then
    sed -i "s/^MNCS_FABRIC_SOURCE_COMMIT=.*/MNCS_FABRIC_SOURCE_COMMIT=$fabric_revision/" \
      "$config_root/controller.env"
  else
    printf 'MNCS_FABRIC_SOURCE_COMMIT=%s\n' "$fabric_revision" >> "$config_root/controller.env"
  fi
else
  sed -i '/^MNCS_FABRIC_SOURCE_COMMIT=/d' "$config_root/controller.env"
fi
chmod 0600 "$config_root/controller.env"

systemctl --user daemon-reload
systemctl --user enable --now mncs-fabric-controller.service
systemctl --user restart mncs-fabric-controller.service
systemctl --user --no-pager status mncs-fabric-controller.service
