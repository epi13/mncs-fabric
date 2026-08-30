#!/usr/bin/env bash
set -euo pipefail

unit="$HOME/.config/systemd/user/mncs-fabric-controller.service"
systemctl --user disable --now mncs-fabric-controller.service 2>/dev/null || true
if [[ -f $unit ]]; then
  rm "$unit"
fi
systemctl --user daemon-reload
echo "Controller service removed. Fabric configuration and authoritative state were preserved."
echo "No worker membership was revoked; use 'mncs-fabric worker revoke' separately when intended."
