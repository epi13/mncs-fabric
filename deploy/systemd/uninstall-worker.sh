#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 WORKER_ID" >&2
  exit 2
fi
worker_id=$1
if [[ ! $worker_id =~ ^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$ ]]; then
  echo "worker identity is invalid" >&2
  exit 2
fi

unit="mncs-fabric-worker-rendezvous@$worker_id.service"
environment="$HOME/.config/mncs-fabric/workers/$worker_id.env"
systemctl --user disable --now "$unit" 2>/dev/null || true
if [[ -f $environment ]]; then
  retired="$environment.retired"
  if [[ -e $retired ]]; then
    echo "refusing to overwrite existing retired environment: $retired" >&2
    exit 1
  fi
  mv "$environment" "$retired"
fi
systemctl --user daemon-reload
echo "Worker service disabled and its installed environment retired."
echo "Private keys, worker ledgers, and installation identity were preserved."
echo "Controller membership was not revoked; revoke it explicitly from the controller if intended."
