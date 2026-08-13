#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 WORKER_ID status|doctor|logs|restart|stop" >&2
  exit 2
fi

worker_id=$1
action=$2
if [[ ! $worker_id =~ ^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$ ]]; then
  echo "worker identity is invalid" >&2
  exit 2
fi
unit="mncs-fabric-worker-rendezvous@$worker_id.service"
case "$action" in
  status)
    systemctl --user --no-pager status "$unit"
    ;;
  doctor)
    systemctl --user is-enabled "$unit"
    systemctl --user is-active "$unit"
    "$HOME/.local/share/mncs-fabric/venv/bin/mncs-fabric" contract show --json
    ;;
  logs)
    journalctl --user --unit "$unit" --lines 100 --no-pager
    ;;
  restart)
    systemctl --user restart "$unit"
    ;;
  stop)
    systemctl --user stop "$unit"
    ;;
  *)
    echo "unknown action: $action" >&2
    exit 2
    ;;
esac
