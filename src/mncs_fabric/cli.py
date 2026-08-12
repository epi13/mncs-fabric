from __future__ import annotations

import argparse
from pathlib import Path

from .artifacts import build_manifest, verify_manifest
from .contracts import build_public_contract
from .errors import FabricError
from .enrollment import TrustStore
from .io import load_json, write_json
from .lifecycle import LifecycleStore, default_lifecycle_path
from .controller_service import ControllerConfig, ControllerService
from .api import FabricAdminClient, FabricClient
from .registry import RegistryWorker, WorkerRegistry
from .service import FabricService
from .transport import TLSWorkerServer
from .worker import LocalWorker
from . import __version__

_SERVICE = FabricService()


def _path(value: str) -> Path:
    return Path(value).expanduser()


def _duration(value: str) -> float:
    value = value.strip().lower()
    units = {"s": 1.0, "m": 60.0, "h": 3600.0, "d": 86400.0}
    if len(value) < 2 or value[-1] not in units:
        raise ValueError("duration must use a number followed by s, m, h, or d")
    try:
        amount = float(value[:-1])
    except ValueError as exc:
        raise ValueError("duration amount is invalid") from exc
    if amount <= 0:
        raise ValueError("duration must be positive")
    return amount * units[value[-1]]


def _metadata(values: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for value in values:
        if "=" not in value:
            raise ValueError("metadata must use KEY=VALUE")
        key, item = value.split("=", 1)
        result[key] = item
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mncs-fabric", description="Bounded execution and evidence primitives for MNCS")
    sub = parser.add_subparsers(dest="command", required=True)

    node = sub.add_parser("node", help="inspect a local node")
    node_sub = node.add_subparsers(dest="node_command", required=True)
    inspect = node_sub.add_parser("inspect", help="emit local node capabilities")
    inspect.add_argument("--label", required=True)
    inspect.add_argument("--output", type=_path)

    artifacts = sub.add_parser("artifacts", help="create or verify artifact manifests")
    artifacts_sub = artifacts.add_subparsers(dest="artifacts_command", required=True)
    create = artifacts_sub.add_parser("create", help="create a deterministic manifest")
    create.add_argument("root", type=_path)
    create.add_argument("--output", type=_path)
    verify = artifacts_sub.add_parser("verify", help="verify a bundle against a manifest")
    verify.add_argument("root", type=_path)
    verify.add_argument("manifest", type=_path)

    bundle = sub.add_parser("bundle", help="verify MNCS experimental immutable execution bundles")
    bundle_sub = bundle.add_subparsers(dest="bundle_command", required=True)
    bundle_verify = bundle_sub.add_parser("verify", help="verify a bundle archive without extraction")
    bundle_verify.add_argument("archive", type=_path)
    bundle_verify.add_argument("--expected-bundle-identity")
    bundle_verify.add_argument("--expected-archive-identity")
    bundle_verify.add_argument("--output", type=_path)

    plan = sub.add_parser("plan", help="validate a job plan")
    plan_sub = plan.add_subparsers(dest="plan_command", required=True)
    validate = plan_sub.add_parser("validate", help="validate and identify a job plan")
    validate.add_argument("plan", type=_path)
    validate.add_argument("--output", type=_path)

    run = sub.add_parser("run", help="execute a declared job")
    run_sub = run.add_subparsers(dest="run_command", required=True)
    local = run_sub.add_parser("local", help="execute on the current machine")
    local.add_argument("plan", type=_path)
    local.add_argument("--root", type=_path, required=True)
    local.add_argument("--manifest", type=_path, required=True)
    local.add_argument("--label", required=True)
    local.add_argument("--output", type=_path)
    local.add_argument("--results-dir", type=_path)
    local.add_argument("--work-root", type=_path)

    record = sub.add_parser("record", help="verify an execution or cohort record")
    record_sub = record.add_subparsers(dest="record_command", required=True)
    record_verify = record_sub.add_parser("verify", help="verify a record's self-identity")
    record_verify.add_argument("record", type=_path)

    reconcile = sub.add_parser("reconcile", help="reconcile execution records")
    reconcile.add_argument("records", nargs="+", type=_path)
    reconcile.add_argument("--output", type=_path)
    reconcile.add_argument("--allow-repeated-node", action="store_true")

    worker = sub.add_parser("worker", help="serve a worker endpoint explicitly")
    worker_sub = worker.add_subparsers(dest="worker_command", required=True)
    serve = worker_sub.add_parser("serve", help="serve bounded mutually-authenticated TLS requests")
    serve.add_argument("--worker-id", required=True)
    serve.add_argument("--controller-id", required=True)
    serve.add_argument("--bundle-root", type=_path, required=True)
    serve.add_argument("--state", type=_path, required=True)
    serve.add_argument("--trust-state", type=_path, required=True)
    serve.add_argument("--ca", type=_path, required=True)
    serve.add_argument("--certificate", type=_path, required=True)
    serve.add_argument("--key", type=_path, required=True)
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, required=True)
    serve.add_argument("--timeout", type=float, default=5.0)
    serve.add_argument("--max-requests", type=int, default=1, help="stop after this many accepted requests; default: one")
    serve.add_argument("--idle-timeout", type=float, help="stop cleanly after this many idle seconds")
    serve.add_argument("--max-concurrent-connections", type=int, default=1)
    serve.add_argument("--graceful-shutdown-timeout", type=float, default=5.0)
    serve.add_argument("--bundle-cache", type=_path, help="immutable EA-NEXT-002 bundle cache for native transfer")

    contract = sub.add_parser("contract", help="inspect the installed public consumer contract")
    contract_sub = contract.add_subparsers(dest="contract_command", required=True)
    contract_show = contract_sub.add_parser("show", help="emit the versioned public contract")
    contract_show.add_argument("--json", action="store_true", help="retain machine-readable JSON output")
    contract_show.add_argument("--output", type=_path)

    registry = sub.add_parser("registry", help="manage the operator-owned worker catalog")
    registry_sub = registry.add_subparsers(dest="registry_command", required=True)
    registry_list = registry_sub.add_parser("list", help="list known workers without trust paths")
    registry_list.add_argument("path", type=_path)
    registry_validate = registry_sub.add_parser("validate", help="validate structure and trust references")
    registry_validate.add_argument("path", type=_path)
    registry_register = registry_sub.add_parser("register", help="register one explicit enrolled endpoint")
    registry_register.add_argument("path", type=_path)
    registry_register.add_argument("--controller-id", required=True)
    registry_register.add_argument("--worker-id", required=True)
    registry_register.add_argument("--host", required=True)
    registry_register.add_argument("--port", type=int, required=True)
    registry_register.add_argument("--capability", action="append", default=["python"])
    registry_register.add_argument("--ca", type=_path, required=True)
    registry_register.add_argument("--certificate", type=_path, required=True)
    registry_register.add_argument("--key", type=_path, required=True)
    registry_register.add_argument("--trust-state", type=_path, required=True)
    registry_register.add_argument("--concurrency-limit", type=int, default=1)
    registry_register.add_argument("--timeout", type=float, default=5.0)
    registry_register.add_argument("--connect-timeout", type=float)
    registry_register.add_argument("--control-timeout", type=float)
    registry_register.add_argument("--execution-timeout-overhead", type=float, default=5.0)
    registry_register.add_argument("--label", action="append", default=[])
    registry_remove = registry_sub.add_parser("remove", help="remove one known endpoint")
    registry_remove.add_argument("path", type=_path)
    registry_remove.add_argument("worker_id")

    enrollment = sub.add_parser("enrollment", help="manage explicit worker enrollment lifecycle")
    enrollment_sub = enrollment.add_subparsers(dest="enrollment_command", required=True)
    enrollment_create = enrollment_sub.add_parser("create", help="create a one-time enrollment authorization")
    enrollment_create.add_argument("--ttl", default="10m")
    enrollment_create.add_argument("--worker-id")
    enrollment_create.add_argument("--metadata", action="append", default=[])
    enrollment_create.add_argument("--json", action="store_true")
    enrollment_list = enrollment_sub.add_parser("list", help="list redacted authorizations")
    enrollment_list.add_argument("--json", action="store_true")
    enrollment_pending = enrollment_sub.add_parser("pending", help="list pending enrollment requests")
    enrollment_pending.add_argument("--json", action="store_true")
    enrollment_inspect = enrollment_sub.add_parser("inspect", help="inspect one enrollment request")
    enrollment_inspect.add_argument("request_id")
    enrollment_inspect.add_argument("--json", action="store_true")
    enrollment_request = enrollment_sub.add_parser("request", help="submit a bounded local enrollment request")
    enrollment_request.add_argument("--token", required=True)
    enrollment_request.add_argument("--worker-id", required=True)
    enrollment_request.add_argument("--public-key", type=_path, required=True)
    enrollment_request.add_argument("--hostname", required=True)
    enrollment_request.add_argument("--os", dest="operating_system", required=True)
    enrollment_request.add_argument("--architecture", required=True)
    enrollment_request.add_argument("--authorization-id", required=True)
    enrollment_request.add_argument("--metadata", action="append", default=[])
    enrollment_request.add_argument("--json", action="store_true")
    enrollment_approve = enrollment_sub.add_parser("approve", help="approve one exact enrollment request")
    enrollment_approve.add_argument("request_id")
    enrollment_approve.add_argument("--worker-id")
    enrollment_approve.add_argument("--json", action="store_true")
    enrollment_deny = enrollment_sub.add_parser("deny", help="deny one enrollment request")
    enrollment_deny.add_argument("request_id")
    enrollment_deny.add_argument("--reason", default="operator denied enrollment")
    enrollment_deny.add_argument("--json", action="store_true")
    enrollment_expire = enrollment_sub.add_parser("expire", help="record an expired enrollment request")
    enrollment_expire.add_argument("request_id")
    enrollment_expire.add_argument("--json", action="store_true")
    for enrollment_command in (enrollment_create, enrollment_list, enrollment_pending, enrollment_inspect, enrollment_request, enrollment_approve, enrollment_deny, enrollment_expire):
        enrollment_command.add_argument("--state", type=_path, default=default_lifecycle_path())
        enrollment_command.add_argument("--admin-socket", type=_path, help="use the persistent controller operator socket")

    fleet = sub.add_parser("fleet", help="inspect durable fleet membership and current presence")
    fleet_sub = fleet.add_subparsers(dest="fleet_command", required=True)
    fleet_list = fleet_sub.add_parser("list", help="list fleet members")
    fleet_list.add_argument("--json", action="store_true")
    fleet_status = fleet_sub.add_parser("status", help="show one member and current presence")
    fleet_status.add_argument("worker_id")
    fleet_status.add_argument("--json", action="store_true")
    fleet_doctor = fleet_sub.add_parser("doctor", help="verify lifecycle durability and status")
    fleet_doctor.add_argument("--json", action="store_true")
    for fleet_command in (fleet_list, fleet_status, fleet_doctor):
        fleet_command.add_argument("--state", type=_path, default=default_lifecycle_path())
        fleet_command.add_argument("--socket", type=_path, help="use the persistent controller consumer socket")
        fleet_command.add_argument("--admin-socket", type=_path, help="use the persistent controller operator socket")

    worker_revoke = worker_sub.add_parser("revoke", help="revoke durable fleet membership")
    worker_revoke.add_argument("worker_id")
    worker_revoke.add_argument("--state", type=_path, default=default_lifecycle_path())
    worker_revoke.add_argument("--reason", required=True)
    worker_revoke.add_argument("--json", action="store_true")
    worker_status = worker_sub.add_parser("status", help="show durable worker lifecycle status")
    worker_status.add_argument("worker_id")
    worker_status.add_argument("--state", type=_path, default=default_lifecycle_path())
    worker_status.add_argument("--json", action="store_true")
    worker_status.add_argument("--socket", type=_path, help="use the persistent controller consumer socket")
    worker_doctor = worker_sub.add_parser("doctor", help="verify worker lifecycle state")
    worker_doctor.add_argument("--state", type=_path, default=default_lifecycle_path())
    worker_doctor.add_argument("--json", action="store_true")
    worker_doctor.add_argument("--socket", type=_path, help="use the persistent controller consumer socket")
    worker_revoke.add_argument("--admin-socket", type=_path, help="use the persistent controller operator socket")

    controller = sub.add_parser("controller", help="inspect or run the persistent Fabric controller foundation")
    controller.add_argument("--controller-id", default="local")
    controller_sub = controller.add_subparsers(dest="controller_command", required=True)
    controller_status = controller_sub.add_parser("status", help="inspect controller and lifecycle health")
    controller_status.add_argument("--json", action="store_true")
    controller_status.add_argument("--socket", type=_path, help="query an already-running controller")
    controller_doctor = controller_sub.add_parser("doctor", help="run controller durability checks")
    controller_doctor.add_argument("--json", action="store_true")
    controller_doctor.add_argument("--socket", type=_path, help="query an already-running controller")
    controller_service = controller_sub.add_parser("service", help="run the foreground controller service")
    controller_service_sub = controller_service.add_subparsers(dest="service_command", required=True)
    controller_run = controller_service_sub.add_parser("run", help="run until SIGTERM/SIGINT or a bounded test deadline")
    controller_run.add_argument("--max-seconds", type=float)
    controller_run.add_argument("--json", action="store_true")
    controller_status.add_argument("--state", type=_path, default=default_lifecycle_path())
    controller_doctor.add_argument("--state", type=_path, default=default_lifecycle_path())
    controller_run.add_argument("--state", type=_path, default=default_lifecycle_path())
    controller_run.add_argument("--registry", type=_path, help="controller-owned enrolled worker endpoint registry")
    controller_run.add_argument("--worker-state", type=_path, help="controller-owned worker transport ledger")
    controller_run.add_argument("--execution-bundle-root", type=_path, help="allowed root for verified consumer bundles")
    return parser


def _registry_worker(args: argparse.Namespace) -> RegistryWorker:
    labels: list[tuple[str, str]] = []
    for item in args.label:
        if "=" not in item:
            raise ValueError("registry labels must use KEY=VALUE")
        key, value = item.split("=", 1)
        labels.append((key, value))
    return RegistryWorker(
        worker_id=args.worker_id,
        host=args.host,
        port=args.port,
        capabilities=tuple(dict.fromkeys(args.capability)),
        ca_file=str(args.ca),
        client_certificate=str(args.certificate),
        client_key=str(args.key),
        trust_state=str(args.trust_state),
        concurrency_limit=args.concurrency_limit,
        timeout=args.timeout,
        connect_timeout=args.connect_timeout,
        control_timeout=args.control_timeout,
        execution_timeout_overhead=args.execution_timeout_overhead,
        labels=tuple(sorted(labels)),
    )


def _status_code(outcome: str) -> int:
    return 0 if outcome == "PASS" else 1 if outcome == "FAIL" else 2


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "node":
            write_json(args.output, _SERVICE.nodes(args.label))
            return 0
        if args.command == "contract" and args.contract_command == "show":
            write_json(args.output, build_public_contract(__version__))
            return 0
        if args.command == "registry":
            if args.registry_command == "list":
                registry = WorkerRegistry(args.path)
                write_json(
                    None,
                    {
                        "outcome": "PASS",
                        "workers": [worker.public_dict() for worker in registry.load()],
                    },
                )
                return 0
            if args.registry_command == "validate":
                result = WorkerRegistry(args.path).validate()
                write_json(None, result)
                return _status_code(result["outcome"])
            if args.registry_command == "register":
                result = WorkerRegistry(args.path, args.controller_id).register(
                    _registry_worker(args)
                )
                write_json(None, result)
                return 0
            if args.registry_command == "remove":
                result = WorkerRegistry(args.path).remove(args.worker_id)
                write_json(None, result)
                return 0
        if args.command == "enrollment":
            if args.admin_socket and args.enrollment_command != "request":
                admin = FabricAdminClient.connect(args.admin_socket)
                if args.enrollment_command == "create":
                    result = admin.create_enrollment_authorization(ttl_seconds=_duration(args.ttl), expected_worker_identity=args.worker_id, metadata=_metadata(args.metadata))
                elif args.enrollment_command == "list":
                    result = {"outcome": "PASS", "authorizations": admin.enrollment_authorizations()}
                elif args.enrollment_command == "pending":
                    result = {"outcome": "PASS", "requests": admin.enrollment_pending()}
                elif args.enrollment_command == "inspect":
                    result = admin.enrollment_request(args.request_id)
                elif args.enrollment_command == "approve":
                    result = admin.approve_enrollment(args.request_id, worker_id=args.worker_id)
                elif args.enrollment_command == "deny":
                    result = admin.deny_enrollment(args.request_id, reason=args.reason)
                elif args.enrollment_command == "expire":
                    result = admin.expire_enrollment(args.request_id)
                else:
                    raise AssertionError("unreachable service enrollment command")
                admin.close()
                write_json(None, result)
                return _status_code(result.get("outcome", "PASS"))
            lifecycle = LifecycleStore(args.state)
            if args.enrollment_command == "create":
                result = lifecycle.create_authorization(ttl_seconds=_duration(args.ttl), expected_worker_identity=args.worker_id, metadata=_metadata(args.metadata))
            elif args.enrollment_command == "list":
                result = {"outcome": "PASS", "authorizations": lifecycle.list_authorizations()}
            elif args.enrollment_command == "pending":
                result = {"outcome": "PASS", "requests": lifecycle.pending_requests()}
            elif args.enrollment_command == "inspect":
                result = lifecycle.request(args.request_id)
            elif args.enrollment_command == "request":
                request = lifecycle.build_request(
                    worker_identity=args.worker_id,
                    public_key_pem=args.public_key.read_text(encoding="ascii"),
                    hostname_hint=args.hostname,
                    operating_system=args.operating_system,
                    architecture=args.architecture,
                    authorization_id=args.authorization_id,
                    metadata=_metadata(args.metadata),
                )
                result = lifecycle.submit_request(request, args.token)
            elif args.enrollment_command == "approve":
                result = lifecycle.approve_request(args.request_id, worker_id=args.worker_id)
            elif args.enrollment_command == "deny":
                result = lifecycle.deny_request(args.request_id, reason=args.reason)
            elif args.enrollment_command == "expire":
                result = lifecycle.expire_request(args.request_id)
            else:
                raise AssertionError("unreachable enrollment command")
            write_json(None, result)
            return 0
        if args.command == "fleet":
            if args.fleet_command == "doctor" and args.admin_socket:
                admin = FabricAdminClient.connect(args.admin_socket)
                result = admin.fleet_doctor()
                admin.close()
                write_json(None, result)
                return _status_code(result.get("outcome", "PASS"))
            if args.socket:
                client = FabricClient.connect(args.socket)
                if args.fleet_command == "list":
                    result = {"outcome": "PASS", "workers": client.fleet()}
                elif args.fleet_command == "status":
                    result = client.fleet_status(args.worker_id)
                elif args.fleet_command == "doctor":
                    result = client.fleet_doctor()
                else:
                    raise AssertionError("unreachable service fleet command")
                client.close()
                write_json(None, result)
                return _status_code(result.get("outcome", "PASS"))
            lifecycle = LifecycleStore(args.state)
            if args.fleet_command == "list":
                result = {"outcome": "PASS", "workers": lifecycle.memberships()}
            elif args.fleet_command == "status":
                result = lifecycle.membership(args.worker_id)
            elif args.fleet_command == "doctor":
                result = lifecycle.doctor()
            else:
                raise AssertionError("unreachable fleet command")
            write_json(None, result)
            return _status_code(result.get("outcome", "PASS"))
        if args.command == "worker" and args.worker_command in {"revoke", "status", "doctor"}:
            if args.worker_command == "revoke" and args.admin_socket:
                admin = FabricAdminClient.connect(args.admin_socket)
                result = admin.revoke_worker(args.worker_id, reason=args.reason)
                admin.close()
                write_json(None, result)
                return _status_code(result.get("outcome", "PASS"))
            if args.worker_command in {"status", "doctor"} and args.socket:
                client = FabricClient.connect(args.socket)
                result = client.fleet_status(args.worker_id) if args.worker_command == "status" else client.fleet_doctor()
                client.close()
                write_json(None, result)
                return _status_code(result.get("outcome", "PASS"))
            lifecycle = LifecycleStore(args.state)
            if args.worker_command == "revoke":
                result = lifecycle.revoke_worker(args.worker_id, reason=args.reason)
            elif args.worker_command == "status":
                result = lifecycle.membership(args.worker_id)
            else:
                result = lifecycle.doctor()
            write_json(None, result)
            return _status_code(result.get("outcome", "PASS"))
        if args.command == "controller":
            if args.controller_command in {"status", "doctor"} and args.socket:
                client = FabricClient.connect(args.socket)
                result = client.controller_status() if args.controller_command == "status" else client.controller_doctor()
                client.close()
                write_json(None, result)
                return _status_code(result.get("outcome", "PASS"))
            service = ControllerService(ControllerConfig(args.controller_id, args.state, worker_registry_path=getattr(args, "registry", None), worker_state_path=getattr(args, "worker_state", None), execution_bundle_root=getattr(args, "execution_bundle_root", None)))
            if args.controller_command == "status":
                result = service.status()
            elif args.controller_command == "doctor":
                result = service.doctor()
            elif args.controller_command == "service" and args.service_command == "run":
                result = service.run(max_seconds=args.max_seconds)
            else:
                raise AssertionError("unreachable controller command")
            write_json(None, result)
            return _status_code(result.get("outcome", "PASS"))
        if args.command == "artifacts" and args.artifacts_command == "create":
            write_json(args.output, build_manifest(args.root))
            return 0
        if args.command == "artifacts" and args.artifacts_command == "verify":
            manifest = verify_manifest(args.root, load_json(args.manifest))
            write_json(None, {"outcome": "PASS", "manifest_identity": manifest["manifest_identity"]})
            return 0
        if args.command == "bundle" and args.bundle_command == "verify":
            result = _SERVICE.verify_execution_bundle(args.archive, expected_bundle_identity=args.expected_bundle_identity, expected_archive_identity=args.expected_archive_identity)
            write_json(args.output, result)
            return _status_code(result["category"])
        if args.command == "plan":
            write_json(args.output, _SERVICE.validate_plan(load_json(args.plan)))
            return 0
        if args.command == "run":
            record = _SERVICE.execute_local(
                load_json(args.plan), args.root, load_json(args.manifest), args.label,
                results_dir=args.results_dir, work_root=args.work_root,
            )
            write_json(args.output, record)
            return _status_code(record["outcome"])
        if args.command == "record":
            value = load_json(args.record)
            result = _SERVICE.verify_record(value)
            write_json(None, result)
            return _status_code(result["outcome"])
        if args.command == "reconcile":
            cohort = _SERVICE.reconcile([load_json(path) for path in args.records], require_distinct_nodes=not args.allow_repeated_node)
            write_json(args.output, cohort)
            return _status_code(cohort["outcome"])
        if args.command == "worker" and args.worker_command == "serve":
            worker_service = LocalWorker(args.worker_id, args.bundle_root, args.state, bundle_cache_root=args.bundle_cache)
            endpoint = TLSWorkerServer(worker_service, args.host, args.port, ca_file=args.ca, server_cert=args.certificate, server_key=args.key, controller_id=args.controller_id, worker_id=args.worker_id, trust_store=TrustStore(args.trust_state), timeout=args.timeout)
            if args.max_requests == 1 and args.idle_timeout is None and args.max_concurrent_connections == 1:
                endpoint.serve_once()
            else:
                endpoint.serve_forever(max_requests=args.max_requests, idle_timeout=args.idle_timeout, max_concurrent_connections=args.max_concurrent_connections, graceful_shutdown_timeout=args.graceful_shutdown_timeout)
            result = {"outcome": "PASS" if endpoint.last_error is None else "UNKNOWN", "worker_id": args.worker_id, "host": args.host, "port": args.port, "requests": endpoint.handled_requests, "max_requests": args.max_requests, "diagnostic": endpoint.last_error}
            write_json(None, result)
            return _status_code(result["outcome"])
        raise AssertionError("unreachable command")
    except (FabricError, OSError, ValueError) as exc:
        write_json(None, {"outcome": "UNKNOWN", "error": str(exc)})
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
