from __future__ import annotations

import argparse
from pathlib import Path

from .artifacts import build_manifest, verify_manifest
from .canonical import verify_identity
from .errors import FabricError
from .enrollment import TrustStore
from .io import load_json, write_json
from .service import FabricService
from .transport import TLSWorkerServer
from .worker import LocalWorker

_SERVICE = FabricService()


def _path(value: str) -> Path:
    return Path(value).expanduser()


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
    serve = worker_sub.add_parser("serve", help="serve one bounded mutually-authenticated TLS request")
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
    return parser


def _status_code(outcome: str) -> int:
    return 0 if outcome == "PASS" else 1 if outcome == "FAIL" else 2


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "node":
            write_json(args.output, _SERVICE.nodes(args.label))
            return 0
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
            worker_service = LocalWorker(args.worker_id, args.bundle_root, args.state)
            endpoint = TLSWorkerServer(worker_service, args.host, args.port, ca_file=args.ca, server_cert=args.certificate, server_key=args.key, controller_id=args.controller_id, worker_id=args.worker_id, trust_store=TrustStore(args.trust_state), timeout=args.timeout)
            endpoint.serve_once()
            result = {"outcome": "PASS" if endpoint.last_error is None else "UNKNOWN", "worker_id": args.worker_id, "host": args.host, "port": args.port, "diagnostic": endpoint.last_error}
            write_json(None, result)
            return _status_code(result["outcome"])
        raise AssertionError("unreachable command")
    except (FabricError, OSError, ValueError) as exc:
        write_json(None, {"outcome": "UNKNOWN", "error": str(exc)})
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
