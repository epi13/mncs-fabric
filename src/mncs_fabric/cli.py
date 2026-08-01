from __future__ import annotations

import argparse
from pathlib import Path

from .artifacts import build_manifest, verify_manifest
from .canonical import verify_identity
from .errors import FabricError
from .executor import execute_local
from .io import load_json, write_json
from .models import COHORT_SCHEMA, EXECUTION_SCHEMA, validate_job_plan
from .node import collect_node_capabilities
from .reconcile import reconcile_records


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
    return parser


def _status_code(outcome: str) -> int:
    return 0 if outcome == "PASS" else 1 if outcome == "FAIL" else 2


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "node":
            write_json(args.output, collect_node_capabilities(args.label))
            return 0
        if args.command == "artifacts" and args.artifacts_command == "create":
            write_json(args.output, build_manifest(args.root))
            return 0
        if args.command == "artifacts" and args.artifacts_command == "verify":
            manifest = verify_manifest(args.root, load_json(args.manifest))
            write_json(None, {"outcome": "PASS", "manifest_identity": manifest["manifest_identity"]})
            return 0
        if args.command == "plan":
            write_json(args.output, validate_job_plan(load_json(args.plan)))
            return 0
        if args.command == "run":
            record = execute_local(
                load_json(args.plan), args.root, load_json(args.manifest), args.label,
                results_dir=args.results_dir, work_root=args.work_root,
            )
            write_json(args.output, record)
            return _status_code(record["outcome"])
        if args.command == "record":
            value = load_json(args.record)
            schema = value.get("schema_version") if isinstance(value, dict) else None
            field = "record_id" if schema == EXECUTION_SCHEMA else "cohort_id" if schema == COHORT_SCHEMA else None
            if field is None or not verify_identity(value, field):
                write_json(None, {"outcome": "FAIL", "reason": "record identity does not verify"})
                return 1
            write_json(None, {"outcome": "PASS", "identity": value[field]})
            return 0
        if args.command == "reconcile":
            cohort = reconcile_records([load_json(path) for path in args.records], require_distinct_nodes=not args.allow_repeated_node)
            write_json(args.output, cohort)
            return _status_code(cohort["outcome"])
        raise AssertionError("unreachable command")
    except (FabricError, OSError, ValueError) as exc:
        write_json(None, {"outcome": "UNKNOWN", "error": str(exc)})
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
