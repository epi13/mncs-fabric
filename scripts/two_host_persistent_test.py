#!/usr/bin/env python3
"""Run a bounded persistent direct Fabric test against one Fedora worker.

SSH is limited to preflight, exact-revision/bootstrap staging, trust-state
rotation, diagnostics, and stopping the bounded worker. Candidate execution
and all request/reply evidence use direct Fabric mTLS.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import ssl
import time
from datetime import datetime, timezone
from pathlib import Path

from two_host_fedora_test import (
    ROOT,
    Remote,
    _build_transport,
    _cert_fingerprint,
    _fingerprint_record,
    _remote_node,
    _run,
    _shell_quote,
    _start_worker,
    _stop_worker,
    _write_pki,
)

from mncs_fabric.artifacts import verify_manifest
from mncs_fabric.canonical import sha256_identity
from mncs_fabric.challenges import ChallengeReplayStore, issue_execution_challenge
from mncs_fabric.controller import NetworkController
from mncs_fabric.enrollment import TrustStore
from mncs_fabric.errors import FabricError, ProtocolError
from mncs_fabric.io import load_json, write_json
from mncs_fabric.models import validate_job_plan
from mncs_fabric.node import capability_names
from mncs_fabric.receipts import execution_policy_identity_for_plan
from mncs_fabric.service import FabricService


def _issue_challenge(controller_id: str, plan: dict[str, object], manifest: dict[str, object], worker_id: str) -> dict[str, object]:
    scope = {
        "subject_identity": plan["candidate_identity"][7:],
        "candidate_id": "candidate-" + plan["candidate_identity"][7:],
        "bundle_identity": manifest["manifest_identity"][7:],
        "execution_policy_identity": execution_policy_identity_for_plan(plan),
        "runner_identity": f"mncs-fabric-worker-{worker_id}",
    }
    report = issue_execution_challenge(issuer_identity=controller_id, scope=scope, ttl_seconds=300)
    if not report.valid or report.challenge is None:
        raise RuntimeError("could not issue persistent-run challenge: " + "; ".join(report.issues))
    return report.challenge


def run_experiment(args: argparse.Namespace) -> dict[str, object]:
    output = Path(args.output).resolve()
    if output.exists() and any(output.iterdir()):
        raise RuntimeError(f"output directory must be new and empty: {output}")
    output.mkdir(parents=True, exist_ok=True)
    (output / "pki").mkdir(mode=0o700, exist_ok=True)
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    remote = Remote(host=args.ssh_host, user=args.ssh_user, key=Path(args.ssh_key).expanduser())
    preflight = remote.ssh("hostname; id -un; python3 --version; uname -a")
    observed_hostname = preflight.splitlines()[0].strip()
    if observed_hostname != args.expected_hostname:
        raise RuntimeError(f"remote hostname mismatch: expected {args.expected_hostname!r}, observed {observed_hostname!r}")
    remote_home = remote.ssh("printf %s \"$HOME\"").strip()
    if not remote_home.startswith("/") or any(character in remote_home for character in "\n\r\x00"):
        raise RuntimeError("remote home path was not an absolute safe path")
    remote_root = f"{remote_home}/mncs-fabric-worker/runs/{run_id}"

    pki = _write_pki(output / "pki")
    worker_trust = TrustStore(output / "worker-trust.jsonl")
    worker_trust.enroll("controller", args.controller_id, _cert_fingerprint(pki["controller"]), metadata={"experiment": "persistent-two-host"})
    archive = output / "fabric-source.tar.gz"
    _run(["git", "archive", "--format=tar.gz", "--output", str(archive), "HEAD"], cwd=ROOT)
    fabric_commit = _run(["git", "rev-parse", "HEAD"], cwd=ROOT).strip()
    source_archive_identity = "sha256:" + hashlib.sha256(archive.read_bytes()).hexdigest()
    revision_file = output / "fabric-revision.txt"
    revision_file.write_text(fabric_commit + "\n", encoding="ascii")

    remote.ssh(f"mkdir -p {_shell_quote(remote_root + '/repo')} {_shell_quote(remote_root + '/state')} {_shell_quote(remote_root + '/trust')} {_shell_quote(remote_root + '/certs')} {_shell_quote(remote_root + '/logs')} {_shell_quote(remote_root + '/results')}")
    remote.scp_to(archive, remote_root + "/source.tar.gz")
    remote.scp_to(revision_file, remote_root + "/fabric-revision.txt")
    for key in ("ca", "worker", "worker_key"):
        remote.scp_to(pki[key], remote_root + "/certs/" + pki[key].name)
    remote.scp_to(output / "worker-trust.jsonl", remote_root + "/trust/worker-trust.jsonl")
    remote.ssh(f"chmod 700 {_shell_quote(remote_root + '/certs')} {_shell_quote(remote_root + '/trust')} {_shell_quote(remote_root + '/state')} {_shell_quote(remote_root + '/logs')} {_shell_quote(remote_root + '/results')} && chmod 600 {_shell_quote(remote_root + '/certs/worker.key')} {_shell_quote(remote_root + '/trust/worker-trust.jsonl')}")
    remote.ssh(f"tar -xzf {_shell_quote(remote_root + '/source.tar.gz')} -C {_shell_quote(remote_root + '/repo')} && python3 -m venv --system-site-packages {_shell_quote(remote_root + '/venv')} && {_shell_quote(remote_root + '/venv/bin/python')} -m pip install --no-deps --no-build-isolation {_shell_quote(remote_root + '/repo')} >/dev/null")
    if remote.ssh(f"sha256sum {_shell_quote(remote_root + '/source.tar.gz')}").split()[0] != source_archive_identity[7:]:
        raise RuntimeError("remote source archive identity differs from controller archive")
    if remote.ssh(f"cat {_shell_quote(remote_root + '/fabric-revision.txt')}").strip() != fabric_commit:
        raise RuntimeError("remote Fabric revision marker differs from controller revision")

    bundle_root = ROOT / "examples/portable-python/bundle"
    manifest = verify_manifest(bundle_root, load_json(ROOT / "examples/portable-python/artifact-manifest.json"))
    plan = validate_job_plan(load_json(ROOT / "examples/portable-python/job-plan.json"))
    node = _remote_node(remote, remote_root, args.worker_id)
    transport, controller_trust = _build_transport(output=output, worker_id=args.worker_id, host=args.worker_host, port=args.worker_port, pki=pki)
    controller = NetworkController(args.controller_id, output / "controller-ledger.jsonl")
    controller.register_remote(args.worker_id, frozenset(capability_names(node)), transport)
    replay_store = ChallengeReplayStore(output / "challenge-replay.jsonl")
    requests: list[dict[str, object]] = []
    pid: int | None = None
    try:
        pid = _start_worker(remote, remote_root, worker_id=args.worker_id, controller_id=args.controller_id, host=args.worker_host, port=args.worker_port, max_requests=7, idle_timeout=30)
        request_ids = [f"persistent-{index}" for index in range(1, 4)]
        challenges: dict[str, dict[str, object]] = {}
        for request_id in request_ids:
            challenge = _issue_challenge(args.controller_id, plan, manifest, args.worker_id)
            challenges[request_id] = challenge
            started = time.perf_counter()
            response = controller.dispatch_via(transport, plan, manifest, worker_id=args.worker_id, request_id=request_id, challenge=challenge)
            elapsed = time.perf_counter() - started
            receipt = response["payload"].get("receipt")
            replay = replay_store.consume(challenge, receipt)
            if not replay.valid or replay.replay_receipt is None:
                raise RuntimeError("persistent challenge replay consumption failed")
            requests.append({"request_id": request_id, "disposition": response["payload"].get("disposition"), "record_id": response["payload"]["record"]["record_id"], "receipt_identity": receipt["receipt_identity"], "challenge_identity": challenge["challenge_identity"], "replay_identity": replay.replay_receipt["replay_identity"], "round_trip_seconds": round(elapsed, 6)})

        duplicate_started = time.perf_counter()
        duplicate = controller.dispatch_via(transport, plan, manifest, worker_id=args.worker_id, request_id="persistent-3", challenge=challenges["persistent-3"])
        requests.append({"request_id": "persistent-3", "disposition": duplicate["payload"].get("disposition"), "record_id": duplicate["payload"]["record"]["record_id"], "round_trip_seconds": round(time.perf_counter() - duplicate_started, 6)})

        changed = copy.deepcopy(plan)
        changed["candidate_identity"] = "sha256:" + "b" * 64
        changed = validate_job_plan(changed)
        conflicting = controller.dispatch_via(transport, changed, manifest, worker_id=args.worker_id, request_id="persistent-3", challenge=challenges["persistent-3"])
        requests.append({"request_id": "persistent-3", "disposition": conflicting["payload"].get("disposition")})

        fresh_challenge = _issue_challenge(args.controller_id, plan, manifest, args.worker_id)
        fresh_started = time.perf_counter()
        fresh = controller.dispatch_via(transport, plan, manifest, worker_id=args.worker_id, request_id="persistent-4", challenge=fresh_challenge)
        fresh_receipt = fresh["payload"].get("receipt")
        fresh_replay = replay_store.consume(fresh_challenge, fresh_receipt)
        if not fresh_replay.valid or fresh_replay.replay_receipt is None:
            raise RuntimeError("fresh persistent challenge replay consumption failed")
        requests.append({"request_id": "persistent-4", "disposition": fresh["payload"].get("disposition"), "record_id": fresh["payload"]["record"]["record_id"], "receipt_identity": fresh_receipt["receipt_identity"], "challenge_identity": fresh_challenge["challenge_identity"], "replay_identity": fresh_replay.replay_receipt["replay_identity"], "round_trip_seconds": round(time.perf_counter() - fresh_started, 6)})

        process_identity = remote.ssh(f"ps -o pid= -p {pid} 2>/dev/null || true").strip()
        pid_stable = process_identity == str(pid)

        # Rotate the worker's controller trust state while its listener stays
        # alive. The replacement ledger is staged atomically by this bounded
        # harness; the worker reads it on the next authorization attempt.
        revoked_trust = TrustStore(output / "worker-trust-revoked.jsonl")
        revoked_trust.enroll("controller", args.controller_id, _cert_fingerprint(pki["controller"]), metadata={"experiment": "persistent-two-host"})
        revoked_trust.revoke("controller", args.controller_id, reason="persistent-between-request-test")
        remote.scp_to(output / "worker-trust-revoked.jsonl", remote_root + "/trust/worker-trust-revoked.jsonl")
        remote.ssh(f"chmod 600 {_shell_quote(remote_root + '/trust/worker-trust-revoked.jsonl')} && mv {_shell_quote(remote_root + '/trust/worker-trust-revoked.jsonl')} {_shell_quote(remote_root + '/trust/worker-trust.jsonl')}")
        try:
            controller.dispatch_via(transport, plan, manifest, worker_id=args.worker_id, request_id="persistent-revoked")
            revoked_disposition = "UNEXPECTED_ACCEPT"
        except (FabricError, OSError, TimeoutError, ProtocolError) as exc:
            revoked_disposition = {"disposition": "FAIL_CLOSED", "diagnostic": type(exc).__name__}
    finally:
        _stop_worker(remote, remote_root, pid)

    local_service = FabricService()
    local_record = local_service.execute_local(plan, bundle_root, manifest, args.controller_id, results_dir=output / "local-results")
    remote_record = fresh["payload"]["record"]
    cohort = local_service.reconcile([local_record, remote_record], require_distinct_nodes=True)
    evidence = {
        "schema_version": "mncs-fabric.persistent-two-host.v0.1",
        "record_type": "mncs-fabric.persistent-two-host",
        "experiment_id": f"persistent-two-host-{run_id}",
        "controller_fabric_commit": fabric_commit,
        "worker_fabric_commit": fabric_commit,
        "worker_fabric_source_archive_identity": source_archive_identity,
        "direct_fabric_tls": True,
        "ssh_tunnel_used": False,
        "bootstrap_material_staged_by_ssh": True,
        "persistent_service": {"max_requests": 7, "idle_timeout_seconds": 30, "max_concurrent_connections": 1, "pid_stable": pid_stable},
        "controller_identity": args.controller_id,
        "worker_identity": args.worker_id,
        "worker_hostname": observed_hostname,
        "node_records": {"controller": _fingerprint_record(local_record["node"]), "worker": _fingerprint_record(remote_record["node"])},
        "execution": {"job_identity": remote_record["job_identity"], "candidate_identity": remote_record["candidate_identity"], "artifact_manifest_identity": remote_record["artifact_manifest_identity"], "worker_record_id": remote_record["record_id"], "result_identities": [entry["sha256"] for entry in remote_record.get("results", [])], "cohort_id": cohort["cohort_id"], "cohort_outcome": cohort["outcome"]},
        "requests": requests,
        "adversarial": {"duplicate_request": requests[3]["disposition"], "conflicting_replay": requests[4]["disposition"], "revoked_controller_between_requests": revoked_disposition},
        "claim_boundary": "operator-controlled development evidence; persistent direct mTLS observations only; no sandbox, correctness, custody, independence, conformance, or certification claim",
        "limitations": ["EA-NEXT-002 execution material was staged through SSH; native Fabric bundle transfer was not exercised.", "EA-NEXT-005 freshness and replay consumption remain in an operator-controlled local store.", "The two hosts share one operator trust domain."],
    }
    write_json(output / "persistent-experiment-evidence.json", evidence)
    return evidence


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run bounded persistent direct Fedora-to-Fedora Fabric requests")
    parser.add_argument("--ssh-host", required=True)
    parser.add_argument("--ssh-user", required=True)
    parser.add_argument("--ssh-key", required=True)
    parser.add_argument("--worker-host", required=True)
    parser.add_argument("--worker-port", type=int, default=7443)
    parser.add_argument("--expected-hostname", required=True)
    parser.add_argument("--controller-id", default="fabric-controller-01")
    parser.add_argument("--worker-id", default="fabric-worker-01")
    parser.add_argument("--output", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
        evidence = run_experiment(args)
        print(json.dumps({"outcome": evidence["execution"]["cohort_outcome"], "evidence": str(Path(args.output).resolve() / "persistent-experiment-evidence.json"), "direct_fabric_tls": evidence["direct_fabric_tls"], "pid_stable": evidence["persistent_service"]["pid_stable"], "adversarial": evidence["adversarial"]}, sort_keys=True, separators=(",", ":")))
        return 0 if evidence["execution"]["cohort_outcome"] == "PASS" else 2
    except (OSError, RuntimeError, ValueError, FabricError) as exc:
        print(json.dumps({"outcome": "UNKNOWN", "error": str(exc)}, sort_keys=True, separators=(",", ":")))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
