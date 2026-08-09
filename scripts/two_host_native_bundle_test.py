#!/usr/bin/env python3
"""Exercise the public Fabric API and native EA-NEXT-002 transfer on Fedora.

SSH stages only the Fabric source subset, trust material, and worker bootstrap.
The candidate execution bundle is transferred over Fabric mTLS and independently
verified by the worker before dispatch.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path

from two_host_fedora_test import ROOT, Remote, _cert_fingerprint, _remote_node, _run, _shell_quote, _start_worker, _stop_worker, _write_pki

from mncs_fabric.api import ConsumerContext, FabricClient, RemoteWorkerConfig, PlacementRequest
from mncs_fabric.artifacts import verify_manifest
from mncs_fabric.bundles import build_bundle_archive
from mncs_fabric.challenges import ChallengeReplayStore, issue_execution_challenge
from mncs_fabric.enrollment import TrustStore
from mncs_fabric.errors import FabricError, ProtocolError
from mncs_fabric.io import load_json, write_json
from mncs_fabric.models import validate_job_plan
from mncs_fabric.node import capability_names
from mncs_fabric.receipts import execution_policy_identity_for_plan
from mncs_fabric.worker import LocalWorker


def _challenge(controller_id: str, plan: dict[str, object], bundle_identity: str, worker_id: str) -> dict[str, object]:
    scope = {
        "subject_identity": plan["candidate_identity"][7:],
        "candidate_id": "candidate-" + plan["candidate_identity"][7:],
        "bundle_identity": bundle_identity,
        "execution_policy_identity": execution_policy_identity_for_plan(plan),
        "runner_identity": f"mncs-fabric-worker-{worker_id}",
    }
    report = issue_execution_challenge(issuer_identity=controller_id, scope=scope, ttl_seconds=300)
    if not report.valid or report.challenge is None:
        raise RuntimeError("could not issue native-transfer challenge")
    return report.challenge


def _remote_resources(remote: Remote, run_root: str, worker_id: str) -> dict[str, object]:
    code = "import json; from mncs_fabric.resources import capture_resource_snapshot; print(json.dumps(capture_resource_snapshot(" + json.dumps(worker_id) + "), sort_keys=True, separators=(\",\", \":\")))"
    output = remote.ssh(
        f"cd {_shell_quote(run_root + '/repo')} && "
        f"{_shell_quote(run_root + '/venv/bin/python')} -c "
        f"{_shell_quote(code)}"
    )
    value = json.loads(output)
    if not isinstance(value, dict) or value.get("worker_identity") != worker_id:
        raise RuntimeError("remote resource snapshot identity did not match the requested worker ID")
    return value


def run(args: argparse.Namespace) -> dict[str, object]:
    output = Path(args.output).resolve()
    if output.exists() and any(output.iterdir()):
        raise RuntimeError(f"output directory must be new and empty: {output}")
    output.mkdir(parents=True, exist_ok=True)
    (output / "pki").mkdir(mode=0o700)
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    remote = Remote(host=args.ssh_host, user=args.ssh_user, key=Path(args.ssh_key).expanduser())
    preflight = remote.ssh("hostname; id -un; python3 --version; uname -a")
    if preflight.splitlines()[0].strip() != args.expected_hostname:
        raise RuntimeError("remote hostname mismatch")
    remote_home = remote.ssh("printf %s \"$HOME\"").strip()
    remote_root = f"{remote_home}/mncs-fabric-worker/runs/{run_id}"

    pki = _write_pki(output / "pki")
    worker_trust = TrustStore(output / "worker-trust.jsonl")
    worker_trust.enroll("controller", args.controller_id, _cert_fingerprint(pki["controller"]), metadata={"experiment": "native-bundle-two-host"})
    source_archive = output / "fabric-source-subset.tar.gz"
    _run(["git", "archive", "--format=tar.gz", "--output", str(source_archive), "HEAD", "pyproject.toml", "src", "scripts/remote_worker_launcher.py"], cwd=ROOT)
    fabric_commit = _run(["git", "rev-parse", "HEAD"], cwd=ROOT).strip()
    source_archive_identity = "sha256:" + hashlib.sha256(source_archive.read_bytes()).hexdigest()
    remote.ssh(f"mkdir -p {_shell_quote(remote_root + '/repo')} {_shell_quote(remote_root + '/state')} {_shell_quote(remote_root + '/trust')} {_shell_quote(remote_root + '/certs')} {_shell_quote(remote_root + '/logs')} {_shell_quote(remote_root + '/empty-bundle')} {_shell_quote(remote_root + '/results')}")
    remote.scp_to(source_archive, remote_root + "/source.tar.gz")
    for key in ("ca", "worker", "worker_key"):
        remote.scp_to(pki[key], remote_root + "/certs/" + pki[key].name)
    remote.scp_to(output / "worker-trust.jsonl", remote_root + "/trust/worker-trust.jsonl")
    remote.ssh(f"chmod 700 {_shell_quote(remote_root + '/certs')} {_shell_quote(remote_root + '/trust')} {_shell_quote(remote_root + '/state')} {_shell_quote(remote_root + '/logs')} && chmod 600 {_shell_quote(remote_root + '/certs/worker.key')} {_shell_quote(remote_root + '/trust/worker-trust.jsonl')}")
    remote.ssh(f"tar -xzf {_shell_quote(remote_root + '/source.tar.gz')} -C {_shell_quote(remote_root + '/repo')} && python3 -m venv --system-site-packages {_shell_quote(remote_root + '/venv')} && {_shell_quote(remote_root + '/venv/bin/python')} -m pip install --no-deps --no-build-isolation {_shell_quote(remote_root + '/repo')} >/dev/null")
    if remote.ssh(f"sha256sum {_shell_quote(remote_root + '/source.tar.gz')}").split()[0] != source_archive_identity[7:]:
        raise RuntimeError("remote source subset identity differs")

    source_root = ROOT / "examples/portable-python/bundle"
    manifest = verify_manifest(source_root, load_json(ROOT / "examples/portable-python/artifact-manifest.json"))
    plan = validate_job_plan(load_json(ROOT / "examples/portable-python/job-plan.json"))
    archive = output / "execution-bundle.zip"
    bundle = build_bundle_archive(source_root, archive, bundle_id="mncs-fabric.portable-python.native.v0.1")
    node = _remote_node(remote, remote_root, args.worker_id)
    remote_resources = _remote_resources(remote, remote_root, args.worker_id)
    controller_trust = TrustStore(output / "controller-trust.jsonl")
    controller_trust.enroll("worker", args.worker_id, _cert_fingerprint(pki["worker"]), metadata={"experiment": "native-bundle-two-host"})
    controller = FabricClient(args.controller_id, output / "controller-public.jsonl")
    controller.register_remote_worker(RemoteWorkerConfig(args.worker_id, args.worker_host, args.worker_port, tuple(sorted(capability_names(node))), pki["ca"], pki["controller"], pki["controller_key"], output / "controller-trust.jsonl", timeout=8, resource_snapshot=remote_resources))
    controller.register_local_worker(LocalWorker("fabric-controller-local", source_root, output / "local-worker.jsonl"))
    pid: int | None = None
    pid_stable = False
    requests: list[dict[str, object]] = []
    replay_store = ChallengeReplayStore(output / "challenge-replay.jsonl")
    context = ConsumerContext("MNEL", "sha256:" + "1" * 64, experiment_identity="sha256:" + "2" * 64, forge_workflow_identity="sha256:" + "3" * 64, provider_identity="sha256:" + "4" * 64)
    placement = PlacementRequest(execution_device="cpu", minimum_host_memory_bytes=64 * 1024 * 1024)
    try:
        pid = _start_worker(remote, remote_root, worker_id=args.worker_id, controller_id=args.controller_id, host=args.worker_host, port=args.worker_port, max_requests=9, idle_timeout=30, bundle_root=remote_root + "/empty-bundle")
        transfer = controller.ensure_bundle(args.worker_id, archive, expected_bundle_identity=bundle.bundle_identity)
        started = time.perf_counter()
        first = controller.execute(plan, manifest, worker_id=args.worker_id, request_id="native-1", consumer_context=context, placement=placement)
        requests.append({"request_id": "native-1", "disposition": first[0]["disposition"], "record_identity": first[0]["record_identity"], "receipt_identity": first[0]["receipt_identity"], "round_trip_seconds": round(time.perf_counter() - started, 6)})
        duplicate = controller.execute(plan, manifest, worker_id=args.worker_id, request_id="native-1", consumer_context=context, placement=placement)
        requests.append({"request_id": "native-1", "disposition": duplicate[0]["disposition"], "record_identity": duplicate[0].get("record_identity")})
        changed = dict(plan)
        changed["candidate_identity"] = "sha256:" + "b" * 64
        changed = validate_job_plan(changed)
        conflicting = controller.execute(changed, manifest, worker_id=args.worker_id, request_id="native-1", consumer_context=context, placement=placement)
        requests.append({"request_id": "native-1", "disposition": conflicting[0]["disposition"]})
        challenge = _challenge(args.controller_id, plan, bundle.bundle_identity or "", args.worker_id)
        fresh = controller.execute(plan, manifest, worker_id=args.worker_id, request_id="native-2", challenge=challenge, consumer_context=context, placement=placement)
        replay = replay_store.consume(challenge, fresh[0]["receipt"])
        requests.append({"request_id": "native-2", "disposition": fresh[0]["disposition"], "record_identity": fresh[0]["record_identity"], "receipt_identity": fresh[0]["receipt_identity"], "challenge_identity": challenge["challenge_identity"], "replay_identity": replay.replay_receipt["replay_identity"] if replay.replay_receipt else None})
        local = controller.execute(plan, manifest, worker_id="fabric-controller-local", consumer_context=context, placement=placement)[0]
        reconciliation = controller.reconcile([local, first[0]])
        pid_stable = remote.ssh(f"ps -o pid= -p {pid} 2>/dev/null || true").strip() == str(pid)

        revoked = TrustStore(output / "worker-trust-revoked.jsonl")
        revoked.enroll("controller", args.controller_id, _cert_fingerprint(pki["controller"]), metadata={"experiment": "native-bundle-two-host"})
        revoked.revoke("controller", args.controller_id, reason="native-between-request-test")
        remote.scp_to(output / "worker-trust-revoked.jsonl", remote_root + "/trust/worker-trust-revoked.jsonl")
        remote.ssh(f"chmod 600 {_shell_quote(remote_root + '/trust/worker-trust-revoked.jsonl')} && mv {_shell_quote(remote_root + '/trust/worker-trust-revoked.jsonl')} {_shell_quote(remote_root + '/trust/worker-trust.jsonl')}")
        try:
            controller.execute(plan, manifest, worker_id=args.worker_id, request_id="native-revoked", consumer_context=context, placement=placement)
            revoked_disposition = "UNEXPECTED_ACCEPT"
        except (FabricError, OSError, TimeoutError, ProtocolError) as exc:
            revoked_disposition = {"disposition": "FAIL_CLOSED", "diagnostic": type(exc).__name__}
    finally:
        _stop_worker(remote, remote_root, pid)

    evidence = {
        "schema_version": "mncs-fabric.native-bundle-two-host.v0.1",
        "record_type": "mncs-fabric.native-bundle-two-host",
        "experiment_id": "native-bundle-two-host-" + run_id,
        "fabric_commit": fabric_commit,
        "worker_fabric_commit": fabric_commit,
        "direct_fabric_tls": True,
        "ssh_tunnel_used": False,
        "ssh_staged_candidate_material": False,
        "source_archive_identity": source_archive_identity,
        "controller_identity": args.controller_id,
        "worker_identity": args.worker_id,
        "worker_hostname": args.expected_hostname,
        "persistent_pid_stable": pid_stable,
        "bundle": {"logical_identity": bundle.bundle_identity, "archive_identity": bundle.archive_identity, "transfer_status": transfer["status"]},
        "resource_snapshot": first[0].get("resource_snapshot", remote_resources),
        "resource_snapshot_preflight": remote_resources,
        "placement": {"request_identity": placement.placement_request_identity, "resource_snapshot_identity": first[0].get("resource_snapshot", {}).get("resource_snapshot_identity"), "admission_decision_identity": first[0].get("placement_admission", {}).get("decision_identity"), "mode": first[0].get("placement_admission", {}).get("admission_mode")},
        "consumer_context": context.to_dict(),
        "requests": requests,
        "local_record_identity": local["record_identity"],
        "remote_record_identity": first[0]["record_identity"],
        "reconciliation": reconciliation,
        "adversarial": {"duplicate_request": requests[1]["disposition"], "conflicting_replay": requests[2]["disposition"], "revoked_controller": revoked_disposition, "challenge_replay": requests[3]["replay_identity"] is not None},
        "claim_boundary": "operator-controlled development evidence; native bundle transfer and direct mTLS observations only; no semantic consumer verdict, sandbox, correctness, custody, independence, conformance, or certification claim",
        "limitations": ["The Fabric source, bootstrap trust, and certificates were staged through SSH; candidate execution material was transferred by Fabric.", "The two hosts share one operator trust domain.", "Consumer context is provenance-only and does not establish MNEL or RAVEL semantic truth."],
    }
    write_json(output / "native-bundle-experiment-evidence.json", evidence)
    return evidence


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run native EA-NEXT-002 transfer through public Fabric API")
    parser.add_argument("--ssh-host", required=True)
    parser.add_argument("--ssh-user", required=True)
    parser.add_argument("--ssh-key", required=True)
    parser.add_argument("--worker-host", required=True)
    parser.add_argument("--worker-port", type=int, default=7443)
    parser.add_argument("--expected-hostname", required=True)
    parser.add_argument("--controller-id", default="fabric-controller-01")
    parser.add_argument("--worker-id", default="fabric-worker-01")
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        evidence = run(args)
        print(json.dumps({"outcome": evidence["reconciliation"]["outcome"], "bundle_transfer": evidence["bundle"]["transfer_status"], "direct_fabric_tls": evidence["direct_fabric_tls"], "adversarial": evidence["adversarial"]}, sort_keys=True, separators=(",", ":")))
        return 0 if evidence["reconciliation"]["outcome"] == "PASS" else 2
    except (OSError, RuntimeError, ValueError, FabricError) as exc:
        print(json.dumps({"outcome": "UNKNOWN", "error": str(exc)}, sort_keys=True, separators=(",", ":")))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
