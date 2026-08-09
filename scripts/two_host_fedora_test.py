#!/usr/bin/env python3
"""Bounded operator harness for a real Fedora-to-Fedora Fabric run.

SSH is used only for identity checks, exact source/material staging, worker
lifecycle, and diagnostics.  The candidate execution is performed by Fabric's
direct TLS transport and the remote LocalWorker.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import shlex
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from mncs_fabric.artifacts import verify_manifest  # noqa: E402
from mncs_fabric.canonical import sha256_identity  # noqa: E402
from mncs_fabric.challenges import ChallengeReplayStore, issue_execution_challenge  # noqa: E402
from mncs_fabric.controller import NetworkController  # noqa: E402
from mncs_fabric.enrollment import TrustStore, certificate_fingerprint  # noqa: E402
from mncs_fabric.errors import FabricError, ProtocolError  # noqa: E402
from mncs_fabric.io import load_json, write_json  # noqa: E402
from mncs_fabric.models import validate_job_plan  # noqa: E402
from mncs_fabric.node import capability_names  # noqa: E402
from mncs_fabric.receipts import build_execution_receipt, execution_policy_identity_for_plan  # noqa: E402
from mncs_fabric.service import FabricService  # noqa: E402
from mncs_fabric.transport import TLSNetworkTransport  # noqa: E402


def _run(command: list[str], *, cwd: Path | None = None, input_text: str | None = None, timeout: float = 60) -> str:
    try:
        result = subprocess.run(command, cwd=cwd, input=input_text, text=True, capture_output=True, check=False, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"command timed out after {timeout}s: {shlex.join(command)}") from exc
    if result.returncode != 0:
        raise RuntimeError(f"command failed ({result.returncode}): {shlex.join(command)}\n{result.stderr.strip()}")
    return result.stdout


def _shell_quote(value: str) -> str:
    return shlex.quote(value)


class Remote:
    def __init__(self, *, host: str, user: str, key: Path) -> None:
        self.host = host
        self.user = user
        self.key = key
        self.destination = f"{user}@{host}"
        self.options = ["-i", str(key), "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=10"]

    def ssh(self, command: str) -> str:
        return _run(["ssh", "-n", *self.options, self.destination, command], timeout=20)

    def scp_to(self, source: Path, destination: str) -> None:
        _run(["scp", *self.options, str(source), f"{self.destination}:{destination}"], timeout=60)


def _write_pki(directory: Path) -> dict[str, Path]:
    openssl = shutil.which("openssl")
    if openssl is None:
        raise RuntimeError("openssl is required for the disposable Fabric test PKI")
    directory.mkdir(parents=True, exist_ok=True)
    directory.chmod(0o700)
    ca_key, ca_cert = directory / "ca.key", directory / "ca.pem"
    _run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(ca_key), "-out", str(ca_cert), "-subj", "/CN=MNCS Fabric disposable test CA", "-days", "2", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign"])
    paths: dict[str, Path] = {"ca": ca_cert}
    for name, common_name, usage in (("controller", "fabric-controller-01", "clientAuth"), ("worker", "fabric-worker-01", "serverAuth")):
        key = directory / f"{name}.key"
        csr = directory / f"{name}.csr"
        cert = directory / f"{name}.pem"
        ext = directory / f"{name}.ext"
        ext.write_text(f"basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage={usage}\nsubjectKeyIdentifier=hash\n", encoding="ascii")
        _run([openssl, "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(csr), "-subj", f"/CN={common_name}"])
        _run([openssl, "x509", "-req", "-in", str(csr), "-CA", str(ca_cert), "-CAkey", str(ca_key), "-CAcreateserial", "-out", str(cert), "-days", "2", "-sha256", "-extfile", str(ext)])
        key.chmod(0o600)
        paths[name] = cert
        paths[f"{name}_key"] = key
    return paths


def _cert_fingerprint(path: Path) -> str:
    return certificate_fingerprint(ssl.PEM_cert_to_DER_cert(path.read_text(encoding="ascii")))


def _json_output(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _remote_node(remote: Remote, run_root: str, worker_id: str) -> dict[str, Any]:
    output = remote.ssh(f"cd {_shell_quote(run_root + '/repo')} && {_shell_quote(run_root + '/venv/bin/python')} -m mncs_fabric node inspect --label {_shell_quote(worker_id)}")
    value = json.loads(output)
    if not isinstance(value, dict) or value.get("machine_label") != worker_id:
        raise RuntimeError("remote node identity did not match the requested worker ID")
    return value


def _start_worker(remote: Remote, run_root: str, *, worker_id: str, controller_id: str, host: str, port: int, max_requests: int = 1, idle_timeout: float | None = None, max_concurrent_connections: int = 1) -> int:
    command = (
        f"{_shell_quote(run_root + '/venv/bin/python')} "
        f"{_shell_quote(run_root + '/repo/scripts/remote_worker_launcher.py')} "
        f"--worker-id {_shell_quote(worker_id)} --controller-id {_shell_quote(controller_id)} "
        f"--bundle-root {_shell_quote(run_root + '/repo/examples/portable-python/bundle')} "
        f"--state {_shell_quote(run_root + '/state/worker-ledger.jsonl')} "
        f"--trust-state {_shell_quote(run_root + '/trust/worker-trust.jsonl')} "
        f"--ca {_shell_quote(run_root + '/certs/ca.pem')} "
        f"--certificate {_shell_quote(run_root + '/certs/worker.pem')} "
        f"--key {_shell_quote(run_root + '/certs/worker.key')} "
        # Physical startup and repeated SSH readiness probes must not consume
        # the service's bounded accept window.
        f"--host {_shell_quote(host)} --port {port} --timeout 30 "
        f"--max-requests {max_requests} --max-concurrent-connections {max_concurrent_connections} "
    )
    if idle_timeout is not None:
        command += f"--idle-timeout {idle_timeout} "
    command += f"--log {_shell_quote(run_root + '/logs/worker.log')}"
    output = remote.ssh(command).strip().splitlines()
    if not output or not output[-1].isdigit():
        raise RuntimeError("remote worker did not return a process ID")
    pid = int(output[-1])
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        listeners = remote.ssh(f"ss -ltn sport = :{port}")
        if f":{port}" in listeners:
            return pid
        time.sleep(0.15)
    diagnostic = remote.ssh(f"sed -n '1,80p' {_shell_quote(run_root + '/logs/worker.log')} 2>/dev/null || true")
    raise RuntimeError(f"remote worker did not reach LISTEN state on {host}:{port}: {diagnostic.strip()}")


def _stop_worker(remote: Remote, run_root: str, pid: int | None) -> None:
    if pid is None:
        return
    remote.ssh(f"kill -TERM {pid} 2>/dev/null || true")


def _fingerprint_record(value: dict[str, Any]) -> dict[str, Any]:
    return {key: value.get(key) for key in ("record_id", "node_fingerprint", "machine_label", "os", "os_release", "architecture", "python_version", "cpu_count")}


def _build_transport(*, output: Path, worker_id: str, host: str, port: int, pki: dict[str, Path]) -> tuple[TLSNetworkTransport, TrustStore]:
    trust = TrustStore(output / "controller-trust.jsonl")
    trust.enroll("worker", worker_id, _cert_fingerprint(pki["worker"]), metadata={"experiment": "fedora-two-host"})
    transport = TLSNetworkTransport(host, port, ca_file=pki["ca"], client_cert=pki["controller"], client_key=pki["controller_key"], expected_worker_id=worker_id, trust_store=trust, timeout=8)
    return transport, trust


def _remote_dispatch(controller: NetworkController, transport: TLSNetworkTransport, plan: dict[str, Any], manifest: dict[str, Any], worker_id: str, request_id: str) -> dict[str, Any]:
    response = controller.dispatch_via(transport, plan, manifest, worker_id=worker_id, request_id=request_id)
    return response


def run_experiment(args: argparse.Namespace) -> dict[str, Any]:
    output = Path(args.output).resolve()
    if output.exists() and any(output.iterdir()):
        raise RuntimeError(f"output directory must be new and empty: {output}")
    output.mkdir(parents=True, exist_ok=True)
    (output / "pki").mkdir(mode=0o700, exist_ok=True)
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    remote = Remote(host=args.ssh_host, user=args.ssh_user, key=Path(args.ssh_key).expanduser())
    expected_hostname = args.expected_hostname
    preflight = remote.ssh("hostname; id -un; python3 --version; uname -a")
    observed_hostname = preflight.splitlines()[0].strip()
    if observed_hostname != expected_hostname:
        raise RuntimeError(f"remote hostname mismatch: expected {expected_hostname!r}, observed {observed_hostname!r}")
    remote_home = remote.ssh("printf %s \"$HOME\"").strip()
    if not remote_home.startswith("/") or any(character in remote_home for character in "\n\r\x00"):
        raise RuntimeError("remote home path was not an absolute safe path")
    remote_root = f"{remote_home}/mncs-fabric-worker/runs/{run_id}"

    pki = _write_pki(output / "pki")
    worker_fingerprint = _cert_fingerprint(pki["worker"])
    controller_fingerprint = _cert_fingerprint(pki["controller"])
    worker_trust = TrustStore(output / "worker-trust.jsonl")
    worker_trust.enroll("controller", args.controller_id, controller_fingerprint, metadata={"experiment": "fedora-two-host"})

    archive = output / "fabric-source.tar.gz"
    _run(["git", "archive", "--format=tar.gz", "--output", str(archive), "HEAD"], cwd=ROOT)
    fabric_commit = _run(["git", "rev-parse", "HEAD"], cwd=ROOT).strip()
    revision_file = output / "fabric-revision.txt"
    revision_file.write_text(fabric_commit + "\n", encoding="ascii")
    source_archive_identity = "sha256:" + hashlib.sha256(archive.read_bytes()).hexdigest()

    remote.ssh(f"mkdir -p {_shell_quote(remote_root + '/repo')} {_shell_quote(remote_root + '/state')} {_shell_quote(remote_root + '/trust')} {_shell_quote(remote_root + '/certs')} {_shell_quote(remote_root + '/logs')} {_shell_quote(remote_root + '/results')}")
    remote.scp_to(archive, remote_root + "/source.tar.gz")
    remote.scp_to(revision_file, remote_root + "/fabric-revision.txt")
    for key in ("ca", "worker", "worker_key"):
        remote.scp_to(pki[key], remote_root + "/certs/" + pki[key].name)
    remote.scp_to(output / "worker-trust.jsonl", remote_root + "/trust/worker-trust.jsonl")
    remote.ssh(f"chmod 700 {_shell_quote(remote_root + '/certs')} {_shell_quote(remote_root + '/trust')} {_shell_quote(remote_root + '/state')} {_shell_quote(remote_root + '/logs')} {_shell_quote(remote_root + '/results')} && chmod 600 {_shell_quote(remote_root + '/certs/worker.key')} {_shell_quote(remote_root + '/trust/worker-trust.jsonl')}")
    remote.ssh(f"tar -xzf {_shell_quote(remote_root + '/source.tar.gz')} -C {_shell_quote(remote_root + '/repo')} && python3 -m venv --system-site-packages {_shell_quote(remote_root + '/venv')} && {_shell_quote(remote_root + '/venv/bin/python')} -m pip install --no-deps --no-build-isolation {_shell_quote(remote_root + '/repo')} >/dev/null && sha256sum {_shell_quote(remote_root + '/source.tar.gz')}")
    remote_archive_identity = remote.ssh(f"sha256sum {_shell_quote(remote_root + '/source.tar.gz')}").split()[0]
    if remote_archive_identity != source_archive_identity.removeprefix("sha256:"):
        raise RuntimeError("remote source archive identity differs from controller archive")
    worker_fabric_commit = remote.ssh(f"cat {_shell_quote(remote_root + '/fabric-revision.txt')}").strip()
    if worker_fabric_commit != fabric_commit:
        raise RuntimeError("remote Fabric revision marker differs from controller revision")

    node = _remote_node(remote, remote_root, args.worker_id)
    bundle_root = ROOT / "examples/portable-python/bundle"
    manifest = verify_manifest(bundle_root, load_json(ROOT / "examples/portable-python/artifact-manifest.json"))
    plan = validate_job_plan(load_json(ROOT / "examples/portable-python/job-plan.json"))
    controller_state = output / "controller-ledger.jsonl"
    controller = NetworkController(args.controller_id, controller_state)
    transport, controller_trust = _build_transport(output=output, worker_id=args.worker_id, host=args.worker_host, port=args.worker_port, pki=pki)
    controller.register_remote(args.worker_id, frozenset(capability_names(node)), transport)
    challenge_scope = {"subject_identity": plan["candidate_identity"][7:], "candidate_id": "candidate-" + plan["candidate_identity"][7:], "bundle_identity": manifest["manifest_identity"][7:], "execution_policy_identity": execution_policy_identity_for_plan(plan), "runner_identity": f"mncs-fabric-worker-{args.worker_id}"}
    challenge_report = issue_execution_challenge(issuer_identity=args.controller_id, scope=challenge_scope, ttl_seconds=300)
    if not challenge_report.valid or challenge_report.challenge is None:
        raise RuntimeError("could not issue the scoped EA-NEXT-005 execution challenge: " + "; ".join(challenge_report.issues))
    challenge = challenge_report.challenge
    write_json(output / "execution-challenge.json", challenge)
    pid: int | None = None
    first_response: dict[str, Any] | None = None
    duplicate_response: dict[str, Any] | None = None
    conflicting_response: dict[str, Any] | None = None
    adversarial: dict[str, Any] = {}
    try:
        pid = _start_worker(remote, remote_root, worker_id=args.worker_id, controller_id=args.controller_id, host=args.worker_host, port=args.worker_port)
        request_id = sha256_identity({"job_identity": plan["job_identity"], "worker_id": args.worker_id, "replica": 0})
        first_response = controller.dispatch_via(transport, plan, manifest, worker_id=args.worker_id, request_id=request_id, challenge=challenge)
        first_record = first_response["payload"]["record"]
        first_receipt = first_response["payload"].get("receipt")
        if not isinstance(first_receipt, dict):
            raise RuntimeError("challenge dispatch response did not include an MNCS execution receipt")

        # The one-request endpoint is restarted with the same durable ledger;
        # the exact request is therefore a real process-restart retry.
        pid = None
        pid = _start_worker(remote, remote_root, worker_id=args.worker_id, controller_id=args.controller_id, host=args.worker_host, port=args.worker_port)
        duplicate_response = controller.dispatch_via(transport, plan, manifest, worker_id=args.worker_id, request_id=request_id, challenge=challenge)
        adversarial["duplicate_after_restart"] = duplicate_response.get("payload", {}).get("disposition")

        changed = copy.deepcopy(plan)
        changed["candidate_identity"] = "sha256:" + "b" * 64
        changed = validate_job_plan(changed)
        pid = None
        pid = _start_worker(remote, remote_root, worker_id=args.worker_id, controller_id=args.controller_id, host=args.worker_host, port=args.worker_port)
        conflicting_response = _remote_dispatch(controller, transport, changed, manifest, args.worker_id, request_id)
        adversarial["conflicting_replay"] = conflicting_response.get("payload", {}).get("disposition")

        # A fresh controller object reuses the persisted ledger and trust state.
        restarted_controller = NetworkController(args.controller_id, controller_state)
        restarted_controller.register_remote(args.worker_id, frozenset(capability_names(node)), transport)
        pid = None
        pid = _start_worker(remote, remote_root, worker_id=args.worker_id, controller_id=args.controller_id, host=args.worker_host, port=args.worker_port)
        restarted_response = restarted_controller.dispatch_remote(plan, manifest, challenge=challenge)
        adversarial["controller_restart_retry"] = restarted_response[0].get("payload", {}).get("disposition")

        # Revocation is checked over the real TLS connection before dispatch.
        controller_trust.revoke("worker", args.worker_id, reason="real-two-host-adversarial-test")
        pid = None
        pid = _start_worker(remote, remote_root, worker_id=args.worker_id, controller_id=args.controller_id, host=args.worker_host, port=args.worker_port)
        try:
            controller.dispatch_via(transport, plan, manifest, worker_id=args.worker_id, request_id=sha256_identity({"revoked": request_id}), challenge=challenge)
            adversarial["revoked_worker"] = "UNEXPECTED_ACCEPT"
        except (FabricError, OSError, TimeoutError) as exc:
            adversarial["revoked_worker"] = {"disposition": "FAIL_CLOSED", "diagnostic": type(exc).__name__}
    finally:
        _stop_worker(remote, remote_root, pid)

    local_service = FabricService()
    local_record = local_service.execute_local(plan, bundle_root, manifest, args.controller_id, results_dir=output / "local-results")
    remote_record = first_response["payload"]["record"] if first_response else None
    if not isinstance(remote_record, dict):
        raise RuntimeError("first Fabric response did not contain an execution record")
    remote_receipt = first_receipt
    replay = ChallengeReplayStore(output / "challenge-replay.jsonl").consume(challenge, remote_receipt)
    if not replay.valid or replay.replay_receipt is None:
        raise RuntimeError("challenge replay consumption failed: " + "; ".join(replay.issues))
    cohort = local_service.reconcile([local_record, remote_record], require_distinct_nodes=True)
    evidence = {
        "schema_version": "mncs-fabric.two-host-experiment.v0.1",
        "record_type": "mncs-fabric.two-host-experiment",
        "experiment_id": f"fedora-two-host-{run_id}",
        "controller_fabric_commit": fabric_commit,
        "worker_fabric_commit": worker_fabric_commit,
        "worker_fabric_source_archive_identity": source_archive_identity,
        "direct_fabric_tls": True,
        "ssh_tunnel_used": False,
        "bootstrap_material_staged_by_ssh": True,
        "controller_identity": args.controller_id,
        "worker_identity": args.worker_id,
        "worker_hostname": observed_hostname,
        "worker_certificate_fingerprint": worker_fingerprint,
        "controller_certificate_fingerprint": controller_fingerprint,
        "node_records": {"controller": _fingerprint_record(local_record["node"]), "worker": _fingerprint_record(remote_record["node"])},
        "execution": {"job_identity": remote_record["job_identity"], "candidate_identity": remote_record["candidate_identity"], "artifact_manifest_identity": remote_record["artifact_manifest_identity"], "controller_record_id": local_record["record_id"], "worker_record_id": remote_record["record_id"], "controller_receipt_identity": build_execution_receipt(local_record, runner_identity=f"mncs-fabric-local-{args.controller_id}", runner_version="0.2.0a0")["receipt_identity"], "worker_receipt_identity": remote_receipt["receipt_identity"], "result_identities": [entry["sha256"] for entry in remote_record.get("results", [])], "cohort_id": cohort["cohort_id"], "cohort_outcome": cohort["outcome"]},
        "challenge": {"challenge_identity": challenge["challenge_identity"], "replay_identity": replay.replay_receipt["replay_identity"], "replay_store_entry_identity": replay.replay_receipt["store_entry_identity"]},
        "adversarial": adversarial,
        "claim_boundary": "operator-controlled development evidence; direct mTLS and durable identity-linked execution observations only; no sandbox, correctness, custody, independence, conformance, or certification claim",
        "limitations": ["EA-NEXT-002 material was staged through the operator bootstrap channel; Fabric bulk bundle transfer was not exercised.", "EA-NEXT-005 freshness is scoped to the controller's operator-controlled local replay store.", "The worker service was a bounded one-request endpoint.", "The two hosts share one operator trust domain."],
    }
    write_json(output / "experiment-evidence.json", evidence)
    return evidence


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run a bounded direct Fedora-to-Fedora Fabric experiment")
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
    args = build_parser().parse_args(argv)
    try:
        evidence = run_experiment(args)
        print(_json_output({"outcome": evidence["execution"]["cohort_outcome"], "evidence": str(Path(args.output).resolve() / "experiment-evidence.json"), "worker": evidence["worker_identity"], "direct_fabric_tls": evidence["direct_fabric_tls"], "adversarial": evidence["adversarial"]}))
        return 0 if evidence["execution"]["cohort_outcome"] == "PASS" else 2
    except (OSError, RuntimeError, ValueError, FabricError) as exc:
        print(_json_output({"outcome": "UNKNOWN", "error": str(exc)}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
