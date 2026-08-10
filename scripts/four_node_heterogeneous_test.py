#!/usr/bin/env python3
"""Run the bounded four-substrate Fabric portability experiment.

SSH in this harness stages only the Fabric source, disposable trust material,
and bounded worker bootstrap.  The portable candidate bundle is transferred
through Fabric's authenticated native bundle protocol.  The Windows path uses
the already-provisioned GPU Python environment and the Windows lifecycle
helper; it does not use an SSH tunnel or a remote shell as execution.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from two_host_fedora_test import (
    ROOT,
    Remote,
    _cert_fingerprint,
    _remote_node,
    _run,
    _shell_quote,
    _start_worker,
    _stop_worker,
)

from mncs_fabric.api import ConsumerContext, FabricClient, PlacementRequest, RemoteWorkerConfig
from mncs_fabric.artifacts import verify_manifest
from mncs_fabric.bundles import build_bundle_archive
from mncs_fabric.enrollment import TrustStore
from mncs_fabric.errors import FabricError, ProtocolError
from mncs_fabric.io import load_json, write_json
from mncs_fabric.models import validate_job_plan
from mncs_fabric.node import capability_names
from mncs_fabric.worker import LocalWorker
from mncs_fabric.collections import build_work_item


def _sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


class WindowsRemote:
    """Strict SSH bootstrap helper for explicit Windows operator access."""

    def __init__(self, host: str, user: str, key: Path) -> None:
        self.destination = f"{user}@{host}"
        self.options = [
            "-i", str(key), "-o", "IdentitiesOnly=yes",
            "-o", "PreferredAuthentications=publickey",
            "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
            "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
            "-o", "ConnectTimeout=10",
        ]

    def powershell(self, script: str, *, timeout: float = 30) -> str:
        encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
        return _run(["ssh", *self.options, self.destination, "powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded], timeout=timeout)

    def scp_to(self, source: Path, destination: str) -> None:
        unix_destination = destination.replace("\\", "/")
        _run(["scp", *self.options, str(source), f"{self.destination}:{unix_destination}"], timeout=60)


def _write_pki(directory: Path, worker_ids: list[str]) -> dict[str, Any]:
    directory.mkdir(parents=True, exist_ok=True)
    directory.chmod(0o700)
    openssl = "openssl"
    ca_key, ca_cert = directory / "ca.key", directory / "ca.pem"
    _run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(ca_key), "-out", str(ca_cert), "-subj", "/CN=MNCS Fabric four-node test CA", "-days", "2", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign"])
    result: dict[str, Any] = {"ca": ca_cert, "controller": None, "controller_key": None, "workers": {}}
    for name, common_name, usage in [("controller", "fabric-controller-01", "clientAuth"), *[(worker_id, worker_id, "serverAuth") for worker_id in worker_ids]]:
        key = directory / f"{name}.key"
        csr = directory / f"{name}.csr"
        cert = directory / f"{name}.pem"
        ext = directory / f"{name}.ext"
        ext.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=" + usage + "\nsubjectKeyIdentifier=hash\n", encoding="ascii")
        _run([openssl, "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(csr), "-subj", f"/CN={common_name}"])
        _run([openssl, "x509", "-req", "-in", str(csr), "-CA", str(ca_cert), "-CAkey", str(ca_key), "-CAcreateserial", "-out", str(cert), "-days", "2", "-sha256", "-extfile", str(ext)])
        key.chmod(0o600)
        if name == "controller":
            result["controller"], result["controller_key"] = cert, key
        else:
            result["workers"][name] = {"certificate": cert, "key": key}
    return result


def _worker_trust(path: Path, controller_id: str, pki: dict[str, Any], experiment: str) -> Path:
    trust = TrustStore(path)
    trust.enroll("controller", controller_id, _cert_fingerprint(pki["controller"]), metadata={"experiment": experiment})
    return path


def _controller_trust(path: Path, worker_ids: list[str], pki: dict[str, Any], experiment: str) -> Path:
    trust = TrustStore(path)
    for worker_id in worker_ids:
        trust.enroll("worker", worker_id, _cert_fingerprint(pki["workers"][worker_id]["certificate"]), metadata={"experiment": experiment})
    return path


def _json_line(output: str) -> dict[str, Any]:
    for line in reversed(output.splitlines()):
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            value = json.loads(line)
            if isinstance(value, dict):
                return value
    raise RuntimeError("remote command did not return a JSON object")


def _stage_linux(remote: Remote, root: str, source: Path, pki: dict[str, Any], worker_id: str, controller_id: str, trust: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    remote.ssh(f"mkdir -p {_shell_quote(root + '/repo')} {_shell_quote(root + '/state')} {_shell_quote(root + '/trust')} {_shell_quote(root + '/certs')} {_shell_quote(root + '/logs')} {_shell_quote(root + '/bundle-cache')} {_shell_quote(root + '/empty-bundle')}")
    remote.scp_to(source, root + "/source.tar.gz")
    remote.scp_to(pki["ca"], root + "/certs/ca.pem")
    remote.scp_to(pki["workers"][worker_id]["certificate"], root + "/certs/worker.pem")
    remote.scp_to(pki["workers"][worker_id]["key"], root + "/certs/worker.key")
    remote.scp_to(trust, root + "/trust/worker-trust.jsonl")
    remote.ssh(f"chmod 700 {_shell_quote(root + '/certs')} {_shell_quote(root + '/trust')} {_shell_quote(root + '/state')} && chmod 600 {_shell_quote(root + '/certs/worker.key')} {_shell_quote(root + '/trust/worker-trust.jsonl')}")
    remote.ssh(f"tar -xzf {_shell_quote(root + '/source.tar.gz')} -C {_shell_quote(root + '/repo')} && python3 -m venv --system-site-packages {_shell_quote(root + '/venv')} && {_shell_quote(root + '/venv/bin/python')} -m pip install --no-deps --no-build-isolation {_shell_quote(root + '/repo')} >/dev/null", timeout=180)
    node = _remote_node(remote, root, worker_id)
    resources = json.loads(remote.ssh(f"cd {_shell_quote(root + '/repo')} && {_shell_quote(root + '/venv/bin/python')} -c {_shell_quote('import json; from mncs_fabric.resources import capture_resource_snapshot; print(json.dumps(capture_resource_snapshot(' + repr(worker_id) + '), sort_keys=True, separators=(\",\", \":\")))')}").strip())
    if not isinstance(resources, dict):
        raise RuntimeError(f"{worker_id} resource observation is not an object")
    return node, resources


def _stage_windows(remote: WindowsRemote, root: str, source: Path, pki: dict[str, Any], worker_id: str, trust: Path, python_path: str) -> tuple[dict[str, Any], dict[str, Any]]:
    repo = root + r"\repo"
    remote.powershell("; ".join(f"New-Item -ItemType Directory -Force -Path {_ps_quote(path)} | Out-Null" for path in (root, repo, root + r"\state", root + r"\trust", root + r"\certs", root + r"\logs", root + r"\bundle-cache", root + r"\empty-bundle")))
    remote.scp_to(source, "/Users/epicu/mncs-fabric-four-node/" + root.rsplit("\\", 1)[-1] + "/source.tar.gz")
    run_root = "/Users/epicu/mncs-fabric-four-node/" + root.rsplit("\\", 1)[-1]
    for local, subdir, remote_name in ((pki["ca"], "certs", "ca.pem"), (pki["workers"][worker_id]["certificate"], "certs", "worker.pem"), (pki["workers"][worker_id]["key"], "certs", "worker.key"), (trust, "trust", "worker-trust.jsonl")):
        remote.scp_to(local, run_root + "/" + subdir + "/" + remote_name)
    remote.powershell(f"tar -xzf {_ps_quote(root + '\\source.tar.gz')} -C {_ps_quote(repo)}")
    node_output = remote.powershell(f"$env:PYTHONPATH={_ps_quote(repo + '\\src')}; & {_ps_quote(python_path)} -m mncs_fabric node inspect --label {_ps_quote(worker_id)}")
    resource_code = "import json; from mncs_fabric.resources import capture_resource_snapshot; print(json.dumps(capture_resource_snapshot(" + repr(worker_id) + "), sort_keys=True))"
    resource_output = remote.powershell(f"$env:PYTHONPATH={_ps_quote(repo + '\\src')}; & {_ps_quote(python_path)} -c {_ps_quote(resource_code)}")
    return _json_line(node_output), _json_line(resource_output)


def _start_windows(remote: WindowsRemote, root: str, worker_id: str, controller_id: str, python_path: str, port: int) -> int:
    repo = root + r"\repo"
    script = "\n".join([
        f"$env:PYTHONPATH={_ps_quote(repo + r'\src')}",
        f"$launcher={_ps_quote(repo + r'\scripts\windows_worker_launcher.py')}",
        f"& {_ps_quote(python_path)} $launcher start --state {_ps_quote(root + r'\state\launcher.json')} --worker-id {_ps_quote(worker_id)} --stdout {_ps_quote(root + r'\logs\worker.stdout.log')} --stderr {_ps_quote(root + r'\logs\worker.stderr.log')} --cwd {_ps_quote(repo)} -- {_ps_quote(python_path)} -m mncs_fabric worker serve --worker-id {_ps_quote(worker_id)} --controller-id {_ps_quote(controller_id)} --bundle-root {_ps_quote(root + r'\empty-bundle')} --state {_ps_quote(root + r'\state\worker-ledger.jsonl')} --trust-state {_ps_quote(root + r'\trust\worker-trust.jsonl')} --ca {_ps_quote(root + r'\certs\ca.pem')} --certificate {_ps_quote(root + r'\certs\worker.pem')} --key {_ps_quote(root + r'\certs\worker.key')} --host 0.0.0.0 --port {port} --timeout 30 --max-requests 30 --max-concurrent-connections 1 --idle-timeout 60 --bundle-cache {_ps_quote(root + r'\bundle-cache')}",
    ])
    value = _json_line(remote.powershell(script))
    if value.get("outcome") != "PASS" or not isinstance(value.get("pid"), int):
        raise RuntimeError("Windows worker launcher did not start the worker")
    return int(value["pid"])


def _stop_windows(remote: WindowsRemote, root: str, python_path: str) -> None:
    repo = root + r"\repo"
    remote.powershell(f"$env:PYTHONPATH={_ps_quote(repo + r'\src')}; & {_ps_quote(python_path)} {_ps_quote(repo + r'\scripts\windows_worker_launcher.py')} stop --state {_ps_quote(root + r'\state\launcher.json')}", timeout=20)


def run(args: argparse.Namespace) -> dict[str, Any]:
    output = Path(args.output).resolve()
    if output.exists() and any(output.iterdir()):
        raise RuntimeError(f"output directory must be new and empty: {output}")
    output.mkdir(parents=True, exist_ok=True)
    (output / "pki").mkdir(mode=0o700)
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    worker_ids = ["fabric-worker-01", "raspberry-pi", "collamore02-windows"]
    pki = _write_pki(output / "pki", worker_ids)
    controller_trust_path = _controller_trust(output / "controller-trust.jsonl", worker_ids, pki, "four-node-heterogeneous")
    worker_trust: dict[str, Path] = {}
    for worker_id in worker_ids:
        worker_trust[worker_id] = _worker_trust(output / f"worker-trust-{worker_id}.jsonl", args.controller_id, pki, "four-node-heterogeneous")

    source_archive = output / "fabric-source-subset.tar.gz"
    _run(["git", "archive", "--format=tar.gz", "--output", str(source_archive), "HEAD", "pyproject.toml", "src", "scripts/remote_worker_launcher.py", "scripts/windows_worker_launcher.py"], cwd=ROOT)
    fabric_commit = _run(["git", "rev-parse", "HEAD"], cwd=ROOT).strip()
    source_archive_identity = _sha256(source_archive)
    linux_remote = Remote(host=args.fedora_host, user=args.fedora_user, key=Path(args.fedora_key).expanduser())
    pi_remote = Remote(host=args.pi_host, user=args.pi_user, key=Path(args.pi_key).expanduser())
    windows_remote = WindowsRemote(args.windows_host, args.windows_user, Path(args.windows_key).expanduser())
    linux_root = linux_remote.ssh('printf %s "$HOME"').strip() + f"/mncs-fabric-worker/runs/{run_id}"
    pi_root = pi_remote.ssh('printf %s "$HOME"').strip() + f"/mncs-fabric-worker/runs/{run_id}"
    windows_root = f"C:\\Users\\{args.windows_user}\\mncs-fabric-four-node\\{run_id}"
    linux_node, linux_resources = _stage_linux(linux_remote, linux_root, source_archive, pki, "fabric-worker-01", args.controller_id, worker_trust["fabric-worker-01"])
    pi_node, pi_resources = _stage_linux(pi_remote, pi_root, source_archive, pki, "raspberry-pi", args.controller_id, worker_trust["raspberry-pi"])
    windows_node, windows_resources = _stage_windows(windows_remote, windows_root, source_archive, pki, "collamore02-windows", worker_trust["collamore02-windows"], args.windows_python)
    source_root = ROOT / "examples/portable-python/bundle"
    manifest = verify_manifest(source_root, load_json(ROOT / "examples/portable-python/artifact-manifest.json"))
    plan = validate_job_plan(load_json(ROOT / "examples/portable-python/job-plan.json"))
    archive = output / "execution-bundle.zip"
    bundle = build_bundle_archive(source_root, archive, bundle_id="mncs-fabric.portable-python.native.v0.1")
    controller = FabricClient(args.controller_id, output / "controller-public.jsonl")
    controller.register_local_worker(LocalWorker("fabric-controller-local", source_root, output / "local-worker.jsonl"))
    descriptions: dict[str, Any] = {}
    nodes = {"fabric-worker-01": linux_node, "raspberry-pi": pi_node, "collamore02-windows": windows_node}
    resources = {"fabric-worker-01": linux_resources, "raspberry-pi": pi_resources, "collamore02-windows": windows_resources}
    windows_worker_host = args.windows_worker_host or args.windows_host
    for worker_id, host, node in (("fabric-worker-01", args.fedora_worker_host, linux_node), ("raspberry-pi", args.pi_worker_host, pi_node), ("collamore02-windows", windows_worker_host, windows_node)):
        controller.register_remote_worker(RemoteWorkerConfig(worker_id, host, args.worker_port, tuple(sorted(capability_names(node))), pki["ca"], pki["controller"], pki["controller_key"], controller_trust_path, timeout=10, resource_snapshot=resources[worker_id]))

    linux_pid: int | None = None
    pi_pid: int | None = None
    windows_pid: int | None = None
    try:
        linux_pid = _start_worker(linux_remote, linux_root, worker_id="fabric-worker-01", controller_id=args.controller_id, host=args.fedora_worker_host, port=args.worker_port, max_requests=20, idle_timeout=60, bundle_root=linux_root + "/empty-bundle")
        pi_pid = _start_worker(pi_remote, pi_root, worker_id="raspberry-pi", controller_id=args.controller_id, host=args.pi_worker_host, port=args.worker_port, max_requests=20, idle_timeout=60, bundle_root=pi_root + "/empty-bundle")
        windows_pid = _start_windows(windows_remote, windows_root, "collamore02-windows", args.controller_id, args.windows_python, args.worker_port)
        for worker_id in worker_ids:
            descriptions[worker_id] = controller.refresh_worker(worker_id)
        transfers = {worker_id: controller.ensure_bundle(worker_id, archive, expected_bundle_identity=bundle.bundle_identity) for worker_id in worker_ids}
        context = ConsumerContext("MNEL", "sha256:" + "1" * 64, experiment_identity="sha256:" + "2" * 64, forge_workflow_identity="sha256:" + "3" * 64, provider_identity="sha256:" + "4" * 64)
        placement = PlacementRequest(execution_device="cpu", minimum_host_memory_bytes=32 * 1024 * 1024)
        results: dict[str, dict[str, Any]] = {}
        for worker_id in ["fabric-controller-local", *worker_ids]:
            result = controller.execute(plan, manifest, worker_id=worker_id, request_id="four-node-" + worker_id, consumer_context=context, placement=placement)[0]
            results[worker_id] = result
            if result.get("disposition") != "EXECUTED" or not isinstance(result.get("record"), dict) or not isinstance(result.get("receipt"), dict):
                raise RuntimeError(f"four-node execution did not pass on {worker_id}: {result.get('disposition')}")
            controller.verify_record(result["record"])
            controller.verify_receipt(result["receipt"])
        work_items = [build_work_item(job_identity=plan["job_identity"], partition_identity="sha256:" + f"{index:064x}", bundle_identity=bundle.bundle_identity, consumer_context_identity=context.context_identity, placement_request_identity=placement.placement_request_identity) for index in range(4)]
        collection_results = [{"work_item_identity": item["work_item_identity"], "disposition": results[worker_id]["disposition"], "worker_identity": worker_id, "request_identity": results[worker_id]["request_identity"], "record_identity": results[worker_id]["record_identity"], "receipt_identity": results[worker_id]["receipt_identity"]} for item, worker_id in zip(work_items, ["fabric-controller-local", *worker_ids])]
        collection = controller.collect_work_items(work_items, collection_results)
        reconciliation = controller.reconcile([results[worker_id] for worker_id in ["fabric-controller-local", *worker_ids]])
        cuda = PlacementRequest(execution_device="accelerator", accelerator_backend="cuda", precision="float32", model_storage_bytes=1, estimated_workspace_bytes=1)
        pi_cuda = controller.execute(plan, manifest, worker_id="raspberry-pi", request_id="pi-cuda-ineligible", consumer_context=context, placement=cuda)[0]
        _stop_worker(pi_remote, pi_root, pi_pid)
        pi_pid = None
        try:
            controller.refresh_worker("raspberry-pi")
            pi_loss = {"disposition": "UNEXPECTED_AVAILABLE", "availability": "AVAILABLE"}
        except (FabricError, OSError, TimeoutError, ProtocolError) as exc:
            pi_loss = {"disposition": "UNKNOWN", "availability": controller.network.worker_state("raspberry-pi").get("availability"), "diagnostic": type(exc).__name__}
        try:
            pi_missing = controller.execute(plan, manifest, worker_id="raspberry-pi", request_id="pi-missing", consumer_context=context, placement=placement)[0]
        except (FabricError, OSError, TimeoutError, ProtocolError) as exc:
            pi_missing = {"disposition": "UNKNOWN", "reason": "worker unavailable before dispatch", "diagnostic": type(exc).__name__}
        pi_pid = _start_worker(pi_remote, pi_root, worker_id="raspberry-pi", controller_id=args.controller_id, host=args.pi_worker_host, port=args.worker_port, max_requests=8, idle_timeout=60, bundle_root=pi_root + "/empty-bundle")
        pi_recovery = controller.refresh_worker("raspberry-pi")
        recovered = controller.execute(plan, manifest, worker_id="raspberry-pi", request_id="pi-recovery", consumer_context=context, placement=placement)[0]
        evidence = {
            "schema_version": "mncs-fabric.four-node-heterogeneous.v0.1",
            "record_type": "mncs-fabric.four-node-heterogeneous",
            "experiment_id": "four-node-heterogeneous-" + run_id,
            "fabric_commit": fabric_commit,
            "worker_fabric_commit": fabric_commit,
            "source_archive_identity": source_archive_identity,
            "direct_fabric_tls": True,
            "ssh_tunnel_used": False,
            "ssh_staged_candidate_material": False,
            "controller_identity": args.controller_id,
            "nodes": ["fabric-controller-local", *worker_ids],
            "node_observations": {worker_id: {"machine_label": nodes[worker_id].get("machine_label"), "os": nodes[worker_id].get("os"), "architecture": nodes[worker_id].get("architecture"), "node_fingerprint": nodes[worker_id].get("node_fingerprint"), "resource_snapshot_identity": resources[worker_id].get("resource_snapshot_identity"), "runtime_profile_identity": ((descriptions[worker_id].get("description") or {}).get("runtime_profile") or {}).get("runtime_profile_identity") if isinstance(descriptions.get(worker_id), dict) else None} for worker_id in worker_ids},
            "bundle": {"bundle_identity": bundle.bundle_identity, "archive_identity": bundle.archive_identity},
            "native_bundle_transfer": {worker_id: transfers[worker_id]["status"] for worker_id in worker_ids},
            "records": [{"worker_identity": worker_id, "record_identity": results[worker_id]["record_identity"], "receipt_identity": results[worker_id]["receipt_identity"], "result_identity": results[worker_id]["record"].get("results", [{}])[0].get("sha256"), "disposition": results[worker_id]["disposition"]} for worker_id in ["fabric-controller-local", *worker_ids]],
            "collection": collection,
            "collection_identity": collection["collection_identity"],
            "collection_outcome": collection["outcome"],
            "reconciliation": reconciliation,
            "reconciliation_identity": reconciliation["cohort_id"],
            "reconciliation_outcome": reconciliation["outcome"],
            "placement": {"request_identity": placement.placement_request_identity, "mode": "cpu", "pi_cuda_disposition": pi_cuda.get("disposition"), "pi_cuda_reason": pi_cuda.get("reason"), "pi_cuda_admissions": pi_cuda.get("admissions")},
            "fault": {"pi_loss": pi_loss, "pi_missing": pi_missing, "pi_recovery": {"availability": pi_recovery.get("availability"), "description_identity": pi_recovery.get("description", {}).get("description_identity") if isinstance(pi_recovery.get("description"), dict) else None}, "recovered_disposition": recovered.get("disposition")},
            "claim_boundary": "operator-controlled development evidence; cross-architecture execution, native transfer, collection, and reconciliation only; no attestation, sandbox, correctness, custody, independence, conformance, or certification claim",
            "limitations": ["SSH staged only Fabric source, trust material, certificates, and bounded worker bootstrap; candidate material used native Fabric transfer.", "Worker descriptions and resources are authenticated self-reports, not attestation.", "All machines share one operator trust domain.", "The portable result is a bounded deterministic fixture, not a general platform conformance claim."],
        }
        write_json(output / "four-node-heterogeneous-evidence.json", evidence)
        return evidence
    finally:
        _stop_worker(linux_remote, linux_root, linux_pid)
        _stop_worker(pi_remote, pi_root, pi_pid)
        if windows_pid is not None:
            try:
                _stop_windows(windows_remote, windows_root, args.windows_python)
            except (OSError, RuntimeError):
                pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="run the explicit four-node heterogeneous Fabric experiment")
    parser.add_argument("--fedora-host", default="192.168.1.16")
    parser.add_argument("--fedora-user", default="fabric")
    parser.add_argument("--fedora-key", default="~/.ssh/mncs_fabric_worker")
    parser.add_argument("--fedora-worker-host", default="192.168.1.16")
    parser.add_argument("--pi-host", default="mncs-pi.local")
    parser.add_argument("--pi-user", default="epi13")
    parser.add_argument("--pi-key", default="~/.ssh/id_ed25519")
    parser.add_argument("--pi-worker-host", default="mncs-pi.local")
    parser.add_argument("--windows-host", required=True)
    parser.add_argument("--windows-user", required=True)
    parser.add_argument("--windows-key", required=True)
    parser.add_argument("--windows-worker-host", default=None)
    parser.add_argument("--windows-python", default=r"C:\Users\epicu\mncs-fabric-gpu\.venv\Scripts\python.exe")
    parser.add_argument("--worker-port", type=int, default=7443)
    parser.add_argument("--controller-id", default="fabric-controller-01")
    parser.add_argument("--output", required=True)
    return parser


def main() -> int:
    try:
        evidence = run(build_parser().parse_args())
        print(json.dumps({"outcome": evidence["reconciliation_outcome"], "collection": evidence["collection_identity"], "reconciliation": evidence["reconciliation_identity"], "nodes": evidence["nodes"]}, sort_keys=True, separators=(",", ":")))
        return 0 if evidence["reconciliation_outcome"] == "PASS" else 2
    except (OSError, RuntimeError, ValueError, FabricError) as exc:
        print(json.dumps({"outcome": "UNKNOWN", "error": str(exc)}, sort_keys=True, separators=(",", ":")))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
