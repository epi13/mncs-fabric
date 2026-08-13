"""Explicit file-mediated worker commissioning for the Fedora lifecycle.

The operator moves bounded enrollment and credential documents over a channel
they already trust. Fabric never transfers the worker private key and does not
discover controllers, scan networks, or create ambient remote-shell authority.
"""

from __future__ import annotations

import json
import os
import platform
import re
import secrets
import shutil
import ssl
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Mapping

from .canonical import attach_identity, sha256_identity
from .enrollment import TrustStore, certificate_fingerprint
from .errors import ProtocolError, StorageError, ValidationError
from .lifecycle import LifecycleStore, public_key_identity

MATERIAL_SCHEMA = "mncs-fabric.enrollment-material.v0.1"
JOIN_SCHEMA = "mncs-fabric.worker-join-request.v0.1"
CREDENTIAL_SCHEMA = "mncs-fabric.worker-credentials.v0.1"
STATE_SCHEMA = "mncs-fabric.worker-installation.v0.1"
MAX_DOCUMENT_BYTES = 256 * 1024
_IDENTITY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_HOST = re.compile(r"^[A-Za-z0-9.:[\]_-]{1,255}$")


def _identity(value: object, field: str) -> str:
    if not isinstance(value, str) or not _IDENTITY.fullmatch(value):
        raise ValidationError(f"{field} is invalid")
    return value


def _pem(value: object, label: str, maximum: int = 64 * 1024) -> str:
    if not isinstance(value, str) or len(value.encode("ascii", errors="ignore")) > maximum:
        raise ValidationError(f"{label} is invalid")
    if "-----BEGIN " not in value or "-----END " not in value or "\x00" in value:
        raise ValidationError(f"{label} is invalid")
    try:
        value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValidationError(f"{label} is not ASCII PEM") from exc
    return value


def _host(value: object) -> str:
    if not isinstance(value, str) or not _HOST.fullmatch(value):
        raise ValidationError("controller host is invalid")
    return value


def _environment_value(value: object, field: str) -> str:
    rendered = str(value)
    if not rendered or any(character in rendered for character in "\r\n\x00\"\\"):
        raise ValidationError(f"{field} cannot be represented safely in the service environment")
    return rendered


def _safe_root(root: Path) -> Path:
    root = Path(root).expanduser()
    if root.is_symlink():
        raise StorageError("worker state root must not be a symbolic link")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    resolved = root.resolve(strict=True)
    if os.name == "posix":
        entry = os.stat(resolved)
        if entry.st_uid != os.getuid():
            raise StorageError("worker state root is owned by another account")
        os.chmod(resolved, 0o700)
    return resolved


def _write_private(path: Path, value: str | bytes) -> None:
    data = value.encode("utf-8") if isinstance(value, str) else value
    if path.exists() and path.is_symlink():
        raise StorageError("commissioning output path is a symbolic link")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    try:
        with temporary.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def write_protected_json(path: Path, value: Mapping[str, Any]) -> None:
    _write_private(path, json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")


def _openssl(arguments: list[str], *, timeout: float = 20.0) -> str:
    executable = shutil.which("openssl")
    if executable is None:
        raise ProtocolError("Fedora worker commissioning requires the openssl executable")
    try:
        completed = subprocess.run(
            [executable, *arguments],
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise ProtocolError("bounded openssl commissioning operation failed") from exc
    return completed.stdout


def certificate_fingerprint_pem(certificate_pem: str) -> str:
    try:
        return certificate_fingerprint(ssl.PEM_cert_to_DER_cert(certificate_pem))
    except ValueError as exc:
        raise ValidationError("certificate PEM is invalid") from exc


def _certificate_public_key(path: Path) -> str:
    return _openssl(["x509", "-in", str(path), "-pubkey", "-noout"])


def _certificate_subject(path: Path, *, request: bool = False) -> str:
    kind = "req" if request else "x509"
    output = _openssl(
        [kind, "-in", str(path), "-noout", "-subject", "-nameopt", "RFC2253"]
    ).strip()
    if not output.startswith("subject="):
        raise ProtocolError("certificate subject could not be validated")
    return output.removeprefix("subject=")


def _require_worker_subject(path: Path, worker_id: str, *, request: bool = False) -> None:
    if _certificate_subject(path, request=request) != f"CN={worker_id}":
        raise ProtocolError("certificate subject does not match approved worker identity")


def _verify_certificate_chain(ca_certificate: Path, certificate: Path) -> None:
    _openssl(["verify", "-CAfile", str(ca_certificate), str(certificate)])


def _require_ca_key_pair(ca_certificate: Path, ca_key: Path) -> None:
    certificate_key = _certificate_public_key(ca_certificate)
    private_key = _openssl(["pkey", "-in", str(ca_key), "-pubout"])
    if public_key_identity(certificate_key) != public_key_identity(private_key):
        raise ProtocolError("CA certificate does not match the configured CA private key")


def build_enrollment_material(
    authorization: Mapping[str, Any],
    *,
    controller_id: str,
    controller_host: str,
    controller_port: int,
    controller_certificate_pem: str,
) -> dict[str, Any]:
    token = authorization.get("token")
    authorization_id = authorization.get("authorization_id")
    if not isinstance(token, str) or not isinstance(authorization_id, str):
        raise ValidationError("authorization lacks one-time enrollment material")
    controller_host = _host(controller_host)
    if not 1 <= controller_port <= 65535:
        raise ValidationError("controller port is invalid")
    certificate = _pem(controller_certificate_pem, "controller certificate")
    return attach_identity(
        {
            "schema_version": MATERIAL_SCHEMA,
            "authorization_id": authorization_id,
            "token": token,
            "expires_at": authorization.get("expires_at"),
            "expected_worker_identity": authorization.get("expected_worker_identity"),
            "controller_id": _identity(controller_id, "controller_id"),
            "controller_host": controller_host,
            "controller_port": controller_port,
            "controller_certificate_fingerprint": certificate_fingerprint_pem(certificate),
        },
        "material_identity",
    )


def validate_enrollment_material(value: Mapping[str, Any]) -> dict[str, Any]:
    expected = {
        "schema_version", "authorization_id", "token", "expires_at",
        "expected_worker_identity", "controller_id", "controller_host",
        "controller_port", "controller_certificate_fingerprint", "material_identity",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        raise ValidationError("enrollment material fields are invalid")
    checked = dict(value)
    identity = checked.pop("material_identity", None)
    if checked.get("schema_version") != MATERIAL_SCHEMA or sha256_identity(checked) != identity:
        raise ValidationError("enrollment material identity is invalid")
    _identity(checked.get("controller_id"), "controller_id")
    _host(checked.get("controller_host"))
    if not isinstance(checked.get("controller_port"), int) or not 1 <= checked["controller_port"] <= 65535:
        raise ValidationError("controller port is invalid")
    return dict(value)


def prepare_join_request(
    material: Mapping[str, Any],
    *,
    worker_id: str,
    state_root: Path,
    hostname: str | None = None,
    operating_system: str | None = None,
    architecture: str | None = None,
) -> dict[str, Any]:
    enrollment = validate_enrollment_material(material)
    worker_id = _identity(worker_id, "worker_id")
    expected = enrollment.get("expected_worker_identity")
    if expected is not None and expected != worker_id:
        raise ProtocolError("enrollment material is bound to another worker identity")
    root = _safe_root(state_root)
    tls = root / "tls"
    tls.mkdir(mode=0o700, exist_ok=True)
    key = tls / "worker.key"
    csr = tls / "worker.csr"
    public_key = tls / "worker-public.pem"
    if not key.exists():
        _openssl(["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072", "-out", str(key)])
        os.chmod(key, 0o600)
    elif key.is_symlink():
        raise StorageError("worker private key path is a symbolic link")
    _openssl(["req", "-new", "-key", str(key), "-subj", f"/CN={worker_id}", "-out", str(csr)])
    _write_private(public_key, _openssl(["pkey", "-in", str(key), "-pubout"]))
    request = LifecycleStore(root / "join-local.jsonl").build_request(
        worker_identity=worker_id,
        public_key_pem=public_key.read_text(encoding="ascii"),
        hostname_hint=hostname or platform.node() or worker_id,
        operating_system=operating_system or platform.system().lower(),
        architecture=architecture or platform.machine().lower(),
        authorization_id=str(enrollment["authorization_id"]),
        metadata={"commissioning": "explicit-file-handoff"},
    )
    result = attach_identity(
        {
            "schema_version": JOIN_SCHEMA,
            "material": enrollment,
            "request": request,
            "certificate_request_pem": _pem(csr.read_text(encoding="ascii"), "certificate request"),
        },
        "join_identity",
    )
    write_protected_json(root / "join-request.json", result)
    return result


def validate_join_request(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "schema_version", "material", "request", "certificate_request_pem", "join_identity"
    }:
        raise ValidationError("worker join request fields are invalid")
    unsigned = {key: value[key] for key in value if key != "join_identity"}
    if value.get("schema_version") != JOIN_SCHEMA or sha256_identity(unsigned) != value.get("join_identity"):
        raise ValidationError("worker join request identity is invalid")
    material = validate_enrollment_material(value["material"])
    request = value.get("request")
    if not isinstance(request, Mapping) or request.get("authorization_id") != material["authorization_id"]:
        raise ValidationError("worker request is not bound to enrollment material")
    _pem(value.get("certificate_request_pem"), "certificate request")
    return dict(value)


def submit_join_request(lifecycle: LifecycleStore, value: Mapping[str, Any]) -> dict[str, Any]:
    join = validate_join_request(value)
    return lifecycle.submit_request(join["request"], str(join["material"]["token"]))


def issue_worker_credentials(
    lifecycle: LifecycleStore,
    value: Mapping[str, Any],
    *,
    ca_certificate: Path,
    ca_key: Path,
    controller_certificate: Path,
    controller_trust_state: Path,
    days: int = 365,
) -> dict[str, Any]:
    join = validate_join_request(value)
    request = lifecycle.request(str(join["request"]["request_id"]))
    if request.get("status") != "APPROVED":
        raise ProtocolError("worker credentials require explicit enrollment approval")
    if not 1 <= days <= 825:
        raise ValidationError("certificate lifetime is outside the bounded range")
    ca_pem = _pem(Path(ca_certificate).read_text(encoding="ascii"), "CA certificate")
    controller_pem = _pem(
        Path(controller_certificate).read_text(encoding="ascii"), "controller certificate"
    )
    material = join["material"]
    if certificate_fingerprint_pem(controller_pem) != material["controller_certificate_fingerprint"]:
        raise ProtocolError("controller certificate does not match enrollment material")
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        ca = root / "ca.pem"
        controller = root / "controller.pem"
        csr = root / "worker.csr"
        certificate = root / "worker.pem"
        _write_private(ca, ca_pem)
        _write_private(controller, controller_pem)
        _write_private(csr, str(join["certificate_request_pem"]))
        _require_ca_key_pair(ca, Path(ca_key))
        _verify_certificate_chain(ca, controller)
        worker_id = str(request["worker_identity"])
        _require_worker_subject(csr, worker_id, request=True)
        csr_public = _openssl(["req", "-in", str(csr), "-pubkey", "-noout"])
        if public_key_identity(csr_public) != request["public_key_identity"]:
            raise ProtocolError("certificate request does not match approved worker key")
        serial = "0x" + secrets.token_hex(16)
        _openssl([
            "x509", "-req", "-in", str(csr), "-CA", str(ca),
            "-CAkey", str(ca_key), "-set_serial", serial, "-days", str(days),
            "-sha256", "-out", str(certificate),
        ])
        _verify_certificate_chain(ca, certificate)
        _require_worker_subject(certificate, worker_id)
        if public_key_identity(_certificate_public_key(certificate)) != request["public_key_identity"]:
            raise ProtocolError("issued certificate does not preserve the approved worker key")
        worker_pem = _pem(certificate.read_text(encoding="ascii"), "worker certificate")
    fingerprint = certificate_fingerprint_pem(worker_pem)
    TrustStore(controller_trust_state).enroll(
        "worker", worker_id, fingerprint, metadata={"request_id": request["request_id"]}
    )
    return attach_identity(
        {
            "schema_version": CREDENTIAL_SCHEMA,
            "worker_id": worker_id,
            "request_id": request["request_id"],
            "public_key_identity": request["public_key_identity"],
            "controller_id": material["controller_id"],
            "controller_host": material["controller_host"],
            "controller_port": material["controller_port"],
            "controller_certificate_fingerprint": material["controller_certificate_fingerprint"],
            "ca_certificate_pem": ca_pem,
            "controller_certificate_pem": controller_pem,
            "worker_certificate_pem": worker_pem,
        },
        "credential_identity",
    )


def activate_worker_credentials(value: Mapping[str, Any], *, state_root: Path) -> dict[str, Any]:
    if not isinstance(value, Mapping) or value.get("schema_version") != CREDENTIAL_SCHEMA:
        raise ValidationError("worker credential document is invalid")
    unsigned = {key: value[key] for key in value if key != "credential_identity"}
    if set(value) != set(unsigned) | {"credential_identity"} or sha256_identity(unsigned) != value.get("credential_identity"):
        raise ValidationError("worker credential identity is invalid")
    root = _safe_root(state_root)
    tls = root / "tls"
    key = tls / "worker.key"
    if not key.is_file() or key.is_symlink():
        raise StorageError("locally generated worker private key is missing or unsafe")
    worker_id = _identity(value.get("worker_id"), "worker_id")
    controller_id = _identity(value.get("controller_id"), "controller_id")
    controller_host = _host(value.get("controller_host"))
    controller_port = value.get("controller_port")
    if not isinstance(controller_port, int) or not 1 <= controller_port <= 65535:
        raise ValidationError("controller port is invalid")
    worker_pem = _pem(value.get("worker_certificate_pem"), "worker certificate")
    controller_pem = _pem(value.get("controller_certificate_pem"), "controller certificate")
    if certificate_fingerprint_pem(controller_pem) != value.get("controller_certificate_fingerprint"):
        raise ProtocolError("credential controller certificate pin is invalid")
    ca_pem = _pem(value.get("ca_certificate_pem"), "CA certificate")
    with tempfile.TemporaryDirectory() as directory:
        validation = Path(directory)
        staged_worker = validation / "worker.pem"
        staged_ca = validation / "ca.pem"
        staged_controller = validation / "controller.pem"
        _write_private(staged_worker, worker_pem)
        _write_private(staged_ca, ca_pem)
        _write_private(staged_controller, controller_pem)
        local_public = _openssl(["pkey", "-in", str(key), "-pubout"])
        certificate_public = _certificate_public_key(staged_worker)
        certificate_identity = public_key_identity(certificate_public)
        if public_key_identity(local_public) != certificate_identity:
            raise ProtocolError("issued certificate does not match the local worker private key")
        if certificate_identity != value.get("public_key_identity"):
            raise ProtocolError("issued certificate does not match the approved worker key identity")
        _require_worker_subject(staged_worker, worker_id)
        _verify_certificate_chain(staged_ca, staged_worker)
        _verify_certificate_chain(staged_ca, staged_controller)

    worker_cert = tls / "worker.pem"
    ca_cert = tls / "ca.pem"
    controller_cert = tls / "controller.pem"
    _write_private(worker_cert, worker_pem)
    _write_private(ca_cert, ca_pem)
    _write_private(controller_cert, controller_pem)
    TrustStore(root / "worker-trust.jsonl").enroll(
        "controller", controller_id, str(value["controller_certificate_fingerprint"])
    )
    environment_values = {
        "controller_id": controller_id,
        "controller_host": controller_host,
        "controller_port": controller_port,
        "bundle_root": root / "bundles",
        "worker_state": root / "worker.jsonl",
        "trust_state": root / "worker-trust.jsonl",
        "ca": ca_cert,
        "certificate": worker_cert,
        "key": key,
    }
    environment_values = {
        name: _environment_value(item, name) for name, item in environment_values.items()
    }
    environment = "\n".join(
        [
            f"MNCS_FABRIC_CONTROLLER_ID={environment_values['controller_id']}",
            f"MNCS_FABRIC_CONTROLLER_HOST={environment_values['controller_host']}",
            f"MNCS_FABRIC_CONTROLLER_PORT={environment_values['controller_port']}",
            f"MNCS_FABRIC_BUNDLE_ROOT={environment_values['bundle_root']}",
            f"MNCS_FABRIC_WORKER_STATE={environment_values['worker_state']}",
            f"MNCS_FABRIC_TRUST_STATE={environment_values['trust_state']}",
            f"MNCS_FABRIC_CA={environment_values['ca']}",
            f"MNCS_FABRIC_CERTIFICATE={environment_values['certificate']}",
            f"MNCS_FABRIC_CERTIFICATE_KEY={environment_values['key']}",
            f"MNCS_FABRIC_CONTAINMENT_MODE={'required' if sys.platform.startswith('linux') else 'compatibility-uncontained'}",
            "",
        ]
    )
    _write_private(root / "worker.env", environment)
    state = attach_identity(
        {
            "schema_version": STATE_SCHEMA,
            "worker_id": worker_id,
            "controller_id": controller_id,
            "controller_host": controller_host,
            "controller_port": controller_port,
            "public_key_identity": value["public_key_identity"],
            "credential_identity": value["credential_identity"],
            "lifecycle": "ENROLLED",
            "environment_file": str(root / "worker.env"),
        },
        "installation_identity",
    )
    write_protected_json(root / "installation.json", state)
    return state
