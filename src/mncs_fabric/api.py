"""Stable consumer-facing Fabric API.

This facade composes the existing controller, worker, transport, and trust
boundaries.  Consumers do not need to assemble those implementation objects or
reconstruct Fabric receipts.  It remains an execution substrate: consumer
contexts are opaque provenance and never evaluator or promotion authority.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from . import __version__
from .capabilities import (
    MAX_CAPABILITY_AGE_SECONDS,
    build_capability_observation,
    capability_observation_is_fresh,
    validate_capability_observation,
)
from .contracts import (
    CONSUMER_RESULT_SCHEMA,
    ConsumerContext,
    build_provenance_binding,
    build_public_contract,
    validate_consumer_context,
)
from .controller import LocalController, NetworkController
from .bundle_transfer import MAX_CHUNK_BYTES, transfer_archive
from .bundles import verify_bundle_archive
from .canonical import is_sha256_identity, sha256_identity
from .collections import build_execution_collection, validate_execution_collection
from .enrollment import TrustStore
from .errors import ProtocolError, TransportTimeoutError, ValidationError
from .protocol import dispatch_request_identity
from .receipts import verify_execution_receipt
from .resources import (
    PlacementRequest,
    build_placement_binding,
    validate_placement_observation,
    validate_resource_snapshot,
)
from .runtime import (
    build_runtime_binding,
    build_runtime_capability_observation,
    build_runtime_environment,
    build_runtime_observation,
    validate_runtime_environment,
    validate_runtime_observation,
    validate_runtime_profile,
)
from .service import FabricService
from .transport import InProcessTransport, TLSNetworkTransport
from .targets import ExecutionTargetReference, validate_execution_target_reference
from .service_transport import ServiceClientTransport
from .worker import LocalWorker
from .models import validate_job_plan
from .scheduler import WorkerSlot, schedule
from .registry import WorkerRegistry
from .lifecycle import LifecycleStore


@dataclass(frozen=True, slots=True)
class LocalWorkerConfig:
    """Consumer-safe configuration for one in-process worker."""

    worker_id: str
    bundle_root: Path
    state_path: Path
    concurrency_limit: int = 1
    bundle_cache_root: Path | None = None

    def __post_init__(self) -> None:
        if not self.worker_id or self.concurrency_limit < 1:
            raise ValidationError("local worker identity or concurrency limit is invalid")
        if not Path(self.bundle_root).is_dir():
            raise ValidationError(f"local worker bundle root is unavailable: {self.bundle_root}")


@dataclass(frozen=True, slots=True)
class RemoteWorkerConfig:
    """Validated operator configuration for one enrolled TLS worker."""

    worker_id: str
    host: str
    port: int
    capabilities: tuple[str, ...]
    ca_file: Path
    client_certificate: Path
    client_key: Path
    trust_state: Path
    concurrency_limit: int = 1
    timeout: float = 5.0
    connect_timeout: float | None = None
    control_timeout: float | None = None
    execution_timeout_overhead: float = 5.0
    resource_snapshot: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        if not self.worker_id or not self.host or not 1 <= self.port <= 65535:
            raise ValidationError("remote worker identity, host, or port is invalid")
        if not self.capabilities or len(set(self.capabilities)) != len(self.capabilities):
            raise ValidationError("remote worker capabilities must be unique and non-empty")
        if (
            self.concurrency_limit < 1
            or self.timeout <= 0
            or (self.connect_timeout is not None and self.connect_timeout <= 0)
            or (self.control_timeout is not None and self.control_timeout <= 0)
            or not 0 < self.execution_timeout_overhead <= 300
        ):
            raise ValidationError("remote worker bounds are invalid")
        for field in ("ca_file", "client_certificate", "client_key", "trust_state"):
            value = Path(getattr(self, field))
            if not value.is_file():
                raise ValidationError(f"remote worker {field} is unavailable: {value}")
        if self.resource_snapshot is not None:
            validate_resource_snapshot(self.resource_snapshot, error_type=ValidationError)
            if self.resource_snapshot.get("worker_identity") != self.worker_id:
                raise ValidationError("remote worker resource snapshot identity does not match worker_id")

    def public_dict(self) -> dict[str, Any]:
        return {
            "worker_id": self.worker_id,
            "host": self.host,
            "port": self.port,
            "capabilities": list(self.capabilities),
            "concurrency_limit": self.concurrency_limit,
            "connect_timeout": self.connect_timeout or self.timeout,
            "control_timeout": self.control_timeout or self.timeout,
            "execution_timeout_overhead": self.execution_timeout_overhead,
            "transport": "tls-mutual-authenticated",
            "resource_snapshot_identity": self.resource_snapshot.get("resource_snapshot_identity") if self.resource_snapshot else None,
            "capability_source": "operator-declared",
        }


def _context_payload(context: ConsumerContext | Mapping[str, Any] | None) -> tuple[ConsumerContext | None, dict[str, Any] | None]:
    if context is None:
        return None, None
    if isinstance(context, ConsumerContext):
        return context, context.to_dict()
    checked = validate_consumer_context(dict(context), error_type=ValidationError)
    return ConsumerContext(
        source_project=checked["source_project"],
        consumer_workload_identity=checked["consumer_workload_identity"],
        experiment_identity=checked["experiment_identity"],
        forge_workflow_identity=checked["forge_workflow_identity"],
        provider_identity=checked["provider_identity"],
        partition_identity=checked["partition_identity"],
    ), checked


def _consumer_result(response: Mapping[str, Any], context: ConsumerContext | None) -> dict[str, Any]:
    payload = response.get("payload") if isinstance(response.get("payload"), dict) else {}
    record = payload.get("record") if isinstance(payload.get("record"), dict) else None
    receipt = payload.get("receipt") if isinstance(payload.get("receipt"), dict) else None
    execution_bundle = payload.get("execution_bundle") if isinstance(payload.get("execution_bundle"), dict) else None
    record_identity = record.get("record_id") if record else None
    receipt_identity = receipt.get("receipt_identity") if receipt else None
    result: dict[str, Any] = {
        "schema_version": CONSUMER_RESULT_SCHEMA,
        "disposition": payload.get("disposition", "EXECUTED") if isinstance(payload, dict) else response.get("disposition", "UNKNOWN"),
        "worker_identity": response.get("worker_id"),
        "request_identity": response.get("request_id"),
        "job_identity": record.get("job_identity") if record else None,
        "record": record,
        "record_identity": record_identity,
        "receipt": receipt,
        "receipt_identity": receipt_identity,
        "bundle_identity": execution_bundle.get("bundle_identity") if execution_bundle else (record.get("artifact_manifest_identity") if record else None),
        "challenge_identity": (receipt.get("extensions", {}).get("mncs-fabric:challenge-identity") if receipt else None),
    }
    if isinstance(payload.get("placement_admission"), dict):
        result["placement_admission"] = dict(payload["placement_admission"])
    if isinstance(payload.get("resource_snapshot"), dict):
        result["resource_snapshot"] = dict(payload["resource_snapshot"])
    if isinstance(payload.get("runtime_observation"), dict):
        result["runtime_observation"] = dict(payload["runtime_observation"])
    if isinstance(payload.get("runtime_binding"), dict):
        result["runtime_binding"] = dict(payload["runtime_binding"])
    if isinstance(payload.get("runtime_capability_observation"), dict):
        result["runtime_capability_observation"] = dict(payload["runtime_capability_observation"])
    if isinstance(payload.get("runtime_capability_binding"), dict):
        result["runtime_capability_binding"] = dict(payload["runtime_capability_binding"])
    if context is not None:
        result["consumer_context_identity"] = context.context_identity
        result["provenance_binding"] = build_provenance_binding(
            context=context,
            request_identity=result["request_identity"],
            job_identity=result["job_identity"],
            worker_identity=result["worker_identity"],
            record_identity=record_identity,
            receipt_identity=receipt_identity,
            bundle_identity=result["bundle_identity"],
            challenge_identity=result["challenge_identity"],
        )
    return result


class FabricClient:
    """The documented entrypoint for local and authenticated remote consumers."""

    def __init__(self, controller_id: str, state_path: Path, *, lifecycle_state_path: Path | None = None) -> None:
        if not controller_id:
            raise ValidationError("controller_id is required")
        self.controller_id = controller_id
        self.state_path = Path(state_path)
        self._service_transport: ServiceClientTransport | None = None
        self.service = FabricService()
        # The default preserves embedded compatibility.  A persistent
        # controller can supply its Fabric-owned lifecycle path explicitly;
        # closing this client never writes a worker-disconnected event.
        lifecycle_path = lifecycle_state_path or self.state_path.with_name(self.state_path.stem + "-lifecycle" + self.state_path.suffix)
        self.lifecycle = LifecycleStore(lifecycle_path)
        self.local = LocalController(controller_id, self.state_path)
        self.network = NetworkController(controller_id, self.state_path.with_name(self.state_path.stem + "-network" + self.state_path.suffix))
        self.remote_configs: dict[str, RemoteWorkerConfig] = {}
        self.bundle_links: dict[str, dict[str, str]] = {}
        self.runtime_observations: dict[str, dict[str, Any]] = {}
        self.runtime_capability_observations: dict[str, dict[str, Any]] = {}
        self.registry_entries: dict[str, dict[str, Any]] = {}
        self.registry_errors: dict[str, str] = {}
        self.blocked_worker_ids: set[str] = set()

    @classmethod
    def connect(
        cls,
        socket_path: Path,
        *,
        client_identity: str = "consumer",
        timeout: float = 5.0,
    ) -> "FabricClient":
        """Connect to a Fabric-owned persistent controller consumer surface.

        Service mode does not load controller ledgers, worker keys, or
        endpoint registries into the consumer process.  The existing
        constructor remains the embedded compatibility mode.
        """

        client = cls.__new__(cls)
        client.controller_id = "persistent"
        client.state_path = Path(socket_path)
        client.service = FabricService()
        client.lifecycle = None
        client.local = None
        client.network = None
        client.remote_configs = {}
        client.bundle_links = {}
        client.runtime_observations = {}
        client.runtime_capability_observations = {}
        client.registry_entries = {}
        client.registry_errors = {}
        client.blocked_worker_ids = set()
        client._service_transport = ServiceClientTransport(Path(socket_path), client_identity=client_identity, timeout=timeout)
        return client

    def close(self) -> None:
        """Close only this client connection; never claim worker disconnect."""

        self._service_transport = None

    def _service_payload(self, operation: str, arguments: Mapping[str, Any] | None = None) -> dict[str, Any]:
        if self._service_transport is None:
            raise ProtocolError("client is not connected to a persistent service")
        return self._service_transport.request(operation, arguments)

    def _require_embedded(self, operation: str) -> None:
        if self._service_transport is not None:
            raise ProtocolError(f"{operation} is not implemented over the persistent service boundary")

    @staticmethod
    def contract() -> dict[str, Any]:
        return build_public_contract(__version__)

    def register_local_worker(self, worker: Any) -> dict[str, Any]:
        self._require_embedded("local worker registration")
        if isinstance(worker, LocalWorkerConfig):
            worker = LocalWorker(worker.worker_id, worker.bundle_root, worker.state_path, concurrency_limit=worker.concurrency_limit, bundle_cache_root=worker.bundle_cache_root)
        if worker.worker_id in self.remote_configs:
            raise ProtocolError(f"worker identity is already registered remotely: {worker.worker_id}")
        return self.local.register(worker)

    def register_remote_worker(self, config: RemoteWorkerConfig) -> dict[str, Any]:
        self._require_embedded("remote worker registration")
        if config.worker_id in self.local.workers:
            raise ProtocolError(f"worker identity is already registered locally: {config.worker_id}")
        if config.worker_id in self.remote_configs:
            raise ProtocolError(f"worker is already registered: {config.worker_id}")
        for worker_id, existing in self.remote_configs.items():
            if (
                existing.host.casefold() == config.host.casefold()
                and existing.port == config.port
                and worker_id != config.worker_id
            ):
                raise ProtocolError(
                    "remote endpoint is already registered to another worker identity"
                )
        transport = TLSNetworkTransport(
            config.host,
            config.port,
            ca_file=config.ca_file,
            client_cert=config.client_certificate,
            client_key=config.client_key,
            expected_worker_id=config.worker_id,
            trust_store=TrustStore(config.trust_state),
            timeout=config.timeout,
            connect_timeout=config.connect_timeout,
            control_timeout=config.control_timeout,
            execution_timeout_overhead=config.execution_timeout_overhead,
        )
        self.network.register_remote(config.worker_id, frozenset(config.capabilities), transport, concurrency_limit=config.concurrency_limit, resource_snapshot=config.resource_snapshot)
        self.remote_configs[config.worker_id] = config
        return {"outcome": "PASS", **config.public_dict()}

    def load_registry(self, path: Path, *, strict: bool = False) -> dict[str, Any]:
        self._require_embedded("endpoint registry loading")
        """Load known endpoints from local operator state without weakening trust.

        Structurally valid entries remain visible even when their referenced
        trust material is missing or revoked.  Only entries that produce a
        validated ``RemoteWorkerConfig`` are registered for transport.
        """

        registry = WorkerRegistry(Path(path), controller_id=self.controller_id)
        workers = registry.load()
        self.registry_entries = {
            worker.worker_id: worker.public_dict() for worker in workers
        }
        self.registry_errors = {}
        registered: list[str] = []
        for worker in workers:
            try:
                existing = self.remote_configs.get(worker.worker_id)
                if existing is not None:
                    if (
                        existing.host.casefold() != worker.host.casefold()
                        or existing.port != worker.port
                    ):
                        raise ProtocolError(
                            "explicit worker and registry entry disagree on endpoint identity"
                        )
                    registered.append(worker.worker_id)
                    continue
                self.register_remote_worker(worker.to_remote_config())
                registered.append(worker.worker_id)
            except Exception as exc:
                self.registry_errors[worker.worker_id] = str(exc)
        if strict and self.registry_errors:
            detail = "; ".join(
                f"{worker_id}: {error}"
                for worker_id, error in sorted(self.registry_errors.items())
            )
            raise ProtocolError(f"worker registry could not be loaded: {detail}")
        return {
            "outcome": "PASS" if not self.registry_errors else "UNKNOWN",
            "registry_path": str(Path(path).expanduser()),
            "known_workers": sorted(self.registry_entries),
            "registered_workers": sorted(registered),
            "errors": dict(sorted(self.registry_errors.items())),
        }

    def refresh_worker(self, worker_id: str) -> dict[str, Any]:
        """Refresh one remote worker through authenticated Fabric protocol."""

        self._require_embedded("worker refresh")
        if worker_id not in self.remote_configs:
            raise ProtocolError(f"worker is not registered: {worker_id}")
        return self.network.refresh_remote(worker_id)

    def refresh_workers(self) -> list[dict[str, Any]]:
        self._require_embedded("worker refresh")
        return self.network.refresh_all()

    def runtime_profile(self, worker_id: str) -> dict[str, Any]:
        """Return the worker's authenticated/observed runtime profile."""

        self._require_embedded("runtime profile access")
        if worker_id in self.local.workers:
            return self.local.workers[worker_id].runtime_profile()
        state = self.network.worker_state(worker_id)
        description = state.get("description")
        if not isinstance(description, dict) or not isinstance(description.get("runtime_profile"), dict):
            raise ProtocolError("worker has no runtime profile observation; refresh it first")
        return validate_runtime_profile(description["runtime_profile"], expected_worker_id=worker_id)

    def ingest_runtime_observation(
        self,
        worker_id: str,
        probe: Mapping[str, Any],
        *,
        runtime_profile: Mapping[str, Any] | None = None,
        captured_at: str | None = None,
    ) -> dict[str, Any]:
        """Validate optional provider probe output without requiring a receipt."""

        profile = runtime_profile or self.runtime_profile(worker_id)
        observation = build_runtime_observation(worker_identity=worker_id, runtime_profile=profile, probe=probe, captured_at=captured_at)
        self.local.ledger.append("runtime.observation", observation) if worker_id in self.local.workers else self.network.ledger.append("runtime.observation", observation)
        self.runtime_observations[worker_id] = observation
        if worker_id in self.network.remote_workers:
            self.network.set_runtime_observation(worker_id, observation)
        return observation

    def ingest_runtime_capability_observation(
        self,
        worker_id: str,
        capability: str,
        status: str,
        evidence: Mapping[str, Any],
        *,
        components: Mapping[str, str],
        runtime_profile: Mapping[str, Any] | None = None,
        captured_at: str | None = None,
    ) -> dict[str, Any]:
        """Ingest proof for a capability of one exact operator-provisioned runtime."""

        profile = runtime_profile or self.runtime_profile(worker_id)
        environment = build_runtime_environment(runtime_profile=profile, components=components, captured_at=captured_at)
        observation = build_runtime_capability_observation(worker_identity=worker_id, runtime_profile=profile, runtime_environment=environment, capability=capability, status=status, evidence=evidence, captured_at=captured_at)
        validate_runtime_environment(environment, expected_worker_id=worker_id, expected_profile_identity=profile["runtime_profile_identity"])
        self.local.ledger.append("runtime.capability-observation", observation) if worker_id in self.local.workers else self.network.ledger.append("runtime.capability-observation", observation)
        self.runtime_capability_observations[worker_id] = observation
        if worker_id in self.network.remote_workers:
            self.network.set_runtime_capability_observation(worker_id, observation)
        return observation

    @staticmethod
    def bind_runtime_observation(result: Mapping[str, Any], observation: Mapping[str, Any]) -> dict[str, Any]:
        worker_id = result.get("worker_identity")
        if not isinstance(worker_id, str):
            raise ProtocolError("consumer result has no worker identity")
        binding = build_runtime_binding(
            observation=observation,
            worker_identity=worker_id,
            request_identity=result.get("request_identity"),
            record_identity=result.get("record_identity"),
            receipt_identity=result.get("receipt_identity"),
        )
        validate_runtime_observation(observation, expected_worker_id=worker_id)
        return binding

    def _capability_ledger(self, worker_id: str):
        self._require_embedded("capability observation access")
        if worker_id in self.local.workers:
            return self.local.ledger
        if worker_id in self.remote_configs:
            return self.network.ledger
        raise ProtocolError(f"worker is not registered: {worker_id}")

    def ingest_capability_observation(
        self,
        worker_id: str,
        capabilities: list[Mapping[str, Any]] | tuple[Mapping[str, Any], ...],
        *,
        availability: str = "AVAILABLE",
        captured_at: str | None = None,
        observation_source: str = "consumer-bounded-worker-probe",
        status_reason: str | None = None,
    ) -> dict[str, Any]:
        """Validate and durably retain one worker-bound capability observation."""

        if self._service_transport is not None:
            return dict(
                self._service_payload(
                    "worker.capability.ingest",
                    {
                        "worker_id": worker_id,
                        "capabilities": [dict(item) for item in capabilities],
                        "availability": availability,
                        "captured_at": captured_at,
                        "observation_source": observation_source,
                        "status_reason": status_reason,
                    },
                ).get("observation", {})
            )

        ledger = self._capability_ledger(worker_id)
        observation = build_capability_observation(
            worker_identity=worker_id,
            capabilities=capabilities,
            availability=availability,
            captured_at=captured_at,
            observation_source=observation_source,
            status_reason=status_reason,
        )
        validate_capability_observation(observation, expected_worker_id=worker_id)
        ledger.append("worker.capability-observation", observation)
        return observation

    def capability_observations(
        self,
        worker_id: str,
        *,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        """Return retained observations in append order for one registered worker."""

        if self._service_transport is not None:
            return [
                dict(item)
                for item in self._service_payload(
                    "worker.capability.observations",
                    {"worker_id": worker_id, "limit": limit},
                ).get("observations", [])
            ]

        ledger = self._capability_ledger(worker_id)
        observations: list[dict[str, Any]] = []
        for entry in ledger.records(record_type="worker.capability-observation", limit=limit):
            record = entry["record"]
            if record.get("worker_identity") != worker_id:
                continue
            observations.append(
                validate_capability_observation(record, expected_worker_id=worker_id)
            )
        return observations

    def latest_capability_observation(self, worker_id: str) -> dict[str, Any] | None:
        observations = self.capability_observations(worker_id)
        return observations[-1] if observations else None

    def capability_inventory(
        self,
        worker_id: str,
        *,
        max_age_seconds: float = MAX_CAPABILITY_AGE_SECONDS,
        now: str | None = None,
    ) -> dict[str, Any]:
        """Return current/stale/unknown status without discarding retained evidence."""

        observation = self.latest_capability_observation(worker_id)
        if self._service_transport is not None:
            worker_availability = str(
                self.fleet_status(worker_id).get("availability", "UNKNOWN")
            )
        elif worker_id in self.local.workers:
            worker_availability = "AVAILABLE"
        else:
            worker_availability = str(
                self.network.worker_state(worker_id).get("availability", "UNKNOWN")
            )
        fresh = bool(
            observation
            and capability_observation_is_fresh(
                observation,
                max_age_seconds=max_age_seconds,
                now=now,
            )
        )
        if worker_availability != "AVAILABLE":
            status = "UNAVAILABLE" if worker_availability == "UNAVAILABLE" else "UNKNOWN"
        elif observation is None:
            status = "UNKNOWN"
        elif not fresh:
            status = "STALE"
        elif observation["availability"] == "AVAILABLE":
            status = "CURRENT"
        else:
            status = observation["availability"]
        return {
            "worker_identity": worker_id,
            "status": status,
            "fresh": fresh,
            "worker_availability": worker_availability,
            "observation": dict(observation) if observation is not None else None,
        }

    def workers(
        self,
        *,
        capability_max_age_seconds: float = MAX_CAPABILITY_AGE_SECONDS,
    ) -> list[dict[str, Any]]:
        if self._service_transport is not None:
            return list(self._service_payload("fleet.list").get("workers", []))
        local = [{**item, "transport": "in-process", "source": "local"} for item in self.local.inspect()]
        remote = [{**self.network.worker_state(worker_id), "source": "remote"} for worker_id in sorted(self.remote_configs)]
        known_unregistered = [
            {
                **entry,
                "source": "registry",
                "availability": "UNKNOWN",
                "available": False,
                "capabilities": list(entry.get("capabilities", [])),
                "diagnostic": self.registry_errors.get(worker_id),
                "registry_status": "INVALID_REFERENCE",
                "capability_inventory_status": "UNKNOWN",
                "capability_observation_fresh": False,
                "capability_observation": None,
            }
            for worker_id, entry in sorted(self.registry_entries.items())
            if worker_id not in self.remote_configs
        ]
        workers = local + remote + known_unregistered
        for worker in workers:
            if worker.get("worker_id") in self.blocked_worker_ids:
                worker.update({
                    "membership_status": "REVOKED",
                    "availability": "UNAVAILABLE",
                    "available": False,
                    "liveness": "REVOKED",
                })
                continue
            if worker.get("source") == "registry":
                continue
            inventory = self.capability_inventory(
                str(worker["worker_id"]),
                max_age_seconds=capability_max_age_seconds,
            )
            worker["capability_inventory_status"] = inventory["status"]
            worker["capability_observation_fresh"] = inventory["fresh"]
            worker["capability_observation"] = inventory["observation"]
        return workers

    def execute(
        self,
        plan: object,
        manifest: object,
        *,
        worker_id: str | None = None,
        replicas: int = 1,
        request_id: str | None = None,
        challenge: dict[str, Any] | None = None,
        consumer_context: ConsumerContext | Mapping[str, Any] | None = None,
        execution_bundle: dict[str, str] | None = None,
        execution_bundle_archive: Path | None = None,
        placement: PlacementRequest | Mapping[str, Any] | None = None,
        runtime_observation: Mapping[str, Any] | None = None,
        runtime_capability_observation: Mapping[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        if worker_id is not None and worker_id in self.blocked_worker_ids:
            raise ProtocolError("worker Fabric membership is not active")
        if self._service_transport is not None:
            context, context_value = _context_payload(consumer_context)
            placement_value = placement.to_dict() if isinstance(placement, PlacementRequest) else (dict(placement) if placement is not None else None)
            bundle_reference = (
                self._upload_service_bundle(Path(execution_bundle_archive))
                if execution_bundle_archive is not None
                else None
            )
            payload = self._service_payload(
                "execution.dispatch",
                {
                    "plan": dict(plan),
                    "manifest": dict(manifest),
                    "worker_id": worker_id,
                    "replicas": replicas,
                    "request_id": request_id,
                    "challenge": challenge,
                    "consumer_context": context_value,
                    "placement": placement_value,
                    "runtime_observation": dict(runtime_observation) if runtime_observation is not None else None,
                    "runtime_capability_observation": dict(runtime_capability_observation) if runtime_capability_observation is not None else None,
                    "execution_bundle_reference": bundle_reference,
                },
            )
            return [dict(item) for item in payload.get("results", [])]
        self._require_embedded("execution")
        context, context_value = _context_payload(consumer_context)
        placement_value = placement.to_dict() if isinstance(placement, PlacementRequest) else (dict(placement) if placement is not None else None)
        if (
            execution_bundle is None
            and worker_id is not None
            and execution_bundle_archive is None
        ):
            execution_bundle = self.bundle_links.get(worker_id)
        if worker_id is not None and worker_id in self.local.workers:
            outputs = []
            worker = self.local.workers[worker_id]
            for index in range(replicas):
                selected_runtime = dict(runtime_observation or self.runtime_observations.get(worker_id)) if (runtime_observation or self.runtime_observations.get(worker_id)) else None
                selected_capability = dict(runtime_capability_observation or self.runtime_capability_observations.get(worker_id)) if (runtime_capability_observation or self.runtime_capability_observations.get(worker_id)) else None
                rid = request_id or dispatch_request_identity(plan=self.service.validate_plan(plan), manifest=dict(manifest), challenge=challenge, consumer_context=context_value, execution_bundle=execution_bundle, placement_request=placement_value, runtime_observation=selected_runtime, runtime_capability_observation=selected_capability) + f":{index}"
                outputs.append(self.local.dispatch_via(InProcessTransport(worker), plan, manifest, worker_id=worker_id, request_id=rid, challenge=challenge, consumer_context=context_value, execution_bundle=execution_bundle, placement_request=placement_value, runtime_observation=selected_runtime, runtime_capability_observation=selected_capability))
            return [_consumer_result(response, context) for response in outputs]
        if worker_id is None and self.remote_configs and (
            self.local.workers
            or placement_value is not None
            or execution_bundle_archive is not None
        ):
            return self._execute_registered(plan, manifest, replicas=replicas, request_id=request_id, challenge=challenge, context=context, context_value=context_value, execution_bundle=execution_bundle, execution_bundle_archive=execution_bundle_archive, placement_value=placement_value, runtime_observation=runtime_observation, runtime_capability_observation=runtime_capability_observation)
        if worker_id is not None or self.remote_configs:
            if worker_id is not None and worker_id not in self.remote_configs:
                raise ProtocolError(f"worker is not registered: {worker_id}")
            if worker_id is not None:
                if execution_bundle is None and execution_bundle_archive is not None:
                    report = self.ensure_bundle(worker_id, execution_bundle_archive)
                    execution_bundle = {
                        "bundle_identity": report["bundle_identity"],
                        "archive_identity": report["archive_identity"],
                    }
                transport, _ = self.network.remote_workers[worker_id]
                selected_runtime = dict(runtime_observation or self.runtime_observations.get(worker_id)) if (runtime_observation or self.runtime_observations.get(worker_id)) else None
                selected_capability = dict(runtime_capability_observation or self.runtime_capability_observations.get(worker_id)) if (runtime_capability_observation or self.runtime_capability_observations.get(worker_id)) else None
                response = self.network.dispatch_via(transport, plan, manifest, worker_id=worker_id, request_id=request_id or dispatch_request_identity(plan=self.service.validate_plan(plan), manifest=dict(manifest), challenge=challenge, consumer_context=context_value, execution_bundle=execution_bundle, placement_request=placement_value, runtime_observation=selected_runtime, runtime_capability_observation=selected_capability), challenge=challenge, consumer_context=context_value, execution_bundle=execution_bundle, placement_request=placement_value, runtime_observation=selected_runtime, runtime_capability_observation=selected_capability)
                return [_consumer_result(response, context)]
            responses = self.network.dispatch_remote(plan, manifest, replicas=replicas, request_id=request_id, challenge=challenge, consumer_context=context_value, execution_bundle=execution_bundle, placement_request=placement_value, runtime_observation=runtime_observation, runtime_capability_observation=runtime_capability_observation)
            return [_consumer_result(response, context) for response in responses]
        responses = self.local.dispatch(plan, manifest, replicas=replicas, request_id=request_id, consumer_context=context_value, execution_bundle=execution_bundle, placement_request=placement_value, runtime_observation=dict(runtime_observation) if runtime_observation else None, runtime_capability_observation=dict(runtime_capability_observation) if runtime_capability_observation else None)
        return [_consumer_result(response, context) for response in responses]

    def submit_execution(
        self,
        plan: object,
        manifest: object,
        *,
        worker_id: str | None = None,
        replicas: int = 1,
        request_id: str | None = None,
        idempotency_key: str | None = None,
        consumer_context: ConsumerContext | Mapping[str, Any] | None = None,
        execution_bundle_archive: Path,
        placement: PlacementRequest | Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Persist and enqueue execution, returning before worker completion."""

        if self._service_transport is None:
            raise ProtocolError("detached execution requires a persistent service client")
        _context, context_value = _context_payload(consumer_context)
        placement_value = (
            placement.to_dict()
            if isinstance(placement, PlacementRequest)
            else (dict(placement) if placement is not None else None)
        )
        bundle_reference = self._upload_service_bundle(Path(execution_bundle_archive))
        return self._service_payload(
            "execution.submit",
            {
                "plan": dict(plan),
                "manifest": dict(manifest),
                "worker_id": worker_id,
                "replicas": replicas,
                "request_id": request_id,
                "idempotency_key": idempotency_key,
                "consumer_context": context_value,
                "placement": placement_value,
                "execution_bundle_reference": bundle_reference,
            },
        )

    def execution_status(self, work_id: str) -> dict[str, Any]:
        if self._service_transport is None:
            raise ProtocolError("detached execution status requires a persistent service client")
        return self._service_payload("execution.status", {"work_id": work_id})

    def execution_result(self, work_id: str) -> dict[str, Any]:
        if self._service_transport is None:
            raise ProtocolError("detached execution result requires a persistent service client")
        return self._service_payload("execution.result", {"work_id": work_id})

    def executions(self, *, limit: int = 100) -> list[dict[str, Any]]:
        if self._service_transport is None:
            raise ProtocolError("detached execution listing requires a persistent service client")
        return list(self._service_payload("execution.list", {"limit": limit}).get("work", []))

    def _upload_service_bundle(self, archive: Path) -> dict[str, str]:
        """Transfer a verified archive without exposing consumer filesystem paths."""

        candidate = Path(archive).expanduser()
        if candidate.is_symlink():
            raise ProtocolError("persistent execution bundle must not be a symbolic link")
        archive = candidate.resolve(strict=True)
        if not archive.is_file():
            raise ProtocolError("persistent execution bundle must be a regular file")
        report = verify_bundle_archive(archive)
        if not report.valid or report.bundle_identity is None or report.archive_identity is None:
            raise ProtocolError("persistent service will not accept an unverified execution bundle")
        total_bytes = archive.stat().st_size
        chunk_bytes = min(32 * 1024, MAX_CHUNK_BYTES)
        chunk_count = (total_bytes + chunk_bytes - 1) // chunk_bytes
        transfer_id = "service-" + sha256_identity(
            {
                "bundle_identity": report.bundle_identity,
                "archive_identity": report.archive_identity,
            }
        )[7:39]
        base = {
            "transfer_id": transfer_id,
            "bundle_identity": report.bundle_identity,
            "archive_identity": report.archive_identity,
            "total_bytes": total_bytes,
            "chunk_bytes": chunk_bytes,
            "chunk_count": chunk_count,
        }
        offered = self._service_payload("execution.bundle.begin", base)
        if offered.get("status") == "TRANSFER_REQUIRED":
            next_sequence = offered.get("next_sequence")
            received_bytes = offered.get("received_bytes")
            if (
                not isinstance(next_sequence, int)
                or not 0 <= next_sequence <= chunk_count
                or received_bytes != min(next_sequence * chunk_bytes, total_bytes)
            ):
                raise ProtocolError("persistent service returned invalid bundle progress")
            with archive.open("rb") as stream:
                stream.seek(int(received_bytes))
                for sequence in range(next_sequence, chunk_count):
                    data = stream.read(chunk_bytes)
                    accepted = self._service_payload(
                        "execution.bundle.chunk",
                        {
                            "transfer_id": transfer_id,
                            "bundle_identity": report.bundle_identity,
                            "archive_identity": report.archive_identity,
                            "sequence": sequence,
                            "data": base64.b64encode(data).decode("ascii"),
                        },
                    )
                    if accepted.get("status") != "ACCEPTED":
                        raise ProtocolError("persistent service rejected an execution bundle chunk")
            committed = self._service_payload("execution.bundle.commit", base)
            if committed.get("status") not in {"COMMITTED", "ALREADY_PRESENT"}:
                raise ProtocolError("persistent service did not commit the execution bundle")
        elif offered.get("status") != "ALREADY_PRESENT":
            raise ProtocolError("persistent service rejected the execution bundle offer")
        return {
            "bundle_identity": report.bundle_identity,
            "archive_identity": report.archive_identity,
        }

    def execute_target(
        self,
        target: ExecutionTargetReference | Mapping[str, Any],
        plan: object,
        manifest: object,
        *,
        consumer_context: ConsumerContext | Mapping[str, Any],
        consumer_authorization_identity: str,
        execution_bundle_archive: Path,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        """Execute one bounded workload on one exact consumer-selected target.

        The authorization identity is bound as consumer provenance only. Fabric
        authenticates the local peer and exact request but does not interpret
        the identity as semantic policy permission.
        """

        if self._service_transport is None:
            raise ProtocolError("target-aware execution requires a persistent controller connection")
        if request_id is not None and not is_sha256_identity(request_id):
            raise ValidationError("target execution request identity is invalid")
        context, context_value = _context_payload(consumer_context)
        if context is None or context_value is None:
            raise ValidationError("target-aware execution requires consumer context")
        target_value = target.to_dict() if isinstance(target, ExecutionTargetReference) else dict(target)
        checked_target = validate_execution_target_reference(
            target_value, expected_consumer_context_identity=context.context_identity
        )
        checked_plan = validate_job_plan(plan)
        if not isinstance(manifest, dict) or manifest.get("manifest_identity") != checked_plan["artifact_manifest_identity"]:
            raise ProtocolError("target dispatch requires a matching manifest")
        bundle_reference = self._upload_service_bundle(Path(execution_bundle_archive))
        execution_request_identity = request_id or sha256_identity({
            "operation": "execution.target.dispatch",
            "target_identity": checked_target["target_identity"],
            "job_identity": checked_plan["job_identity"],
            "manifest_identity": manifest["manifest_identity"],
            "bundle_identity": bundle_reference["bundle_identity"],
            "archive_identity": bundle_reference["archive_identity"],
            "consumer_context_identity": context.context_identity,
            "consumer_authorization_identity": consumer_authorization_identity,
        })
        payload = self._service_payload(
            "execution.target.dispatch",
            {
                "target": checked_target,
                "plan": checked_plan,
                "manifest": dict(manifest),
                "consumer_context": context_value,
                "consumer_authorization_identity": consumer_authorization_identity,
                "execution_request_identity": execution_request_identity,
                "execution_bundle_reference": bundle_reference,
            },
        )
        result = payload.get("result")
        if not isinstance(result, dict):
            raise ProtocolError("persistent controller returned no target execution result")
        return dict(result)

    def _execute_registered(self, plan: object, manifest: object, *, replicas: int, request_id: str | None, challenge: dict[str, Any] | None, context: ConsumerContext | None, context_value: dict[str, Any] | None, execution_bundle: dict[str, str] | None, execution_bundle_archive: Path | None, placement_value: dict[str, Any] | None, runtime_observation: Mapping[str, Any] | None, runtime_capability_observation: Mapping[str, Any] | None) -> list[dict[str, Any]]:
        """Schedule across registered local and remote workers deterministically."""

        checked = validate_job_plan(plan)
        if placement_value is not None:
            self.network.refresh_all()
        local_items = [(worker_id, WorkerSlot(worker_id=worker_id, capabilities=worker.capabilities(), resource_snapshot=worker.resource_snapshot() if placement_value is not None else None, runtime_observation=self.runtime_observations.get(worker_id), runtime_capability_observation=self.runtime_capability_observations.get(worker_id))) for worker_id, worker in self.local.workers.items() if worker_id not in self.blocked_worker_ids]
        remote_items = [(worker_id, slot) for worker_id, (_, slot) in self.network.remote_workers.items() if worker_id not in self.blocked_worker_ids]
        decision = schedule(checked, [slot for _, slot in local_items + remote_items], replicas=replicas, placement=placement_value)
        if decision.disposition != "PASS":
            return [{"schema_version": CONSUMER_RESULT_SCHEMA, "disposition": decision.disposition, "worker_identity": None, "request_identity": None, "job_identity": checked["job_identity"], "record": None, "record_identity": None, "receipt": None, "receipt_identity": None, "reason": decision.reason, "admissions": [dict(item) for item in decision.admissions]}]
        outputs: list[dict[str, Any]] = []
        for worker_id in decision.worker_ids:
            remote_bundle = execution_bundle
            if remote_bundle is None and execution_bundle_archive is None:
                remote_bundle = self.bundle_links.get(worker_id)
            if worker_id in self.remote_configs and remote_bundle is None and execution_bundle_archive is not None:
                report = self.ensure_bundle(worker_id, execution_bundle_archive)
                remote_bundle = {
                    "bundle_identity": report["bundle_identity"],
                    "archive_identity": report["archive_identity"],
                }
            selected_runtime = dict(runtime_observation or self.runtime_observations.get(worker_id)) if (runtime_observation or self.runtime_observations.get(worker_id)) else None
            selected_capability = dict(runtime_capability_observation or self.runtime_capability_observations.get(worker_id)) if (runtime_capability_observation or self.runtime_capability_observations.get(worker_id)) else None
            rid = request_id or dispatch_request_identity(plan=checked, manifest=dict(manifest), challenge=challenge, consumer_context=context_value, execution_bundle=remote_bundle, placement_request=placement_value, runtime_observation=selected_runtime, runtime_capability_observation=selected_capability)
            rid = rid + ":" + worker_id
            try:
                if worker_id in self.local.workers:
                    response = self.local.dispatch_via(InProcessTransport(self.local.workers[worker_id]), checked, manifest, worker_id=worker_id, request_id=rid, challenge=challenge, consumer_context=context_value, execution_bundle=execution_bundle, placement_request=placement_value, runtime_observation=selected_runtime, runtime_capability_observation=selected_capability)
                else:
                    transport, _ = self.network.remote_workers[worker_id]
                    response = self.network.dispatch_via(transport, checked, manifest, worker_id=worker_id, request_id=rid, challenge=challenge, consumer_context=context_value, execution_bundle=remote_bundle, placement_request=placement_value, runtime_observation=selected_runtime, runtime_capability_observation=selected_capability)
                outputs.append(_consumer_result(response, context))
            except (ProtocolError, OSError, TimeoutError) as exc:
                if worker_id in self.remote_configs:
                    self.network._set_remote_state(worker_id, description=None, state="UNAVAILABLE", failure=str(exc))
                reason = (
                    "TRANSPORT_TIMEOUT"
                    if isinstance(exc, TransportTimeoutError)
                    else "WORKER_UNAVAILABLE"
                )
                outputs.append({"schema_version": CONSUMER_RESULT_SCHEMA, "disposition": "UNKNOWN", "worker_identity": worker_id, "request_identity": rid, "job_identity": checked["job_identity"], "record": None, "record_identity": None, "receipt": None, "receipt_identity": None, "reason": reason, "diagnostic": str(exc)})
        return outputs

    def replicate(self, plan: object, manifest: object, *, replicas: int, consumer_context: ConsumerContext | Mapping[str, Any] | None = None, execution_bundle_archive: Path | None = None, placement: PlacementRequest | Mapping[str, Any] | None = None, runtime_observation: Mapping[str, Any] | None = None, runtime_capability_observation: Mapping[str, Any] | None = None) -> list[dict[str, Any]]:
        self._require_embedded("replication")
        return self.execute(plan, manifest, replicas=replicas, consumer_context=consumer_context, execution_bundle_archive=execution_bundle_archive, placement=placement, runtime_observation=runtime_observation, runtime_capability_observation=runtime_capability_observation)

    def ensure_bundle(self, worker_id: str, archive: Path, *, expected_bundle_identity: str | None = None) -> dict[str, Any]:
        self._require_embedded("bundle transfer")
        """Verify and transfer one typed bundle; arbitrary files are rejected."""

        if worker_id not in self.network.remote_workers:
            raise ProtocolError("native bundle transfer requires a registered remote worker")
        transport, _ = self.network.remote_workers[worker_id]
        result = transfer_archive(transport, controller_id=self.controller_id, worker_id=worker_id, archive=Path(archive), expected_bundle_identity=expected_bundle_identity)
        self.bundle_links[worker_id] = {"bundle_identity": result["bundle_identity"], "archive_identity": result["archive_identity"]}
        return result

    def collect(self, results: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
        return [dict(result) for result in results]

    def collect_work_items(self, work_items: list[Mapping[str, Any]], results: list[Mapping[str, Any]]) -> dict[str, Any]:
        """Collect generic identified work items without interpreting domains."""

        collection = build_execution_collection(work_items, results)
        return validate_execution_collection(collection)

    def verify_collection(self, collection: object) -> dict[str, Any]:
        return validate_execution_collection(collection)

    def reconcile(self, results: list[Mapping[str, Any]], *, require_distinct_nodes: bool = True) -> dict[str, Any]:
        records = [dict(result["record"]) for result in results if isinstance(result.get("record"), dict)]
        if len(records) != len(results):
            return {"outcome": "UNKNOWN", "reason": "one or more worker results are unavailable", "record_count": len(records), "response_count": len(results)}
        return self.service.reconcile(records, require_distinct_nodes=require_distinct_nodes)

    def verify_record(self, record: object) -> dict[str, Any]:
        return self.service.verify_record(record)

    def verify_receipt(self, receipt: object) -> dict[str, Any]:
        return verify_execution_receipt(receipt)

    def verify_execution_bundle(self, archive: Path, **kwargs: Any) -> dict[str, Any]:
        return self.service.verify_execution_bundle(archive, **kwargs)

    def verify_resource_snapshot(self, snapshot: object) -> dict[str, Any]:
        return validate_resource_snapshot(snapshot, error_type=ValidationError)

    def verify_placement_observation(self, observation: object) -> dict[str, Any]:
        return validate_placement_observation(observation, error_type=ValidationError)

    def bind_placement_observation(self, result: Mapping[str, Any], observation: Mapping[str, Any]) -> dict[str, Any]:
        return build_placement_binding(result=result, observation=observation)

    # Lifecycle methods are intentionally thin public delegates.  Consumers
    # receive redacted records and status boundaries, never token material or
    # transport/private-key internals.
    def create_enrollment_authorization(self, **kwargs: Any) -> dict[str, Any]:
        if self._service_transport is not None:
            raise ProtocolError("administrative operation requires FabricAdminClient")
        return self.lifecycle.create_authorization(**kwargs)

    def submit_enrollment_request(self, request: Mapping[str, Any], token: str, *, now: str | None = None) -> dict[str, Any]:
        if self._service_transport is not None:
            raise ProtocolError("administrative operation requires FabricAdminClient")
        return self.lifecycle.submit_request(request, token, now=now)

    def enrollment_authorizations(self, *, now: str | None = None) -> list[dict[str, Any]]:
        if self._service_transport is not None:
            raise ProtocolError("administrative operation requires FabricAdminClient")
        return self.lifecycle.list_authorizations(now=now)

    def enrollment_pending(self, *, now: str | None = None) -> list[dict[str, Any]]:
        if self._service_transport is not None:
            raise ProtocolError("administrative operation requires FabricAdminClient")
        return self.lifecycle.pending_requests(now=now)

    def enrollment_request(self, request_id: str, *, now: str | None = None) -> dict[str, Any]:
        if self._service_transport is not None:
            raise ProtocolError("administrative operation requires FabricAdminClient")
        return self.lifecycle.request(request_id, now=now)

    def approve_enrollment(self, request_id: str, *, worker_id: str | None = None, now: str | None = None) -> dict[str, Any]:
        if self._service_transport is not None:
            raise ProtocolError("administrative operation requires FabricAdminClient")
        return self.lifecycle.approve_request(request_id, worker_id=worker_id, now=now)

    def deny_enrollment(self, request_id: str, *, reason: str = "operator denied enrollment", now: str | None = None) -> dict[str, Any]:
        if self._service_transport is not None:
            raise ProtocolError("administrative operation requires FabricAdminClient")
        return self.lifecycle.deny_request(request_id, reason=reason, now=now)

    def expire_enrollment(self, request_id: str, *, now: str | None = None) -> dict[str, Any]:
        if self._service_transport is not None:
            raise ProtocolError("administrative operation requires FabricAdminClient")
        return self.lifecycle.expire_request(request_id, now=now)

    def fleet(self, *, now: str | None = None) -> list[dict[str, Any]]:
        if self._service_transport is not None:
            return list(self._service_payload("fleet.list").get("workers", []))
        return self.lifecycle.memberships(now=now)

    def fleet_status(self, worker_id: str, *, now: str | None = None) -> dict[str, Any]:
        if self._service_transport is not None:
            return self._service_payload("fleet.status", {"worker_id": worker_id})
        return self.lifecycle.membership(worker_id, now=now)

    def fleet_doctor(self, *, now: str | None = None) -> dict[str, Any]:
        if self._service_transport is not None:
            raise ProtocolError("administrative operation requires FabricAdminClient")
        return self.lifecycle.doctor(now=now)

    def revoke_worker(self, worker_id: str, *, reason: str, now: str | None = None) -> dict[str, Any]:
        if self._service_transport is not None:
            raise ProtocolError("administrative operation requires FabricAdminClient")
        return self.lifecycle.revoke_worker(worker_id, reason=reason, now=now)

    def controller_status(self) -> dict[str, Any]:
        if self._service_transport is None:
            raise ProtocolError("controller status requires a persistent service client")
        return self._service_payload("controller.status")

    def controller_doctor(self) -> dict[str, Any]:
        if self._service_transport is None:
            raise ProtocolError("controller doctor requires a persistent service client")
        return self._service_payload("controller.doctor")

    def authenticate_worker_session(self, worker_id: str, *, public_key_identity: str, session_id: str, generation: int, now: str | None = None) -> dict[str, Any]:
        self._require_embedded("worker session authentication")
        return self.lifecycle.authenticate_session(worker_id, public_key_identity_value=public_key_identity, session_id=session_id, generation=generation, now=now)

    def disconnect_worker_session(self, worker_id: str, *, session_id: str, generation: int, now: str | None = None) -> dict[str, Any]:
        self._require_embedded("worker session disconnect")
        return self.lifecycle.disconnect_session(worker_id, session_id=session_id, generation=generation, now=now)


class FabricAdminClient:
    """Explicit operator surface for a persistent controller."""

    def __init__(self, transport: ServiceClientTransport) -> None:
        if not transport.admin:
            raise ValidationError("FabricAdminClient requires the admin service surface")
        self._transport = transport

    @classmethod
    def connect(cls, socket_path: Path, *, client_identity: str = "operator", timeout: float = 5.0) -> "FabricAdminClient":
        return cls(ServiceClientTransport(Path(socket_path), client_identity=client_identity, admin=True, timeout=timeout))

    def _request(self, operation: str, arguments: Mapping[str, Any] | None = None) -> dict[str, Any]:
        return self._transport.request(operation, arguments)

    def controller_status(self) -> dict[str, Any]:
        return self._request("controller.status")

    def controller_doctor(self) -> dict[str, Any]:
        return self._request("controller.doctor")

    def fleet(self) -> list[dict[str, Any]]:
        return list(self._request("fleet.list").get("workers", []))

    def fleet_status(self, worker_id: str) -> dict[str, Any]:
        return self._request("fleet.status", {"worker_id": worker_id})

    def fleet_doctor(self) -> dict[str, Any]:
        return self._request("fleet.doctor")

    def create_enrollment_authorization(self, **kwargs: Any) -> dict[str, Any]:
        return self._request("enrollment.create", kwargs)

    def enrollment_authorizations(self) -> list[dict[str, Any]]:
        return list(self._request("enrollment.list").get("authorizations", []))

    def enrollment_pending(self) -> list[dict[str, Any]]:
        return list(self._request("enrollment.pending").get("requests", []))

    def enrollment_request(self, request_id: str) -> dict[str, Any]:
        return self._request("enrollment.inspect", {"request_id": request_id})

    def approve_enrollment(self, request_id: str, *, worker_id: str | None = None) -> dict[str, Any]:
        return self._request("enrollment.approve", {"request_id": request_id, "worker_id": worker_id})

    def deny_enrollment(self, request_id: str, *, reason: str = "operator denied enrollment") -> dict[str, Any]:
        return self._request("enrollment.deny", {"request_id": request_id, "reason": reason})

    def expire_enrollment(self, request_id: str) -> dict[str, Any]:
        return self._request("enrollment.expire", {"request_id": request_id})

    def submit_enrollment(self, request: Mapping[str, Any], token: str) -> dict[str, Any]:
        return self._request("enrollment.submit", {"request": dict(request), "token": token})

    def revoke_worker(self, worker_id: str, *, reason: str) -> dict[str, Any]:
        return self._request("worker.revoke", {"worker_id": worker_id, "reason": reason})

    def close(self) -> None:
        self._transport = None  # type: ignore[assignment]


__all__ = [
    "ConsumerContext", "FabricClient", "FabricAdminClient", "LocalWorkerConfig", "RemoteWorkerConfig",
    "ExecutionTargetReference", "PlacementRequest", "WorkerRegistry",
]
