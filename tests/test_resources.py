from __future__ import annotations

from datetime import datetime, timezone
import unittest

from mncs_fabric.resources import (
    PlacementRequest,
    ResourceSnapshot,
    build_placement_observation,
    evaluate_placement,
    validate_placement_observation,
    validate_resource_snapshot,
)


def _snapshot(*, free_vram: int | None = None, probe: str = "UNKNOWN", precision: dict[str, str] | None = None, host_available: int | None = 8 * 1024**3, captured_at: str | None = None) -> dict[str, object]:
    accelerators = ()
    if free_vram is not None:
        accelerators = ({
            "index": 0,
            "vendor": "nvidia",
            "backend": "cuda",
            "device_name": "fixture-gpu",
            "hardware_identity": "sha256:" + "a" * 64,
            "total_memory_bytes": 8 * 1024**3,
            "free_memory_bytes": free_vram,
            "driver_version": "fixture",
            "runtime_version": "12.4",
            "execution_probe": probe,
            "precision_probes": precision or ({"float32": "PASS"} if probe == "PASS" else {}),
            "observation_source": "fixture",
        },)
    value = ResourceSnapshot(
        worker_identity="worker-a",
        captured_at=captured_at or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        host_memory_total_bytes=16 * 1024**3,
        host_memory_available_bytes=host_available,
        cpu_logical_count=8,
        architecture="x86_64",
        accelerators=accelerators,
        observation_source="fixture",
        node_fingerprint="sha256:" + "b" * 64,
    ).to_dict()
    validate_resource_snapshot(value)
    return value


class ResourcePlacementTests(unittest.TestCase):
    def test_cpu_admission_is_identity_addressable(self) -> None:
        request = PlacementRequest(execution_device="cpu", minimum_host_memory_bytes=1024)
        admission = evaluate_placement(request, _snapshot())
        self.assertEqual(admission["disposition"], "PASS")
        self.assertEqual(admission["admission_mode"], "cpu")
        self.assertEqual(admission["reason_code"], "CPU_ELIGIBLE")
        self.assertEqual(admission["placement_request_identity"], request.placement_request_identity)

    def test_discovered_but_unverified_accelerator_fails_closed(self) -> None:
        request = PlacementRequest(execution_device="accelerator", accelerator_backend="cuda")
        admission = evaluate_placement(request, _snapshot(free_vram=7 * 1024**3))
        self.assertEqual(admission["disposition"], "UNKNOWN")
        self.assertEqual(admission["reason_code"], "ACCELERATOR_EXECUTION_UNVERIFIED")

    def test_full_accelerator_and_sequential_offload_are_distinct(self) -> None:
        snapshot = _snapshot(free_vram=2 * 1024**3, probe="PASS")
        full = evaluate_placement(PlacementRequest(execution_device="accelerator", offload="none", model_storage_bytes=3 * 1024**3), snapshot)
        self.assertEqual(full["reason_code"], "INSUFFICIENT_VRAM")
        offload = evaluate_placement(PlacementRequest(execution_device="accelerator", offload="sequential-cpu", model_storage_bytes=3 * 1024**3, estimated_workspace_bytes=128 * 1024**2, minimum_accelerator_working_bytes=128 * 1024**2, runtime_supports_sequential_cpu_offload=True), snapshot)
        self.assertEqual(offload["disposition"], "PASS")
        self.assertEqual(offload["admission_mode"], "sequential-cpu-offload")
        self.assertEqual(offload["reason_code"], "SEQUENTIAL_CPU_OFFLOAD_ELIGIBLE")

    def test_auto_can_choose_offload_but_explicit_requests_do_not_fallback(self) -> None:
        snapshot = _snapshot(free_vram=2 * 1024**3, probe="PASS")
        auto = evaluate_placement(PlacementRequest(execution_device="auto", offload="auto", model_storage_bytes=3 * 1024**3, runtime_supports_sequential_cpu_offload=True), snapshot)
        self.assertEqual(auto["admission_mode"], "sequential-cpu-offload")
        unsupported = evaluate_placement(PlacementRequest(execution_device="accelerator", offload="sequential-cpu", model_storage_bytes=3 * 1024**3), snapshot)
        self.assertEqual(unsupported["disposition"], "UNKNOWN")
        self.assertEqual(unsupported["reason_code"], "SEQUENTIAL_OFFLOAD_RUNTIME_UNSUPPORTED")

    def test_stale_and_unknown_resources_are_not_treated_as_zero(self) -> None:
        old = "2000-01-01T00:00:00Z"
        request = PlacementRequest(execution_device="accelerator", resource_max_age_seconds=1)
        stale = evaluate_placement(request, _snapshot(free_vram=7 * 1024**3, probe="PASS", captured_at=old))
        self.assertEqual(stale["reason_code"], "RESOURCE_OBSERVATION_STALE")
        unknown = evaluate_placement(PlacementRequest(execution_device="cpu", minimum_host_memory_bytes=1), _snapshot(host_available=None))
        self.assertEqual(unknown["reason_code"], "RESOURCE_OBSERVATION_UNKNOWN")

    def test_placement_observation_substitution_is_detected(self) -> None:
        snapshot = _snapshot()
        request = PlacementRequest(execution_device="cpu")
        admission = evaluate_placement(request, snapshot)
        observation = build_placement_observation(
            worker_identity="worker-a",
            placement_request_identity=request.placement_request_identity,
            resource_snapshot_identity=snapshot["resource_snapshot_identity"],
            admission_decision_identity=admission["decision_identity"],
            planned_mode="cpu",
            actual_mode="cpu",
            precision="float32",
        )
        self.assertEqual(validate_placement_observation(observation)["observation_identity"], observation["observation_identity"])
        changed = dict(observation)
        changed["actual_mode"] = "full-accelerator"
        with self.assertRaises(Exception):
            validate_placement_observation(changed)


if __name__ == "__main__":
    unittest.main()
