"""Stable public Fabric application boundary for CLI and future Forge adapters."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .bundles import bind_receipt_to_bundle, verify_bundle_archive
from .canonical import verify_identity
from .errors import ValidationError
from .executor import execute_local
from .models import COHORT_SCHEMA, EXECUTION_SCHEMA, validate_job_plan
from .node import capability_names, collect_node_capabilities
from .reconcile import reconcile_records
from .lifecycle import LifecycleStore


class FabricService:
    """Typed, machine-readable service operations with no CLI or Forge imports."""

    def nodes(self, label: str) -> dict[str, Any]:
        return collect_node_capabilities(label)

    def capabilities(self, label: str) -> dict[str, Any]:
        node = self.nodes(label)
        return {"schema_version": node["schema_version"], "node_fingerprint": node["node_fingerprint"], "machine_label": node["machine_label"], "capabilities": sorted(capability_names(node))}

    def validate_plan(self, plan: object) -> dict[str, Any]:
        return validate_job_plan(plan)

    def execute_local(self, plan: object, root: Path, manifest: object, label: str, *, results_dir: Path | None = None, work_root: Path | None = None) -> dict[str, Any]:
        return execute_local(plan, root, manifest, label, results_dir=results_dir, work_root=work_root)

    def verify_record(self, record: object) -> dict[str, Any]:
        if not isinstance(record, dict):
            raise ValidationError("record must be an object")
        schema = record.get("schema_version")
        field = "record_id" if schema == EXECUTION_SCHEMA else "cohort_id" if schema == COHORT_SCHEMA else None
        if field is None or not verify_identity(record, field):
            return {"outcome": "FAIL", "reason": "record identity does not verify"}
        return {"outcome": "PASS", "identity": record[field]}

    def collect(self, record: object) -> dict[str, Any]:
        if not isinstance(record, dict):
            raise ValidationError("record must be an object")
        return record

    def reconcile(self, records: list[dict[str, Any]], *, require_distinct_nodes: bool = True) -> dict[str, Any]:
        return reconcile_records(records, require_distinct_nodes=require_distinct_nodes)

    def verify_execution_bundle(self, archive: Path, *, expected_bundle_identity: str | None = None, expected_archive_identity: str | None = None) -> dict[str, Any]:
        return verify_bundle_archive(archive, expected_bundle_identity=expected_bundle_identity, expected_archive_identity=expected_archive_identity).as_dict()

    def bind_receipt_to_execution_bundle(self, receipt: object, archive: Path) -> dict[str, Any]:
        bundle = verify_bundle_archive(archive)
        return bind_receipt_to_bundle(receipt, bundle).as_dict()

    def lifecycle(self, state_path: Path) -> LifecycleStore:
        """Open controller-owned lifecycle state without exposing ledger internals."""

        return LifecycleStore(Path(state_path))
