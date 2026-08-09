"""Generic identified work-item and execution-collection contracts."""

from __future__ import annotations

from typing import Any, Mapping

from .canonical import attach_identity, is_sha256_identity, sha256_identity, verify_identity
from .errors import ValidationError

WORK_ITEM_SCHEMA = "mncs-fabric.work-item.v0.1"
COLLECTION_SCHEMA = "mncs-fabric.execution-collection.v0.1"


def _identity(value: object, field: str, *, optional: bool = True) -> str | None:
    if value is None and optional:
        return None
    if not is_sha256_identity(value):
        raise ValidationError(f"{field} must be a sha256 identity")
    return str(value)


def build_work_item(*, job_identity: str, partition_identity: str | None = None, bundle_identity: str | None = None, consumer_context_identity: str | None = None, placement_request_identity: str | None = None, replica_count: int = 1) -> dict[str, Any]:
    _identity(job_identity, "job_identity", optional=False)
    for value, field in ((partition_identity, "partition_identity"), (consumer_context_identity, "consumer_context_identity"), (placement_request_identity, "placement_request_identity")):
        _identity(value, field)
    if bundle_identity is not None and (not isinstance(bundle_identity, str) or len(bundle_identity) != 64 or any(char not in "0123456789abcdef" for char in bundle_identity)):
        raise ValidationError("bundle_identity is invalid")
    if not isinstance(replica_count, int) or isinstance(replica_count, bool) or not 1 <= replica_count <= 64:
        raise ValidationError("replica_count is outside its bound")
    return attach_identity({
        "schema_version": WORK_ITEM_SCHEMA,
        "job_identity": job_identity,
        "partition_identity": partition_identity,
        "bundle_identity": bundle_identity,
        "consumer_context_identity": consumer_context_identity,
        "placement_request_identity": placement_request_identity,
        "replica_count": replica_count,
    }, "work_item_identity")


def validate_work_item(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema_version") != WORK_ITEM_SCHEMA:
        raise ValidationError("unsupported work-item schema")
    required = {"schema_version", "job_identity", "partition_identity", "bundle_identity", "consumer_context_identity", "placement_request_identity", "replica_count", "work_item_identity"}
    if set(value) != required or not verify_identity(value, "work_item_identity"):
        raise ValidationError("work-item fields or identity are invalid")
    build = build_work_item(job_identity=value["job_identity"], partition_identity=value["partition_identity"], bundle_identity=value["bundle_identity"], consumer_context_identity=value["consumer_context_identity"], placement_request_identity=value["placement_request_identity"], replica_count=value["replica_count"])
    if build != value:
        raise ValidationError("work-item identity or fields do not verify")
    return dict(value)


def build_execution_collection(work_items: list[Mapping[str, Any]], results: list[Mapping[str, Any]], *, collection_identity: str | None = None) -> dict[str, Any]:
    checked_items = [validate_work_item(dict(item)) for item in work_items]
    item_ids = [item["work_item_identity"] for item in checked_items]
    if not item_ids or len(set(item_ids)) != len(item_ids):
        raise ValidationError("declared work items must be unique and non-empty")
    declaration_identity = sha256_identity({"schema_version": COLLECTION_SCHEMA, "work_item_identities": item_ids})
    entries: list[dict[str, Any]] = []
    by_item: dict[str, list[Mapping[str, Any]]] = {item_id: [] for item_id in item_ids}
    for result in results:
        if not isinstance(result, Mapping) or not is_sha256_identity(result.get("work_item_identity")):
            raise ValidationError("collection result requires a work-item identity")
        item_id = str(result["work_item_identity"])
        if item_id not in by_item:
            raise ValidationError("collection result references an undeclared work item")
        by_item[item_id].append(result)
    for item_id in item_ids:
        candidates = by_item[item_id]
        if not candidates:
            entries.append({"work_item_identity": item_id, "disposition": "MISSING"})
            continue
        for candidate in candidates:
            if candidate.get("disposition") in {"PASS", "EXECUTED"} and not is_sha256_identity(candidate.get("record_identity")):
                raise ValidationError("successful collection result requires a record identity")
            entry = {"work_item_identity": item_id, "disposition": str(candidate.get("disposition", "UNKNOWN")), "worker_identity": candidate.get("worker_identity"), "request_identity": candidate.get("request_identity"), "record_identity": candidate.get("record_identity"), "receipt_identity": candidate.get("receipt_identity")}
            entries.append(entry)
        identities = {candidate.get("record_identity") for candidate in candidates}
        if len(identities) > 1:
            entries.append({"work_item_identity": item_id, "disposition": "CONFLICTING_DUPLICATE"})
        elif len(candidates) > 1:
            entries.append({"work_item_identity": item_id, "disposition": "DUPLICATE_IDEMPOTENT"})
    dispositions = {entry["disposition"] for entry in entries}
    if "CONFLICTING_DUPLICATE" in dispositions or "FAIL" in dispositions:
        outcome = "FAIL"
    elif "MISSING" in dispositions or "UNKNOWN" in dispositions:
        outcome = "UNKNOWN"
    else:
        outcome = "PASS"
    value: dict[str, Any] = {"schema_version": COLLECTION_SCHEMA, "declaration_identity": declaration_identity, "work_item_identities": item_ids, "entries": entries, "outcome": outcome, "claim_boundary": "collection completeness and Fabric evidence only; no consumer semantic verdict"}
    value = attach_identity(value, "collection_identity")
    if collection_identity is not None and value["collection_identity"] != collection_identity:
        raise ValidationError("collection identity does not match")
    return value


def validate_execution_collection(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema_version") != COLLECTION_SCHEMA or not verify_identity(value, "collection_identity"):
        raise ValidationError("collection schema or identity is invalid")
    if not is_sha256_identity(value.get("declaration_identity")) or not isinstance(value.get("work_item_identities"), list) or not value["work_item_identities"] or len(set(value["work_item_identities"])) != len(value["work_item_identities"]):
        raise ValidationError("collection declaration is invalid")
    if not isinstance(value.get("entries"), list) or value.get("outcome") not in {"PASS", "FAIL", "UNKNOWN"}:
        raise ValidationError("collection result is invalid")
    return dict(value)
