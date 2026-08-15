"""MNCS Fabric: bounded execution and evidence primitives."""

__version__ = "0.2.0a29"

from .api import ConsumerContext, FabricAdminClient, FabricClient, LocalWorkerConfig, RemoteWorkerConfig
from .capabilities import CAPABILITY_OBSERVATION_SCHEMA
from .runtime import RuntimeProfile
from .registry import RegistryWorker, WorkerRegistry, WORKER_REGISTRY_SCHEMA
from .lifecycle import (
    AUTHORIZATION_SCHEMA, DECISION_SCHEMA, LIFECYCLE_SCHEMA, MEMBERSHIP_SCHEMA,
    PRESENCE_SCHEMA, REQUEST_SCHEMA, LifecycleStore, default_lifecycle_path,
)
from .controller_service import CONTROLLER_CONFIG_SCHEMA, CONTROLLER_SERVICE_SCHEMA, ControllerConfig, ControllerService
from .service_transport import SERVICE_REQUEST_SCHEMA, SERVICE_RESPONSE_SCHEMA
from .targets import (
    EXECUTION_TARGET_SCHEMA,
    TARGET_ADMISSION_SCHEMA,
    TARGET_EXECUTION_EVIDENCE_SCHEMA,
    ExecutionTargetReference,
    validate_target_admission,
    validate_target_execution_evidence,
)
from .inventory import INVENTORY_SCHEMA
from .desired_state import DESIRED_STATE_SCHEMA, PROFILE_SCHEMA
from .management import MANAGEMENT_STATE_SCHEMA
from .maintenance import PLAN_SCHEMA, RECEIPT_SCHEMA
from .certify import CERTIFICATION_SCHEMA
from .conformance import CONFORMANCE_SCHEMA
from .package_artifact import PACKAGE_ARTIFACT_SCHEMA
from .update_lifecycle import UPDATE_TRANSACTION_SCHEMA

__all__ = [
    "CAPABILITY_OBSERVATION_SCHEMA", "ConsumerContext", "FabricClient", "FabricAdminClient",
    "LocalWorkerConfig", "RegistryWorker", "RemoteWorkerConfig", "RuntimeProfile",
    "WORKER_REGISTRY_SCHEMA", "WorkerRegistry", "__version__",
    "AUTHORIZATION_SCHEMA", "REQUEST_SCHEMA", "DECISION_SCHEMA",
    "MEMBERSHIP_SCHEMA", "PRESENCE_SCHEMA", "LIFECYCLE_SCHEMA",
    "LifecycleStore", "default_lifecycle_path",
    "ControllerConfig", "ControllerService",
    "CONTROLLER_CONFIG_SCHEMA", "CONTROLLER_SERVICE_SCHEMA",
    "SERVICE_REQUEST_SCHEMA", "SERVICE_RESPONSE_SCHEMA",
    "EXECUTION_TARGET_SCHEMA", "TARGET_ADMISSION_SCHEMA",
    "TARGET_EXECUTION_EVIDENCE_SCHEMA", "ExecutionTargetReference",
    "validate_target_admission", "validate_target_execution_evidence",
    "INVENTORY_SCHEMA", "DESIRED_STATE_SCHEMA", "PROFILE_SCHEMA",
    "MANAGEMENT_STATE_SCHEMA", "PLAN_SCHEMA", "RECEIPT_SCHEMA",
    "CERTIFICATION_SCHEMA",
    "CONFORMANCE_SCHEMA",
    "PACKAGE_ARTIFACT_SCHEMA",
    "UPDATE_TRANSACTION_SCHEMA",
]
