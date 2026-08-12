"""MNCS Fabric: bounded execution and evidence primitives."""

__version__ = "0.2.0a16"

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
]
