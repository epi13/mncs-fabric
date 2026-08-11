"""MNCS Fabric: bounded execution and evidence primitives."""

__version__ = "0.2.0a13"

from .api import ConsumerContext, FabricClient, LocalWorkerConfig, RemoteWorkerConfig
from .capabilities import CAPABILITY_OBSERVATION_SCHEMA
from .runtime import RuntimeProfile
from .registry import RegistryWorker, WorkerRegistry, WORKER_REGISTRY_SCHEMA

__all__ = [
    "CAPABILITY_OBSERVATION_SCHEMA", "ConsumerContext", "FabricClient",
    "LocalWorkerConfig", "RegistryWorker", "RemoteWorkerConfig", "RuntimeProfile",
    "WORKER_REGISTRY_SCHEMA", "WorkerRegistry", "__version__",
]
