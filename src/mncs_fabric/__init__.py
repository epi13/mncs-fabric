"""MNCS Fabric: bounded execution and evidence primitives."""

__version__ = "0.2.0a11"

from .api import ConsumerContext, FabricClient, LocalWorkerConfig, RemoteWorkerConfig
from .capabilities import CAPABILITY_OBSERVATION_SCHEMA
from .runtime import RuntimeProfile

__all__ = ["CAPABILITY_OBSERVATION_SCHEMA", "ConsumerContext", "FabricClient", "LocalWorkerConfig", "RemoteWorkerConfig", "RuntimeProfile", "__version__"]
