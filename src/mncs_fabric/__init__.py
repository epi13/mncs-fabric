"""MNCS Fabric: bounded execution and evidence primitives."""

__version__ = "0.2.0a6"

from .api import ConsumerContext, FabricClient, LocalWorkerConfig, RemoteWorkerConfig
from .runtime import RuntimeProfile

__all__ = ["ConsumerContext", "FabricClient", "LocalWorkerConfig", "RemoteWorkerConfig", "RuntimeProfile", "__version__"]
