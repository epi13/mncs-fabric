"""MNCS Fabric: bounded execution and evidence primitives."""

__version__ = "0.2.0a4"

from .api import ConsumerContext, FabricClient, LocalWorkerConfig, RemoteWorkerConfig

__all__ = ["ConsumerContext", "FabricClient", "LocalWorkerConfig", "RemoteWorkerConfig", "__version__"]
