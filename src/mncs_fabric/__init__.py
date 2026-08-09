"""MNCS Fabric: bounded execution and evidence primitives."""

__version__ = "0.2.0a2"

from .api import ConsumerContext, FabricClient, RemoteWorkerConfig

__all__ = ["ConsumerContext", "FabricClient", "RemoteWorkerConfig", "__version__"]
