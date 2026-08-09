class FabricError(Exception):
    """Base exception for bounded, user-visible Fabric failures."""


class ValidationError(FabricError):
    """Raised when a declared record or plan violates its schema contract."""


class IntegrityError(FabricError):
    """Raised when a content identity or artifact manifest does not verify."""


class ProtocolError(FabricError):
    """Raised when a versioned controller/worker message is unsafe or unsupported."""


class StorageError(FabricError):
    """Raised when durable Fabric state cannot be verified or published."""
