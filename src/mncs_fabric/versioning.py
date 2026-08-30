"""Deterministic Fabric package version comparison.

Prerelease numbers are integers.  A release (no ``aN`` suffix) sorts after
every alpha of the same X.Y.Z.  Invalid strings do not produce mixed-type
tuples and never compare greater than a valid version.
"""

from __future__ import annotations

from dataclasses import dataclass

RELEASE_PRERELEASE = 10**9


@dataclass(frozen=True, order=True)
class FabricVersion:
    major: int
    minor: int
    patch: int
    prerelease: int

    @property
    def is_prerelease(self) -> bool:
        return self.prerelease < RELEASE_PRERELEASE

    def as_tuple(self) -> tuple[int, int, int, int]:
        return (self.major, self.minor, self.patch, self.prerelease)


def parse_fabric_version(value: str | None) -> FabricVersion | None:
    """Parse ``X.Y.Z`` or ``X.Y.ZaN``.  Return None when the string is not a Fabric version."""

    if not isinstance(value, str) or not value or len(value) > 32 or "\x00" in value:
        return None
    core, sep, pre = value.partition("a")
    if sep and (not pre or not pre.isdigit()):
        return None
    parts = core.split(".")
    if not 1 <= len(parts) <= 3:
        return None
    numbers: list[int] = []
    for item in parts:
        if not item.isdigit():
            return None
        numbers.append(int(item))
    while len(numbers) < 3:
        numbers.append(0)
    prerelease = int(pre) if sep else RELEASE_PRERELEASE
    return FabricVersion(numbers[0], numbers[1], numbers[2], prerelease)


def classify_worker_version(version: str | None, *, minimum: FabricVersion) -> str:
    parsed = parse_fabric_version(version)
    if parsed is None:
        return "unsupported"
    if parsed >= minimum:
        return "current"
    if parsed >= FabricVersion(0, 2, 0, 6):
        return "upgradeable"
    if parsed > FabricVersion(0, 0, 0, 0):
        return "bootstrap-required"
    return "unsupported"
