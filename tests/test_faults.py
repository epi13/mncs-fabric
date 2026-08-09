from __future__ import annotations

import unittest

from mncs_fabric.errors import ProtocolError
from mncs_fabric.faults import FaultInjectingTransport, FaultPlan


class _Transport:
    def __init__(self) -> None:
        self.calls = 0

    def request(self, envelope: dict[str, object]) -> dict[str, object]:
        self.calls += 1
        return {"message_type": "execution.result", "payload": {"result_identity": "same"}}


class FaultTests(unittest.TestCase):
    def test_duplicate_is_exercised_without_semantic_duplicate(self) -> None:
        underlying = _Transport()
        result = FaultInjectingTransport(underlying, FaultPlan("duplicate-request")).request({})
        self.assertEqual(result["payload"]["result_identity"], "same")
        self.assertEqual(underlying.calls, 2)

    def test_drop_is_explicit_and_delay_is_bounded(self) -> None:
        with self.assertRaises(ProtocolError):
            FaultInjectingTransport(_Transport(), FaultPlan("drop-request")).request({})
        with self.assertRaises(ValueError):
            FaultInjectingTransport(_Transport(), FaultPlan("drop-result"))
