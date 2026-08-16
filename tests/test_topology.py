from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mncs_fabric.canonical import attach_identity
from mncs_fabric.controller import NetworkController
from mncs_fabric.topology import (
    TOPOLOGY_SCHEMA,
    build_topology_snapshot,
    collect_network_topology,
    validate_network_topology,
)
from mncs_fabric.transport import InProcessTransport
from mncs_fabric.worker import LocalWorker


def _observation(worker: str, interface: str, mac: str, address: str, peer_ip: str, peer_mac: str):
    value = {
        "schema_version": TOPOLOGY_SCHEMA,
        "worker_identity": worker,
        "captured_at": "2026-08-15T18:00:00Z",
        "interfaces": [{
            "name": interface,
            "if_index": 4,
            "state": "UP",
            "medium": "usb",
            "speed_mbps": 480,
            "mtu": 1500,
            "mac_address": mac,
            "addresses": [address],
        }],
        "routes": [{"interface": interface, "destination": "10.42.0.0/30", "gateway": None, "metric": 10}],
        "neighbors": [{"ip_address": peer_ip, "mac_address": peer_mac, "interface": interface, "state": "REACHABLE"}],
        "observation_source": "worker-local-os",
        "claim_boundary": "passive test observation; not attestation",
    }
    return attach_identity(value, "topology_identity")


class TopologyTests(unittest.TestCase):
    def test_local_topology_collection_is_identity_bound(self) -> None:
        observation = collect_network_topology("worker-local")
        checked = validate_network_topology(observation, expected_worker_identity="worker-local")
        self.assertEqual(checked["schema_version"], TOPOLOGY_SCHEMA)
        self.assertIsInstance(checked["interfaces"], list)
        self.assertTrue(checked["topology_identity"].startswith("sha256:"))

    def test_usb_peer_observations_project_a_direct_ip_edge(self) -> None:
        left = _observation(
            "worker-a", "usb0", "02:00:00:00:00:0a", "10.42.0.1/30",
            "10.42.0.2", "02:00:00:00:00:0b",
        )
        right = _observation(
            "worker-b", "usb0", "02:00:00:00:00:0b", "10.42.0.2/30",
            "10.42.0.1", "02:00:00:00:00:0a",
        )
        snapshot = build_topology_snapshot([left, right])
        self.assertEqual(len(snapshot["edges"]), 1)
        edge = snapshot["edges"][0]
        self.assertEqual((edge["left_worker"], edge["right_worker"]), ("worker-a", "worker-b"))
        self.assertEqual(edge["medium"], "usb")
        self.assertEqual(edge["transport"], "ip")
        self.assertEqual(edge["speed_mbps"], 480)
        self.assertTrue(edge["direct"])

    def test_refreshed_worker_state_exposes_topology(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "bundle"
            bundle.mkdir()
            worker = LocalWorker("worker-topology", bundle, root / "worker.jsonl")
            controller = NetworkController("controller", root / "controller.jsonl")
            controller.register_remote("worker-topology", worker.capabilities(), InProcessTransport(worker))
            state = controller.refresh_remote("worker-topology")
            self.assertEqual(state["availability"], "AVAILABLE")
            self.assertEqual(state["network_topology"]["worker_identity"], "worker-topology")
            self.assertEqual(state["topology_identity"], state["network_topology"]["topology_identity"])


if __name__ == "__main__":
    unittest.main()
