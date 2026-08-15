from __future__ import annotations

import unittest
from unittest.mock import patch

from mncs_fabric.certify import certify_inventory, format_certification, validate_certification
from tests.test_inventory import sample_inventory


class CertificationTests(unittest.TestCase):
    def test_build_node_does_not_require_models(self) -> None:
        inventory = sample_inventory(models=[], harness="0.1.0")
        # Pretend ollama is absent so this is a build-only node.
        payload = dict(inventory)
        payload.pop("inventory_identity")
        payload["runtimes"] = [{
            "name": "ollama",
            "present": False,
            "install_type": "absent",
            "service_type": "absent",
            "endpoint": None,
            "version": None,
            "reachable": False,
            "models": [],
        }]
        from mncs_fabric.inventory import build_worker_inventory

        rebuilt = build_worker_inventory(
            worker_id=payload["worker_identity"],
            identity=payload["identity"],
            hardware=payload["hardware"],
            fabric=payload["fabric"],
            tools=payload["tools"],
            runtimes=payload["runtimes"],
            repositories=payload["repositories"],
            services=[item for item in payload["services"] if item["name"] != "ollama"] + [{
                "name": "ollama", "present": False, "manager": "absent", "unit": None, "state": "absent", "install_type": "absent",
            }],
            health=payload["health"],
            credentials=payload["credentials"],
            captured_at=payload["captured_at"],
        )
        result = certify_inventory(rebuilt, profiles=["mncs-linux-worker", "mncs-build-worker"])
        checked = validate_certification(result)
        ollama = next(layer for layer in checked["layers"] if layer["name"] == "ollama")
        inference = next(layer for layer in checked["layers"] if layer["name"] == "inference")
        self.assertFalse(ollama["applicable"])
        self.assertFalse(inference["applicable"])
        self.assertEqual(checked["disposition"], "CERTIFIED")

    def test_inference_failure_names_the_layer(self) -> None:
        inventory = sample_inventory(harness="0.1.0")
        result = certify_inventory(
            inventory,
            profiles=["mncs-inference-worker"],
            inference_probe={"status": "FAIL", "detail": "generate failed"},
        )
        self.assertEqual(result["disposition"], "FAILED")
        self.assertEqual(result["failing_layer"], "inference")
        summary = format_certification(result)
        self.assertIn("FAILED", summary)
        self.assertIn("failing layer: inference", summary)

    def test_generic_inference_probe_does_not_hardcode_a_model(self) -> None:
        inventory = sample_inventory(models=[{"name": "brand-new-model:latest", "digest": None, "size_bytes": None, "family": None, "parameter_size": None, "quantization": None}])
        with patch("mncs_fabric.certify.probe_inference", return_value={"status": "PASS", "detail": "generic generate succeeded on brand-new-model:latest"}):
            result = certify_inventory(inventory, profiles=["mncs-inference-worker"])
        self.assertNotIn("granite", result["layers"][8]["detail"].lower())
        self.assertIn("brand-new-model", next(layer["detail"] for layer in result["layers"] if layer["name"] == "inference"))

    def test_probe_uses_requested_model_not_inventory_order(self) -> None:
        inventory = sample_inventory(models=[
            {"name": "aaa:1", "digest": None, "size_bytes": 1, "family": None, "parameter_size": None, "quantization": None},
            {"name": "zzz:1", "digest": None, "size_bytes": 1, "family": None, "parameter_size": None, "quantization": None},
        ])
        from mncs_fabric.certify import probe_inference

        with patch("urllib.request.urlopen") as opener:
            class _Resp:
                def read(self, _n):
                    return b'{"response":"pong","done":true}'
                def __enter__(self):
                    return self
                def __exit__(self, *args):
                    return False
            opener.return_value = _Resp()
            probed = probe_inference(inventory, model="zzz:1")
        self.assertEqual(probed["model"], "zzz:1")
        self.assertEqual(probed["status"], "PASS")
