"""Semantic-conformance sweep: capability-scheduled plans plus aggregation."""

import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from mncs_fabric import scheduler, semantic_conformance as sc
from mncs_fabric.errors import ValidationError
from mncs_fabric.models import validate_job_plan


def slot(capabilities, identity="test-worker"):
    return scheduler.WorkerSlot(worker_id=identity, capabilities=frozenset(capabilities))


class CapabilityTests(unittest.TestCase):
    def test_tokens_use_verified_inventory_names(self):
        self.assertEqual(
            sc.conformance_capabilities(os="linux", arch="x86_64"),
            ["os:linux", "arch:x86_64", "tool:mncs"],
        )

    def test_rejects_empty_or_wild_values(self):
        for bad in ("", "linux/x86", "LINUX", "a" * 65):
            with self.assertRaises(ValidationError):
                sc.conformance_capabilities(os=bad, arch="x86_64")

    def test_known_backend_sets(self):
        self.assertIn("mncs-portable-wasm-mvp", sc.PORTABLE_BACKENDS)
        self.assertIn("mncs-ptx64", sc.ACCELERATOR_BACKENDS)
        self.assertIn("mncs-riscv32", sc.EMULATED_BACKENDS)
        self.assertEqual(
            len(set(sc.KNOWN_BACKENDS)), len(sc.KNOWN_BACKENDS), "backend sets must not overlap"
        )


class PlanTests(unittest.TestCase):
    def _plan(self, **overrides):
        kwargs = {
            "job_id": "conf:test",
            "program_sha256": "a" * 64,
            "bundle_manifest_sha256": "b" * 64,
            "mncs_argv0": "/usr/local/bin/mncs",
            "program_relpath": "contract.mncs",
            "backend": "mncs-portable-wasm-mvp",
            "seed": 1,
            "cases": 4,
            "step_budget": 4096,
            "os": "linux",
            "arch": "x86_64",
        }
        kwargs.update(overrides)
        return sc.build_conformance_job_plan(**kwargs)

    def test_plan_validates_and_pins_report(self):
        plan = self._plan()
        self.assertEqual(plan["result_paths"], ["conformance-report.json"])
        self.assertEqual(plan["network_policy"], "DECLARED_OFFLINE")
        self.assertIn("tool:mncs", plan["required_capabilities"])
        self.assertIn("--backends", plan["argv"])
        # Already validated; revalidation is stable.
        self.assertEqual(validate_job_plan(plan)["job_identity"], plan["job_identity"])

    def test_plan_rejects_unknown_backend(self):
        with self.assertRaises(ValidationError):
            self._plan(backend="mncs-no-such-backend")

    def test_plan_rejects_relative_binary(self):
        with self.assertRaises(ValidationError):
            self._plan(mncs_argv0="mncs")

    def test_plan_rejects_case_bounds(self):
        for bad in (0, 513):
            with self.assertRaises(ValidationError):
                self._plan(cases=bad)

    def test_sweep_builds_one_plan_per_cell(self):
        cells = [
            {"os": "linux", "arch": "x86_64", "backend": "mncs-portable-wasm-mvp"},
            {"os": "windows", "arch": "x86_64", "backend": "mncs-portable-wasm-mvp"},
        ]
        plans = sc.plan_sweep(
            cells,
            job_id_prefix="conf:sweep",
            program_sha256="a" * 64,
            bundle_manifest_sha256="b" * 64,
            mncs_argv0="/usr/local/bin/mncs",
            program_relpath="contract.mncs",
            seed=1,
            cases=2,
            step_budget=4096,
        )
        self.assertEqual(len(plans), 2)
        self.assertIn("os:windows", plans[1]["required_capabilities"])
        self.assertNotEqual(plans[0]["job_identity"], plans[1]["job_identity"])


class SchedulerPlacementTests(unittest.TestCase):
    def test_capability_scheduling_never_names_machines(self):
        plans = sc.plan_sweep(
            [{"os": "linux", "arch": "x86_64", "backend": "mncs-portable-wasm-mvp"}],
            job_id_prefix="conf:place",
            program_sha256="a" * 64,
            bundle_manifest_sha256="b" * 64,
            mncs_argv0="/usr/local/bin/mncs",
            program_relpath="contract.mncs",
            seed=1,
            cases=2,
            step_budget=4096,
        )
        workers = [slot({"os:linux", "arch:x86_64", "tool:mncs"})]
        decision = scheduler.schedule(plans[0], workers, replicas=1)
        self.assertEqual(decision.disposition, "PASS")
        self.assertEqual(list(decision.worker_ids), ["test-worker"])

    def test_missing_tool_is_unavailable_not_pass(self):
        plans = sc.plan_sweep(
            [{"os": "linux", "arch": "x86_64", "backend": "mncs-portable-wasm-mvp"}],
            job_id_prefix="conf:miss",
            program_sha256="a" * 64,
            bundle_manifest_sha256="b" * 64,
            mncs_argv0="/usr/local/bin/mncs",
            program_relpath="contract.mncs",
            seed=1,
            cases=2,
            step_budget=4096,
        )
        workers = [slot({"os:linux", "arch:x86_64"})]
        decision = scheduler.schedule(plans[0], workers, replicas=1)
        self.assertEqual(decision.disposition, "UNKNOWN")
        self.assertIn("CAPABILITY_UNAVAILABLE", decision.reason)


class AggregateTests(unittest.TestCase):
    def cell(self, os="linux", arch="x86_64", backend="mncs-portable-wasm-mvp"):
        return {"os": os, "arch": arch, "backend": backend}

    def test_fail_dominates(self):
        evidence = sc.aggregate_sweep([
            {"cell": self.cell(), "disposition": "executed-pass", "detail": ""},
            {"cell": self.cell(arch="aarch64"), "disposition": "executed-fail", "detail": "contract violated"},
        ])
        self.assertEqual(evidence["verdict"], "FAIL")
        self.assertEqual(evidence["schema_version"], sc.SWEEP_EVIDENCE_SCHEMA)

    def test_empty_sweep_is_unknown(self):
        evidence = sc.aggregate_sweep([])
        self.assertEqual(evidence["verdict"], "UNKNOWN")

    def test_unplaced_only_is_unknown_with_obligations(self):
        evidence = sc.aggregate_sweep([
            {"cell": self.cell(os="windows"), "disposition": "unplaced", "detail": "CAPABILITY_UNAVAILABLE"},
        ])
        self.assertEqual(evidence["verdict"], "UNKNOWN")
        self.assertEqual(len(evidence["obligations"]), 1)

    def test_pass_with_obligations_stays_pass(self):
        evidence = sc.aggregate_sweep([
            {"cell": self.cell(), "disposition": "executed-pass", "detail": ""},
            {"cell": self.cell(os="windows"), "disposition": "unplaced", "detail": "CAPABILITY_UNAVAILABLE"},
        ])
        self.assertEqual(evidence["verdict"], "PASS")
        self.assertEqual(len(evidence["obligations"]), 1)

    def test_rejects_unknown_disposition(self):
        with self.assertRaises(ValidationError):
            sc.aggregate_sweep([{"cell": self.cell(), "disposition": "passed", "detail": ""}])


class InventoryProbeTests(unittest.TestCase):
    def test_mncs_probe_present_when_on_path(self):
        from mncs_fabric import inventory

        with tempfile.TemporaryDirectory() as tmp:
            fake = Path(tmp) / "mncs"
            fake.write_text("#!/bin/sh\necho 'mncs 0.1.0'\n", encoding="utf-8")
            fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
            with mock.patch.dict(os.environ, {"PATH": tmp}):
                record = inventory._probe_tool("mncs", ("--version",))
        self.assertTrue(record["present"])
        self.assertIn("0.1.0", record.get("version") or "")

    def test_mncs_probe_absent_is_honest_miss(self):
        from mncs_fabric import inventory

        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"PATH": tmp}):
                record = inventory._probe_tool("mncs", ("--version",))
        self.assertFalse(record["present"])

    def test_tool_specs_include_mncs(self):
        from mncs_fabric import inventory

        self.assertIn(("mncs", ("--version",)), inventory.TOOL_SPECS)


class NodeProbeTests(unittest.TestCase):
    def test_node_advertises_mncs_when_on_path(self):
        from mncs_fabric import node

        with tempfile.TemporaryDirectory() as tmp:
            fake = Path(tmp) / "mncs"
            fake.write_text("#!/bin/sh\necho 'mncs 0.1.0'\n", encoding="utf-8")
            fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
            with mock.patch.dict(os.environ, {"PATH": tmp}):
                record = node.collect_node_capabilities("probe-node")
        self.assertIn("mncs", record["tools"])
        self.assertIn("tool:mncs", node.capability_names(record))

    def test_node_omits_mncs_when_absent(self):
        from mncs_fabric import node

        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"PATH": tmp}):
                record = node.collect_node_capabilities("probe-node")
        self.assertNotIn("mncs", record["tools"])
        self.assertNotIn("tool:mncs", node.capability_names(record))


if __name__ == "__main__":
    unittest.main()
