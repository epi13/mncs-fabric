"""Capability-aware scheduling: selection, rejection, and explanations.

Every test schedules by capability, never by machine name: fixtures are
named by property (``cuda-worker``), and renaming any worker id must not
change any verdict (``test_names_are_identifiers_only``).
"""

import unittest

from mncs_fabric.capability_resolution import (
    NO_ELIGIBLE_WORKER,
    CapabilityQuery,
    WorkerSnapshot,
    default_env,
    default_policy,
    env_tokens,
    explain_selection,
    policy_tokens,
    resolve_fleet,
    resolve_worker,
    validate_policy,
)
from mncs_fabric.errors import ValidationError
from mncs_fabric.scheduler import WorkerSlot, explain_eligibility, schedule


def fedora_env(**overrides):
    env = dict(default_env())
    env.update({
        "os": "linux",
        "arch": "x86_64",
        "libc": "gnu",
        "init": "systemd",
        "accel": "cuda",
        "cuda_major": 6,
        "cuda_minor": 1,
        "has_ebpf": True,
        "has_wasm": False,
        "has_ptx": False,
        "mem_mib": 16 * 1024,
        "cpu_count": 8,
        "shells": ["bash", "sh"],
    })
    env.update(overrides)
    return env


def stable_policy(**overrides):
    policy = dict(default_policy())
    policy.update(overrides)
    return dict(policy)


def experimental_root_policy():
    return stable_policy(
        experimental=True,
        disposable=True,
        allow_root_mutation=True,
        allow_reboot=True,
        allow_toolchain_install=True,
    )


def snapshot(worker_id, env=None, policy=None, **overrides):
    kwargs = {
        "worker_id": worker_id,
        "capabilities": frozenset(),
        "env": dict(env) if env is not None else fedora_env(),
        "policy": dict(policy) if policy is not None else stable_policy(),
    }
    kwargs.update(overrides)
    return WorkerSnapshot(**kwargs)


def plan(required):
    return {
        "schema_version": "mncs-fabric.job-plan.v0.1",
        "job_id": "cap:test",
        "candidate_identity": "sha256:" + "a" * 64,
        "artifact_manifest_identity": "sha256:" + "b" * 64,
        "argv": ["@python", "task.py"],
        "working_directory": ".",
        "timeout_seconds": 5,
        "output_limit_bytes": 4096,
        "environment": {},
        "required_capabilities": list(required),
        "result_paths": [],
        "network_policy": "UNSPECIFIED",
    }


def slot(worker_id, capabilities, env=None, policy=None, **overrides):
    kwargs = {
        "worker_id": worker_id,
        "capabilities": frozenset(capabilities),
        "worker_env": dict(env) if env is not None else fedora_env(),
        "worker_policy": dict(policy) if policy is not None else stable_policy(),
    }
    kwargs.update(overrides)
    return WorkerSlot(**kwargs)


class MirrorOrderingTests(unittest.TestCase):
    def test_liveness_dominates_everything(self):
        worker = snapshot("w", liveness="UNAVAILABLE", capability_age_seconds=10**6,
                           provenance="consumer-declared")
        resolution = resolve_worker(CapabilityQuery(require_all=frozenset({"os:linux"})), worker)
        self.assertEqual(resolution.code, "WORKER_UNAVAILABLE")
        self.assertFalse(resolution.eligible)

    def test_disconnected_is_not_unavailable(self):
        worker = snapshot("w", liveness="DISCONNECTED")
        resolution = resolve_worker(CapabilityQuery(), worker)
        self.assertEqual(resolution.code, "WORKER_DISCONNECTED")

    def test_stale_beats_missing_capability(self):
        worker = snapshot("w", capability_age_seconds=10**6)
        resolution = resolve_worker(CapabilityQuery(require_all=frozenset({"nope:x"})), worker)
        self.assertEqual(resolution.code, "WORKER_STALE")

    def test_untrusted_provenance_beats_missing_capability(self):
        worker = snapshot("w", provenance="consumer-declared")
        resolution = resolve_worker(CapabilityQuery(require_all=frozenset({"nope:x"})), worker)
        self.assertEqual(resolution.code, "PROVENANCE_UNVERIFIED")

    def test_missing_capability_beats_policy_denial(self):
        worker = snapshot("w")
        query = CapabilityQuery(require_all=frozenset({"nope:x"}), intent="privileged")
        resolution = resolve_worker(query, worker)
        self.assertEqual(resolution.code, "CAPABILITY_UNSATISFIED")

    def test_live_derived_snapshots_have_no_age(self):
        worker = snapshot("w", capability_age_seconds=None)
        resolution = resolve_worker(CapabilityQuery(), worker)
        self.assertTrue(resolution.eligible)

    def test_future_skew_is_stale(self):
        worker = snapshot("w", capability_age_seconds=-5.0)
        resolution = resolve_worker(CapabilityQuery(), worker)
        self.assertEqual(resolution.code, "WORKER_STALE")


class TokenResolutionTests(unittest.TestCase):
    def test_missing_tokens_are_named(self):
        # The classified environment synthesizes arch facts, so a genuinely
        # missing arch token needs a worker on another architecture.
        worker = snapshot("w", capabilities=frozenset({"os:linux"}), env=fedora_env(arch="aarch64"))
        resolution = resolve_worker(CapabilityQuery(require_all=frozenset({"os:linux", "arch:x86_64"})), worker)
        self.assertEqual(resolution.code, "CAPABILITY_UNSATISFIED")
        self.assertIn("missing arch:x86_64", resolution.missing)

    def test_toolchain_only_missing_is_toolchain_missing(self):
        worker = snapshot("w")
        resolution = resolve_worker(CapabilityQuery(require_all=frozenset({"tool:ptxas"})), worker)
        self.assertEqual(resolution.code, "TOOLCHAIN_MISSING")

    def test_runtime_only_missing_is_runtime_missing(self):
        worker = snapshot("w")
        resolution = resolve_worker(CapabilityQuery(require_all=frozenset({"runtime:wasmtime"})), worker)
        self.assertEqual(resolution.code, "RUNTIME_MISSING")

    def test_alternatives_accept_either_branch(self):
        worker = snapshot("w", env=fedora_env(arch="x86_64", emulates_req_arch=True, exec_mode="emulated"))
        query = CapabilityQuery(require_any=(frozenset({"arch:riscv64", "emulation:riscv64"}),))
        # Token-level: emulation token present via env synthesis.
        worker = snapshot(
            "w",
            capabilities=frozenset({"emulation:riscv64"}),
            env=fedora_env(arch="x86_64"),
        )
        resolution = resolve_worker(query, worker)
        self.assertTrue(resolution.eligible, resolution)

    def test_unsatisfied_alternative_names_the_group(self):
        worker = snapshot("w")
        query = CapabilityQuery(require_any=(frozenset({"arch:riscv64", "emulation:riscv64"}),))
        resolution = resolve_worker(query, worker)
        self.assertEqual(resolution.code, "CAPABILITY_UNSATISFIED")
        self.assertTrue(any("one_of" in item for item in resolution.missing))

    def test_forbidden_capability_denies_policy(self):
        worker = snapshot("w", policy=experimental_root_policy())
        query = CapabilityQuery(forbid=frozenset({"policy:disposable"}))
        resolution = resolve_worker(query, worker)
        self.assertEqual(resolution.code, "POLICY_DENIED")
        self.assertFalse(resolution.eligible)


class StructuredResolutionTests(unittest.TestCase):
    def test_cuda_floor_filters(self):
        query = CapabilityQuery(req_env={"require_cuda": True, "cuda_major": 7, "cuda_minor": 0})
        ok_worker = snapshot("node-c81d", env=fedora_env(cuda_major=8, cuda_minor=0))
        old_worker = snapshot("node-2f07", env=fedora_env(cuda_major=6, cuda_minor=1))
        self.assertTrue(resolve_worker(query, ok_worker).eligible)
        denied = resolve_worker(query, old_worker)
        self.assertEqual(denied.code, "CAPABILITY_UNSATISFIED")
        self.assertTrue(any("cuda.compute" in item for item in denied.missing))

    def test_ebpf_requires_verified_kernel_feature(self):
        query = CapabilityQuery(req_env={"require_ebpf": True})
        self.assertTrue(resolve_worker(query, snapshot("a")).eligible)
        denied = resolve_worker(query, snapshot("b", env=fedora_env(has_ebpf=False)))
        self.assertEqual(denied.code, "CAPABILITY_UNSATISFIED")
        self.assertIn("missing kernel.ebpf", denied.missing)

    def test_memory_floor_filters(self):
        query = CapabilityQuery(req_env={"min_mem_mib": 4096, "min_cpu_count": 4})
        self.assertTrue(resolve_worker(query, snapshot("node-9b44")).eligible)
        denied = resolve_worker(query, snapshot("node-51e0", env=fedora_env(mem_mib=1024, cpu_count=2)))
        self.assertEqual(denied.code, "CAPABILITY_UNSATISFIED")
        self.assertTrue(any("resources" in item for item in denied.missing))

    def test_os_and_libc_mismatch_are_named(self):
        query = CapabilityQuery(req_env={"os": "windows"})
        denied = resolve_worker(query, snapshot("w"))
        self.assertIn("missing os.windows", denied.missing)
        query = CapabilityQuery(req_env={"libc": "musl"})
        denied = resolve_worker(query, snapshot("w"))
        self.assertIn("missing libc.musl", denied.missing)

    def test_riscv_emulation_path(self):
        query = CapabilityQuery(req_env={"arch": "riscv64", "allow_emulation": True})
        native = snapshot("riscv", env=fedora_env(arch="riscv64"))
        emulated = snapshot("emu", env=fedora_env(arch="x86_64", emulates_req_arch=True, exec_mode="emulated"))
        bare = snapshot("bare", env=fedora_env(arch="x86_64"))
        self.assertTrue(resolve_worker(query, native).eligible)
        self.assertTrue(resolve_worker(query, emulated).eligible)
        self.assertFalse(resolve_worker(query, bare).eligible)

    def test_emulation_refused_without_permission(self):
        query = CapabilityQuery(req_env={"arch": "riscv64", "allow_emulation": False})
        emulated = snapshot("emu", env=fedora_env(arch="x86_64", emulates_req_arch=True, exec_mode="emulated"))
        self.assertFalse(resolve_worker(query, emulated).eligible)


class PolicyTests(unittest.TestCase):
    def test_privileged_workload_needs_explicit_root_permission(self):
        query = CapabilityQuery(intent="privileged")
        self.assertEqual(resolve_worker(query, snapshot("stable")).code, "POLICY_DENIED")
        self.assertTrue(resolve_worker(query, snapshot("exp", policy=experimental_root_policy())).eligible)

    def test_experimental_status_alone_grants_nothing(self):
        query = CapabilityQuery(intent="privileged")
        bare = snapshot("bare", policy=stable_policy(experimental=True))
        self.assertEqual(resolve_worker(query, bare).code, "POLICY_DENIED")

    def test_mutating_workload_needs_toolchain_permission(self):
        query = CapabilityQuery(intent="mutating")
        self.assertEqual(resolve_worker(query, snapshot("stable")).code, "POLICY_DENIED")
        allowed = snapshot("exp", policy=stable_policy(experimental=True, allow_toolchain_install=True))
        self.assertTrue(resolve_worker(query, allowed).eligible)

    def test_normal_work_runs_on_stable_and_experimental(self):
        query = CapabilityQuery()
        self.assertTrue(resolve_worker(query, snapshot("stable")).eligible)
        self.assertTrue(resolve_worker(query, snapshot("exp", policy=experimental_root_policy())).eligible)

    def test_policy_must_be_declared_not_inferred(self):
        with self.assertRaises(ValidationError):
            validate_policy({"experimental": False, "allow_root_mutation": True})
        with self.assertRaises(ValidationError):
            validate_policy({"experimental": False, "disposable": True})
        with self.assertRaises(ValidationError):
            validate_policy({"experimental": True, "allow_root_mutation": "yes"})

    def test_policy_tokens_never_come_from_probes(self):
        tokens = policy_tokens(stable_policy())
        self.assertIn("policy:stable", tokens)
        tokens = policy_tokens(experimental_root_policy())
        self.assertIn("policy:experimental", tokens)
        self.assertIn("policy:root-mutation", tokens)
        # Observed environment synthesis never emits policy tokens.
        self.assertFalse(any(item.startswith("policy:") for item in env_tokens(fedora_env())))


class FleetTests(unittest.TestCase):
    def fleet(self):
        return [
            snapshot("stable-fedora", env=fedora_env(), policy=stable_policy()),
            snapshot("experimental-nixos", env=fedora_env(libc="gnu", init="unknown", shells=["sh"]), policy=experimental_root_policy()),
            snapshot("experimental-musl", env=fedora_env(libc="musl", init="openrc", shells=["sh"], has_ebpf=False, accel="none", cuda_major=0, cuda_minor=0), policy=experimental_root_policy()),
            snapshot("windows", env=fedora_env(os="windows", arch="x86_64", libc="win-crt", init="win-service", accel="none", cuda_major=0, cuda_minor=0, has_ebpf=False, shells=["powershell"]), policy=stable_policy()),
            snapshot("arm-board", env=fedora_env(arch="aarch64", accel="none", cuda_major=0, cuda_minor=0, has_ebpf=False, mem_mib=2048, cpu_count=4), policy=stable_policy(resource_constrained=True)),
        ]

    def test_no_eligible_worker_is_first_class_with_reasons(self):
        query = CapabilityQuery(
            req_env={
                "os": "linux",
                "arch": "x86_64",
                "require_cuda": True,
                "cuda_major": 9,
                "cuda_minor": 0,
                "require_ebpf": True,
                "min_mem_mib": 4096,
                "min_cpu_count": 2,
            },
            intent="privileged",
        )
        fleet = resolve_fleet(query, self.fleet(), replicas=1)
        self.assertEqual(fleet.verdict, NO_ELIGIBLE_WORKER)
        self.assertEqual(fleet.selected, ())
        by_id = {item.worker_id: item for item in fleet.per_worker}
        # Resolution order is environment before policy: the 9.0 floor
        # excludes both CUDA workers on capability, each naming the floor.
        self.assertEqual(by_id["stable-fedora"].code, "CAPABILITY_UNSATISFIED")
        self.assertTrue(any("cuda.compute" in item for item in by_id["stable-fedora"].missing))
        self.assertEqual(by_id["experimental-nixos"].code, "CAPABILITY_UNSATISFIED")
        self.assertTrue(any("cuda.compute" in item for item in by_id["experimental-nixos"].missing))
        self.assertIn("missing os.linux", by_id["windows"].missing)
        self.assertTrue(any("arch" in item for item in by_id["arm-board"].missing))
        explanation = explain_selection(fleet)
        self.assertEqual(explanation["verdict"], NO_ELIGIBLE_WORKER)
        self.assertEqual(len(explanation["per_worker"]), 5)
        # Policy denial is its own first-class cause: with a satisfiable
        # 6.0 floor, the stable CUDA worker passes environment and is
        # denied exactly on privileged intent.
        policy_query = CapabilityQuery(
            req_env={
                "os": "linux",
                "arch": "x86_64",
                "require_cuda": True,
                "cuda_major": 6,
                "cuda_minor": 0,
                "require_ebpf": True,
            },
            intent="privileged",
        )
        policy_fleet = resolve_fleet(policy_query, self.fleet(), replicas=1)
        policy_by_id = {item.worker_id: item for item in policy_fleet.per_worker}
        self.assertEqual(policy_by_id["stable-fedora"].code, "POLICY_DENIED")

    def test_cuda_ebpf_privileged_selects_capable_experimental(self):
        query = CapabilityQuery(
            req_env={
                "os": "linux",
                "arch": "x86_64",
                "require_cuda": True,
                "cuda_major": 6,
                "cuda_minor": 0,
                "require_ebpf": True,
            },
            intent="privileged",
        )
        fleet = resolve_fleet(query, self.fleet(), replicas=1)
        self.assertEqual(fleet.verdict, "ELIGIBLE")
        self.assertEqual(fleet.selected, ("experimental-nixos",))

    def test_windows_workload_selects_windows(self):
        query = CapabilityQuery(req_env={"os": "windows", "arch": "x86_64"})
        fleet = resolve_fleet(query, self.fleet(), replicas=1)
        self.assertEqual(fleet.selected, ("windows",))

    def test_arm_workload_selects_arm(self):
        query = CapabilityQuery(req_env={"os": "linux", "arch": "aarch64"})
        fleet = resolve_fleet(query, self.fleet(), replicas=1)
        self.assertEqual(fleet.selected, ("arm-board",))

    def test_musl_preference_selects_musl_without_excluding_gnu(self):
        query = CapabilityQuery(
            req_env={"os": "linux", "arch": "x86_64", "libc": "any"},
            prefer=frozenset({"libc:musl"}),
        )
        fleet = resolve_fleet(query, self.fleet(), replicas=1)
        self.assertIn("experimental-musl", fleet.eligible)
        self.assertIn("stable-fedora", fleet.eligible)
        self.assertEqual(fleet.selected, ("experimental-musl",))

    def test_names_are_identifiers_only(self):
        query = CapabilityQuery(
            req_env={"os": "linux", "arch": "x86_64", "require_ebpf": True},
            intent="privileged",
        )
        renamed = [
            WorkerSnapshot(
                worker_id=f"remote-community-worker-{index}",
                capabilities=item.capabilities,
                env=dict(item.env),
                policy=dict(item.policy),
                liveness=item.liveness,
                capability_age_seconds=item.capability_age_seconds,
                provenance=item.provenance,
                available=item.available,
                active=item.active,
                concurrency_limit=item.concurrency_limit,
                management_state=item.management_state,
            )
            for index, item in enumerate(self.fleet())
        ]
        first = resolve_fleet(query, self.fleet(), replicas=1)
        second = resolve_fleet(query, renamed, replicas=1)
        # Renaming re-sorts per-worker order, so compare as multisets:
        # identical properties must resolve identically under any names.
        self.assertEqual(
            sorted(item.code for item in first.per_worker),
            sorted(item.code for item in second.per_worker),
        )
        self.assertEqual(first.verdict, second.verdict)


class SchedulerIntegrationTests(unittest.TestCase):
    def test_scheduler_explains_rejection_per_worker(self):
        workers = [
            slot("stable-fedora", {"os:linux", "arch:x86_64"}),
            slot("windows", {"os:windows", "arch:x86_64"}, env=fedora_env(os="windows", libc="win-crt", init="win-service", has_ebpf=False, accel="none", cuda_major=0, cuda_minor=0)),
        ]
        decision = schedule(plan(["os:linux", "kernel:ebpf", "compiler:ptx"]), workers)
        self.assertEqual(decision.disposition, "UNKNOWN")
        self.assertIn("NO_ELIGIBLE_WORKER", decision.reason)
        self.assertIn("CAPABILITY_UNAVAILABLE", decision.reason)
        self.assertIsNotNone(decision.resolution)
        self.assertEqual(decision.resolution["verdict"], NO_ELIGIBLE_WORKER)
        by_id = {item["worker_id"]: item for item in decision.resolution["per_worker"]}
        self.assertFalse(by_id["stable-fedora"]["eligible"])
        self.assertFalse(by_id["windows"]["eligible"])

    def test_scheduler_selects_eligible_and_reports_resolution(self):
        workers = [
            slot("stable-fedora", {"os:linux", "arch:x86_64", "kernel:ebpf"}),
            slot("windows", {"os:windows", "arch:x86_64"}),
        ]
        decision = schedule(plan(["os:linux", "kernel:ebpf"]), workers)
        self.assertEqual(decision.disposition, "PASS")
        self.assertEqual(list(decision.worker_ids), ["stable-fedora"])
        self.assertIsNotNone(decision.resolution)

    def test_scheduler_enforces_intent_against_stable_workers(self):
        workers = [slot("stable-fedora", {"os:linux", "arch:x86_64"})]
        decision = schedule(plan(["os:linux"]), workers, intent="privileged")
        self.assertEqual(decision.disposition, "UNKNOWN")
        self.assertIn("NO_ELIGIBLE_WORKER", decision.reason)
        by_id = {item["worker_id"]: item for item in decision.resolution["per_worker"]}
        self.assertEqual(by_id["stable-fedora"]["code"], "POLICY_DENIED")

    def test_scheduler_refuses_stale_observations(self):
        workers = [slot("node-d3a9", {"os:linux"}, capability_age_seconds=3600.0)]
        decision = schedule(plan(["os:linux"]), workers)
        self.assertEqual(decision.disposition, "UNKNOWN")
        by_id = {item["worker_id"]: item for item in decision.resolution["per_worker"]}
        self.assertEqual(by_id["node-d3a9"]["code"], "WORKER_STALE")

    def test_scheduler_structured_query_with_cuda_floor(self):
        from mncs_fabric.capability_resolution import CapabilityQuery as Query

        workers = [
            slot("node-2f07", {"os:linux"}, env=fedora_env(cuda_major=6, cuda_minor=1)),
            slot("node-c81d", {"os:linux"}, env=fedora_env(cuda_major=8, cuda_minor=0)),
        ]
        query = Query(req_env={"require_cuda": True, "cuda_major": 7, "cuda_minor": 0})
        decision = schedule(plan(["os:linux"]), workers, query=query)
        self.assertEqual(decision.disposition, "PASS")
        self.assertEqual(list(decision.worker_ids), ["node-c81d"])

    def test_explain_eligibility_matches_scheduling(self):
        workers = [slot("a", {"os:linux"}), slot("b", {"os:windows"})]
        fleet = explain_eligibility(["os:linux"], workers)
        self.assertEqual(fleet.verdict, "ELIGIBLE")
        self.assertEqual(fleet.selected, ("a",))


if __name__ == "__main__":
    unittest.main()
