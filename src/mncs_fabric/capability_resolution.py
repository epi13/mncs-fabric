"""Pre-execution capability resolution for Fabric scheduling.

Decision ownership (see ``mncs/worker_capability.mncs``):

- the MNCS module owns the resolution relation itself (provenance trust,
  freshness lattice, intent/policy compatibility, and the ordered reason
  codes). The functions below marked MIRROR implement those arms exactly;
  ``tests/test_mncs_capability_policy.py`` pins every arm mechanically so
  the two cannot drift;
- this Python module additionally owns what MNCS cannot express today:
  unbounded text classification (``classify_*`` maps observed strings such
  as ``"x86_64"`` into the finite enums), fleet aggregation, preference
  ranking, and machine-readable eligibility explanations.

Host-language boundary (minimal, explicit, pressured toward MNCS):

- string classification, subprocess discovery, clocks, hashing, and
  transport stay here; there is no safe observable MNCS surface for
  unbounded text or IO yet;
- the pure decision core stays in MNCS. If a new decision arm is needed,
  add it to ``mncs/worker_capability.mncs`` (and ``library/std`` when it
  is reusable) first, extend the corpus, and only then mirror it here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from .errors import ValidationError

# ---------------------------------------------------------------------------
# Section 1: MIRROR of mncs/fabric_platform_decision.mncs (finite platform
# vocabulary) and mncs.std.platform.v1. The MNCS module owns the decision
# over already-classified finite values; `tests/test_mncs_platform_decision.py`
# pins every arm mechanically so the two cannot drift.
# ---------------------------------------------------------------------------

OS_VALUES = ("linux", "windows", "macos", "unknown")
ARCH_VALUES = ("x86_64", "aarch64", "riscv64", "x86", "arm32", "unknown")
LIBC_VALUES = ("gnu", "musl", "wasi-c", "win-crt", "unknown")
ACCEL_VALUES = ("none", "cuda", "rocm", "metal", "unknown")
EXEC_VALUES = ("native", "emulated")
REQ_OS_VALUES = ("any", "linux", "windows", "macos")
REQ_ARCH_VALUES = ("any", "x86_64", "aarch64", "riscv64", "x86", "arm32")
REQ_LIBC_VALUES = ("any", "gnu", "musl", "wasi-c", "win-crt")
PROVENANCE_VALUES = ("worker-observed", "operator-asserted", "consumer-declared")
INTENT_VALUES = ("normal", "mutating", "privileged")
LIVENESS_VALUES = ("AVAILABLE", "UNAVAILABLE", "DISCONNECTED")
FRESHNESS_VALUES = ("fresh", "stale")
RESOLUTION_CODES = (
    "ELIGIBLE",
    "CAPABILITY_UNSATISFIED",
    "POLICY_DENIED",
    "PROVENANCE_UNVERIFIED",
    "WORKER_STALE",
    "WORKER_UNAVAILABLE",
    "WORKER_DISCONNECTED",
    "TOOLCHAIN_MISSING",
    "RUNTIME_MISSING",
)
# Fleet-level verdict when no worker resolves ELIGIBLE. This is a
# first-class scheduling result, not an execution failure.
NO_ELIGIBLE_WORKER = "NO_ELIGIBLE_WORKER"
MAX_CAPABILITY_AGE_SECONDS = 300.0


def _enum(value: object, allowed: tuple[str, ...], field: str) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise ValidationError(f"{field} must be one of {sorted(allowed)}")
    return value


def os_satisfies(req: str, got: str) -> bool:  # MIRROR platform.os_satisfies
    _enum(req, REQ_OS_VALUES, "req_os")
    _enum(got, OS_VALUES, "os")
    if req == "any":
        return True
    return req == got and got != "unknown"


def arch_matches(req: str, got: str) -> bool:  # MIRROR platform.arch_matches
    _enum(req, REQ_ARCH_VALUES, "req_arch")
    _enum(got, ARCH_VALUES, "arch")
    if req == "any":
        return True
    return req == got and got != "unknown"


def arch_satisfies(  # MIRROR platform.arch_satisfies
    req: str, got: str, *, allow_emulation: bool, emulates_req_arch: bool, exec_mode: str
) -> bool:
    _enum(exec_mode, EXEC_VALUES, "exec_mode")
    if arch_matches(req, got):
        return True if exec_mode == "native" else bool(allow_emulation)
    if allow_emulation and emulates_req_arch and exec_mode == "emulated":
        return True
    return False


def libc_satisfies(req: str, got: str) -> bool:  # MIRROR platform.libc_satisfies
    _enum(req, REQ_LIBC_VALUES, "req_libc")
    _enum(got, LIBC_VALUES, "libc")
    if req == "any":
        return True
    return req == got and got != "unknown"


def cuda_satisfies(  # MIRROR platform.cuda_satisfies
    require: bool, req_major: int, req_minor: int, got: str, got_major: int, got_minor: int
) -> bool:
    if not require:
        return True
    _enum(got, ACCEL_VALUES, "accel")
    if got != "cuda":
        return False
    return (int(got_major), int(got_minor)) >= (int(req_major), int(req_minor))


def resources_satisfy(min_mem_mib: int, min_cpus: int, got_mem_mib: int, got_cpus: int) -> bool:
    return int(min_mem_mib) <= int(got_mem_mib) and int(min_cpus) <= int(got_cpus)


def flag_satisfies(require: bool, got: bool) -> bool:  # MIRROR platform.flag_satisfies
    return bool(got) if require else True


def normalize_req_env(req: Mapping[str, Any] | None) -> dict[str, Any]:
    """Total requirement record: absent dimensions mean "no requirement"."""
    source = dict(req or {})
    return {
        "os": source.get("os", "any"),
        "arch": source.get("arch", "any"),
        "libc": source.get("libc", "any"),
        "require_cuda": bool(source.get("require_cuda", False)),
        "cuda_major": int(source.get("cuda_major", 0)),
        "cuda_minor": int(source.get("cuda_minor", 0)),
        "require_ebpf": bool(source.get("require_ebpf", False)),
        "require_wasm": bool(source.get("require_wasm", False)),
        "require_ptx": bool(source.get("require_ptx", False)),
        "allow_emulation": bool(source.get("allow_emulation", False)),
        "min_mem_mib": int(source.get("min_mem_mib", 0)),
        "min_cpu_count": int(source.get("min_cpu_count", 0)),
    }


def normalize_env(env: Mapping[str, Any] | None) -> dict[str, Any]:
    """Total environment record: absent facts stay unknown, never assumed."""
    source = dict(env or {})
    merged = default_env()
    merged.update(source)
    return merged


def env_satisfies(req: Mapping[str, Any], env: Mapping[str, Any]) -> bool:
    """MIRROR platform.env_satisfies over string-keyed records."""
    want = normalize_req_env(req)
    got = normalize_env(env)
    checks = [
        os_satisfies(want["os"], got["os"]),
        arch_satisfies(
            want["arch"],
            got["arch"],
            allow_emulation=want["allow_emulation"],
            emulates_req_arch=bool(got.get("emulates_req_arch", False)),
            exec_mode=got.get("exec_mode", "native"),
        ),
        libc_satisfies(want["libc"], got["libc"]),
        cuda_satisfies(
            want["require_cuda"],
            want["cuda_major"],
            want["cuda_minor"],
            got["accel"],
            int(got.get("cuda_major", 0)),
            int(got.get("cuda_minor", 0)),
        ),
        flag_satisfies(want["require_ebpf"], bool(got.get("has_ebpf", False))),
        flag_satisfies(want["require_wasm"], bool(got.get("has_wasm", False))),
        flag_satisfies(want["require_ptx"], bool(got.get("has_ptx", False))),
        resources_satisfy(
            want["min_mem_mib"],
            want["min_cpu_count"],
            int(got.get("mem_mib", 0)),
            int(got.get("cpu_count", 0)),
        ),
    ]
    return all(checks)


# ---------------------------------------------------------------------------
# Section 2: MIRROR of fabric.worker_capability (resolution ordering).
# ---------------------------------------------------------------------------


def provenance_trusted(provenance: str) -> bool:  # MIRROR worker_capability
    _enum(provenance, PROVENANCE_VALUES, "provenance")
    return provenance in ("worker-observed", "operator-asserted")


def freshness_of(age_seconds: float | None, max_age_seconds: float = MAX_CAPABILITY_AGE_SECONDS) -> str:
    """MIRROR worker_capability.freshness_of.

    ``None`` means the snapshot was derived live at schedule time (the
    controller read the worker directly instead of consulting a stored
    observation), so there is no observation age to bound. A stored
    observation always carries a numeric age and is bounded.
    """
    if age_seconds is None:
        return "fresh"
    try:
        age = float(age_seconds)
    except (TypeError, ValueError) as exc:
        raise ValidationError("capability age must be numeric or null") from exc
    if age < 0 or age > float(max_age_seconds):
        return "stale"
    return "fresh"


def intent_allowed(policy: Mapping[str, Any], intent: str) -> bool:  # MIRROR
    _enum(intent, INTENT_VALUES, "intent")
    experimental = bool(policy.get("experimental", False))
    if intent == "normal":
        return True
    if intent == "mutating":
        return experimental and bool(policy.get("allow_toolchain_install", False))
    return experimental and bool(policy.get("allow_root_mutation", False))


def resolve_code(  # MIRROR worker_capability.resolve
    *, liveness: str, freshness: str, provenance_ok: bool, env_ok: bool, intent_ok: bool
) -> str:
    _enum(liveness, LIVENESS_VALUES, "liveness")
    _enum(freshness, FRESHNESS_VALUES, "freshness")
    if liveness == "UNAVAILABLE":
        return "WORKER_UNAVAILABLE"
    if liveness == "DISCONNECTED":
        return "WORKER_DISCONNECTED"
    if freshness == "stale":
        return "WORKER_STALE"
    if not provenance_ok:
        return "PROVENANCE_UNVERIFIED"
    if not env_ok:
        return "CAPABILITY_UNSATISFIED"
    if not intent_ok:
        return "POLICY_DENIED"
    return "ELIGIBLE"


def is_eligible(code: str) -> bool:  # MIRROR worker_capability.is_eligible
    if code not in RESOLUTION_CODES:
        raise ValidationError(f"resolution code {code!r} is unsupported")
    return code == "ELIGIBLE"


# ---------------------------------------------------------------------------
# Section 3: host boundary — text classification and token synthesis.
# ---------------------------------------------------------------------------

_OS_ALIASES = {
    "linux": "linux",
    "windows": "windows",
    "darwin": "macos",
    "macos": "macos",
}
_ARCH_ALIASES = {
    "x86_64": "x86_64",
    "amd64": "x86_64",
    "aarch64": "aarch64",
    "arm64": "aarch64",
    "riscv64": "riscv64",
    "i386": "x86",
    "i686": "x86",
    "x86": "x86",
    "armv7l": "arm32",
    "arm32": "arm32",
}


def classify_os(raw: object) -> str:
    """Map an observed ``platform.system()`` string into the finite Os enum."""
    if isinstance(raw, str) and raw.strip().lower() in _OS_ALIASES:
        return _OS_ALIASES[raw.strip().lower()]
    return "unknown"


def classify_arch(raw: object) -> str:
    """Map an observed ``platform.machine()`` string into Arch."""
    if isinstance(raw, str) and raw.strip().lower() in _ARCH_ALIASES:
        return _ARCH_ALIASES[raw.strip().lower()]
    return "unknown"


def classify_libc(raw: object) -> str:
    if isinstance(raw, str):
        lowered = raw.strip().lower()
        for token in ("musl", "wasi", "msvc", "win", "crt", "glibc", "gnu"):
            if token in lowered:
                if token == "musl":
                    return "musl"
                if token == "wasi":
                    return "wasi-c"
                if token in ("msvc", "win", "crt"):
                    return "win-crt"
                return "gnu"
    return "unknown"


def classify_init(raw: object) -> str:
    if isinstance(raw, str):
        lowered = raw.strip().lower().replace("_", "-")
        if lowered in ("systemd", "openrc", "sysv", "launchd", "win-service", "windows-service"):
            return "windows-service" if lowered.startswith("win") else lowered
    return "unknown"


def classify_accel(raw: object) -> str:
    if isinstance(raw, str):
        lowered = raw.strip().lower()
        if lowered in ACCEL_VALUES:
            return lowered
    return "unknown"


def default_env() -> dict[str, Any]:
    """Honest all-unknown environment; satisfies nothing concrete."""
    return {
        "os": "unknown",
        "arch": "unknown",
        "libc": "unknown",
        "init": "unknown",
        "accel": "unknown",
        "exec_mode": "native",
        "cuda_major": 0,
        "cuda_minor": 0,
        "has_ebpf": False,
        "has_wasm": False,
        "has_ptx": False,
        "mem_mib": 0,
        "cpu_count": 0,
        "emulates_req_arch": False,
    }


def default_policy() -> dict[str, Any]:
    """Stable reference policy: every permission denied until declared."""
    return {
        "experimental": False,
        "disposable": False,
        "allow_root_mutation": False,
        "allow_reboot": False,
        "allow_toolchain_install": False,
        "resource_constrained": False,
    }


def validate_policy(policy: Mapping[str, Any]) -> dict[str, Any]:
    """Policy is declared operator configuration, never inferred hardware."""
    if not isinstance(policy, Mapping):
        raise ValidationError("worker policy must be an object")
    allowed = {
        "experimental",
        "disposable",
        "allow_root_mutation",
        "allow_reboot",
        "allow_toolchain_install",
        "resource_constrained",
    }
    unknown = set(policy) - allowed
    if unknown:
        raise ValidationError(f"worker policy carries unsupported fields: {sorted(unknown)}")
    checked = dict(default_policy())
    for key in allowed:
        value = policy.get(key, False)
        if not isinstance(value, bool):
            raise ValidationError(f"worker policy field {key} must be a boolean")
        checked[key] = value
    if checked["allow_root_mutation"] and not checked["experimental"]:
        raise ValidationError("root mutation requires the experimental role; stable workers cannot hold it")
    if checked["disposable"] and not checked["experimental"]:
        raise ValidationError("disposable workers must be experimental")
    return checked


def env_tokens(env: Mapping[str, Any]) -> set[str]:
    """Synthesize factual capability tokens from a classified environment."""
    tokens = {
        f"os:{env.get('os', 'unknown')}",
        f"arch:{env.get('arch', 'unknown')}",
        f"libc:{env.get('libc', 'unknown')}",
        f"init:{env.get('init', 'unknown')}",
        f"accel:{env.get('accel', 'unknown')}",
        f"exec:{env.get('exec_mode', 'native')}",
    }
    if env.get("accel") == "cuda":
        tokens.add(f"cuda:compute-{env.get('cuda_major', 0)}-{env.get('cuda_minor', 0)}")
        tokens.add("accelerator:cuda")
    if env.get("has_ebpf"):
        tokens.add("kernel:ebpf")
    if env.get("has_wasm"):
        tokens.add("runtime:wasm")
    if env.get("has_ptx"):
        tokens.add("compiler:ptx")
    if env.get("emulates_req_arch"):
        tokens.add("exec:emulated-capable")
    for shell in env.get("shells", []) or []:
        tokens.add(f"shell:{shell}")
    return tokens


def policy_tokens(policy: Mapping[str, Any]) -> set[str]:
    """Synthesize declared-policy tokens. Authorization is declared, never probed."""
    checked = validate_policy(policy)
    tokens = {"policy:stable"} if not checked["experimental"] else {"policy:experimental"}
    if checked["disposable"]:
        tokens.add("policy:disposable")
    if checked["resource_constrained"]:
        tokens.add("policy:resource-constrained")
    if checked["allow_root_mutation"]:
        tokens.add("policy:root-mutation")
    if checked["allow_reboot"]:
        tokens.add("policy:reboot")
    if checked["allow_toolchain_install"]:
        tokens.add("policy:toolchain-install")
    return tokens


# ---------------------------------------------------------------------------
# Section 4: workload queries and fleet resolution.
# ---------------------------------------------------------------------------

TOOLCHAIN_PREFIXES = ("tool:", "toolchain:", "compiler:")
RUNTIME_PREFIXES = ("runtime:",)


@dataclass(frozen=True)
class CapabilityQuery:
    """What a workload requires, in capability vocabulary.

    ``require_all``: every token must hold (e.g. ``os:linux``).
    ``require_any``: each group needs at least one token (alternatives,
    e.g. native RISC-V or declared emulation).
    ``forbid``: no token may hold (e.g. a production workload forbidding
    ``policy:disposable``).
    ``prefer``: ranking only; never promotes an ineligible worker.
    Structured floors (CUDA compute, memory, CPUs, feature flags,
    emulation) stay structured so versions compare instead of matching
    as opaque strings.
    """

    require_all: frozenset[str] = frozenset()
    require_any: tuple[frozenset[str], ...] = ()
    forbid: frozenset[str] = frozenset()
    prefer: frozenset[str] = frozenset()
    req_env: Mapping[str, Any] | None = None
    intent: str = "normal"

    def __post_init__(self) -> None:
        _enum(self.intent, INTENT_VALUES, "intent")
        for group in (self.require_all, self.forbid, self.prefer):
            if not isinstance(group, frozenset) or any(not isinstance(t, str) or not t for t in group):
                raise ValidationError("capability token sets must hold non-empty strings")
        for group in self.require_any:
            if not isinstance(group, frozenset) or not group:
                raise ValidationError("require_any groups must be non-empty token sets")


@dataclass(frozen=True)
class WorkerSnapshot:
    """One worker's resolution inputs. Names are identifiers only."""

    worker_id: str
    capabilities: frozenset[str] = frozenset()
    env: Mapping[str, Any] | None = None
    policy: Mapping[str, Any] | None = None
    liveness: str = "AVAILABLE"
    capability_age_seconds: float | None = None
    provenance: str = "worker-observed"
    available: bool = True
    active: int = 0
    concurrency_limit: int = 1
    management_state: str | None = None


@dataclass(frozen=True)
class WorkerResolution:
    worker_id: str
    eligible: bool
    code: str
    missing: tuple[str, ...] = ()
    preferred_hits: tuple[str, ...] = ()
    detail: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "worker_id": self.worker_id,
            "eligible": self.eligible,
            "code": self.code,
            "missing": list(self.missing),
            "preferred_hits": list(self.preferred_hits),
            "detail": self.detail,
        }


@dataclass(frozen=True)
class FleetResolution:
    verdict: str
    eligible: tuple[str, ...] = ()
    selected: tuple[str, ...] = ()
    per_worker: tuple[WorkerResolution, ...] = ()
    detail: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "eligible": list(self.eligible),
            "selected": list(self.selected),
            "per_worker": [item.as_dict() for item in self.per_worker],
            "detail": self.detail,
        }


def _missing_detail(missing: Iterable[str]) -> str:
    items = sorted(set(missing))
    if not items:
        return ""
    if all(item.startswith(TOOLCHAIN_PREFIXES) for item in items):
        return "toolchain-missing"
    if all(item.startswith(RUNTIME_PREFIXES) for item in items):
        return "runtime-missing"
    return "capability-unsatisfied"


def resolve_worker(query: CapabilityQuery, worker: WorkerSnapshot) -> WorkerResolution:
    """Resolve one worker through the MNCS-ordered stages plus token checks."""
    liveness = worker.liveness if worker.liveness in LIVENESS_VALUES else "DISCONNECTED"
    if not worker.available and liveness == "AVAILABLE":
        liveness = "UNAVAILABLE"
    freshness = freshness_of(worker.capability_age_seconds)
    provenance_ok = provenance_trusted(worker.provenance) if worker.provenance in PROVENANCE_VALUES else False
    policy = validate_policy(worker.policy or {})
    tokens = set(worker.capabilities) | env_tokens(worker.env or default_env()) | policy_tokens(policy)

    missing: list[str] = []
    forbidden_hit: str | None = None
    if liveness != "AVAILABLE" or freshness != "fresh" or not provenance_ok:
        pass
    else:
        required_missing = sorted(set(query.require_all) - tokens)
        missing.extend(f"missing {item}" for item in required_missing)
        for group in query.require_any:
            if not (set(group) & tokens):
                missing.append(f"missing one_of [{', '.join(sorted(group))}]")
        for token in sorted(set(query.forbid) & tokens):
            if forbidden_hit is None:
                forbidden_hit = token
            missing.append(f"forbidden {token} present")
        env_req = normalize_req_env(query.req_env)
        if query.req_env:
            env = normalize_env(worker.env)
            if not env_satisfies(env_req, env):
                if env_req["require_cuda"] and not cuda_satisfies(
                    True,
                    env_req["cuda_major"],
                    env_req["cuda_minor"],
                    str(env.get("accel", "unknown")),
                    int(env.get("cuda_major", 0)),
                    int(env.get("cuda_minor", 0)),
                ):
                    missing.append(
                        f"missing cuda.compute >= {env_req['cuda_major']}.{env_req['cuda_minor']}"
                    )
                if env_req["arch"] != "any" and not arch_satisfies(
                    env_req["arch"],
                    str(env.get("arch", "unknown")),
                    allow_emulation=env_req["allow_emulation"],
                    emulates_req_arch=bool(env.get("emulates_req_arch", False)),
                    exec_mode=str(env.get("exec_mode", "native")),
                ):
                    missing.append(f"missing arch.{env_req['arch']}")
                if not os_satisfies(env_req["os"], str(env.get("os", "unknown"))):
                    missing.append(f"missing os.{env_req['os']}")
                if not libc_satisfies(env_req["libc"], str(env.get("libc", "unknown"))):
                    missing.append(f"missing libc.{env_req['libc']}")
                for flag, label, env_key in (
                    ("require_ebpf", "kernel.ebpf", "has_ebpf"),
                    ("require_wasm", "runtime.wasm", "has_wasm"),
                    ("require_ptx", "compiler.ptx", "has_ptx"),
                ):
                    if env_req[flag] and not flag_satisfies(True, bool(env.get(env_key, False))):
                        missing.append(f"missing {label}")
                if not resources_satisfy(
                    env_req["min_mem_mib"],
                    env_req["min_cpu_count"],
                    int(env.get("mem_mib", 0)),
                    int(env.get("cpu_count", 0)),
                ):
                    missing.append(
                        f"missing resources >= {env_req['min_mem_mib']}MiB/{env_req['min_cpu_count']}cpu"
                    )

    env_ok = not missing
    intent_ok = intent_allowed(policy, query.intent)
    code = resolve_code(
        liveness=liveness,
        freshness=freshness,
        provenance_ok=provenance_ok,
        env_ok=env_ok,
        intent_ok=intent_ok,
    )
    if code == "ELIGIBLE" and forbidden_hit is not None:
        code = "POLICY_DENIED"
    elif code == "CAPABILITY_UNSATISFIED" and forbidden_hit is not None and not [
        item for item in missing if item.startswith("missing")
    ]:
        code = "POLICY_DENIED"
    if code in ("CAPABILITY_UNSATISFIED",) and missing:
        detail = _missing_detail(item.split(" ", 1)[1] for item in missing if " " in item)
        if detail == "toolchain-missing":
            code = "TOOLCHAIN_MISSING"
        elif detail == "runtime-missing":
            code = "RUNTIME_MISSING"
    preferred = tuple(sorted(set(query.prefer) & tokens))
    detail_text = "; ".join(missing)
    if code == "POLICY_DENIED" and not missing:
        detail_text = f"intent {query.intent} denied by worker policy"
        missing = [f"missing policy for intent {query.intent}"]
    return WorkerResolution(
        worker_id=worker.worker_id,
        eligible=code == "ELIGIBLE",
        code=code,
        missing=tuple(missing),
        preferred_hits=preferred,
        detail=detail_text,
    )


def resolve_fleet(
    query: CapabilityQuery, workers: Iterable[WorkerSnapshot], *, replicas: int = 1
) -> FleetResolution:
    """Fleet resolution with deterministic preference ranking.

    Selection never consults worker names: among eligible workers it
    prefers more ``prefer`` hits, then non-resource-constrained workers,
    then lexicographic worker id. Experimental status alone never wins
    selection; intent gating already ran inside ``resolve_worker``.
    """
    if not isinstance(replicas, int) or replicas < 1 or replicas > 64:
        raise ValidationError("replicas must be between 1 and 64")
    resolutions = tuple(resolve_worker(query, worker) for worker in workers)
    eligible = [item for item in resolutions if item.eligible]

    constrained_ids: set[str] = set()
    for worker in workers:
        policy = validate_policy(worker.policy or {})
        if policy.get("resource_constrained"):
            constrained_ids.add(worker.worker_id)

    def _ranked(item: WorkerResolution) -> tuple[int, int, str]:
        return (-len(item.preferred_hits), 1 if item.worker_id in constrained_ids else 0, item.worker_id)

    eligible.sort(key=_ranked)
    if len(eligible) < replicas:
        detail = "; ".join(
            f"{item.worker_id}: {item.code}"
            + (f" ({item.detail})" if item.detail else "")
            for item in sorted(resolutions, key=lambda item: item.worker_id)
        )
        return FleetResolution(
            verdict=NO_ELIGIBLE_WORKER,
            eligible=tuple(item.worker_id for item in eligible),
            selected=(),
            per_worker=tuple(sorted(resolutions, key=lambda item: item.worker_id)),
            detail=detail,
        )
    selected = tuple(item.worker_id for item in eligible[:replicas])
    return FleetResolution(
        verdict="ELIGIBLE",
        eligible=tuple(item.worker_id for item in eligible),
        selected=selected,
        per_worker=tuple(sorted(resolutions, key=lambda item: item.worker_id)),
        detail=f"selected {', '.join(selected)} by capability match and preference rank",
    )


def explain_selection(fleet: FleetResolution) -> dict[str, Any]:
    """Machine-consumable scheduling explanation from one fleet resolution."""
    return {
        "verdict": fleet.verdict,
        "selected": list(fleet.selected),
        "eligible": list(fleet.eligible),
        "per_worker": [item.as_dict() for item in fleet.per_worker],
        "detail": fleet.detail,
    }
