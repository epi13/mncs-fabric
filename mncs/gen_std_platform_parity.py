#!/usr/bin/env python3
"""Generate the parity corpus pinning Fabric decisions to mncs.std.platform.v1.

Fabric's platform vocabulary is the shared standard library, not a Fabric
copy: this corpus calls ``mncs.std.platform.v1`` entrypoints directly with
expectations computed from the Python authority in
``src/mncs_fabric/capability_resolution.py``. `mncs experiment run`
executes the *standard library file itself*
(``<mncs-language>/library/std/platform.mncs`` at the pinned revision);
``tests/test_mncs_platform_decision.py`` asserts the execution agrees with
Python on every case.

The worker environment carries an ``init`` fact the composed check
ignores on both sides. Env scenarios run under two init values to prove
that independence rather than assume it.

Run from the repository root: python3 mncs/gen_std_platform_parity.py
"""

import json
import os
import sys
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "src"))

from mncs_fabric.capability_resolution import (  # noqa: E402
    arch_matches,
    arch_satisfies,
    cuda_satisfies,
    env_satisfies,
    flag_satisfies,
    libc_satisfies,
    os_satisfies,
    resources_satisfy,
)

MODULE = "mncs.std.platform.v1"

OS_MNCS = ["Linux", "Windows", "MacOs", "Unknown"]
OS_PY = ["linux", "windows", "macos", "unknown"]
REQ_OS_MNCS = ["Any", "Linux", "Windows", "MacOs"]
REQ_OS_PY = ["any", "linux", "windows", "macos"]
ARCH_MNCS = ["X86_64", "Aarch64", "Riscv64", "X86", "Arm32", "Unknown"]
ARCH_PY = ["x86_64", "aarch64", "riscv64", "x86", "arm32", "unknown"]
REQ_ARCH_MNCS = ["Any", "X86_64", "Aarch64", "Riscv64", "X86", "Arm32"]
REQ_ARCH_PY = ["any", "x86_64", "aarch64", "riscv64", "x86", "arm32"]
LIBC_MNCS = ["Gnu", "Musl", "WasiC", "WinCrt", "Unknown"]
LIBC_PY = ["gnu", "musl", "wasi-c", "win-crt", "unknown"]
REQ_LIBC_MNCS = ["Any", "Gnu", "Musl", "WasiC", "WinCrt"]
REQ_LIBC_PY = ["any", "gnu", "musl", "wasi-c", "win-crt"]
ACCEL_MNCS = ["None", "Cuda", "Rocm", "Metal", "Unknown"]
ACCEL_PY = ["none", "cuda", "rocm", "metal", "unknown"]
EXEC_MNCS = ["Native", "Emulated"]
EXEC_PY = ["native", "emulated"]
INIT_MNCS = ["Systemd", "OpenRC", "SysV", "Launchd", "WinService", "Unknown"]


def finite(module, type_name, variant_name, discriminant):
    return {
        "finite": {
            "type_identity": f"mncs:0.2:finite-type:{module}::{type_name}",
            "variant_identity": (
                f"mncs:0.2:finite-variant:{module}::{type_name}::{variant_name}"
            ),
            "discriminant": discriminant,
        }
    }


def boolean(value):
    return {"boolean": {"value": bool(value)}}


def integer32(value):
    return {"integer": {"value": int(value), "type": {"bits": 32, "signed": True}}}


def integer64(value):
    return {"integer": {"value": int(value), "type": {"bits": 64, "signed": True}}}


def case(case_id, function, arguments, expected, step_budget=4096):
    return {
        "id": case_id,
        "request": {
            "schema_version": "0.1",
            "target": {"module": MODULE, "function": function},
            "arguments": list(arguments),
            "step_budget": step_budget,
        },
        "expected": [expected],
    }


def record(module, type_name, fields):
    # Encoding matches mncs-model serde: percent-encoded `name:type;` spec
    # over alphabetically sorted fields, plus the record name, with fields
    # as an ordered list of [name, value] pairs. Enum-typed fields name the
    # bare variant type. Verified byte-identical against `mncs abi` output.
    names = sorted(fields)
    spec = "".join(f"{name}:{fields[name][1]};" for name in names)
    return {
        "record": {
            "type_identity": (
                f"mncs:0.2:record-type:{module}::{type_name}::"
                f"{urllib.parse.quote(spec, safe='')}"
            ),
            "name": type_name,
            "fields": [[name, fields[name][0]] for name in names],
        }
    }


def env_record(env):
    return record(
        MODULE,
        "WorkerEnv",
        {
            "os": (finite(MODULE, "Os", env["os_mncs"], OS_MNCS.index(env["os_mncs"])), "Os"),
            "arch": (finite(MODULE, "Arch", env["arch_mncs"], ARCH_MNCS.index(env["arch_mncs"])), "Arch"),
            "libc": (finite(MODULE, "Libc", env["libc_mncs"], LIBC_MNCS.index(env["libc_mncs"])), "Libc"),
            "init": (finite(MODULE, "Init", env["init_mncs"], INIT_MNCS.index(env["init_mncs"])), "Init"),
            "accel": (finite(MODULE, "Accel", env["accel_mncs"], ACCEL_MNCS.index(env["accel_mncs"])), "Accel"),
            "exec": (finite(MODULE, "ExecMode", env["exec_mncs"], EXEC_MNCS.index(env["exec_mncs"])), "ExecMode"),
            "cuda_major": (integer32(env["cuda_major"]), "i32"),
            "cuda_minor": (integer32(env["cuda_minor"]), "i32"),
            "has_ebpf": (boolean(env["has_ebpf"]), "bool"),
            "has_wasm": (boolean(env["has_wasm"]), "bool"),
            "has_ptx": (boolean(env["has_ptx"]), "bool"),
            "mem_mib": (integer64(env["mem_mib"]), "i64"),
            "cpu_count": (integer32(env["cpu_count"]), "i32"),
            "emulates_req_arch": (boolean(env["emulates_req_arch"]), "bool"),
        },
    )


def req_record(req):
    return record(
        MODULE,
        "WorkloadReq",
        {
            "os": (finite(MODULE, "ReqOs", req["os_mncs"], REQ_OS_MNCS.index(req["os_mncs"])), "ReqOs"),
            "arch": (finite(MODULE, "ReqArch", req["arch_mncs"], REQ_ARCH_MNCS.index(req["arch_mncs"])), "ReqArch"),
            "libc": (finite(MODULE, "ReqLibc", req["libc_mncs"], REQ_LIBC_MNCS.index(req["libc_mncs"])), "ReqLibc"),
            "require_cuda": (boolean(req["require_cuda"]), "bool"),
            "cuda_major": (integer32(req["cuda_major"]), "i32"),
            "cuda_minor": (integer32(req["cuda_minor"]), "i32"),
            "require_ebpf": (boolean(req["require_ebpf"]), "bool"),
            "require_wasm": (boolean(req["require_wasm"]), "bool"),
            "require_ptx": (boolean(req["require_ptx"]), "bool"),
            "allow_emulation": (boolean(req["allow_emulation"]), "bool"),
            "min_mem_mib": (integer64(req["min_mem_mib"]), "i64"),
            "min_cpu_count": (integer32(req["min_cpu_count"]), "i32"),
        },
    )


def py_env(env):
    return {
        "os": OS_PY[OS_MNCS.index(env["os_mncs"])],
        "arch": ARCH_PY[ARCH_MNCS.index(env["arch_mncs"])],
        "libc": LIBC_PY[LIBC_MNCS.index(env["libc_mncs"])],
        "accel": ACCEL_PY[ACCEL_MNCS.index(env["accel_mncs"])],
        "exec_mode": EXEC_PY[EXEC_MNCS.index(env["exec_mncs"])],
        "cuda_major": env["cuda_major"],
        "cuda_minor": env["cuda_minor"],
        "has_ebpf": env["has_ebpf"],
        "has_wasm": env["has_wasm"],
        "has_ptx": env["has_ptx"],
        "mem_mib": env["mem_mib"],
        "cpu_count": env["cpu_count"],
        "emulates_req_arch": env["emulates_req_arch"],
    }


def py_req(req):
    return {
        "os": REQ_OS_PY[REQ_OS_MNCS.index(req["os_mncs"])],
        "arch": REQ_ARCH_PY[REQ_ARCH_MNCS.index(req["arch_mncs"])],
        "libc": REQ_LIBC_PY[REQ_LIBC_MNCS.index(req["libc_mncs"])],
        "require_cuda": req["require_cuda"],
        "cuda_major": req["cuda_major"],
        "cuda_minor": req["cuda_minor"],
        "require_ebpf": req["require_ebpf"],
        "require_wasm": req["require_wasm"],
        "require_ptx": req["require_ptx"],
        "allow_emulation": req["allow_emulation"],
        "min_mem_mib": req["min_mem_mib"],
        "min_cpu_count": req["min_cpu_count"],
    }


def main():
    cases = []
    for req_mncs, req_py in zip(REQ_OS_MNCS, REQ_OS_PY):
        for got_mncs, got_py in zip(OS_MNCS, OS_PY):
            cases.append(
                case(
                    f"os-{req_mncs}-{got_mncs}",
                    "candidate_os",
                    [
                        finite(MODULE, "ReqOs", req_mncs, REQ_OS_MNCS.index(req_mncs)),
                        finite(MODULE, "Os", got_mncs, OS_MNCS.index(got_mncs)),
                    ],
                    boolean(os_satisfies(req_py, got_py)),
                )
            )
    for req_mncs, req_py in zip(REQ_ARCH_MNCS, REQ_ARCH_PY):
        for got_mncs, got_py in zip(ARCH_MNCS, ARCH_PY):
            cases.append(
                case(
                    f"arch-match-{req_mncs}-{got_mncs}",
                    "arch_matches",
                    [
                        finite(MODULE, "ReqArch", req_mncs, REQ_ARCH_MNCS.index(req_mncs)),
                        finite(MODULE, "Arch", got_mncs, ARCH_MNCS.index(got_mncs)),
                    ],
                    boolean(arch_matches(req_py, got_py)),
                )
            )
    for req_mncs, req_py in zip(REQ_ARCH_MNCS, REQ_ARCH_PY):
        for got_mncs, got_py in zip(ARCH_MNCS, ARCH_PY):
            for allow in (False, True):
                for emulates in (False, True):
                    for exec_mncs, exec_py in zip(EXEC_MNCS, EXEC_PY):
                        cases.append(
                            case(
                                f"arch-{req_mncs}-{got_mncs}-allow{int(allow)}-emul{int(emulates)}-{exec_mncs}",
                                "candidate_arch",
                                [
                                    finite(MODULE, "ReqArch", req_mncs, REQ_ARCH_MNCS.index(req_mncs)),
                                    finite(MODULE, "Arch", got_mncs, ARCH_MNCS.index(got_mncs)),
                                    boolean(allow),
                                    boolean(emulates),
                                    finite(MODULE, "ExecMode", exec_mncs, EXEC_MNCS.index(exec_mncs)),
                                ],
                                boolean(
                                    arch_satisfies(
                                        req_py, got_py,
                                        allow_emulation=allow,
                                        emulates_req_arch=emulates,
                                        exec_mode=exec_py,
                                    )
                                ),
                            )
                        )
    for req_mncs, req_py in zip(REQ_LIBC_MNCS, REQ_LIBC_PY):
        for got_mncs, got_py in zip(LIBC_MNCS, LIBC_PY):
            cases.append(
                case(
                    f"libc-{req_mncs}-{got_mncs}",
                    "candidate_libc",
                    [
                        finite(MODULE, "ReqLibc", req_mncs, REQ_LIBC_MNCS.index(req_mncs)),
                        finite(MODULE, "Libc", got_mncs, LIBC_MNCS.index(got_mncs)),
                    ],
                    boolean(libc_satisfies(req_py, got_py)),
                )
            )
    for require in (False, True):
        for req_ver in ((0, 0), (12, 0)):
            for got_mncs, got_py in zip(ACCEL_MNCS, ACCEL_PY):
                for got_ver in ((0, 0), (11, 8), (12, 0)):
                    cases.append(
                        case(
                            f"cuda-req{int(require)}-{req_ver[0]}-{req_ver[1]}-{got_mncs}-{got_ver[0]}-{got_ver[1]}",
                            "candidate_cuda",
                            [
                                boolean(require),
                                integer32(req_ver[0]),
                                integer32(req_ver[1]),
                                finite(MODULE, "Accel", got_mncs, ACCEL_MNCS.index(got_mncs)),
                                integer32(got_ver[0]),
                                integer32(got_ver[1]),
                            ],
                            boolean(
                                cuda_satisfies(
                                    require, req_ver[0], req_ver[1],
                                    got_py, got_ver[0], got_ver[1],
                                )
                            ),
                        )
                    )
    for min_mem, min_cpu, got_mem, got_cpu in [
        (0, 0, 0, 0), (0, 0, 512, 2), (512, 2, 512, 2),
        (512, 2, 511, 2), (512, 2, 512, 1), (1024, 4, 2048, 8),
        (2048, 8, 1024, 8), (100, 4, 200, 2),
    ]:
        cases.append(
            case(
                f"resources-{min_mem}-{min_cpu}-{got_mem}-{got_cpu}",
                "candidate_resources",
                [integer64(min_mem), integer32(min_cpu), integer64(got_mem), integer32(got_cpu)],
                boolean(resources_satisfy(min_mem, min_cpu, got_mem, got_cpu)),
            )
        )
    for require in (False, True):
        for got in (False, True):
            cases.append(
                case(
                    f"flag-req{int(require)}-got{int(got)}",
                    "candidate_flag",
                    [boolean(require), boolean(got)],
                    boolean(flag_satisfies(require, got)),
                )
            )
    base_env = {
        "os_mncs": "Linux", "arch_mncs": "X86_64", "libc_mncs": "Gnu",
        "init_mncs": "Unknown",
        "accel_mncs": "None", "exec_mncs": "Native",
        "cuda_major": 0, "cuda_minor": 0,
        "has_ebpf": False, "has_wasm": True, "has_ptx": False,
        "mem_mib": 2048, "cpu_count": 4, "emulates_req_arch": False,
    }
    base_req = {
        "os_mncs": "Linux", "arch_mncs": "X86_64", "libc_mncs": "Gnu",
        "require_cuda": False, "cuda_major": 0, "cuda_minor": 0,
        "require_ebpf": False, "require_wasm": True, "require_ptx": False,
        "allow_emulation": False, "min_mem_mib": 512, "min_cpu_count": 2,
    }
    scenarios = [("base", {}, {})]
    scenarios.append(("os-mismatch", {"os_mncs": "Windows"}, {}))
    scenarios.append(("arch-emulated-allowed", {"arch_mncs": "Aarch64", "exec_mncs": "Emulated", "emulates_req_arch": True}, {"allow_emulation": True}))
    scenarios.append(("arch-emulated-denied", {"arch_mncs": "Aarch64", "exec_mncs": "Emulated", "emulates_req_arch": True}, {"allow_emulation": False}))
    scenarios.append(("cuda-floor-met", {"accel_mncs": "Cuda", "cuda_major": 12, "cuda_minor": 0}, {"require_cuda": True, "cuda_major": 11, "cuda_minor": 8}))
    scenarios.append(("cuda-floor-missed", {"accel_mncs": "Cuda", "cuda_major": 11, "cuda_minor": 8}, {"require_cuda": True, "cuda_major": 12, "cuda_minor": 0}))
    scenarios.append(("cuda-absent", {}, {"require_cuda": True, "cuda_major": 12, "cuda_minor": 0}))
    scenarios.append(("ebpf-required", {}, {"require_ebpf": True}))
    scenarios.append(("resources-short", {"mem_mib": 256}, {}))
    scenarios.append(("unknown-os", {"os_mncs": "Unknown"}, {}))
    scenarios.append(("any-os", {"os_mncs": "Unknown"}, {"os_mncs": "Any"}))
    scenarios.append(("wasm-missing", {"has_wasm": False}, {}))
    for name, env_delta, req_delta in scenarios:
        for init in ("Unknown", "Systemd"):
            env = dict(base_env)
            env.update(env_delta)
            env["init_mncs"] = init
            req = dict(base_req)
            req.update(req_delta)
            # Python ignores init on both sides; the std module must agree
            # under either value, proving init-independence.
            expected = env_satisfies(py_req(req), py_env(env))
            cases.append(
                case(f"env-{name}-init-{init.lower()}", "candidate_env",
                     [req_record(req), env_record(env)], boolean(expected))
            )
    document = {
        "schema_version": "0.1",
        "name": "fabric-std-platform-parity",
        "cases": cases,
    }
    out = os.path.join(HERE, "std_platform_parity_corpus.json")
    with open(out, "w") as handle:
        json.dump(document, handle, indent=1)
        handle.write("\n")
    print(f"wrote {out}: {len(cases)} cases")


if __name__ == "__main__":
    main()
