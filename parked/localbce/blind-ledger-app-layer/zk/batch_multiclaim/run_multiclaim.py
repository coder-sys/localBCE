from __future__ import annotations

import json
import math
import os
import re
import shutil
import subprocess
import sys
import time
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from app.batch.nullifier import IndexedLeaf, IndexedNullifierTree, MAX_NULLIFIER  # noqa: E402
from app.batch.poseidon import FIELD_MODULUS, poseidon_hash  # noqa: E402


ZK_DIR = ROOT / "zk"
PHASE_DIR = ZK_DIR / "batch_multiclaim"
BASE_CIRCUIT = PHASE_DIR / "batch_nullifier_nonmembership.circom"
GENERATED_DIR = PHASE_DIR / "generated"
BUILD_DIR = PHASE_DIR / "build"
KEYS_DIR = PHASE_DIR / "keys"
INPUTS_DIR = PHASE_DIR / "inputs"
WITNESSES_DIR = PHASE_DIR / "witnesses"
PROOFS_DIR = PHASE_DIR / "proofs"
LOGS_DIR = PHASE_DIR / "logs"
REPORT_PATH = PHASE_DIR / "multiclaim_run_report.json"

NODE_DIR = ROOT / "toolchains" / "node" / "node-v24.16.0-win-x64"
NODE = NODE_DIR / "node.exe"
SNARKJS = ZK_DIR / "node_modules" / ".bin" / "snarkjs.cmd"
CIRCOM = ROOT / "toolchains" / "circom" / "bin" / "circom.exe"
CIRCOMSPECT = ROOT / "toolchains" / "circomspect" / "bin" / "circomspect.exe"

DEPTH = 32


def env() -> Dict[str, str]:
    out = os.environ.copy()
    out["PATH"] = f"{NODE_DIR};{out.get('PATH', '')}"
    return out


def run_cmd(args: List[str], *, cwd: Path = ROOT, timeout: int = 600) -> Tuple[int, str, str, int]:
    start = time.perf_counter()
    proc = subprocess.run(args, cwd=cwd, text=True, capture_output=True, env=env(), timeout=timeout)
    elapsed_ms = int((time.perf_counter() - start) * 1000)
    return proc.returncode, proc.stdout, proc.stderr, elapsed_ms


def ensure_dirs() -> None:
    for path in [GENERATED_DIR, BUILD_DIR, KEYS_DIR, INPUTS_DIR, WITNESSES_DIR, PROOFS_DIR, LOGS_DIR]:
        path.mkdir(parents=True, exist_ok=True)


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def as_str(value: int) -> str:
    return str(int(value))


def commitment(values: Iterable[int]) -> int:
    acc = 0
    for value in values:
        acc = poseidon_hash([acc, int(value)])
    return acc


def strings(values: Iterable[int]) -> List[str]:
    return [as_str(value) for value in values]


def wrapper_for_n(n_claims: int) -> Path:
    if n_claims <= 0:
        raise ValueError("N must be positive; N=0 is rejected before circuit generation")
    wrapper = GENERATED_DIR / f"batch_nullifier_nonmembership_N{n_claims}.circom"
    wrapper.write_text(
        '\n'.join(
            [
                "pragma circom 2.2.0;",
                'include "../batch_nullifier_nonmembership.circom";',
                "",
                f"component main {{ public [rootBefore, rootAfter, batchNullifierCommitment] }} = BatchNullifierNonMembership({DEPTH}, {n_claims});",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return wrapper


def circuit_name(n_claims: int) -> str:
    return f"batch_nullifier_nonmembership_N{n_claims}"


def circuit_paths(n_claims: int) -> Dict[str, Path]:
    name = circuit_name(n_claims)
    build = BUILD_DIR / f"N{n_claims}"
    return {
        "build": build,
        "r1cs": build / f"{name}.r1cs",
        "wasm": build / f"{name}_js" / f"{name}.wasm",
        "witness_js": build / f"{name}_js" / "generate_witness.js",
        "sym": build / f"{name}.sym",
        "zkey0": KEYS_DIR / f"{name}_0000.zkey",
        "zkey": KEYS_DIR / f"{name}_final.zkey",
        "vkey": KEYS_DIR / f"{name}_verification_key.json",
    }


def parse_constraints(stdout: str, stderr: str) -> int:
    text = stdout + "\n" + stderr
    match = re.search(r"# Constraints:\s+(\d+)", text)
    if not match:
        match = re.search(r"Constraints:\s+(\d+)", text)
    if not match:
        raise ValueError(f"could not parse constraints from snarkjs output:\n{text}")
    return int(match.group(1))


def ptau_for_constraints(constraints: int) -> Path:
    power = max(12, math.ceil(math.log2(constraints + 1)))
    reusable_floor = max(power, 19)
    reusable = []
    for candidate in KEYS_DIR.glob("pot*_final.ptau"):
        match = re.fullmatch(r"pot(\d+)_final\.ptau", candidate.name)
        if match and candidate.stat().st_size > 0 and int(match.group(1)) >= reusable_floor:
            reusable.append((int(match.group(1)), candidate))
    if reusable:
        return sorted(reusable)[0][1]

    final = KEYS_DIR / f"pot{power}_final.ptau"
    if final.exists():
        return final

    p0 = KEYS_DIR / f"pot{power}_0000.ptau"
    p1 = KEYS_DIR / f"pot{power}_0001.ptau"
    code, out, err, _ = run_cmd([str(SNARKJS), "powersoftau", "new", "bn128", str(power), str(p0), "-v"], timeout=1200)
    write_text(LOGS_DIR / f"pot{power}_new.log", out + err)
    if code != 0:
        raise RuntimeError(f"powersoftau new failed for power {power}: {out}{err}")
    code, out, err, _ = run_cmd(
        [str(SNARKJS), "powersoftau", "contribute", str(p0), str(p1), "--name=blind-ledger-batch", "-v", "-e=local prototype entropy"],
        timeout=1200,
    )
    write_text(LOGS_DIR / f"pot{power}_contribute.log", out + err)
    if code != 0:
        raise RuntimeError(f"powersoftau contribute failed for power {power}: {out}{err}")
    code, out, err, _ = run_cmd([str(SNARKJS), "powersoftau", "prepare", "phase2", str(p1), str(final), "-v"], timeout=1200)
    write_text(LOGS_DIR / f"pot{power}_prepare.log", out + err)
    if code != 0:
        raise RuntimeError(f"powersoftau prepare failed for power {power}: {out}{err}")
    return final


def compile_and_setup(n_claims: int) -> Dict[str, Any]:
    wrapper = wrapper_for_n(n_claims)
    paths = circuit_paths(n_claims)
    paths["build"].mkdir(parents=True, exist_ok=True)

    code, out, err, compile_ms = run_cmd(
        [str(CIRCOM), str(wrapper), "--r1cs", "--wasm", "--sym", "-o", str(paths["build"])],
        timeout=1800,
    )
    write_text(LOGS_DIR / f"N{n_claims}_compile.log", out + err)
    if code != 0:
        raise RuntimeError(f"circom compile failed N={n_claims}: {out}{err}")

    code, out, err, spect_ms = run_cmd(
        [str(CIRCOMSPECT), str(wrapper), "-L", str(ZK_DIR / "node_modules")],
        timeout=1200,
    )
    write_text(LOGS_DIR / f"N{n_claims}_circomspect.log", out + err)
    if code not in (0, 1):
        raise RuntimeError(f"circomspect failed N={n_claims}: {out}{err}")

    code, out, err, _ = run_cmd([str(SNARKJS), "r1cs", "info", str(paths["r1cs"])], timeout=300)
    write_text(LOGS_DIR / f"N{n_claims}_r1cs_info.log", out + err)
    if code != 0:
        raise RuntimeError(f"r1cs info failed N={n_claims}: {out}{err}")
    constraints = parse_constraints(out, err)
    ptau = ptau_for_constraints(constraints)

    if not paths["zkey"].exists():
        code, out, err, setup_ms = run_cmd(
            [str(SNARKJS), "groth16", "setup", str(paths["r1cs"]), str(ptau), str(paths["zkey0"])],
            timeout=2400,
        )
        write_text(LOGS_DIR / f"N{n_claims}_groth16_setup.log", out + err)
        if code != 0:
            raise RuntimeError(f"groth16 setup failed N={n_claims}: {out}{err}")

        code, out, err, contribute_ms = run_cmd(
            [
                str(SNARKJS),
                "zkey",
                "contribute",
                str(paths["zkey0"]),
                str(paths["zkey"]),
                "--name=blind-ledger-batch",
                "-v",
                "-e=local prototype zkey entropy",
            ],
            timeout=2400,
        )
        write_text(LOGS_DIR / f"N{n_claims}_zkey_contribute.log", out + err)
        if code != 0:
            raise RuntimeError(f"zkey contribute failed N={n_claims}: {out}{err}")
    else:
        setup_ms = 0
        contribute_ms = 0

    code, out, err, verify_zkey_ms = run_cmd(
        [str(SNARKJS), "zkey", "verify", str(paths["r1cs"]), str(ptau), str(paths["zkey"])],
        timeout=1200,
    )
    write_text(LOGS_DIR / f"N{n_claims}_zkey_verify.log", out + err)
    if code != 0:
        raise RuntimeError(f"zkey verify failed N={n_claims}: {out}{err}")

    code, out, err, _ = run_cmd(
        [str(SNARKJS), "zkey", "export", "verificationkey", str(paths["zkey"]), str(paths["vkey"])],
        timeout=300,
    )
    write_text(LOGS_DIR / f"N{n_claims}_vkey_export.log", out + err)
    if code != 0:
        raise RuntimeError(f"vkey export failed N={n_claims}: {out}{err}")

    return {
        "n": n_claims,
        "wrapper": str(wrapper),
        "constraints": constraints,
        "ptau": str(ptau),
        "compile_ms": compile_ms,
        "circomspect_ms": spect_ms,
        "setup_ms": setup_ms,
        "contribute_ms": contribute_ms,
        "zkey_verify_ms": verify_zkey_ms,
        "circomspect_log": str(LOGS_DIR / f"N{n_claims}_circomspect.log"),
    }


def step_fields_from_tree(tree: IndexedNullifierTree, value: int, *, allow_invalid_duplicate: bool = False) -> Tuple[Dict[str, Any], IndexedNullifierTree]:
    try:
        witness = tree.prove_nonmembership(value)
        duplicate = False
    except Exception:
        if not allow_invalid_duplicate:
            raise
        witness = tree.duplicate_rejection_witness(value)
        duplicate = True

    predecessor = tree._nodes[witness.leafIndex]
    insert_index = tree._next_index

    intermediate = tree.clone()
    intermediate._nodes[predecessor.index] = IndexedLeaf(predecessor.index, predecessor.value, int(value), insert_index)
    _, insert_path_elements, insert_path_indices = intermediate._root_and_path(insert_index)

    next_tree = tree.clone()
    if not duplicate:
        next_tree.insert(value)

    return (
        {
            "nullifier": int(value),
            "leafIndex": witness.leafIndex,
            "leafValue": witness.leafValue,
            "nextValue": witness.nextValue,
            "nextIndex": witness.nextIndex,
            "insertIndex": insert_index,
            "predPathElements": witness.pathElements,
            "predPathIndices": witness.pathIndices,
            "insertPathElements": insert_path_elements,
            "insertPathIndices": insert_path_indices,
        },
        next_tree,
    )


def batch_input(values: List[int], *, start_tree: IndexedNullifierTree | None = None, allow_invalid_duplicate: bool = False) -> Tuple[Dict[str, Any], IndexedNullifierTree]:
    if not values:
        raise ValueError("N=0 is rejected: empty nullifier batches are not a valid circuit instance")

    tree = start_tree.clone() if start_tree else IndexedNullifierTree()
    root_before = tree.root
    steps = []
    for value in values:
        step, tree = step_fields_from_tree(tree, int(value), allow_invalid_duplicate=allow_invalid_duplicate)
        steps.append(step)

    data = {
        "rootBefore": as_str(root_before),
        "rootAfter": as_str(tree.root),
        "batchNullifierCommitment": as_str(commitment(values)),
        "nullifiers": strings(step["nullifier"] for step in steps),
        "leafIndex": strings(step["leafIndex"] for step in steps),
        "leafValue": strings(step["leafValue"] for step in steps),
        "nextValue": strings(step["nextValue"] for step in steps),
        "nextIndex": strings(step["nextIndex"] for step in steps),
        "insertIndex": strings(step["insertIndex"] for step in steps),
        "predPathElements": [strings(step["predPathElements"]) for step in steps],
        "predPathIndices": [strings(step["predPathIndices"]) for step in steps],
        "insertPathElements": [strings(step["insertPathElements"]) for step in steps],
        "insertPathIndices": [strings(step["insertPathIndices"]) for step in steps],
    }
    return data, tree


def values_for_n(n_claims: int, offset: int = 0) -> List[int]:
    return [poseidon_hash([0xB17D, offset + idx + 1, 0xA11CE]) for idx in range(n_claims)]


def run_proof_case(n_claims: int, case_name: str, data: Dict[str, Any], *, expect_accept: bool) -> Dict[str, Any]:
    paths = circuit_paths(n_claims)
    safe = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in case_name)
    input_path = INPUTS_DIR / f"N{n_claims}_{safe}.json"
    witness_path = WITNESSES_DIR / f"N{n_claims}_{safe}.wtns"
    proof_path = PROOFS_DIR / f"N{n_claims}_{safe}.proof.json"
    public_path = PROOFS_DIR / f"N{n_claims}_{safe}.public.json"
    input_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    result: Dict[str, Any] = {
        "n": n_claims,
        "case": case_name,
        "expected": "ACCEPT" if expect_accept else "REJECT",
        "input": str(input_path),
    }

    code, out, err, witness_ms = run_cmd(
        [str(NODE), str(paths["witness_js"]), str(paths["wasm"]), str(input_path), str(witness_path)],
        timeout=1200,
    )
    write_text(LOGS_DIR / f"N{n_claims}_{safe}_witness.log", out + err)
    result["witness_ms"] = witness_ms
    if code != 0:
        result.update({"result": "REJECTED", "stage": "witness", "evidence": (out + err)[-1200:]})
        if expect_accept:
            result["unexpected"] = True
        return result

    code, out, err, check_ms = run_cmd([str(SNARKJS), "wtns", "check", str(paths["r1cs"]), str(witness_path)], timeout=1200)
    write_text(LOGS_DIR / f"N{n_claims}_{safe}_wtns_check.log", out + err)
    result["wtns_check_ms"] = check_ms
    if code != 0:
        result.update({"result": "REJECTED", "stage": "wtns_check", "evidence": (out + err)[-1200:]})
        if expect_accept:
            result["unexpected"] = True
        return result

    code, out, err, prove_ms = run_cmd(
        [str(SNARKJS), "groth16", "prove", str(paths["zkey"]), str(witness_path), str(proof_path), str(public_path)],
        timeout=2400,
    )
    write_text(LOGS_DIR / f"N{n_claims}_{safe}_prove.log", out + err)
    result["prove_ms"] = prove_ms
    if code != 0:
        result.update({"result": "REJECTED", "stage": "prove", "evidence": (out + err)[-1200:]})
        if expect_accept:
            result["unexpected"] = True
        return result

    code, out, err, verify_ms = run_cmd(
        [str(SNARKJS), "groth16", "verify", str(paths["vkey"]), str(public_path), str(proof_path)],
        timeout=1200,
    )
    write_text(LOGS_DIR / f"N{n_claims}_{safe}_verify.log", out + err)
    accepted = code == 0 and "OK!" in (out + err)
    result.update(
        {
            "result": "ACCEPTED" if accepted else "REJECTED",
            "stage": "verify",
            "verify_ms": verify_ms,
            "proof": str(proof_path),
            "public": str(public_path),
            "proof_size_bytes": proof_path.stat().st_size if proof_path.exists() else 0,
            "public_values": json.loads(public_path.read_text(encoding="utf-8")) if public_path.exists() else [],
            "evidence": (out + err)[-1200:],
        }
    )
    if accepted != expect_accept:
        result["unexpected"] = True
    return result


def mutate(data: Dict[str, Any]) -> Dict[str, Any]:
    return deepcopy(data)


def attack_cases(n_claims: int) -> Dict[str, Tuple[Dict[str, Any], bool]]:
    base_values = values_for_n(n_claims, offset=1000)
    base, final_tree = batch_input(base_values)

    cases: Dict[str, Tuple[Dict[str, Any], bool]] = {}
    cases["all_distinct_accepts"] = (base, True)

    duplicate_existing_tree = IndexedNullifierTree([base_values[0]])
    dup_existing_values = [base_values[0], *values_for_n(n_claims - 1, offset=2000)]
    dup_existing, _ = batch_input(dup_existing_values, start_tree=duplicate_existing_tree, allow_invalid_duplicate=True)
    cases["one_duplicate_existing_rejects"] = (dup_existing, False)

    repeat_values = list(base_values)
    if n_claims >= 2:
        repeat_values[-1] = repeat_values[0]
    in_batch_repeat, _ = batch_input(repeat_values, allow_invalid_duplicate=True)
    cases["in_batch_repeat_rejects"] = (in_batch_repeat, False)

    tampered = mutate(base)
    tampered["predPathElements"][min(1, n_claims - 1)][0] = as_str(int(tampered["predPathElements"][min(1, n_claims - 1)][0]) + 1)
    cases["tampered_sub_witness_rejects"] = (tampered, False)

    reordered = mutate(base)
    reversed_values = list(reversed([int(v) for v in reordered["nullifiers"]]))
    reordered["nullifiers"] = strings(reversed_values)
    reordered["batchNullifierCommitment"] = as_str(commitment(reversed_values))
    cases["reordered_nullifiers_with_old_witnesses_rejects"] = (reordered, False)

    padded = mutate(base)
    padded["nullifiers"][-1] = "0"
    padded["batchNullifierCommitment"] = as_str(commitment(int(v) for v in padded["nullifiers"]))
    cases["zero_padding_slot_rejects"] = (padded, False)

    overflow = mutate(base)
    overflow["nullifiers"][-1] = str(FIELD_MODULUS)
    overflow["batchNullifierCommitment"] = as_str(commitment(int(v) for v in overflow["nullifiers"]))
    cases["field_modulus_wraparound_rejects"] = (overflow, False)

    gap = mutate(base)
    second_values = values_for_n(n_claims, offset=3000)
    second, _ = batch_input(second_values, start_tree=final_tree)
    gap = mutate(second)
    gap["rootBefore"] = base["rootBefore"]
    cases["cross_batch_gap_root_rejects"] = (gap, False)

    overlap_values = [base_values[0], *values_for_n(n_claims - 1, offset=4000)]
    overlap, _ = batch_input(overlap_values, start_tree=final_tree, allow_invalid_duplicate=True)
    cases["cross_batch_overlap_rejects"] = (overlap, False)

    malleated = mutate(base)
    malleated["insertIndex"][0] = as_str(int(malleated["insertIndex"][0]) + 99)
    cases["witness_malleability_insert_index_rejects"] = (malleated, False)

    return cases


def run_escalation() -> Dict[str, Any]:
    ensure_dirs()
    summary: Dict[str, Any] = {
        "label": "soundness-checked, PROTOTYPE, PENDING CRYPTO AUDIT",
        "construction": "multi-claim indexed Merkle non-membership with sequential root transition root_0 -> root_N",
        "tooling": {},
        "scaling": [],
        "phase1_tests": [],
        "attacks": [],
        "walls": [],
    }

    for name, args in {
        "node": [str(NODE), "--version"],
        "circom": [str(CIRCOM), "--version"],
        "snarkjs": [str(SNARKJS), "--version"],
        "circomspect_help": [str(CIRCOMSPECT), "--help"],
    }.items():
        code, out, err, _ = run_cmd(args, timeout=60)
        summary["tooling"][name] = {"code": code, "output": (out + err).splitlines()[:5]}

    largest_n = 0
    largest_setup: Dict[str, Any] | None = None
    n_list = [int(item.strip()) for item in os.environ.get("MULTICLAIM_N_LIST", "4,8,16,32").split(",") if item.strip()]
    for n_claims in n_list:
        try:
            setup = compile_and_setup(n_claims)
            data, _ = batch_input(values_for_n(n_claims))
            proof = run_proof_case(n_claims, "scale_all_distinct", data, expect_accept=True)
            setup.update(
                {
                    "proof_size_bytes": proof.get("proof_size_bytes", 0),
                    "witness_ms": proof.get("witness_ms", 0),
                    "prove_ms": proof.get("prove_ms", 0),
                    "verify_ms": proof.get("verify_ms", 0),
                    "proof_result": proof.get("result"),
                }
            )
            summary["scaling"].append(setup)
            if proof.get("result") == "ACCEPTED" and not proof.get("unexpected"):
                largest_n = n_claims
                largest_setup = setup
            else:
                summary["walls"].append({"phase": "scale", "n": n_claims, "reason": proof})
                break
        except Exception as exc:
            summary["walls"].append({"phase": "scale", "n": n_claims, "reason": repr(exc)})
            break

    summary["largest_n"] = largest_n
    if largest_n > 0:
        cases = attack_cases(largest_n)
        required_names = [
            "all_distinct_accepts",
            "one_duplicate_existing_rejects",
            "in_batch_repeat_rejects",
            "tampered_sub_witness_rejects",
        ]
        for name in required_names:
            data, expect_accept = cases[name]
            summary["phase1_tests"].append(run_proof_case(largest_n, name, data, expect_accept=expect_accept))

        for name, (data, expect_accept) in cases.items():
            if name in required_names:
                continue
            summary["attacks"].append(run_proof_case(largest_n, name, data, expect_accept=expect_accept))

        n1_setup = compile_and_setup(1)
        n1_input, _ = batch_input(values_for_n(1, offset=9000))
        boundary_n1 = run_proof_case(1, "boundary_N1_accepts", n1_input, expect_accept=True)
        summary["attacks"].append(boundary_n1)
        summary["boundary_n1_constraints"] = n1_setup["constraints"]

        try:
            batch_input([])
            summary["attacks"].append({"case": "boundary_N0_rejected_before_circuit", "result": "UNEXPECTED_ACCEPT"})
        except Exception as exc:
            summary["attacks"].append({"case": "boundary_N0_rejected_before_circuit", "result": "REJECTED", "stage": "input_builder", "evidence": str(exc)})

    REPORT_PATH.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


if __name__ == "__main__":
    try:
        report = run_escalation()
        print(json.dumps(report, indent=2))
    except Exception as exc:
        partial = {"fatal": repr(exc), "label": "soundness-checked, PROTOTYPE, PENDING CRYPTO AUDIT"}
        REPORT_PATH.write_text(json.dumps(partial, indent=2), encoding="utf-8")
        print(json.dumps(partial, indent=2))
        raise
