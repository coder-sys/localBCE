"""Generate a Blind Ledger batch proof and verify it with a separate verifier.

LOCAL BENCHMARK MEASUREMENT ONLY: the Python rules-engine fallback used to build
synthetic claims must never be enabled for production adjudication.

This runner only emits controlled off-chain qualification evidence.  It does
not establish a production or settlement verifier.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import secrets
import subprocess
import sys
from time import perf_counter

os.environ.setdefault("BL_ENV", "test")
os.environ.setdefault("BL_ALLOW_LOCAL_RULES_ENGINE_FALLBACK", "1")
os.environ.setdefault("BL_FORCE_PYTHON_RULES_ENGINE", "1")

from tools import measure_proving as measure
from tools import proving_evidence_policy as evidence_policy
from tools.batch_package import load_batch_package, validate_batch_package


# The local verifier-clean thread sweep preserved identical proof hashes at
# 2/4/8/16 threads; eight threads gave the best repeated median on this host.
DEFAULT_PROVER_THREADS = min(os.cpu_count() or 1, 8)
PROVER_CHANNELS = ("blake2s", "poseidon252")


def _command_text(command: list[str]) -> str:
    return shlex.join(command)


def _run(command: list[str], *, timeout: int | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        text=True,
        capture_output=True,
        check=False,
        timeout=timeout,
    )


def _require_success(
    result: subprocess.CompletedProcess[str], command: list[str], stage: str
) -> None:
    if result.returncode == 0:
        return
    raise RuntimeError(
        f"{stage} failed.\n"
        f"command: {_command_text(command)}\n"
        f"stdout:\n{result.stdout}\n"
        f"stderr:\n{result.stderr}"
    )


def _duration_seconds(log_text: str, marker: str) -> float | None:
    pattern = re.compile(r"close time\.busy=([0-9.]+)(ns|us|µs|ms|s)")
    factors = {"ns": 1e-9, "us": 1e-6, "µs": 1e-6, "ms": 1e-3, "s": 1.0}
    for line in reversed(log_text.splitlines()):
        if marker not in line:
            continue
        match = pattern.search(line)
        if match:
            return float(match.group(1)) * factors[match.group(2)]
    return None


def _felt_hex(value: object) -> str:
    if isinstance(value, str):
        return hex(int(value, 0))
    return hex(int(value))


def _tool_version(path: str) -> str:
    command = ["wsl", path, "--version"]
    result = _run(command, timeout=30)
    _require_success(result, command, f"version check for {path}")
    return (result.stdout or result.stderr).strip()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_proving_input(
    claim_count: int | None, batch_package_path: Path | None
) -> tuple[dict[str, object], int, dict[str, object] | None]:
    if batch_package_path is None:
        effective_claim_count = claim_count if claim_count is not None else 1
        if os.environ.get("BL_ENV", "").strip().lower() in {"prod", "production"}:
            raise RuntimeError("synthetic claim-count proving is disabled in production")
        return measure._build_batch_witness(effective_claim_count), effective_claim_count, None
    if os.environ.get("BL_ENV", "").strip().lower() in {"prod", "production"}:
        raise RuntimeError(
            "production forbids plaintext witness package proving; encrypted envelope required"
        )
    package = load_batch_package(batch_package_path.resolve())
    witness = package["witness"]
    bundle: dict[str, object] = {
        "serialized_arguments_hex_json": list(witness["serialized_arguments_hex_json"]),
        "expected_output_values": list(witness["expected_output_values"]),
    }
    return bundle, int(package["claim_count"]), package


def _bundle_from_package(package: object) -> tuple[dict[str, object], int, dict[str, object]]:
    validated = validate_batch_package(package)
    witness = validated["witness"]
    return (
        {
            "serialized_arguments_hex_json": list(witness["serialized_arguments_hex_json"]),
            "expected_output_values": list(witness["expected_output_values"]),
        },
        int(validated["claim_count"]),
        validated,
    )


def _write_wsl_ram_file(path: str, payload: bytes) -> None:
    command = ["wsl", "sh", "-c", 'umask 077; cat > "$1"', "blind-ledger-write", path]
    result = subprocess.run(command, input=payload, capture_output=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(
            "unable to stage witness arguments in WSL RAM\n"
            f"command: {_command_text(command)}\n"
            f"stderr:\n{result.stderr.decode('utf-8', errors='replace')}"
        )


def _prover_parameters(channel_hash: str) -> dict[str, object] | None:
    """Return an explicit upstream prover configuration for non-default channels."""
    if channel_hash == "blake2s":
        return None
    if channel_hash != "poseidon252":
        raise ValueError(f"unsupported prover channel: {channel_hash}")
    return {
        "channel_hash": "poseidon252",
        "channel_salt": 0,
        "pcs_config": {
            "pow_bits": 26,
            "fri_config": {
                "log_last_layer_degree_bound": 0,
                "log_blowup_factor": 1,
                "n_queries": 70,
                "fold_step": 1,
            },
            "lifting_log_size": None,
        },
        "preprocessed_trace": "canonical_without_pedersen",
        "store_polynomials_coefficients": False,
        "include_all_preprocessed_columns": False,
        "opt_n_id_to_big_components": None,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build and prove batch_main, then invoke an independently pinned verifier."
    )
    input_group = parser.add_mutually_exclusive_group()
    input_group.add_argument("--claim-count", type=int)
    input_group.add_argument("--batch-package", type=Path)
    input_group.add_argument("--batch-package-stdin", action="store_true")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--threads", type=int, default=DEFAULT_PROVER_THREADS)
    parser.add_argument("--evidence-policy", type=Path, required=True)
    parser.add_argument("--ram-token")
    args = parser.parse_args()

    if args.claim_count is not None and args.claim_count < 1:
        raise SystemExit("--claim-count must be at least 1")
    if args.threads < 1:
        raise SystemExit("--threads must be at least 1")
    if args.ram_token is not None and not re.fullmatch(r"[0-9a-f]{32}", args.ram_token):
        raise SystemExit("--ram-token must be exactly 32 lowercase hexadecimal characters")
    if shutil.which("wsl") is None:
        raise SystemExit("WSL is not installed or is not available on PATH.")

    output_dir = args.output_dir.resolve()
    cairo_dir = measure.CAIRO_DIR.resolve()
    try:
        output_dir.relative_to(cairo_dir)
    except ValueError:
        pass
    else:
        raise SystemExit("--output-dir must be outside the protected zk-cairo-sharp tree")
    if output_dir.exists() and any(output_dir.iterdir()):
        raise SystemExit(f"--output-dir must be empty or absent: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)

    policy = evidence_policy.load_approved_policy(args.evidence_policy)
    attestation_before = evidence_policy.attest_policy(policy, source_root=cairo_dir)
    tools = policy.value["tools"]
    scarb = tools["scarb"]["wsl_path"]
    prover = tools["prover"]["wsl_path"]
    verifier = tools["verifier"]["wsl_path"]
    bootloader = tools["bootloader_program"]["wsl_path"]
    proof_system = policy.value["proof_system"]
    build_policy = policy.value["build"]
    verifier_policy = policy.value["verification"]

    witness_started = perf_counter()
    stdin_package = args.batch_package_stdin
    if stdin_package:
        payload = sys.stdin.buffer.read(128 * 1024 * 1024 + 1)
        if len(payload) > 128 * 1024 * 1024:
            raise RuntimeError("piped batch package exceeds 128 MiB")
        try:
            bundle, claim_count, batch_package = _bundle_from_package(json.loads(payload))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("piped batch package is invalid JSON") from exc
    else:
        bundle, claim_count, batch_package = _load_proving_input(
            args.claim_count, args.batch_package
        )
    witness_seconds = perf_counter() - witness_started

    arguments_path = output_dir / "batch_main_args.json"
    expected_path = output_dir / "expected_output.json"
    arguments_payload = json.dumps(bundle["serialized_arguments_hex_json"]).encode("utf-8")
    if not stdin_package:
        arguments_path.write_bytes(arguments_payload)
    expected_output = bundle.get("expected_output")
    if expected_output is None:
        expected_output = bundle["expected_output_values"]
    expected_path.write_text(json.dumps(expected_output, indent=2), encoding="utf-8")
    package_snapshot_path: Path | None = None
    if batch_package is not None and not stdin_package:
        package_snapshot_path = output_dir / "batch_package.json"
        package_snapshot_path.write_text(
            json.dumps(batch_package, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    staged_cairo: str | None = None
    ram_arguments_path: str | None = None
    try:
        staged_cairo, staging_seconds = measure._stage_cairo_in_wsl()
        if stdin_package:
            ram_token = args.ram_token or f"{os.getpid():x}{secrets.token_hex(12)}"
            ram_arguments_path = f"/dev/shm/blind-ledger-witness-{ram_token}.json"
            _write_wsl_ram_file(ram_arguments_path, arguments_payload)
            arguments_wsl_path = ram_arguments_path
        else:
            arguments_wsl_path = measure._to_wsl_path(arguments_path)

        build_command = ["wsl", "--cd", staged_cairo, scarb, "--offline", "build"]
        build_started = perf_counter()
        build_result = _run(build_command, timeout=300)
        build_seconds = perf_counter() - build_started
        (output_dir / "build.stdout.log").write_text(build_result.stdout, encoding="utf-8")
        (output_dir / "build.stderr.log").write_text(build_result.stderr, encoding="utf-8")
        _require_success(build_result, build_command, "Cairo build")

        executable = f"{staged_cairo}/{build_policy['executable_relative_path']}"
        executable_digest = evidence_policy.wsl_file_sha3_512(executable, executable=False)
        if executable_digest != build_policy["executable_sha3_512"]:
            raise RuntimeError("built Cairo executable is altered or unapproved")

        bootloader_input = {
            "tasks": [
                {
                    "path": executable,
                    "user_args_file": arguments_wsl_path,
                    "program_hash_function": proof_system["program_hash_function"],
                    "type": "Cairo1Executable",
                }
            ],
            "single_page": True,
        }
        bootloader_input_path = output_dir / "bootloader_input.json"
        bootloader_input_path.write_text(
            json.dumps(bootloader_input, indent=2), encoding="utf-8"
        )

        native_proof = f"{staged_cairo}/batch.proof.json"
        native_output = f"{staged_cairo}/batch.output.json"
        prover_parameters = proof_system["parameters"]
        prover_parameters_path: Path | None = None
        if prover_parameters is not None:
            prover_parameters_path = output_dir / "prover_params.json"
            prover_parameters_path.write_bytes(
                evidence_policy.canonical_json_bytes(prover_parameters) + b"\n"
            )
        prove_command = [
            "wsl",
            "--cd",
            staged_cairo,
            "env",
            f"RAYON_NUM_THREADS={args.threads}",
            "RUST_LOG=info",
            prover,
            "--program",
            bootloader,
            "--program_input",
            measure._to_wsl_path(bootloader_input_path),
            "--proof_path",
            native_proof,
            "--program_output",
            native_output,
        ]
        if prover_parameters_path is not None:
            prove_command.extend(
                [
                    "--prover_params_json",
                    measure._to_wsl_path(prover_parameters_path),
                ]
            )
        prove_started = perf_counter()
        prove_result = _run(prove_command, timeout=1800)
        prove_wall_seconds = perf_counter() - prove_started
        (output_dir / "prove.stdout.log").write_text(prove_result.stdout, encoding="utf-8")
        (output_dir / "prove.stderr.log").write_text(prove_result.stderr, encoding="utf-8")
        _require_success(prove_result, prove_command, "bootloader proof generation")
        prove_log = prove_result.stdout + "\n" + prove_result.stderr

        verify_command = [
            "wsl",
            "--cd",
            staged_cairo,
            verifier,
            "--program",
            bootloader,
            "--program_input",
            measure._to_wsl_path(bootloader_input_path),
            "--proof_path",
            native_proof,
            "--program_output",
            native_output,
        ]
        if prover_parameters_path is not None:
            verify_command.extend(
                [
                    "--prover_params_json",
                    measure._to_wsl_path(prover_parameters_path),
                ]
            )
        verifier_started = perf_counter()
        verify_result = _run(verify_command, timeout=900)
        verifier_wall_seconds = perf_counter() - verifier_started
        (output_dir / "verify.stdout.log").write_text(verify_result.stdout, encoding="utf-8")
        (output_dir / "verify.stderr.log").write_text(verify_result.stderr, encoding="utf-8")
        _require_success(verify_result, verify_command, "independent proof verification")
        verify_log = verify_result.stdout + "\n" + verify_result.stderr
        if verifier_policy["success_marker"] not in verify_log:
            raise RuntimeError(
                "independent verifier exited successfully without its pinned success marker"
            )

        proof_path = output_dir / "proof.json"
        output_path = output_dir / "program_output.json"
        for source, destination in (
            (native_proof, proof_path),
            (native_output, output_path),
        ):
            copy_command = ["wsl", "cp", source, measure._to_wsl_path(destination)]
            copy_result = _run(copy_command, timeout=120)
            _require_success(copy_result, copy_command, f"copying {source}")

        actual_output = json.loads(output_path.read_text(encoding="utf-8"))
        expected_values = (
            list(expected_output.values())
            if isinstance(expected_output, dict)
            else list(expected_output)
        )
        expected_inner = [_felt_hex(value) for value in expected_values]
        actual_inner = [_felt_hex(value) for value in actual_output[3:]]
        frame_valid = (
            len(actual_output) == len(expected_inner) + 3
            and int(actual_output[0], 0) == 1
            and int(actual_output[1], 0) == len(expected_inner) + 2
        )
        if not frame_valid:
            raise RuntimeError(f"invalid simple-bootloader output frame: {actual_output[:3]}")
        if actual_inner != expected_inner:
            raise RuntimeError(
                "proved public output does not match the Python witness expectation\n"
                f"expected: {expected_inner}\nactual: {actual_inner}"
            )

        attestation_after = evidence_policy.attest_policy(policy, source_root=cairo_dir)
        if attestation_after != attestation_before:
            raise RuntimeError("trusted proof source or tool attestation changed during proving")

        proof_section_seconds = _duration_seconds(
            prove_log,
            "run:stwo_run_and_prove:prove: stwo_run_and_prove: close time.busy=",
        )
        cairo_run_seconds = _duration_seconds(
            prove_log,
            "run:stwo_run_and_prove:cairo_run_program:cairo run: cairo_vm::cairo_run: close time.busy=",
        )
        manifest = {
            "status": "independently_verified",
            "claim_count": claim_count,
            "threads": args.threads,
            "evidence_scope": evidence_policy.POLICY_PURPOSE,
            "evidence_policy": {
                "path": str(policy.path),
                "registry_sha3_512": policy.registry_sha3_512,
                "sha3_512": policy.sha3_512,
            },
            "trusted_provenance": evidence_policy.trusted_manifest_bindings(policy),
            "proof": {
                "path": str(proof_path),
                "bytes": proof_path.stat().st_size,
                "sha256": _sha256_file(proof_path),
                "sha3_512": evidence_policy.sha3_512_file(proof_path),
            },
            "semantic_output_match": True,
            "independent_verifier": True,
            "verification_interface": verifier_policy["interface"],
            "verification_success_marker": True,
            "production_verifier_claimed": False,
            "settlement_contract_verification_run": False,
            "timings_seconds": {
                "witness": witness_seconds,
                "wsl_staging": staging_seconds,
                "cairo_build": build_seconds,
                "cairo_run": cairo_run_seconds,
                "prove_serialize": proof_section_seconds,
                "prove_command_wall": prove_wall_seconds,
                "independent_verifier_wall": verifier_wall_seconds,
            },
            "toolchain": {
                "scarb_path": scarb,
                "scarb_version": _tool_version(scarb),
                "prover_path": prover,
                "prover_version": _tool_version(prover),
                "verifier_path": verifier,
                "verifier_version": _tool_version(verifier),
                "bootloader_program": bootloader,
            },
            "protected_source_manifest_sha3_512_before": attestation_before[
                "protected_source_manifest_sha3_512"
            ],
            "protected_source_manifest_sha3_512_after": attestation_after[
                "protected_source_manifest_sha3_512"
            ],
        }
        if batch_package is not None:
            manifest["batch_package"] = {
                "path": str(package_snapshot_path) if package_snapshot_path is not None else None,
                "input_transport": "stdin_and_wsl_ram" if stdin_package else "plaintext_file",
                "package_id": batch_package["package_id"],
                "batch_id": batch_package["batch_id"],
                "package_sha256": batch_package["package_sha256"],
                "witness_sha256": batch_package["witness_sha256"],
                "authorized_principal": batch_package["authorization"]["principal"],
                "key_id": batch_package["authorization"]["key_id"],
                "retain_until": batch_package["retain_until"],
            }
        manifest_path = output_dir / "run_manifest.json"
        manifest_path.write_bytes(evidence_policy.canonical_json_bytes(manifest) + b"\n")

        print(f"verification_status=passed")
        print("verification_mode=independent_pinned_verifier")
        print(f"evidence_policy_sha3_512={policy.sha3_512}")
        print(f"semantic_output_match=true")
        print(f"protected_source_unchanged=true")
        print(f"witness_seconds={witness_seconds:.6f}")
        print(f"wsl_staging_seconds={staging_seconds:.6f}")
        print(f"cairo_build_seconds={build_seconds:.6f}")
        print(f"prove_command_wall_seconds={prove_wall_seconds:.6f}")
        if proof_section_seconds is not None:
            print(f"prove_serialize_seconds={proof_section_seconds:.6f}")
        print(f"independent_verifier_wall_seconds={verifier_wall_seconds:.6f}")
        print(f"proof_bytes={manifest['proof']['bytes']}")
        print(f"proof_sha256={manifest['proof']['sha256']}")
        print(f"proof_sha3_512={manifest['proof']['sha3_512']}")
        print(f"proof_path={proof_path}")
        print(f"run_manifest={manifest_path}")
    finally:
        if ram_arguments_path is not None:
            _run(["wsl", "rm", "-f", "--", ram_arguments_path], timeout=30)
        if staged_cairo is not None:
            measure._remove_staged_wsl_cairo(staged_cairo)


if __name__ == "__main__":
    try:
        main()
    except (FileNotFoundError, RuntimeError, subprocess.TimeoutExpired) as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1) from exc
