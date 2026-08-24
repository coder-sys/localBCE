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
import shutil
import secrets
import signal
import stat
import subprocess
import sys
import threading
import time
from time import perf_counter
from typing import Any

os.environ.setdefault("BL_ENV", "test")
os.environ.setdefault("BL_ALLOW_LOCAL_RULES_ENGINE_FALLBACK", "1")
os.environ.setdefault("BL_FORCE_PYTHON_RULES_ENGINE", "1")

from tools import proving_evidence_policy as evidence_policy
from tools.batch_package import validate_batch_package
from tools.proving_resource_policy import (
    MAX_JOB_BYTES,
    MAX_STDERR_BYTES,
    MAX_STDOUT_BYTES,
    read_policy_file,
)


PROVER_CHANNELS = ("blake2s", "poseidon252")
MAX_RUN_JSON_BYTES = 8 * 1024 * 1024


def _load_measure_module() -> Any:
    try:
        from tools import measure_proving
    except ModuleNotFoundError:
        raise RuntimeError("proof_measure_unavailable") from None
    return measure_proving


class _LazyMeasureModule:
    def __getattr__(self, name: str) -> Any:
        return getattr(_load_measure_module(), name)


measure = _LazyMeasureModule()


def _run(
    command: list[str],
    *,
    timeout: int | None = None,
    input_bytes: bytes | None = None,
) -> subprocess.CompletedProcess[str]:
    if input_bytes is not None and len(input_bytes) > min(MAX_JOB_BYTES, MAX_RUN_JSON_BYTES):
        raise RuntimeError("proof_subprocess_input_cap")
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=os.name != "nt",
            shell=False,
        )
    except (OSError, ValueError):
        raise RuntimeError("proof_subprocess_launch") from None

    streams: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray()}
    overflow = threading.Event()
    reader_error = threading.Event()
    started = time.monotonic()
    terminated = threading.Event()

    def terminate() -> None:
        if terminated.is_set():
            return
        terminated.set()
        try:
            if process.poll() is not None:
                return
            if os.name != "nt":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
        except OSError:
            pass

    def read_stream(name: str, stream: Any, maximum: int) -> None:
        try:
            while True:
                chunk = stream.read(min(64 * 1024, maximum + 1))
                if not chunk:
                    return
                remaining = maximum - len(streams[name])
                if len(chunk) > remaining:
                    if remaining > 0:
                        streams[name].extend(chunk[:remaining])
                    overflow.set()
                    terminate()
                    return
                streams[name].extend(chunk)
        except (OSError, ValueError):
            reader_error.set()
            terminate()

    def write_input() -> None:
        if input_bytes is None or process.stdin is None:
            return
        try:
            process.stdin.write(input_bytes)
            process.stdin.close()
        except (OSError, ValueError):
            terminate()

    assert process.stdout is not None and process.stderr is not None
    readers = [
        threading.Thread(
            target=read_stream,
            args=("stdout", process.stdout, MAX_STDOUT_BYTES),
            daemon=True,
        ),
        threading.Thread(
            target=read_stream,
            args=("stderr", process.stderr, MAX_STDERR_BYTES),
            daemon=True,
        ),
    ]
    for reader in readers:
        reader.start()
    writer = threading.Thread(target=write_input, daemon=True)
    writer.start()
    timed_out = False
    try:
        while process.poll() is None:
            if overflow.is_set():
                break
            if timeout is not None and time.monotonic() - started >= timeout:
                timed_out = True
                terminate()
                break
            time.sleep(0.02)
        if process.poll() is None:
            terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            terminate()
            process.wait()
        writer.join(timeout=5)
        for reader in readers:
            reader.join(timeout=5)
        if reader_error.is_set():
            raise RuntimeError("proof_subprocess_output_read")
        if timed_out:
            raise RuntimeError("proof_subprocess_timeout")
        if overflow.is_set():
            raise RuntimeError("proof_subprocess_output_cap")
        return subprocess.CompletedProcess(
            command,
            process.returncode,
            stdout=bytes(streams["stdout"]).decode("utf-8", errors="replace"),
            stderr=bytes(streams["stderr"]).decode("utf-8", errors="replace"),
        )
    finally:
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass
        if process.poll() is None:
            terminate()


def _require_success(
    result: subprocess.CompletedProcess[str], command: list[str], stage: str
) -> None:
    if result.returncode == 0:
        return
    raise RuntimeError("proof_subprocess_failed")


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


def _write_bounded(path: Path, payload: bytes, maximum_bytes: int = MAX_JOB_BYTES) -> None:
    if type(payload) is not bytes or len(payload) > maximum_bytes:
        raise RuntimeError("proof_output_cap")
    try:
        path.write_bytes(payload)
    except OSError:
        raise RuntimeError("proof_output_write") from None


def _tool_version(path: str) -> str:
    command = ["wsl", path, "--version"]
    result = _run(command, timeout=30)
    _require_success(result, command, f"version check for {path}")
    return "tool_attested_v1"


def _sha256_file(path: Path) -> str:
    try:
        before = os.lstat(path)
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            raise RuntimeError("proof_output_not_regular")
        if before.st_size > MAX_JOB_BYTES:
            raise RuntimeError("proof_output_cap")
        descriptor = os.open(path, os.O_RDONLY | (os.O_BINARY if hasattr(os, "O_BINARY") else 0))
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or opened.st_size > MAX_JOB_BYTES:
                raise RuntimeError("proof_output_identity")
            digest = hashlib.sha256()
            total = 0
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_JOB_BYTES:
                    raise RuntimeError("proof_output_cap")
                digest.update(chunk)
            after_open = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        after = os.lstat(path)
    except RuntimeError:
        raise
    except (OSError, ValueError):
        raise RuntimeError("proof_output_read") from None
    expected = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    if (
        stat.S_ISLNK(after.st_mode)
        or not stat.S_ISREG(after.st_mode)
        or total != before.st_size
        or (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != expected
        or (after_open.st_dev, after_open.st_ino, after_open.st_size, after_open.st_mtime_ns)
        != expected
        or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != expected
    ):
        raise RuntimeError("proof_output_identity")
    return digest.hexdigest()


def _read_bounded_json(path: Path, maximum_bytes: int = MAX_RUN_JSON_BYTES) -> object:
    descriptor: int | None = None
    try:
        before = os.lstat(path)
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            raise RuntimeError("proof_input_not_regular")
        if before.st_size > maximum_bytes:
            raise RuntimeError("proof_input_cap")
        descriptor = os.open(path, os.O_RDONLY | (os.O_BINARY if hasattr(os, "O_BINARY") else 0))
        opened = os.fstat(descriptor)
        if stat.S_ISLNK(opened.st_mode) or not stat.S_ISREG(opened.st_mode):
            raise RuntimeError("proof_input_identity")
        if opened.st_size > maximum_bytes:
            raise RuntimeError("proof_input_cap")
        raw_buffer = bytearray()
        while len(raw_buffer) <= maximum_bytes:
            chunk = os.read(descriptor, maximum_bytes + 1 - len(raw_buffer))
            if not chunk:
                break
            raw_buffer.extend(chunk)
            if len(raw_buffer) > maximum_bytes:
                raise RuntimeError("proof_input_cap")
        after_open = os.fstat(descriptor)
    except RuntimeError:
        raise
    except (OSError, ValueError):
        raise RuntimeError("proof_input_invalid") from None
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                raise RuntimeError("proof_input_invalid") from None
    try:
        after = os.lstat(path)
    except OSError:
        raise RuntimeError("proof_input_identity") from None
    expected = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    if (
        stat.S_ISLNK(after.st_mode)
        or not stat.S_ISREG(after.st_mode)
        or len(raw_buffer) != before.st_size
        or (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != expected
        or (after_open.st_dev, after_open.st_ino, after_open.st_size, after_open.st_mtime_ns)
        != expected
        or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != expected
    ):
        raise RuntimeError("proof_input_identity")
    try:
        value = json.loads(bytes(raw_buffer).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise RuntimeError("proof_input_invalid") from None
    if not isinstance(value, (dict, list)):
        raise RuntimeError("proof_input_object")
    return value


def _load_proving_input(
    claim_count: int | None, batch_package_path: Path | None
) -> tuple[dict[str, object], int, dict[str, object] | None]:
    if batch_package_path is None:
        effective_claim_count = claim_count if claim_count is not None else 1
        if os.environ.get("BL_ENV", "").strip().lower() in {"prod", "production"}:
            raise RuntimeError("proof_synthetic_production")
        return measure._build_batch_witness(effective_claim_count), effective_claim_count, None
    if os.environ.get("BL_ENV", "").strip().lower() in {"prod", "production"}:
        raise RuntimeError("proof_plaintext_production")
    package = validate_batch_package(_read_bounded_json(batch_package_path.resolve()))
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
    result = _run(command, input_bytes=payload, timeout=30)
    if result.returncode != 0:
        raise RuntimeError("proof_staging_failed")


def _prover_parameters(channel_hash: str) -> dict[str, object] | None:
    """Return an explicit upstream prover configuration for non-default channels."""
    if channel_hash == "blake2s":
        return None
    if channel_hash != "poseidon252":
        raise ValueError("proof_channel")
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
    parser.add_argument("--resource-policy", type=Path, required=True)
    parser.add_argument("--evidence-policy", type=Path, required=True)
    parser.add_argument("--ram-token")
    args = parser.parse_args()

    if args.claim_count is not None and args.claim_count < 1:
        raise RuntimeError("proof_claim_count")
    if args.ram_token is not None and not re.fullmatch(r"[0-9a-f]{32}", args.ram_token):
        raise RuntimeError("proof_ram_token")
    if shutil.which("wsl") is None:
        raise RuntimeError("proof_wsl_unavailable")

    output_dir = args.output_dir.resolve()
    cairo_dir = measure.CAIRO_DIR.resolve()
    try:
        output_dir.relative_to(cairo_dir)
    except ValueError:
        pass
    else:
        raise RuntimeError("proof_output_directory")
    if output_dir.exists() and any(output_dir.iterdir()):
        raise RuntimeError("proof_output_directory")
    output_dir.mkdir(parents=True, exist_ok=True)

    resource_policy = read_policy_file(args.resource_policy)
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
        payload = sys.stdin.buffer.read(min(MAX_JOB_BYTES, 8 * 1024 * 1024) + 1)
        if len(payload) > min(MAX_JOB_BYTES, 8 * 1024 * 1024):
            raise RuntimeError("piped batch package exceeds queue input bound")
        try:
            bundle, claim_count, batch_package = _bundle_from_package(json.loads(payload))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise RuntimeError("proof_input_invalid") from None
    else:
        bundle, claim_count, batch_package = _load_proving_input(
            args.claim_count, args.batch_package
        )
    witness_seconds = perf_counter() - witness_started

    arguments_path = output_dir / "batch_main_args.json"
    expected_path = output_dir / "expected_output.json"
    arguments_payload = json.dumps(bundle["serialized_arguments_hex_json"]).encode("utf-8")
    if not stdin_package:
        _write_bounded(arguments_path, arguments_payload)
    expected_output = bundle.get("expected_output")
    if expected_output is None:
        expected_output = bundle["expected_output_values"]
    _write_bounded(expected_path, json.dumps(expected_output, indent=2).encode("utf-8"))
    package_snapshot_path: Path | None = None
    if batch_package is not None and not stdin_package:
        package_snapshot_path = output_dir / "batch_package.json"
        _write_bounded(
            package_snapshot_path,
            (json.dumps(batch_package, indent=2, sort_keys=True) + "\n").encode("utf-8"),
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
        _write_bounded(bootloader_input_path, json.dumps(bootloader_input, indent=2).encode("utf-8"))

        native_proof = f"{staged_cairo}/batch.proof.json"
        native_output = f"{staged_cairo}/batch.output.json"
        prover_parameters = proof_system["parameters"]
        prover_parameters_path: Path | None = None
        if prover_parameters is not None:
            prover_parameters_path = output_dir / "prover_params.json"
            _write_bounded(
                prover_parameters_path,
                evidence_policy.canonical_json_bytes(prover_parameters) + b"\n"
            )
        prove_command = [
            "wsl",
            "--cd",
            staged_cairo,
            "env",
            f"RAYON_NUM_THREADS={resource_policy.threads}",
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
        _require_success(verify_result, verify_command, "independent proof verification")
        verify_log = verify_result.stdout + "\n" + verify_result.stderr
        if verifier_policy["success_marker"] not in verify_log:
            raise RuntimeError("proof_verifier_marker")

        proof_path = output_dir / "proof.json"
        output_path = output_dir / "program_output.json"
        for source, destination in (
            (native_proof, proof_path),
            (native_output, output_path),
        ):
            copy_command = ["wsl", "cp", source, measure._to_wsl_path(destination)]
            copy_result = _run(copy_command, timeout=120)
            _require_success(copy_result, copy_command, f"copying {source}")

        actual_output = _read_bounded_json(output_path)
        if not isinstance(actual_output, list):
            raise RuntimeError("proof_output_frame")
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
            raise RuntimeError("proof_output_frame")
        if actual_inner != expected_inner:
            raise RuntimeError("proof_output_mismatch")

        attestation_after = evidence_policy.attest_policy(policy, source_root=cairo_dir)
        if attestation_after != attestation_before:
            raise RuntimeError("proof_attestation_changed")

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
            "threads": resource_policy.threads,
            "resource_policy_sha256": resource_policy.digest,
            "evidence_scope": evidence_policy.POLICY_PURPOSE,
            "evidence_policy": {
                "storage_key": "trusted-evidence-policy",
                "registry_sha3_512": policy.registry_sha3_512,
                "sha3_512": policy.sha3_512,
            },
            "trusted_provenance": evidence_policy.trusted_manifest_bindings(policy),
            "proof": {
                "path": "proof.json",
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
                "attested": True,
                "scarb_version": _tool_version(scarb),
                "prover_version": _tool_version(prover),
                "verifier_version": _tool_version(verifier),
                "bootloader_attested": True,
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
                "storage_key": "batch_package.json" if package_snapshot_path is not None else "stdin",
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
        _write_bounded(manifest_path, evidence_policy.canonical_json_bytes(manifest) + b"\n")

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
        print("proof_storage_key=proof.json")
        print("manifest_storage_key=run_manifest.json")
    finally:
        if ram_arguments_path is not None:
            _run(["wsl", "rm", "-f", "--", ram_arguments_path], timeout=30)
        if staged_cairo is not None:
            measure._remove_staged_wsl_cairo(staged_cairo)


if __name__ == "__main__":
    try:
        main()
    except (FileNotFoundError, RuntimeError, subprocess.TimeoutExpired, ValueError, OSError):
        print("proof_rejected", file=sys.stderr)
        raise SystemExit(1) from None
