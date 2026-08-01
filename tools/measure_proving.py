#!/usr/bin/env python
# This dev-only rules-engine fallback is for LOCAL BENCHMARK MEASUREMENT ONLY and must
# never be used in production adjudication.
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import shlex
from datetime import date, timedelta
from dataclasses import replace
from functools import lru_cache
from pathlib import Path
from time import perf_counter

from app.batch.batch_orchestrator import BatchConfig, adjudicate_for_batch
from app.batch.nullifier import IndexedNullifierTree
from app.batch.stark_binding import build_monolithic_batch_input_witness, validate_monolithic_batch_input_witness
from app.fact_resolver import resolve_claim_facts
from app.ingestion import parse_837
from app.shared_context import build_shared_context

ROOT = Path(__file__).resolve().parents[1]
CAIRO_DIR = ROOT / "zk-cairo-sharp"
SAMPLE_PAYLOAD = ROOT / "sample_claim_input.json"
_STAGE_SECONDS: dict[str, float] = {}


def _record_stage(name: str, elapsed: float) -> None:
    _STAGE_SECONDS[name] = _STAGE_SECONDS.get(name, 0.0) + elapsed


def _batch_claim_context(claim_id: str, service_date: str) -> tuple:
    os.environ.setdefault("BL_DEV", "1")
    os.environ.setdefault("BL_ENV", "test")
    os.environ.setdefault("BL_ALLOW_LOCAL_RULES_ENGINE_FALLBACK", "1")
    os.environ.setdefault("BL_FORCE_PYTHON_RULES_ENGINE", "1")

    payload = json.loads(SAMPLE_PAYLOAD.read_text(encoding="utf-8"))
    payload["edi"] = (
        payload["edi"]
        .replace("BL-CLAIM-0001", claim_id)
        .replace("DTP*472*D8*20260601", f"DTP*472*D8*{service_date}")
    )
    start = perf_counter()
    parsed = parse_837(payload["edi"])
    _record_stage("parse_837", perf_counter() - start)
    if not parsed.accepted:
        raise RuntimeError(f"unable to parse sample EDI for {claim_id}: {parsed.errors}")

    config = BatchConfig()
    start = perf_counter()
    ctx = build_shared_context(
        parsed,
        payload["flags"],
        strict_oracle=False,
        tar_required_procedure_codes=config.tar_required_procedure_codes,
    )
    _record_stage("build_shared_context", perf_counter() - start)
    start = perf_counter()
    resolved = resolve_claim_facts(ctx, flags=payload["flags"], fee_schedule_cents=config.fee_schedule_cents)
    _record_stage("resolve_claim_facts", perf_counter() - start)
    ctx = replace(
        ctx,
        flags=resolved.flags,
        fact_verification={**ctx.fact_verification, **resolved.fact_verification},
    )
    start = perf_counter()
    result, engine_mode = adjudicate_for_batch(ctx, config=config)
    _record_stage("adjudicate", perf_counter() - start)
    return ctx, result, resolved.evidence_packet.evidence_root, config, engine_mode


def _build_batch_witness(claim_count: int) -> dict:
    if claim_count < 1:
        raise ValueError("claim_count must be at least 1")

    claim_items: list[tuple] = []
    first_claim: tuple | None = None
    base_service_date = date(2026, 6, 1)
    for index in range(claim_count):
        claim_id = f"BL-MEASURE-BATCH-{index + 1:04d}"
        service_date = (base_service_date + timedelta(days=index)).strftime("%Y%m%d")
        ctx, result, evidence_root, config, engine_mode = _batch_claim_context(claim_id, service_date)
        if first_claim is None:
            first_claim = (ctx, result, evidence_root, config, engine_mode)
        claim_items.append((ctx, result, evidence_root, engine_mode))

    assert first_claim is not None
    config = first_claim[3]
    start = perf_counter()
    witness = build_monolithic_batch_input_witness(
        claim_items,
        nullifier_tree=IndexedNullifierTree(),
        config=config,
    )
    _record_stage("build_witness", perf_counter() - start)
    start = perf_counter()
    validate_monolithic_batch_input_witness(witness)
    _record_stage("validate_witness", perf_counter() - start)
    return witness


def _command_to_str(command: list[str]) -> str:
    return " ".join(shlex.quote(part) for part in command)


def _to_wsl_path(path: Path) -> str:
    text = str(path)
    match = re.match(r"^([A-Za-z]):\\?(.*)$", text)
    if match:
        drive = match.group(1).lower()
        tail = match.group(2).replace("\\", "/").lstrip("/")
        return f"/mnt/{drive}/{tail}"
    return text.replace("\\", "/")


@lru_cache(maxsize=1)
def _has_wsl_scarb() -> bool:
    if platform.system() != "Windows":
        return False
    if shutil.which("wsl") is None:
        return False
    result = subprocess.run(
        ["wsl", "bash", "-lc", "command -v scarb >/dev/null 2>&1"],
        text=True,
        capture_output=True,
        check=False,
    )
    return result.returncode == 0


_WSL_NATIVE_PROVE_DIR = re.compile(r"^/tmp/blind-ledger-prove\.[A-Za-z0-9]+$")


def _stage_cairo_in_wsl() -> tuple[str, float]:
    started = perf_counter()
    create = subprocess.run(
        ["wsl", "bash", "-lc", "mktemp -d /tmp/blind-ledger-prove.XXXXXX"],
        text=True,
        capture_output=True,
        check=False,
    )
    staged_dir = create.stdout.strip()
    if create.returncode != 0 or not _WSL_NATIVE_PROVE_DIR.fullmatch(staged_dir):
        raise RuntimeError(
            "failed to create WSL-native proving directory.\n"
            f"stdout:\n{create.stdout}\n"
            f"stderr:\n{create.stderr}"
        )

    source_dir = shlex.quote(_to_wsl_path(CAIRO_DIR))
    destination_dir = shlex.quote(staged_dir)
    copy_script = (
        "set -euo pipefail; "
        f"tar -C {source_dir} --exclude=target --exclude=.git -cf - . | "
        f"tar -C {destination_dir} -xf -"
    )
    copied = subprocess.run(
        ["wsl", "bash", "-lc", copy_script],
        text=True,
        capture_output=True,
        check=False,
    )
    if copied.returncode != 0:
        _remove_staged_wsl_cairo(staged_dir)
        raise RuntimeError(
            "failed to copy Cairo source into WSL-native proving directory.\n"
            f"command: {_command_to_str(['wsl', 'bash', '-lc', copy_script])}\n"
            f"stdout:\n{copied.stdout}\n"
            f"stderr:\n{copied.stderr}"
        )
    return staged_dir, perf_counter() - started


def _remove_staged_wsl_cairo(staged_dir: str) -> None:
    if not _WSL_NATIVE_PROVE_DIR.fullmatch(staged_dir):
        raise RuntimeError(f"refusing to remove unexpected WSL staging path: {staged_dir}")
    result = subprocess.run(
        ["wsl", "rm", "-rf", "--", staged_dir],
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            "failed to remove WSL-native proving directory.\n"
            f"path: {staged_dir}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )


def _proof_metadata(cairo_dir: str | Path, execution_id: str, *, use_wsl: bool) -> tuple[int, str]:
    if not execution_id.isdigit():
        raise RuntimeError(f"unexpected non-numeric execution id: {execution_id}")
    relative = Path("target") / "execute" / "blind_ledger_cairo_adjudication" / f"execution{execution_id}" / "proof" / "proof.json"
    if not use_wsl:
        proof_path = Path(cairo_dir) / relative
        if not proof_path.is_file():
            raise RuntimeError(f"scarb reported success but proof file is missing: {proof_path}")
        return proof_path.stat().st_size, hashlib.sha256(proof_path.read_bytes()).hexdigest()

    proof_path = f"{str(cairo_dir).rstrip('/')}/{relative.as_posix()}"
    size_result = subprocess.run(
        ["wsl", "stat", "-c", "%s", proof_path],
        text=True,
        capture_output=True,
        check=False,
    )
    hash_result = subprocess.run(
        ["wsl", "sha256sum", proof_path],
        text=True,
        capture_output=True,
        check=False,
    )
    size_text = size_result.stdout.strip()
    hash_text = hash_result.stdout.split(maxsplit=1)[0] if hash_result.stdout.strip() else ""
    if (
        size_result.returncode != 0
        or hash_result.returncode != 0
        or not size_text.isdigit()
        or not re.fullmatch(r"[0-9a-f]{64}", hash_text)
    ):
        raise RuntimeError(
            "scarb reported success but proof metadata could not be read.\n"
            f"path: {proof_path}\n"
            f"stat stdout:\n{size_result.stdout}\n"
            f"stat stderr:\n{size_result.stderr}\n"
            f"sha256sum stdout:\n{hash_result.stdout}\n"
            f"sha256sum stderr:\n{hash_result.stderr}"
        )
    return int(size_text), hash_text


def _extract_execution_ids(json_output: str) -> set[str]:
    found: set[str] = set()

    def add(value: object) -> None:
        if isinstance(value, str) and value:
            found.add(value)

    for line in json_output.splitlines():
        text = line.strip()
        if not text:
            continue
        try:
            payload = json.loads(text)
        except Exception:
            continue

        if isinstance(payload, dict):
            add(payload.get("execution_id"))
            add(payload.get("executionId"))
            if "execution" in payload and isinstance(payload["execution"], dict):
                add(payload["execution"].get("id"))
            message = payload.get("message")
            if isinstance(message, str):
                for match in re.finditer(r"\bexecution(\d+)\b", message):
                    found.add(match.group(1))

    for match in re.finditer(r'"execution[_-]id"\s*:\s*"([^"]+)"', json_output):
        found.add(match.group(1))

    for match in re.finditer(r"\bexecution[_-]id[=:]\s*([A-Za-z0-9._/-]+)", json_output):
        found.add(match.group(1))

    for match in re.finditer(r"\bexecution(\d+)\b", json_output):
        found.add(match.group(1))

    return found


def _extract_execution_id(json_output: str) -> str:
    execution_ids = _extract_execution_ids(json_output)
    return next(iter(execution_ids)) if len(execution_ids) == 1 else ""


def _execution_directory_ids(execution_root: Path) -> set[int]:
    if not execution_root.exists():
        return set()
    if not execution_root.is_dir():
        raise RuntimeError("Cairo execution artifact root is not a directory")

    seen_ids: set[int] = set()
    try:
        entries = list(execution_root.iterdir())
        for entry in entries:
            match = re.fullmatch(r"execution(0|[1-9][0-9]*)", entry.name)
            if match and entry.is_dir():
                seen_ids.add(int(match.group(1)))
    except OSError as exc:
        raise RuntimeError("unable to inspect Cairo execution artifacts") from exc
    return seen_ids


def _staged_wsl_execution_directory_ids(staged_dir: str) -> set[int]:
    if not _WSL_NATIVE_PROVE_DIR.fullmatch(staged_dir):
        raise RuntimeError(
            f"refusing to inspect unexpected WSL staging path: {staged_dir}"
        )
    execution_root = (
        f"{staged_dir}/target/execute/blind_ledger_cairo_adjudication"
    )
    quoted_root = shlex.quote(execution_root)
    script = (
        "set -euo pipefail; "
        f"root={quoted_root}; "
        'if [[ ! -e "$root" ]]; then exit 0; fi; '
        'if [[ ! -d "$root" ]]; then exit 41; fi; '
        "shopt -s nullglob; "
        'for path in "$root"/execution*; do '
        'if [[ -d "$path" ]]; then basename -- "$path"; fi; '
        "done"
    )
    result = subprocess.run(
        ["wsl", "bash", "-lc", script],
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            "unable to inspect WSL Cairo execution artifacts.\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )

    seen_ids: set[int] = set()
    for name in result.stdout.splitlines():
        match = re.fullmatch(r"execution(0|[1-9][0-9]*)", name.strip())
        if match:
            seen_ids.add(int(match.group(1)))
    return seen_ids


def _select_new_execution_id(
    json_output: str,
    *,
    previous_ids: set[int],
    current_ids: set[int],
) -> str:
    new_ids = current_ids - previous_ids
    if len(new_ids) != 1:
        raise RuntimeError(
            "scarb execute must create exactly one new execution directory; "
            f"observed {len(new_ids)}"
        )
    new_id = next(iter(new_ids))

    reported_ids = _extract_execution_ids(json_output)
    if len(reported_ids) > 1:
        raise RuntimeError("scarb execute returned multiple execution ids")
    if reported_ids:
        reported = next(iter(reported_ids))
        if not re.fullmatch(r"0|[1-9][0-9]*", reported):
            raise RuntimeError(
                f"scarb execute returned a non-canonical execution id: {reported}"
            )
        reported_id = int(reported)
        if reported_id in previous_ids:
            raise RuntimeError(
                f"scarb execute returned an old execution id: {reported}"
            )
        if reported_id != new_id:
            raise RuntimeError(
                "scarb execute stdout id does not match the newly created "
                "execution directory"
            )
    return str(new_id)


def _run_scarb_prove(
    arguments_hex: list[str],
    prover_threads: int | None,
    cuda_visible_devices: str | None,
    wsl_native_staging: bool,
) -> tuple[float, float, float, float, int, str, str, str, int, str]:
    scarb = shutil.which("scarb")
    use_wsl_scarb = _has_wsl_scarb()
    if scarb is None and not use_wsl_scarb:
        raise FileNotFoundError("scarb is not installed or not available on PATH.")

    staged_wsl_dir = ""
    stage_elapsed = 0.0
    wsl_cairo_dir = _to_wsl_path(CAIRO_DIR)
    workdir_mode = "source_tree"
    if use_wsl_scarb and wsl_native_staging:
        staged_wsl_dir, stage_elapsed = _stage_cairo_in_wsl()
        wsl_cairo_dir = staged_wsl_dir
        workdir_mode = "wsl_native_tmp"

    def _build_scarb_command(
        scarb_subcommand: list[str],
        env_vars: dict[str, str] | None = None,
    ) -> tuple[list[str], str]:
        if not use_wsl_scarb:
            assert scarb is not None
            return [scarb, *scarb_subcommand], _command_to_str([scarb, *scarb_subcommand])

        env_prefix = ""
        if env_vars:
            env_prefix = " ".join(f"{name}={shlex.quote(value)}" for name, value in env_vars.items())
            if env_prefix:
                env_prefix = f"{env_prefix} "
        command = " ".join(shlex.quote(part) for part in scarb_subcommand)
        shell_cmd = f"cd {shlex.quote(wsl_cairo_dir)} && {env_prefix}scarb {command}"
        return ["wsl", "bash", "-lc", shell_cmd], _command_to_str(["wsl", "bash", "-lc", shell_cmd])

    try:
        with tempfile.TemporaryDirectory() as workdir:
            args_path = Path(workdir) / "batch_main_args.json"
            args_path.write_text(json.dumps(arguments_hex), encoding="utf-8")
            execution_root = CAIRO_DIR / "target" / "execute" / "blind_ledger_cairo_adjudication"
            if staged_wsl_dir:
                previous_execution_ids = _staged_wsl_execution_directory_ids(
                    staged_wsl_dir
                )
            else:
                previous_execution_ids = _execution_directory_ids(execution_root)

            execute_args = [
                "execute",
                "--executable-name",
                "batch_main",
                "--arguments-file",
                _to_wsl_path(args_path) if use_wsl_scarb else str(args_path),
                "--target",
                "standalone",
                "--output",
                "standard",
                "--json",
            ]
            execute_command, execute_command_str = _build_scarb_command(execute_args)

            execute_start = perf_counter()
            execute_proc = subprocess.run(
                execute_command,
                cwd=CAIRO_DIR if not use_wsl_scarb else None,
                text=True,
                capture_output=True,
                check=False,
            )
            execute_elapsed = perf_counter() - execute_start
            if execute_proc.returncode != 0:
                raise RuntimeError(
                    "scarb execute failed.\n"
                    f"command: {execute_command_str}\n"
                    f"stdout:\n{execute_proc.stdout}\n"
                    f"stderr:\n{execute_proc.stderr}"
                )

            if staged_wsl_dir:
                current_execution_ids = _staged_wsl_execution_directory_ids(
                    staged_wsl_dir
                )
            else:
                current_execution_ids = _execution_directory_ids(execution_root)
            try:
                execution_id = _select_new_execution_id(
                    execute_proc.stdout,
                    previous_ids=previous_execution_ids,
                    current_ids=current_execution_ids,
                )
            except RuntimeError as exc:
                raise RuntimeError(
                    f"{exc}\n"
                    f"command: {execute_command_str}\n"
                    f"stdout:\n{execute_proc.stdout}\n"
                    f"stderr:\n{execute_proc.stderr}"
                ) from exc

            prove_command_env = {
                "SCARB_OUTPUT_JSON": "true",
            }
            if prover_threads is not None:
                prove_command_env["RAYON_NUM_THREADS"] = str(prover_threads)
            if cuda_visible_devices is not None:
                prove_command_env["CUDA_VISIBLE_DEVICES"] = cuda_visible_devices

            prove_args = [
                "prove",
                "--execution-id",
                execution_id,
                "--json",
            ]
            prove_command, prove_command_str = _build_scarb_command(prove_args, prove_command_env if use_wsl_scarb else None)

            prove_start = perf_counter()
            prove_env = None
            if not use_wsl_scarb:
                prove_env = os.environ.copy()
                prove_env.update(prove_command_env)
            prove_proc = subprocess.run(
                prove_command,
                cwd=CAIRO_DIR if not use_wsl_scarb else None,
                text=True,
                capture_output=True,
                env=prove_env,
                check=False,
            )
            prove_elapsed = perf_counter() - prove_start
            if prove_proc.returncode != 0:
                raise RuntimeError(
                    "scarb prove failed.\n"
                    f"command: {prove_command_str}\n"
                    f"stdout:\n{prove_proc.stdout}\n"
                    f"stderr:\n{prove_proc.stderr}"
                )

            verify_args = [
                "verify",
                "--execution-id",
                execution_id,
                "--json",
            ]
            verify_command, verify_command_str = _build_scarb_command(verify_args)
            verify_start = perf_counter()
            verify_proc = subprocess.run(
                verify_command,
                cwd=CAIRO_DIR if not use_wsl_scarb else None,
                text=True,
                capture_output=True,
                check=False,
            )
            verify_elapsed = perf_counter() - verify_start
            if verify_proc.returncode != 0:
                raise RuntimeError(
                    "scarb verify failed.\n"
                    f"command: {verify_command_str}\n"
                    f"stdout:\n{verify_proc.stdout}\n"
                    f"stderr:\n{verify_proc.stderr}"
                )

            metadata_cairo_dir: str | Path = wsl_cairo_dir if use_wsl_scarb else CAIRO_DIR
            proof_bytes, proof_sha256 = _proof_metadata(metadata_cairo_dir, execution_id, use_wsl=use_wsl_scarb)

        return (
            stage_elapsed,
            execute_elapsed,
            prove_elapsed,
            verify_elapsed,
            prove_proc.returncode,
            execute_proc.stdout + prove_proc.stdout + verify_proc.stdout,
            execute_proc.stderr + prove_proc.stderr + verify_proc.stderr,
            workdir_mode,
            proof_bytes,
            proof_sha256,
        )
    finally:
        if staged_wsl_dir:
            _remove_staged_wsl_cairo(staged_wsl_dir)


def _percent(part: float, total: float) -> float:
    return (part / total * 100.0) if total > 0 else 0.0


def _print_stage_timings(witness_elapsed: float) -> None:
    for stage_name, stage_seconds in sorted(_STAGE_SECONDS.items(), key=lambda item: item[1], reverse=True):
        print(f"stage_seconds[{stage_name}]={stage_seconds:.6f}")
        print(f"stage_pct[{stage_name}]={_percent(stage_seconds, witness_elapsed):.2f}")
    print(f"stage_sum_seconds={sum(_STAGE_SECONDS.values()):.6f}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Measure batch witness build and proving time.")
    parser.add_argument("--claim-count", type=int, default=1, help="Number of claims in the batch (default: 1)")
    parser.add_argument(
        "--prove-threads",
        type=int,
        default=os.cpu_count(),
        help="Override RAYON_NUM_THREADS for scarb prove (default: detected CPU count)",
    )
    parser.add_argument(
        "--prove-cuda-visible-devices",
        default=None,
        help="Override CUDA_VISIBLE_DEVICES for scarb prove (e.g. '0' or '')",
    )
    parser.add_argument(
        "--witness-only",
        action="store_true",
        help="Build and profile the witness without executing or proving it.",
    )
    parser.add_argument(
        "--no-wsl-native-staging",
        action="store_false",
        dest="wsl_native_staging",
        default=True,
        help="Run WSL proving from the Windows-mounted source tree instead of a temporary native Linux copy.",
    )
    args = parser.parse_args()

    try:
        witness_start = perf_counter()
        bundle = _build_batch_witness(args.claim_count)
        arguments_hex = bundle["serialized_arguments_hex_json"]
        witness_elapsed = perf_counter() - witness_start
    except Exception as exc:
        raise SystemExit(f"witness build failed: {exc}") from exc

    if args.witness_only:
        print(f"witness_or_trace_seconds={witness_elapsed:.6f}")
        _print_stage_timings(witness_elapsed)
        return

    if shutil.which("scarb") is None and not _has_wsl_scarb():
        print("scarb is not installed; proving timing is unavailable.")
        print(f"witness_or_trace_seconds={witness_elapsed:.6f}")
        return

    try:
        stage_seconds, execute_seconds, proving_elapsed, verify_seconds, return_code, stdout, stderr, workdir_mode, proof_bytes, proof_sha256 = _run_scarb_prove(
            arguments_hex,
            prover_threads=args.prove_threads,
            cuda_visible_devices=args.prove_cuda_visible_devices,
            wsl_native_staging=args.wsl_native_staging,
        )
    except (FileNotFoundError, RuntimeError) as exc:
        print(f"{exc}")
        print(f"witness_or_trace_seconds={witness_elapsed:.6f}")
        raise SystemExit(1)

    total = witness_elapsed + proving_elapsed
    print(f"witness_or_trace_seconds={witness_elapsed:.6f}")
    print(f"prover_stage_seconds={stage_seconds:.6f}")
    print(f"execute_seconds={execute_seconds:.6f}")
    print(f"prove_seconds={proving_elapsed:.6f}")
    print(f"verify_seconds={verify_seconds:.6f}")
    print("verification_status=passed")
    print(f"prover_workdir_mode={workdir_mode}")
    print(f"proof_bytes={proof_bytes}")
    print(f"proof_sha256={proof_sha256}")
    print(f"witness_or_trace_pct={_percent(witness_elapsed, total):.2f}")
    print(f"prove_pct={_percent(proving_elapsed, total):.2f}")
    _print_stage_timings(witness_elapsed)

    if return_code != 0:
        print("scarb prove failed.")
        if stdout:
            print("=== scarb prove stdout ===")
            print(stdout)
        if stderr:
            print("=== scarb prove stderr ===")
            print(stderr)
        raise SystemExit(return_code)


if __name__ == "__main__":
    if not ROOT.exists():
        raise SystemExit("Repository root could not be resolved.")
    sys.exit(main())
