from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from time import perf_counter
from typing import Iterator


ROOT = Path(__file__).resolve().parents[1]
CAIRO_DIR = ROOT / "zk-cairo-sharp"
SYNTHETIC_SAMPLE = ROOT / "sample_claim_input.json"
SYNTHETIC_SAMPLE_SHA256 = (
    "9ab5b17c29a269373ddea217d7b354328ed3a6de9edc6a0b198dd76e81333939"
)
SYNTHETIC_FIXTURE_ID = "blind-ledger-single-claim-v1"
SYNTHETIC_PROFILER_ENABLE_ENV = "BL_ALLOW_SYNTHETIC_CAIRO_PROFILER"
_ALLOWED_ENVIRONMENTS = frozenset({"local", "test"})
_CANONICAL_HEX = re.compile(r"0x(?:0|[1-9a-f][0-9a-f]*)\Z")
_SYNTHETIC_GENERATION_ENVIRONMENT = {
    "BL_ENV": "test",
    "BL_DEV": "1",
    "BL_ALLOW_LOCAL_RULES_ENGINE_FALLBACK": "1",
    "BL_FORCE_PYTHON_RULES_ENGINE": "1",
    "BL_ALLOW_LOCAL_TEST_ORACLE_KEYS": "1",
}
_SYNTHETIC_SCRUBBED_ENV_PREFIXES = ("BL_", "BLIND_LEDGER_")
_SYNTHETIC_SCRUBBED_ENV_KEYS = frozenset({"CARGO_TARGET_DIR"})


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _resolve_command(name: str) -> str | None:
    candidate = shutil.which(name)
    if not candidate:
        return None
    direct = Path(candidate).expanduser()
    if direct.is_file():
        return str(direct.resolve())
    return shutil.which(candidate)


def _enable_profile_manifest(text: str) -> str:
    def enable_sierra(match: re.Match[str]) -> str:
        block = match.group(0)
        if re.search(r"(?m)^sierra\s*=", block):
            return re.sub(r"(?m)^sierra\s*=.*$", "sierra = true", block)
        return block.rstrip() + "\nsierra = true\n\n"

    text = re.sub(
        r"(?ms)^\[\[target\.executable\]\]\s*\n.*?(?=^\[|\Z)",
        enable_sierra,
        text,
    )

    debug_key = "add-statements-functions-debug-info"
    debug_pattern = rf"(?m)^(?:unstable-)?{re.escape(debug_key)}\s*=.*$"
    if re.search(r"(?m)^\[cairo\]\s*$", text):
        cairo_table = re.compile(r"(?ms)^\[cairo\]\s*\n.*?(?=^\[|\Z)")

        def enable_debug_info(match: re.Match[str]) -> str:
            table = match.group(0)
            if re.search(debug_pattern, table):
                return re.sub(debug_pattern, f"{debug_key} = true", table)
            return table.rstrip() + f"\n{debug_key} = true\n\n"

        return cairo_table.sub(enable_debug_info, text, count=1)

    cairo_config = f"[cairo]\n{debug_key} = true\n\n"
    dependencies = re.search(r"(?m)^\[dependencies\]\s*$", text)
    if dependencies:
        return text[: dependencies.start()] + cairo_config + text[dependencies.start() :]
    return text.rstrip() + "\n\n" + cairo_config


def _run(
    command: list[str], *, cwd: Path, label: str
) -> tuple[subprocess.CompletedProcess[str], float]:
    started = perf_counter()
    completed = subprocess.run(
        command,
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )
    elapsed = perf_counter() - started
    stdout = completed.stdout or ""
    stderr = completed.stderr or ""
    print(f"returncode[{label}]={completed.returncode}")
    print(f"seconds[{label}]={elapsed:.6f}")
    print(f"stdout_bytes[{label}]={len(stdout.encode('utf-8', errors='replace'))}")
    print(f"stdout_lines[{label}]={len(stdout.splitlines())}")
    print(f"stderr_bytes[{label}]={len(stderr.encode('utf-8', errors='replace'))}")
    print(f"stderr_lines[{label}]={len(stderr.splitlines())}")
    return completed, elapsed


def _synthetic_profiler_enabled() -> bool:
    environment = os.environ.get("BL_ENV", "").strip().lower()
    return (
        environment in _ALLOWED_ENVIRONMENTS
        and os.environ.get("BL_DEV") == "1"
        and os.environ.get(SYNTHETIC_PROFILER_ENABLE_ENV) == "1"
    )


@contextmanager
def _synthetic_generation_environment() -> Iterator[None]:
    def scrubbed(key: str) -> bool:
        return key in _SYNTHETIC_SCRUBBED_ENV_KEYS or key.startswith(
            _SYNTHETIC_SCRUBBED_ENV_PREFIXES
        )

    previous = {
        key: value for key, value in os.environ.items() if scrubbed(key)
    }
    for key in previous:
        os.environ.pop(key, None)
    os.environ.update(_SYNTHETIC_GENERATION_ENVIRONMENT)
    try:
        yield
    finally:
        for key in tuple(os.environ):
            if scrubbed(key):
                os.environ.pop(key, None)
        os.environ.update(previous)


def _load_synthetic_bundle() -> dict:
    from tools import measure_proving

    if measure_proving.SAMPLE_PAYLOAD.resolve() != SYNTHETIC_SAMPLE.resolve():
        raise RuntimeError("synthetic_fixture_path_mismatch")
    with _synthetic_generation_environment():
        return measure_proving._build_batch_witness(1)


def _build_synthetic_arguments() -> list[str]:
    if _sha256(SYNTHETIC_SAMPLE) != SYNTHETIC_SAMPLE_SHA256:
        raise RuntimeError("synthetic_fixture_identity_mismatch")

    bundle = _load_synthetic_bundle()
    if _sha256(SYNTHETIC_SAMPLE) != SYNTHETIC_SAMPLE_SHA256:
        raise RuntimeError("synthetic_fixture_identity_changed_during_generation")
    if bundle.get("entrypoint") != "blind_ledger_cairo_adjudication::batch_main":
        raise RuntimeError("synthetic_fixture_entrypoint_mismatch")
    metadata = bundle.get("metadata")
    if not isinstance(metadata, dict) or metadata.get("claim_count") != 1:
        raise RuntimeError("synthetic_fixture_claim_count_mismatch")
    arguments = bundle.get("serialized_arguments_hex_json")
    if (
        not isinstance(arguments, list)
        or not arguments
        or any(
            not isinstance(value, str) or _CANONICAL_HEX.fullmatch(value) is None
            for value in arguments
        )
    ):
        raise RuntimeError("synthetic_fixture_arguments_invalid")
    return list(arguments)


def _parser() -> argparse.ArgumentParser:
    return argparse.ArgumentParser(
        description=(
            "Profile the repository's fixed synthetic Cairo fixture without retaining witness, "
            "trace, profile, path, or raw child-output data."
        )
    )


def _profile_synthetic_fixture() -> int:
    scarb = _resolve_command("scarb")
    profiler = _resolve_command("cairo-profiler")
    if not scarb:
        print("error: required Cairo execution tool is unavailable", file=sys.stderr)
        return 2
    if not profiler:
        print("error: required Cairo profiling tool is unavailable", file=sys.stderr)
        return 2

    arguments = _build_synthetic_arguments()
    source_manifest = CAIRO_DIR / "Scarb.toml"
    source_manifest_hash = _sha256(source_manifest)
    print(f"fixture_id={SYNTHETIC_FIXTURE_ID}")
    print(f"synthetic_argument_count={len(arguments)}")
    print(f"source_manifest_sha256_before={source_manifest_hash}")

    with tempfile.TemporaryDirectory(prefix="blind-ledger-cairo-profile-") as temporary:
        profile_root = Path(temporary)
        profile_cairo_dir = profile_root / "zk-cairo-sharp"
        arguments_file = profile_root / "synthetic_arguments.json"
        arguments_file.write_text(
            json.dumps(arguments, separators=(",", ":")), encoding="utf-8"
        )
        os.chmod(arguments_file, 0o600)
        shutil.copytree(
            CAIRO_DIR,
            profile_cairo_dir,
            ignore=shutil.ignore_patterns("target", ".git", "__pycache__"),
        )
        profile_manifest = profile_cairo_dir / "Scarb.toml"
        original_manifest = profile_manifest.read_text(encoding="utf-8")
        profile_manifest.write_text(_enable_profile_manifest(original_manifest), encoding="utf-8")

        execute_command = [
            scarb,
            "execute",
            "--executable-name",
            "batch_main",
            "--arguments-file",
            str(arguments_file),
            "--target",
            "standalone",
            "--output",
            "standard",
            "--print-resource-usage",
            "--save-profiler-trace-data",
        ]
        execute, _ = _run(execute_command, cwd=profile_cairo_dir, label="execute")
        if execute.returncode != 0:
            print("error: Cairo execution failed; no profiler command was attempted", file=sys.stderr)
            return execute.returncode or 1

        traces = list((profile_cairo_dir / "target" / "execute").glob("**/cairo_profiler_trace.json"))
        print(f"trace_file_count={len(traces)}")
        if not traces:
            print("error: Cairo execution produced no profiler trace", file=sys.stderr)
            return 1
        trace_path = max(traces, key=lambda path: path.stat().st_mtime_ns)
        profile_path = profile_root / "profile.pb.gz"
        print(f"trace_bytes={trace_path.stat().st_size}")

        build_command = [
            profiler,
            "build-profile",
            str(trace_path),
            "--output-path",
            str(profile_path),
            "--show-inlined-functions",
        ]
        build, _ = _run(build_command, cwd=profile_cairo_dir, label="build_profile")
        if build.returncode != 0:
            print("error: cairo-profiler could not build the profile", file=sys.stderr)
            return build.returncode or 1
        if not profile_path.is_file():
            print("error: Cairo profiler produced no aggregate profile", file=sys.stderr)
            return 1
        print(f"profile_bytes={profile_path.stat().st_size}")

    source_manifest_hash_after = _sha256(source_manifest)
    print(f"source_manifest_sha256_after={source_manifest_hash_after}")
    if source_manifest_hash_after != source_manifest_hash:
        print("error: protected source manifest changed during profiling", file=sys.stderr)
        return 1
    print("source_manifest_unchanged=true")
    return 0


def main(argv: list[str] | None = None) -> int:
    _, unknown = _parser().parse_known_args(argv)
    if unknown:
        print("error: caller-supplied paths and profiling inputs are forbidden", file=sys.stderr)
        return 2
    if not _synthetic_profiler_enabled():
        print(
            "error: synthetic profiler requires an explicit local/test environment and opt-in flags",
            file=sys.stderr,
        )
        return 2
    try:
        return _profile_synthetic_fixture()
    except (OSError, RuntimeError, TypeError, ValueError):
        print("error: synthetic profiling failed before completion", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
