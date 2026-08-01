"""Fail-closed, offline installer for reviewed Blind Ledger Python wheels.

The source manifest is intentionally fixed.  Network acquisition and lock refresh are
separate review activities; this module never opens a network connection.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
from email.parser import BytesParser
from email.policy import default
from hashlib import sha256, sha3_512
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import sysconfig
from typing import Any, Iterable, Mapping
from urllib.parse import unquote, urlparse
from zipfile import BadZipFile, ZipFile


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "requirements" / "locks" / "python-artifacts.lock.json"
EXPECTED_SCHEMA = "blind-ledger-python-artifact-lock-v1"
EXPECTED_PYTHON = (3, 14, 4)
MAX_METADATA_BYTES = 1024 * 1024
HEX_256 = re.compile(r"[0-9a-f]{64}")
HEX_512 = re.compile(r"[0-9a-f]{128}")
LOCK_LINE = re.compile(
    r"(?P<name>[a-z0-9]+(?:-[a-z0-9]+)*)=="
    r"(?P<version>[A-Za-z0-9][A-Za-z0-9.!+_-]*) "
    r"--hash=sha256:(?P<sha256>[0-9a-f]{64})"
)
ARTIFACT_KEYS = {
    "filename",
    "license_declared",
    "name",
    "pypi_url",
    "sha256",
    "sha3_512",
    "size",
    "version",
}
LOCK_KEYS = {
    "package_count",
    "path",
    "platform",
    "profile",
    "sha256",
    "sha3_512",
    "size",
}


class SupplyChainError(RuntimeError):
    """A fail-closed dependency-integrity or runtime-policy violation."""


@dataclass(frozen=True)
class FileDigests:
    sha256: str
    sha3_512: str
    size: int


@dataclass(frozen=True)
class VerifiedInputs:
    artifacts: tuple[Mapping[str, Any], ...]
    lock: Mapping[str, Any]
    manifest: Mapping[str, Any]
    manifest_digests: FileDigests
    platform_key: str
    profile: str
    wheelhouse: Path


def _fail(message: str) -> None:
    raise SupplyChainError(message)


def _exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    observed = set(value)
    if observed != expected:
        _fail(
            f"{label} keys differ: missing={sorted(expected - observed)} "
            f"extra={sorted(observed - expected)}"
        )


def _no_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"manifest contains duplicate JSON key {key!r}")
        result[key] = value
    return result


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _hash_file(path: Path) -> FileDigests:
    digest_256 = sha256()
    digest_3 = sha3_512()
    size = 0
    try:
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                size += len(chunk)
                digest_256.update(chunk)
                digest_3.update(chunk)
    except OSError as exc:
        _fail(f"cannot read {path}: {exc}")
    return FileDigests(digest_256.hexdigest(), digest_3.hexdigest(), size)


def _normalize_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _safe_source_path(relative: str) -> Path:
    if not relative or "\\" in relative:
        _fail(f"lock path is not canonical POSIX-relative syntax: {relative!r}")
    candidate = ROOT.joinpath(*relative.split("/"))
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        _fail(f"lock path cannot be resolved: {relative}: {exc}")
    if candidate.is_symlink() or not resolved.is_relative_to(ROOT.resolve()):
        _fail(f"lock path escapes the source tree or is a symlink: {relative}")
    if not resolved.is_file():
        _fail(f"lock path is not a regular file: {relative}")
    return resolved


def _load_manifest() -> tuple[dict[str, Any], FileDigests]:
    if MANIFEST_PATH.is_symlink() or not MANIFEST_PATH.is_file():
        _fail(f"canonical manifest is absent, non-regular, or a symlink: {MANIFEST_PATH}")
    try:
        raw = MANIFEST_PATH.read_bytes()
        manifest = json.loads(raw, object_pairs_hook=_no_duplicate_object)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        _fail(f"cannot parse canonical artifact manifest: {exc}")
    if not isinstance(manifest, dict):
        _fail("canonical artifact manifest must be a JSON object")
    if raw != _canonical_json(manifest):
        _fail("canonical artifact manifest bytes are not normalized JSON plus LF")
    return manifest, _hash_file(MANIFEST_PATH)


def _parse_lock(path: Path) -> list[dict[str, str]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        _fail(f"cannot parse lock {path}: {exc}")
    entries: list[dict[str, str]] = []
    for line_number, line in enumerate(lines, start=1):
        if not line or line.startswith("#"):
            continue
        match = LOCK_LINE.fullmatch(line)
        if match is None:
            _fail(f"{path.name}:{line_number}: non-canonical requirement line")
        entries.append(match.groupdict())
    names = [entry["name"] for entry in entries]
    if names != sorted(names) or len(names) != len(set(names)):
        _fail(f"{path.name}: package names are duplicated or not canonically sorted")
    return entries


def _validate_manifest() -> tuple[dict[str, Any], FileDigests]:
    manifest, manifest_digests = _load_manifest()
    _exact_keys(
        manifest,
        {"artifacts", "locks", "profiles", "python", "review", "schema"},
        "manifest",
    )
    if manifest["schema"] != EXPECTED_SCHEMA:
        _fail(f"unsupported manifest schema: {manifest['schema']!r}")

    python_policy = manifest["python"]
    if not isinstance(python_policy, dict):
        _fail("manifest python policy must be an object")
    _exact_keys(
        python_policy, {"abi", "implementation", "platforms", "version"}, "python policy"
    )
    if (
        python_policy["implementation"] != "CPython"
        or python_policy["version"] != "3.14.4"
        or python_policy["abi"] != "cp314"
    ):
        _fail("manifest interpreter policy differs from reviewed CPython 3.14.4/cp314")
    platforms = python_policy["platforms"]
    expected_platforms = {"cp314-linux_x86_64", "cp314-win_amd64"}
    if not isinstance(platforms, dict) or set(platforms) != expected_platforms:
        _fail("manifest platform set differs from reviewed Windows/Linux x86-64 targets")
    for key, policy in platforms.items():
        if not isinstance(policy, dict):
            _fail(f"platform policy {key} must be an object")
        _exact_keys(policy, {"installer_pip_version", "minimum_glibc"}, key)
        if not isinstance(policy["installer_pip_version"], str):
            _fail(f"{key}: installer pip version must be a string")
    if platforms["cp314-linux_x86_64"]["minimum_glibc"] != "2.28":
        _fail("Linux platform must retain the reviewed glibc >= 2.28 floor")
    if platforms["cp314-win_amd64"]["minimum_glibc"] is not None:
        _fail("Windows platform must not declare a glibc policy")

    profiles = manifest["profiles"]
    if not isinstance(profiles, dict) or set(profiles) != {"development", "production"}:
        _fail("manifest must contain exactly production and development profiles")
    profile_sets: dict[str, set[str]] = {}
    for profile, names in profiles.items():
        if not isinstance(names, list) or not all(isinstance(name, str) for name in names):
            _fail(f"profile {profile} must be a string array")
        if names != sorted(names) or len(names) != len(set(names)):
            _fail(f"profile {profile} is duplicated or not canonically sorted")
        if any(name != _normalize_name(name) for name in names):
            _fail(f"profile {profile} contains a non-canonical package name")
        profile_sets[profile] = set(names)
    if len(profile_sets["production"]) != 18 or len(profile_sets["development"]) != 26:
        _fail("reviewed profile package counts must remain production=18, development=26")
    if not profile_sets["production"] < profile_sets["development"]:
        _fail("production must remain a strict subset of development")

    artifacts = manifest["artifacts"]
    if not isinstance(artifacts, dict) or set(artifacts) != expected_platforms:
        _fail("artifact platform set differs from reviewed platform set")
    by_platform: dict[str, dict[str, Mapping[str, Any]]] = {}
    for platform_key, records in artifacts.items():
        if not isinstance(records, list):
            _fail(f"{platform_key}: artifacts must be an array")
        by_name: dict[str, Mapping[str, Any]] = {}
        filenames: set[str] = set()
        for index, artifact in enumerate(records):
            if not isinstance(artifact, dict):
                _fail(f"{platform_key} artifact {index} must be an object")
            _exact_keys(artifact, ARTIFACT_KEYS, f"{platform_key} artifact {index}")
            name = artifact["name"]
            filename = artifact["filename"]
            if not isinstance(name, str) or name != _normalize_name(name) or name in by_name:
                _fail(f"{platform_key}: duplicate or non-canonical artifact name {name!r}")
            if (
                not isinstance(filename, str)
                or Path(filename).name != filename
                or "\\" in filename
                or not filename.endswith(".whl")
                or filename in filenames
            ):
                _fail(f"{platform_key}: unsafe or duplicate wheel filename {filename!r}")
            if not isinstance(artifact["version"], str) or not artifact["version"]:
                _fail(f"{platform_key}/{name}: version is absent")
            if not isinstance(artifact["size"], int) or artifact["size"] <= 0:
                _fail(f"{platform_key}/{name}: artifact size is invalid")
            if not isinstance(artifact["sha256"], str) or HEX_256.fullmatch(artifact["sha256"]) is None:
                _fail(f"{platform_key}/{name}: SHA-256 is invalid")
            if not isinstance(artifact["sha3_512"], str) or HEX_512.fullmatch(artifact["sha3_512"]) is None:
                _fail(f"{platform_key}/{name}: SHA3-512 is invalid")
            if not isinstance(artifact["license_declared"], str) or not artifact["license_declared"]:
                _fail(f"{platform_key}/{name}: declared license is absent")
            url = artifact["pypi_url"]
            parsed = urlparse(url) if isinstance(url, str) else None
            if (
                parsed is None
                or parsed.scheme != "https"
                or parsed.hostname != "files.pythonhosted.org"
                or Path(unquote(parsed.path)).name != filename
            ):
                _fail(f"{platform_key}/{name}: acquisition URL is not the exact official wheel")
            by_name[name] = artifact
            filenames.add(filename)
        if list(by_name) != sorted(by_name) or set(by_name) != profile_sets["development"]:
            _fail(f"{platform_key}: artifact graph differs from the reviewed development graph")
        by_platform[platform_key] = by_name

    locks = manifest["locks"]
    expected_lock_ids = {
        f"{platform_key}-{profile}"
        for platform_key in expected_platforms
        for profile in profile_sets
    }
    if not isinstance(locks, dict) or set(locks) != expected_lock_ids:
        _fail("manifest lock set differs from the four reviewed platform/profile locks")
    for lock_id, lock in locks.items():
        if not isinstance(lock, dict):
            _fail(f"{lock_id}: lock record must be an object")
        _exact_keys(lock, LOCK_KEYS, lock_id)
        expected_id = f"{lock['platform']}-{lock['profile']}"
        expected_path = f"requirements/locks/{lock_id}.lock"
        if lock_id != expected_id or lock["path"] != expected_path:
            _fail(f"{lock_id}: lock identity/path binding differs")
        if lock["profile"] not in profile_sets or lock["platform"] not in by_platform:
            _fail(f"{lock_id}: references an unknown profile or platform")
        lock_path = _safe_source_path(lock["path"])
        observed = _hash_file(lock_path)
        if (
            lock["sha256"] != observed.sha256
            or lock["sha3_512"] != observed.sha3_512
            or lock["size"] != observed.size
        ):
            _fail(f"{lock_id}: lock bytes differ from dual-hash manifest identity")
        entries = _parse_lock(lock_path)
        selected_names = profile_sets[lock["profile"]]
        if lock["package_count"] != len(entries) or set(entry["name"] for entry in entries) != selected_names:
            _fail(f"{lock_id}: lock package set/count differs from its profile")
        for entry in entries:
            artifact = by_platform[lock["platform"]][entry["name"]]
            if entry["version"] != artifact["version"] or entry["sha256"] != artifact["sha256"]:
                _fail(f"{lock_id}/{entry['name']}: lock pin differs from artifact identity")
    return manifest, manifest_digests


def _version_pair(value: str) -> tuple[int, int]:
    try:
        major, minor, *_ = (int(item) for item in value.split("."))
        return major, minor
    except (TypeError, ValueError):
        _fail(f"cannot parse libc version {value!r}")


def _runtime_platform(manifest: Mapping[str, Any]) -> str:
    if platform.python_implementation() != "CPython":
        _fail("only the reviewed CPython implementation is supported")
    if sys.version_info[:3] != EXPECTED_PYTHON:
        _fail(
            "interpreter version differs from reviewed CPython 3.14.4: "
            f"observed={platform.python_version()}"
        )
    if bool(sysconfig.get_config_var("Py_GIL_DISABLED")):
        _fail("free-threaded cp314t is not covered by the reviewed cp314 wheels")
    machine = platform.machine().lower()
    system = platform.system()
    if system == "Windows" and machine in {"amd64", "x86_64"}:
        key = "cp314-win_amd64"
    elif system == "Linux" and machine in {"amd64", "x86_64"}:
        libc_name, libc_version = platform.libc_ver()
        if libc_name.lower() != "glibc" or _version_pair(libc_version) < (2, 28):
            _fail(
                "Linux target requires reviewed glibc >= 2.28: "
                f"observed={libc_name or 'unknown'} {libc_version or 'unknown'}"
            )
        key = "cp314-linux_x86_64"
    else:
        _fail(f"unsupported runtime target: system={system!r} machine={machine!r}")
    expected_pip = manifest["python"]["platforms"][key]["installer_pip_version"]
    try:
        observed_pip = importlib.metadata.version("pip")
    except importlib.metadata.PackageNotFoundError:
        _fail("pip is absent from the reviewed interpreter environment")
    if observed_pip != expected_pip:
        _fail(f"pip version differs for {key}: expected={expected_pip} observed={observed_pip}")
    return key


def _wheel_metadata(path: Path) -> tuple[str, str]:
    try:
        with ZipFile(path) as archive:
            metadata = [name for name in archive.namelist() if name.endswith(".dist-info/METADATA")]
            if len(metadata) != 1:
                _fail(f"{path.name}: expected exactly one wheel METADATA record")
            info = archive.getinfo(metadata[0])
            if info.file_size > MAX_METADATA_BYTES:
                _fail(f"{path.name}: wheel METADATA exceeds {MAX_METADATA_BYTES} bytes")
            message = BytesParser(policy=default).parsebytes(archive.read(metadata[0]))
    except (BadZipFile, KeyError, OSError) as exc:
        _fail(f"{path.name}: invalid wheel archive: {exc}")
    name, version = message.get("Name"), message.get("Version")
    if not name or not version:
        _fail(f"{path.name}: wheel METADATA omits Name or Version")
    return _normalize_name(str(name)), str(version)


def _verify_wheelhouse(
    wheelhouse: Path, artifacts: Iterable[Mapping[str, Any]]
) -> tuple[Mapping[str, Any], ...]:
    if wheelhouse.is_symlink():
        _fail(f"wheelhouse may not be a symlink: {wheelhouse}")
    try:
        resolved = wheelhouse.resolve(strict=True)
    except OSError as exc:
        _fail(f"wheelhouse cannot be resolved: {exc}")
    if not resolved.is_dir():
        _fail(f"wheelhouse is not a directory: {resolved}")
    expected = {str(item["filename"]): item for item in artifacts}
    observed: dict[str, Path] = {}
    try:
        entries = list(resolved.iterdir())
    except OSError as exc:
        _fail(f"wheelhouse cannot be listed: {exc}")
    for entry in entries:
        if entry.is_symlink() or not entry.is_file():
            _fail(f"wheelhouse contains a symlink or non-file entry: {entry.name}")
        observed[entry.name] = entry
    if set(observed) != set(expected):
        _fail(
            "wheelhouse file set differs: "
            f"missing={sorted(set(expected) - set(observed))} "
            f"extra={sorted(set(observed) - set(expected))}"
        )
    verified: list[Mapping[str, Any]] = []
    for filename in sorted(expected):
        artifact = expected[filename]
        path = observed[filename]
        digests = _hash_file(path)
        if (
            digests.size != artifact["size"]
            or digests.sha256 != artifact["sha256"]
            or digests.sha3_512 != artifact["sha3_512"]
        ):
            _fail(f"{filename}: size, SHA-256, or SHA3-512 differs from reviewed identity")
        name, version = _wheel_metadata(path)
        if name != artifact["name"] or version != artifact["version"]:
            _fail(f"{filename}: embedded Name/Version differs from reviewed identity")
        verified.append(artifact)
    return tuple(verified)


def verify(profile: str, wheelhouse: Path) -> VerifiedInputs:
    manifest, manifest_digests = _validate_manifest()
    platform_key = _runtime_platform(manifest)
    lock_id = f"{platform_key}-{profile}"
    if lock_id not in manifest["locks"]:
        _fail(f"no reviewed lock exists for {lock_id}")
    package_names = set(manifest["profiles"][profile])
    artifacts = tuple(
        item for item in manifest["artifacts"][platform_key] if item["name"] in package_names
    )
    verified = _verify_wheelhouse(wheelhouse, artifacts)
    return VerifiedInputs(
        artifacts=verified,
        lock=manifest["locks"][lock_id],
        manifest=manifest,
        manifest_digests=manifest_digests,
        platform_key=platform_key,
        profile=profile,
        wheelhouse=wheelhouse.resolve(strict=True),
    )


def _distribution_inventory() -> dict[str, str]:
    result: dict[str, str] = {}
    for distribution in importlib.metadata.distributions():
        name = distribution.metadata.get("Name")
        if name:
            canonical = _normalize_name(str(name))
            if canonical in result:
                _fail(f"environment contains duplicate installed distribution {canonical}")
            result[canonical] = distribution.version
    return result


def _interpreter_record() -> dict[str, Any]:
    executable = Path(sys.executable).resolve(strict=True)
    digests = _hash_file(executable)
    return {
        "implementation": platform.python_implementation(),
        "path": str(executable),
        "sha256": digests.sha256,
        "sha3_512": digests.sha3_512,
        "size": digests.size,
        "version": platform.python_version(),
    }


def _attestation(
    verified: VerifiedInputs,
    *,
    command: list[str] | None,
    installed: Mapping[str, str] | None,
    status: str,
) -> dict[str, Any]:
    return {
        "artifacts": [
            {
                "filename": item["filename"],
                "sha256": item["sha256"],
                "sha3_512": item["sha3_512"],
                "size": item["size"],
            }
            for item in verified.artifacts
        ],
        "command": command,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "installed_distributions": dict(sorted(installed.items())) if installed is not None else None,
        "interpreter": _interpreter_record(),
        "lock": {
            "path": verified.lock["path"],
            "sha256": verified.lock["sha256"],
            "sha3_512": verified.lock["sha3_512"],
        },
        "manifest": {
            "path": MANIFEST_PATH.relative_to(ROOT).as_posix(),
            "sha256": verified.manifest_digests.sha256,
            "sha3_512": verified.manifest_digests.sha3_512,
        },
        "pip_version": importlib.metadata.version("pip"),
        "platform": verified.platform_key,
        "profile": verified.profile,
        "schema": "blind-ledger-python-install-attestation-v1",
        "status": status,
        "wheelhouse": str(verified.wheelhouse),
    }


def _write_new_attestation(path: Path, value: Mapping[str, Any]) -> FileDigests:
    raw = _canonical_json(value)
    try:
        parent = path.parent.resolve(strict=True)
    except OSError as exc:
        _fail(f"attestation parent directory does not exist: {path.parent}: {exc}")
    if not parent.is_dir() or path.parent.is_symlink():
        _fail(f"attestation parent is not a regular directory: {path.parent}")
    target = parent / path.name
    if target.exists() or target.is_symlink():
        _fail(f"attestation output already exists; refusing overwrite: {target}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    try:
        descriptor = os.open(target, flags, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as exc:
        _fail(f"cannot create attestation {target}: {exc}")
    return _hash_file(target)


def _offline_pip_command(verified: VerifiedInputs) -> list[str]:
    lock_path = _safe_source_path(str(verified.lock["path"]))
    return [
        sys.executable,
        "-m",
        "pip",
        "--isolated",
        "--disable-pip-version-check",
        "--require-virtualenv",
        "install",
        "--no-input",
        "--no-index",
        "--find-links",
        str(verified.wheelhouse),
        "--require-hashes",
        "--only-binary=:all:",
        "--no-deps",
        "--no-cache-dir",
        "--no-compile",
        "-r",
        str(lock_path),
    ]


def _install(verified: VerifiedInputs, attestation_out: Path) -> FileDigests:
    if sys.prefix == sys.base_prefix:
        _fail("installation requires a fresh virtual environment")
    before = _distribution_inventory()
    if set(before) != {"pip"}:
        _fail(
            "virtual environment is not fresh; unexpected distributions before install: "
            f"{sorted(set(before) - {'pip'})}"
        )
    command = _offline_pip_command(verified)
    environment = {
        key: value for key, value in os.environ.items() if not key.upper().startswith("PIP_")
    }
    environment.update(
        {
            "PIP_CONFIG_FILE": os.devnull,
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_NO_INDEX": "1",
        }
    )
    completed = subprocess.run(command, env=environment, check=False)
    if completed.returncode != 0:
        _fail(f"offline pip install failed with exit code {completed.returncode}")
    check = subprocess.run(
        [sys.executable, "-m", "pip", "--isolated", "check"],
        env=environment,
        check=False,
    )
    if check.returncode != 0:
        _fail(f"post-install pip check failed with exit code {check.returncode}")
    installed = _distribution_inventory()
    expected = {
        str(item["name"]): str(item["version"])
        for item in verified.artifacts
    }
    if set(installed) != set(expected) | {"pip"}:
        _fail(
            "post-install distribution set differs: "
            f"missing={sorted(set(expected) - set(installed))} "
            f"extra={sorted(set(installed) - set(expected) - {'pip'})}"
        )
    mismatches = {
        name: {"expected": version, "observed": installed.get(name)}
        for name, version in expected.items()
        if installed.get(name) != version
    }
    if mismatches:
        _fail(f"post-install versions differ: {mismatches}")
    value = _attestation(
        verified,
        command=command,
        installed=installed,
        status="installed-and-verified",
    )
    return _write_new_attestation(attestation_out, value)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("verify", "install"):
        child = subparsers.add_parser(command)
        child.add_argument("--profile", choices=("production", "development"), required=True)
        child.add_argument("--wheelhouse", type=Path, required=True)
        if command == "verify":
            child.add_argument("--attestation-out", type=Path)
        else:
            child.add_argument("--attestation-out", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        verified = verify(args.profile, args.wheelhouse)
        if args.command == "install":
            digests = _install(verified, args.attestation_out)
            print(
                "OFFLINE_INSTALL_VERIFIED "
                f"platform={verified.platform_key} profile={verified.profile} "
                f"packages={len(verified.artifacts)} attestation_sha256={digests.sha256} "
                f"attestation_sha3_512={digests.sha3_512}"
            )
        else:
            value = _attestation(
                verified,
                command=None,
                installed=None,
                status="wheelhouse-verified",
            )
            if args.attestation_out is not None:
                digests = _write_new_attestation(args.attestation_out, value)
                suffix = (
                    f" attestation_sha256={digests.sha256} "
                    f"attestation_sha3_512={digests.sha3_512}"
                )
            else:
                suffix = ""
            print(
                "WHEELHOUSE_VERIFIED "
                f"platform={verified.platform_key} profile={verified.profile} "
                f"packages={len(verified.artifacts)}{suffix}"
            )
        return 0
    except SupplyChainError as exc:
        print(f"SUPPLY_CHAIN_REJECTED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
