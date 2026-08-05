"""Strict read-back verifier for the bounded H6 evidence manifest.

The manifest is an input to H6, not a qualification switch.  A closed check
must point at immutable raw stdout/stderr captures, match their byte counts and
SHA3-512 identities, and have an exact current-source readback.  Open checks
are retained with their explicit blockers.  The manifest never carries a
proof-suite identity or an activation permission.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Final

from experiments.bl_pq512_crypto_foundation.benchmark_evidence import (
    canonical_json_bytes,
)


ROOT: Final[Path] = Path(__file__).resolve().parents[2]
SCHEMA: Final[str] = "BL-PQ512-H6-EVIDENCE-MANIFEST-v1"
MANIFEST_VERSION: Final[int] = 1
NONACTIVATING_STATUS: Final[str] = "NONACTIVATING"
MAX_MANIFEST_BYTES: Final[int] = 2 * 1024 * 1024
MAX_RAW_EVIDENCE_BYTES: Final[int] = 64 * 1024 * 1024
MAX_SOURCE_FILES: Final[int] = 256
MAX_CHECKS: Final[int] = 32
ZERO_DIGEST: Final[str] = "0" * 128
_DIGEST = re.compile(r"^[0-9a-f]{128}$")
_OBLIGATION_IDS: Final[tuple[str, ...]] = (
    "STRICT_PQ_SECURITY_LEDGER",
    "COMPLETE_SIMULATOR",
    "PROOF_RECEIPT_GRAMMAR",
    "ATTACK_CORPUS",
    "CROSS_LANGUAGE_VERIFIER_KATS",
    "SOURCE_TOOLCHAIN_SBOM",
    "REPRODUCIBLE_BUILDS",
    "H5_RESOURCE_EVIDENCE",
    "SIDE_CHANNEL_UNLINKABILITY",
    "ROLLBACK_RECOVERY",
    "COMPLETE_EVIDENCE_MANIFEST",
    "WAVE3_NONACTIVATING_BOUNDARY",
)
_STATUSES: Final[frozenset[str]] = frozenset(
    {"CLOSED", "OPEN", "BLOCKED", "REFERENCE_ONLY"}
)
_EVIDENCE_CLASSES: Final[frozenset[str]] = frozenset(
    {"OBSERVED", "DERIVED", "INFERRED", "UNKNOWN"}
)
_CHECK_KEYS: Final[frozenset[str]] = frozenset(
    {
        "blockers",
        "command",
        "evidenceClass",
        "evidenceIdentitySha3_512",
        "exitCode",
        "obligationId",
        "sourceId",
        "status",
        "stderrBytes",
        "stderrPath",
        "stderrSha3_512",
        "stdoutBytes",
        "stdoutPath",
        "stdoutSha3_512",
    }
)
_SOURCE_KEYS: Final[frozenset[str]] = frozenset({"path", "sha3_512", "size"})


class H6EvidenceManifestError(ValueError):
    """Stable fail-closed error for malformed or stale H6 evidence."""


@dataclass(frozen=True, slots=True)
class H6EvidenceManifestFacts:
    """Verified public facts consumed by the H6 preflight."""

    manifest_path: Path
    manifest_digest_512: bytes
    source_digest_512: bytes
    closed_obligations: tuple[str, ...]
    check_identities_512: tuple[bytes, ...]

    def is_closed(self, obligation_id: str) -> bool:
        return obligation_id in self.closed_obligations

    def check_identity(self, obligation_id: str) -> bytes:
        try:
            index = _OBLIGATION_IDS.index(obligation_id)
        except ValueError as exc:
            raise H6EvidenceManifestError("h6_manifest_unknown_obligation") from exc
        return self.check_identities_512[index]


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise H6EvidenceManifestError(f"h6_manifest_duplicate_key:{key}")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    raise H6EvidenceManifestError(f"h6_manifest_nonfinite:{value}")


def _object(value: object, keys: frozenset[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or frozenset(value) != keys:
        raise H6EvidenceManifestError(f"h6_manifest_{label}_keys_invalid")
    return value


def _ascii(value: object, label: str, maximum: int = 512) -> str:
    if type(value) is not str or not value or len(value) > maximum:
        raise H6EvidenceManifestError(f"h6_manifest_{label}_invalid")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise H6EvidenceManifestError(f"h6_manifest_{label}_not_ascii") from exc
    if b"\x00" in encoded:
        raise H6EvidenceManifestError(f"h6_manifest_{label}_nul")
    return value


def _digest(value: object, label: str, *, allow_zero: bool = False) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise H6EvidenceManifestError(f"h6_manifest_{label}_invalid")
    if not allow_zero and value == ZERO_DIGEST:
        raise H6EvidenceManifestError(f"h6_manifest_{label}_zero")
    return value


def _u64(value: object, label: str, *, allow_none: bool = False) -> int | None:
    if allow_none and value is None:
        return None
    if type(value) is not int or value < 0 or value >= 1 << 64:
        raise H6EvidenceManifestError(f"h6_manifest_{label}_invalid")
    return value


def _relative_path(value: object, label: str) -> str:
    path = _ascii(value, label, 512).replace("\\", "/")
    candidate = Path(path)
    if candidate.is_absolute() or ":" in path or path.startswith("/"):
        raise H6EvidenceManifestError(f"h6_manifest_{label}_absolute")
    if any(part in {"", ".", ".."} for part in candidate.parts):
        raise H6EvidenceManifestError(f"h6_manifest_{label}_not_normalized")
    return "/".join(candidate.parts)


def _file_digest(path: Path) -> tuple[int, str]:
    try:
        stat = path.stat()
        if not path.is_file() or path.is_symlink():
            raise H6EvidenceManifestError("h6_manifest_evidence_file_not_regular")
        digest = hashlib.sha3_512()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except H6EvidenceManifestError:
        raise
    except OSError as exc:
        raise H6EvidenceManifestError("h6_manifest_evidence_file_read_failed") from exc
    return stat.st_size, digest.hexdigest()


def _contained_file(root: Path, relative: str, label: str) -> Path:
    candidate = root / Path(relative)
    if candidate.is_symlink():
        raise H6EvidenceManifestError(f"h6_manifest_{label}_symlink")
    try:
        resolved_root = root.resolve(strict=True)
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(resolved_root)
    except (OSError, ValueError) as exc:
        raise H6EvidenceManifestError(f"h6_manifest_{label}_outside_root") from exc
    if not resolved.is_file() or resolved.is_symlink():
        raise H6EvidenceManifestError(f"h6_manifest_{label}_not_file")
    return resolved


def _check_identity(check: dict[str, Any]) -> str:
    payload = dict(check)
    payload.pop("evidenceIdentitySha3_512")
    return hashlib.sha3_512(
        b"BL/PQ512/H6/EVIDENCE-CHECK/v1\x00" + canonical_json_bytes(payload)
    ).hexdigest()


def _read_manifest(path: Path) -> tuple[dict[str, Any], bytes]:
    if not isinstance(path, Path):
        raise TypeError("h6_manifest_path_required")
    if path.is_symlink() or not path.is_file():
        raise H6EvidenceManifestError("h6_manifest_not_regular_file")
    try:
        size = path.stat().st_size
        raw = path.read_bytes()
    except OSError as exc:
        raise H6EvidenceManifestError("h6_manifest_read_failed") from exc
    if size != len(raw) or size < 3 or size > MAX_MANIFEST_BYTES:
        raise H6EvidenceManifestError("h6_manifest_size_invalid")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except H6EvidenceManifestError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise H6EvidenceManifestError("h6_manifest_json_invalid") from exc
    if type(value) is not dict or raw != canonical_json_bytes(value) + b"\n":
        raise H6EvidenceManifestError("h6_manifest_not_canonical")
    return value, raw


def verify_h6_evidence_manifest(path: Path) -> H6EvidenceManifestFacts:
    """Verify source and raw-evidence identities and return only derived facts."""

    manifest, raw = _read_manifest(path)
    _object(
        manifest,
        frozenset(
            {
                "activationAllowed",
                "checks",
                "manifestVersion",
                "proofSuiteId",
                "schema",
                "sourceFiles",
                "status",
            }
        ),
        "root",
    )
    if manifest["schema"] != SCHEMA or manifest["manifestVersion"] != MANIFEST_VERSION:
        raise H6EvidenceManifestError("h6_manifest_schema_invalid")
    if (
        manifest["status"] != NONACTIVATING_STATUS
        or manifest["proofSuiteId"] is not None
        or manifest["activationAllowed"] is not False
    ):
        raise H6EvidenceManifestError("h6_manifest_activation_boundary_invalid")

    source_files = manifest["sourceFiles"]
    if (
        type(source_files) is not list
        or not source_files
        or len(source_files) > MAX_SOURCE_FILES
    ):
        raise H6EvidenceManifestError("h6_manifest_source_files_invalid")
    source_paths: list[str] = []
    source_entries: list[dict[str, Any]] = []
    for raw_entry in source_files:
        entry = _object(raw_entry, _SOURCE_KEYS, "source_entry")
        relative = _relative_path(entry["path"], "source_path")
        if relative in source_paths:
            raise H6EvidenceManifestError("h6_manifest_source_duplicate")
        source_paths.append(relative)
        size = _u64(entry["size"], "source_size")
        digest = _digest(entry["sha3_512"], "source_digest")
        source_path = _contained_file(ROOT, relative, "source")
        observed_size, observed_digest = _file_digest(source_path)
        if size != observed_size or digest != observed_digest:
            raise H6EvidenceManifestError(f"h6_manifest_source_readback_mismatch:{relative}")
        source_entries.append(
            {"path": relative, "sha3_512": digest, "size": size}
        )

    checks = manifest["checks"]
    if type(checks) is not list or len(checks) != len(_OBLIGATION_IDS) or len(checks) > MAX_CHECKS:
        raise H6EvidenceManifestError("h6_manifest_checks_invalid")
    checked_ids: list[str] = []
    closed: list[str] = []
    identities: list[bytes] = []
    evidence_root = path.resolve(strict=True).parent
    for raw_check, expected_id in zip(checks, _OBLIGATION_IDS, strict=True):
        check = _object(raw_check, _CHECK_KEYS, "check")
        obligation_id = _ascii(check["obligationId"], "obligation_id", 64)
        if obligation_id != expected_id or obligation_id in checked_ids:
            raise H6EvidenceManifestError("h6_manifest_check_order_invalid")
        checked_ids.append(obligation_id)
        status = _ascii(check["status"], "status", 32)
        evidence_class = _ascii(check["evidenceClass"], "evidence_class", 32)
        if status not in _STATUSES or evidence_class not in _EVIDENCE_CLASSES:
            raise H6EvidenceManifestError("h6_manifest_check_status_invalid")
        _ascii(check["sourceId"], "source_id", 256)
        _ascii(check["command"], "command", 2048)
        blockers = check["blockers"]
        if (
            type(blockers) is not list
            or any(type(item) is not str or not item for item in blockers)
            or len(blockers) != len(set(blockers))
        ):
            raise H6EvidenceManifestError("h6_manifest_check_blockers_invalid")
        for blocker in blockers:
            _ascii(blocker, "blocker", 128)
        stdout_digest = _digest(check["stdoutSha3_512"], "stdout_digest", allow_zero=True)
        stderr_digest = _digest(check["stderrSha3_512"], "stderr_digest", allow_zero=True)
        stdout_bytes = _u64(check["stdoutBytes"], "stdout_bytes")
        stderr_bytes = _u64(check["stderrBytes"], "stderr_bytes")
        exit_code = _u64(check["exitCode"], "exit_code", allow_none=True)
        stdout_path = check["stdoutPath"]
        stderr_path = check["stderrPath"]
        identity = _digest(check["evidenceIdentitySha3_512"], "evidence_identity")
        if identity != _check_identity(check):
            raise H6EvidenceManifestError("h6_manifest_check_identity_mismatch")
        identities.append(bytes.fromhex(identity))
        if status == "CLOSED":
            if evidence_class not in {"OBSERVED", "DERIVED"} or blockers:
                raise H6EvidenceManifestError("h6_manifest_closed_check_invalid")
            if exit_code != 0 or stderr_bytes != 0:
                raise H6EvidenceManifestError("h6_manifest_closed_check_failed")
            stdout_relative = _relative_path(stdout_path, "stdout_path")
            stderr_relative = _relative_path(stderr_path, "stderr_path")
            stdout_file = _contained_file(evidence_root, stdout_relative, "stdout")
            stderr_file = _contained_file(evidence_root, stderr_relative, "stderr")
            observed_stdout_size, observed_stdout_digest = _file_digest(stdout_file)
            observed_stderr_size, observed_stderr_digest = _file_digest(stderr_file)
            if (
                observed_stdout_size != stdout_bytes
                or observed_stdout_digest != stdout_digest
                or observed_stderr_size != stderr_bytes
                or observed_stderr_digest != stderr_digest
            ):
                raise H6EvidenceManifestError(
                    f"h6_manifest_raw_readback_mismatch:{obligation_id}"
                )
            if stdout_digest == ZERO_DIGEST:
                raise H6EvidenceManifestError("h6_manifest_raw_digest_boundary_invalid")
            closed.append(obligation_id)
        else:
            if not blockers or exit_code is not None:
                raise H6EvidenceManifestError("h6_manifest_open_check_invalid")
            if stdout_path is not None or stderr_path is not None:
                raise H6EvidenceManifestError("h6_manifest_open_paths_invalid")
            if stdout_bytes != 0 or stderr_bytes != 0:
                raise H6EvidenceManifestError("h6_manifest_open_bytes_invalid")
            if stdout_digest != ZERO_DIGEST or stderr_digest != ZERO_DIGEST:
                raise H6EvidenceManifestError("h6_manifest_open_digests_invalid")

    source_digest = hashlib.sha3_512(canonical_json_bytes(source_entries)).digest()
    return H6EvidenceManifestFacts(
        manifest_path=path.resolve(strict=True),
        manifest_digest_512=hashlib.sha3_512(raw).digest(),
        source_digest_512=source_digest,
        closed_obligations=tuple(closed),
        check_identities_512=tuple(identities),
    )


__all__: tuple[str, ...] = (
    "H6EvidenceManifestError",
    "H6EvidenceManifestFacts",
    "ROOT",
    "SCHEMA",
    "verify_h6_evidence_manifest",
)
