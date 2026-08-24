"""Commit-bound authority for the seven tracked operational files."""

from __future__ import annotations

from hashlib import sha3_512
from pathlib import Path
from stat import S_ISDIR, S_ISLNK, S_ISREG
from typing import Final


ROOT: Final[Path] = Path(__file__).resolve().parents[1]
CANONICAL_OPS_ROOT: Final[Path] = ROOT / "ops"
OPS_AUTHORITY_STATUS: Final[str] = "VERIFIED_TRACKED_SHA3_512_AUTHORITY"
_WINDOWS_REPARSE_POINT: Final[int] = 0x400

EXPECTED_OPS_FILES: Final[tuple[tuple[str, int, str], ...]] = (
    ("DEPLOYMENT_RUNBOOK.md", 2245, "28a4aa024867c08e5ddc95473408132608d7083e3ece5b36723ab4d7aea14d575c06a5da575851c71c572cae12382c8933d37773b341e6357cb8a832129e31c1"),
    ("KEY_CUSTODY_AND_ROTATION.md", 1858, "04bca72fb7a925c7fc0b0c0f6939f924295a6d5a1178ffbdaac000aa9933a9560d0541e9f8d10bac05b12bee2245368a28e0c89714caf4b817b3de5b16282353"),
    ("MONITORING_AUDIT_EVENTS.md", 1551, "8eb2cb95b00ea2fc181363d04689d288054e0adbe1725e6c52b4620cccb4fee05c07bb04405eaed383818f8b8dbe2133b84c0864cafb7abf35cc4cd06e6cc798"),
    ("PRODUCTION_CONFIG_CHECKLIST.md", 1584, "5675453bfc23cba56567a15e81487782a999aa0c3ef5f260e8bb64809545005c9f0b53096af550f659d42cae89ae31d767fe0325b52b7ee48aed4b83c744dd66"),
    ("RISK_REGISTER.md", 1390, "d5a316f176713e16036d40d490f68fdfb41a1dc739f89d2eff5c44b3fa91f166c49a0a4550f93e231e544dc6344ba4aa4e2a7b5a0899f747a124fe8ffcf0dc6e"),
    ("launch_blockers.json", 1596, "762ad7003bbff2b36d9b4ee0c7454725f0d1863bbc028d4c7faf552a4b1e2cdf1d6c6af7e8261120a2bc7e7a6cec5a9afc6e8cea4c4f7e34a40d02d61cb5060c"),
    ("verifier_artifact_pin.example.json", 251, "40b1d4cbf7b14d07c151a3de9b5a0c127c2a18f53a325205c19732656a2193cad81daaa2e4864aff8bebc857d219fd6574d3325e793c7b9913243729bf753242"),
)


def _reject_redirect(path: Path, *, label: str):
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ValueError(f"ops_authority_{label}_invalid") from exc
    if S_ISLNK(metadata.st_mode) or (
        getattr(metadata, "st_file_attributes", 0) & _WINDOWS_REPARSE_POINT
    ):
        raise ValueError(f"ops_authority_{label}_redirected")
    return metadata


def verify_ops_authority(root: Path = CANONICAL_OPS_ROOT) -> str:
    """Verify the canonical regular-file set, lengths, and SHA3-512 identities."""

    if not isinstance(root, Path):
        raise TypeError("ops_authority_root_must_be_path")
    if root != CANONICAL_OPS_ROOT:
        raise ValueError("ops_authority_root_not_canonical")
    root_metadata = _reject_redirect(root, label="root")
    _reject_redirect(ROOT, label="checkout")
    if not S_ISDIR(root_metadata.st_mode):
        raise ValueError("ops_authority_root_invalid")
    expected_names = tuple(item[0] for item in EXPECTED_OPS_FILES)
    observed_paths = tuple(sorted(root.iterdir(), key=lambda path: path.relative_to(root).as_posix()))
    observed_names = tuple(path.relative_to(root).as_posix() for path in observed_paths)
    if observed_names != expected_names:
        raise ValueError("ops_authority_file_set_mismatch")
    for path, (name, length, digest) in zip(observed_paths, EXPECTED_OPS_FILES, strict=True):
        metadata = _reject_redirect(path, label="file")
        if not S_ISREG(metadata.st_mode):
            raise ValueError("ops_authority_file_shape_mismatch")
        data = path.read_bytes()
        if len(data) != length:
            raise ValueError("ops_authority_file_shape_mismatch")
        if sha3_512(data).hexdigest() != digest:
            raise ValueError("ops_authority_digest_mismatch")
    return OPS_AUTHORITY_STATUS


def main() -> int:
    try:
        verify_ops_authority()
    except Exception:
        print("ops_authority=invalid")
        return 1
    print("ops_authority=verified")
    return 0


__all__ = (
    "CANONICAL_OPS_ROOT",
    "EXPECTED_OPS_FILES",
    "OPS_AUTHORITY_STATUS",
    "verify_ops_authority",
    "main",
)


if __name__ == "__main__":
    raise SystemExit(main())
