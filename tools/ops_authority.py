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
    ("DEPLOYMENT_RUNBOOK.md", 2206, "b6b77c96180cdf1a06506a1996f33984b5fed22b38ab827c2b526f38397bb3b75b5fce16ab30935ea57a4e538d77452e55693df080b8c8f459bf93fb665062ac"),
    ("KEY_CUSTODY_AND_ROTATION.md", 1827, "a20ed81f5022ee22b38511510dfcf10576fec235b44f3430b7e9be7611cc1f34aaafc48bd0bf96713e373198d1deaa317005e4561510833dc9f7dd119496a207"),
    ("MONITORING_AUDIT_EVENTS.md", 1526, "55177959b46aa4e23a4bea1a0811614df32b3111070eda9fc3033b7b0fe362c3dfd6c8e74c0241d964848df0eb5b8e0b82c5e9da34abb552c40167cb5ec952f4"),
    ("PRODUCTION_CONFIG_CHECKLIST.md", 1555, "5982405fd982bae480e670bda789c810cedc33059296da5385d3558bbabff5a7f08b60b3d7080c5413f688564bfa18b88e722c743910d0091f564c62d196836c"),
    ("RISK_REGISTER.md", 1372, "af75f3d8cbea56d56b17df2112adbe9401cbebc61e24df607d931b1237833e61a46c6ce92b30ac91bf015dafbc9c5a142f62831d59fc699a7ffc6d519e4b871b"),
    ("launch_blockers.json", 1535, "60cbc25c78c7ce2dcd0929c52c28695c5db072871db3aa2c3a8a66cde99036b13c366725a69929d6dd81795231efe798fb5261b0998280940ee992a283b9b95e"),
    ("verifier_artifact_pin.example.json", 242, "f07099d8c8336b80de08d0b777312e3b4d8cc899970ebf17d1f65b24bdeac9483118b6577c15fc0111dc9b983faf72ba431c25bf11bdc574edbab324d306fd79"),
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
