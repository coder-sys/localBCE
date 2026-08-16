"""Commit-bound authority for the tracked operational artifact bundle."""

from __future__ import annotations

from hashlib import sha3_512
from pathlib import Path
from stat import S_ISDIR, S_ISLNK, S_ISREG
from typing import Final


ROOT: Final[Path] = Path(__file__).resolve().parents[2]
CANONICAL_OPS_ROOT: Final[Path] = ROOT / "ops"
OPS_AUTHORITY_STATUS: Final[str] = "VERIFIED_TRACKED_SHA3_512_AUTHORITY"
_WINDOWS_REPARSE_POINT: Final[int] = 0x400

EXPECTED_OPS_FILES: Final[tuple[tuple[str, int, str], ...]] = (
    ("DEPLOYMENT_RUNBOOK.md", 1435, "57a38a947d4c7d88c57403f6ad122a024bc707b3082335ab43d9029d15872b13cf067c2a14b3a61481fdbc54e8d00afdf5dce131e59d4311f4670f36f4fde0b9"),
    ("KEY_CUSTODY_AND_ROTATION.md", 2700, "76787aa22795639b4e5bd91365f3c9e8f609d739bfb98a01d5e5e2e3d9797dc0a82b3c3ff411c6cb56b30ecd0cde5ab8fd2389098611b146b30c0b3da5a639a9"),
    ("MONITORING_AUDIT_EVENTS.md", 1643, "d4778636f9f76cc065349c11368aa620cbbf57ab3810677d405e8a8388e5e285c0f9c058b7881f1e12639bec069d0259a77f593d21b8031b77a52dcfc3f38a7f"),
    ("PRODUCTION_CONFIG_CHECKLIST.md", 1257, "286c31e304644ad6fa23a63b7b8940dfd5294f78c3242997628253518b70f9d127b621be40cea92540d83761e19a5e6757bfbab4d237ee90ff55e33e4bd2c0b6"),
    ("RISK_REGISTER.md", 1359, "9ac9ae175f6fd1fd5ebf4b3efa95999f7e3833452e9768966c5bacca1360bdc069b5e56e9c4e1d01046a4e903a5d14514b7c043d87fbe9326705b4de6ae6ea1e"),
    ("governance_config.example.json", 668, "82134027600bdf65ee98ee316fedc7b4ba090177087ace31f5b39b10644c6b7df66a08a44acebb4bd74eb43326c0c3fe331428111b4149d08aa91f49b17695eb"),
    ("launch_blockers.json", 11313, "10dbb608766368b302cb12373aef94470654b2af0164a5bd8c802c8138f842e003de5e55fc195b7ab6bb9dfb91264490ab4d2cafe00418351d50bb3b3e71d1f2"),
    ("monitoring_events.json", 2277, "164929793eed57d5cf30ae953492cb23b1603992ec4c776f0222b30ca462160fd400e3ad2f6fd7ddae0fb7cee45ad2dc44086963aa4f0f15e246a80cf17e3bba"),
    ("native_stark_public_inputs_v2.json", 1807, "cb9e2c4e248f62832f996f4c2a157985643ffef4ff09ab58002f2265cbc97347862093c77361ead8be7ce68dae9a92f9565a133491899dfb130a2f6c4acc122d"),
    ("oracle_source_manifest.example.json", 1062, "2488a56707935bccc892b7dc78cd57c78adccd2348aff2dc75a48a755bb164e8f2a499d52ac896ced70f30cfbfb99181f7b691596b178c7042fcc449b95c98ff"),
    ("policy_spec_v1.yaml", 2006, "86fbce089c246c5631ff824d08af23b9646e6753470a84c9bd810c05c67c9adee4576917fece90d781ffa47e166b500bab9b14720f8511a2474c957a0bceebda"),
    ("production.env.example", 1993, "05d9bf86ef5bfb29660afdcc08f6cf2fb687466a543b169aa34ddbea5d3e6df6e74145bbbb51ecf65a34bc2069c8307fa9357cff86b9fb2238d474be7754f97e"),
    ("verifier_artifact_pin.example.json", 338, "d662d4452ab75ca59d0d35a1e5e584a44a36884447313a033be0e7d9674a9d45206e1b882ad5f0135b061e87eaba0bf68e20d1e44e9efb59d11e30ed0767a908"),
    ("wave2_internal_release_profile.json", 1351, "47c3c707402a1449cf29fc4bd7a3615e32d56b85b9865d8063f833cd6e3164e02830f0994560baa68b1fd9579ee26cf60d0f7eadb570712cde95c1afa1cce99e"),
    ("wave4_release_profile.json", 1200, "3e49c004bf91946ebcc2ff72c1852db7aa60c3d7bcd8afd6250c5bc574ceddf7463c563b6e8aa596edf4aa7eba08e88b709d2e0659cb80185d605865a5534010"),
    ("wave4_sandbox_config.json", 804, "61a6c1649c2c92690de377ae09f1e4da98336c8039274fa5e1740c45b3ca6d66634f2d7d4f7085745b1237ad5d33d254e1515b5ea448e9cb1591cca4a9806ff8"),
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
    """Verify the exact regular-file set, lengths, and SHA3-512 identities."""

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
            raise ValueError(f"ops_authority_file_shape_mismatch:{name}")
        data = path.read_bytes()
        if len(data) != length:
            raise ValueError(f"ops_authority_file_shape_mismatch:{name}")
        if sha3_512(data).hexdigest() != digest:
            raise ValueError(f"ops_authority_digest_mismatch:{name}")
    return OPS_AUTHORITY_STATUS


__all__ = (
    "CANONICAL_OPS_ROOT",
    "EXPECTED_OPS_FILES",
    "OPS_AUTHORITY_STATUS",
    "verify_ops_authority",
)
