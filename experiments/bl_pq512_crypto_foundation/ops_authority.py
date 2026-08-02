"""Commit-bound authority for the tracked operational artifact bundle.

The repository is the sole source of truth.  Operational policy is therefore
read from the tracked ``ops/`` directory and checked against this exact
SHA3-512 inventory.  No sibling copy, fallback path, or environment override
is accepted.
"""

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
    ("DEPLOYMENT_RUNBOOK.md", 3101, "0dfff45c5b1645ea265151763e296311c0a19a5406064558cda853bc625ae5b0345381673fd9c9b1da68707f8c002bd773c74ff0c181279fa29162927d28ddf5"),
    ("KEY_CUSTODY_AND_ROTATION.md", 1543, "b51281f963b34716ed0bfc2e149eb1a4665fcf0fa08d810ef54bebb921d9fd24b9884b131ef4ce84aeddb5820ecbf1b0f70379617e9e72f5d7ac1f04f2830807"),
    ("MONITORING_AUDIT_EVENTS.md", 1794, "1f96c7fa7ba5ca207c5726197112ac2df265772f7e65bb0413753dbb9b48f5bfbb32600aae98b239940fa905bb7583160b45bde2edacb77221d3b7f197def469"),
    ("PRODUCTION_CONFIG_CHECKLIST.md", 2191, "2e16d1f7dcfd861e377831fd42cdaff35aeb362f8adbf30f4e70a8a0f797a45599f48966b2f5834538efc2a969df3004cd1bd9ec242e9a50e891ab87d7489ab9"),
    ("RISK_REGISTER.md", 2355, "8c8e892eb61675e8656483ee19ad4b6780d3698b9b9aad4c2bb454c0035aa5bb524c0e31b3e8869b8750ede7d6b8829d8a1091040906609f062bfc2ff0384b09"),
    ("governance_config.example.json", 668, "82134027600bdf65ee98ee316fedc7b4ba090177087ace31f5b39b10644c6b7df66a08a44acebb4bd74eb43326c0c3fe331428111b4149d08aa91f49b17695eb"),
    ("launch_blockers.json", 7245, "fb885abf4ea9875c168978bc7a781d8a52638c3ca986a7440e54556e65870f30ad5b92d764e1a42816df9fbd23d7be429e5dab9792bd6e31e26646d3db5b3c39"),
    ("monitoring_events.json", 1578, "97a5d885d90297024e278b1e8ae30d2b85f64695ef54236a147332cd0ddeb49cd2d5303d8891d3473e3ca45381ed47576ba514349724d8c0ea400c00fa5fd0a4"),
    ("native_stark_public_inputs_v1.json", 3342, "80bc23bb560442f459ca50821e6c23a4aeda82d93848292078e7925a6ca9cfa754a2059ec7612ce11cf0ba5b276782aa4019801b925c4761fefcf5ae23c3aa3a"),
    ("native_stark_public_inputs_v2.json", 1785, "f85d4b3f8acd4af88966e94c9f6eabf2d1d39a7d9e6bd8ac422b3dad6f01e2395392d9f337d311c0cccff3e1fe8eb516ec55dad2eca39b16f15f056122389cb0"),
    ("oracle_source_manifest.example.json", 1062, "2488a56707935bccc892b7dc78cd57c78adccd2348aff2dc75a48a755bb164e8f2a499d52ac896ced70f30cfbfb99181f7b691596b178c7042fcc449b95c98ff"),
    ("policy_spec_v1.yaml", 2006, "86fbce089c246c5631ff824d08af23b9646e6753470a84c9bd810c05c67c9adee4576917fece90d781ffa47e166b500bab9b14720f8511a2474c957a0bceebda"),
    ("production.env.example", 2104, "5616bd41a4fbff2983da66f43b009c96c4a6b9db35234910918b179551246396ebf64de8645ce8a408ea940a406012c062fee6f74982a731c068155cfb3f4113"),
    ("verifier_artifact_pin.example.json", 922, "175b2c2f004a192868bb258bdb1d497c5af079bcd9cb53701a7d29ff2486c749ebe0bb23bfc653e40959dcea6702d6931b78bd8245fbd63652b669168f0c7aa8"),
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
    observed_paths = tuple(
        sorted(
            root.iterdir(),
            key=lambda path: path.relative_to(root).as_posix(),
        )
    )
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
