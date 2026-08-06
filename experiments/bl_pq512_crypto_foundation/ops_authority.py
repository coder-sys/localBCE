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
    ("KEY_CUSTODY_AND_ROTATION.md", 2358, "e91d4de2e9e405637cb18aa1e99d5582041bfde6dd47e9ffa611191bea92957637e5582f02c7e2d6a0d4759511950a170f1fb16a8463350d726fff3087ea60f0"),
    ("MONITORING_AUDIT_EVENTS.md", 1630, "50d123764ce426d2732cb09963112cf74cc88d24dc7ce399825df143c0f460c196c3000f24afd6edbf4d3f1c4c5d73a41eb280d2e3c4c9230b0a80b96eaaccff"),
    ("PRODUCTION_CONFIG_CHECKLIST.md", 2191, "2e16d1f7dcfd861e377831fd42cdaff35aeb362f8adbf30f4e70a8a0f797a45599f48966b2f5834538efc2a969df3004cd1bd9ec242e9a50e891ab87d7489ab9"),
    ("RISK_REGISTER.md", 2355, "8c8e892eb61675e8656483ee19ad4b6780d3698b9b9aad4c2bb454c0035aa5bb524c0e31b3e8869b8750ede7d6b8829d8a1091040906609f062bfc2ff0384b09"),
    ("governance_config.example.json", 668, "82134027600bdf65ee98ee316fedc7b4ba090177087ace31f5b39b10644c6b7df66a08a44acebb4bd74eb43326c0c3fe331428111b4149d08aa91f49b17695eb"),
    ("launch_blockers.json", 7246, "76cbc0b8030803993e11ed4b676595b137862a33bbe6210b2e0a77205cce612d7d90457366c008bb5b45e38f4b7679fa143a84714126890ebf8857d201304934"),
    ("monitoring_events.json", 2277, "164929793eed57d5cf30ae953492cb23b1603992ec4c776f0222b30ca462160fd400e3ad2f6fd7ddae0fb7cee45ad2dc44086963aa4f0f15e246a80cf17e3bba"),
    ("native_stark_public_inputs_v1.json", 3342, "80bc23bb560442f459ca50821e6c23a4aeda82d93848292078e7925a6ca9cfa754a2059ec7612ce11cf0ba5b276782aa4019801b925c4761fefcf5ae23c3aa3a"),
    ("native_stark_public_inputs_v2.json", 1785, "f85d4b3f8acd4af88966e94c9f6eabf2d1d39a7d9e6bd8ac422b3dad6f01e2395392d9f337d311c0cccff3e1fe8eb516ec55dad2eca39b16f15f056122389cb0"),
    ("oracle_source_manifest.example.json", 1062, "2488a56707935bccc892b7dc78cd57c78adccd2348aff2dc75a48a755bb164e8f2a499d52ac896ced70f30cfbfb99181f7b691596b178c7042fcc449b95c98ff"),
    ("policy_spec_v1.yaml", 2006, "86fbce089c246c5631ff824d08af23b9646e6753470a84c9bd810c05c67c9adee4576917fece90d781ffa47e166b500bab9b14720f8511a2474c957a0bceebda"),
    ("production.env.example", 2104, "5616bd41a4fbff2983da66f43b009c96c4a6b9db35234910918b179551246396ebf64de8645ce8a408ea940a406012c062fee6f74982a731c068155cfb3f4113"),
    ("verifier_artifact_pin.example.json", 922, "175b2c2f004a192868bb258bdb1d497c5af079bcd9cb53701a7d29ff2486c749ebe0bb23bfc653e40959dcea6702d6931b78bd8245fbd63652b669168f0c7aa8"),
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
