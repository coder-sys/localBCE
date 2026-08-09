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
    ("DEPLOYMENT_RUNBOOK.md", 1207, "45e902ee19516bfebccbddfd041cdaac932eff639d2ca2b7e7c8cfe580e8bb1a803e02763a617420afbab99f81f88befac1f3ad0aa487004f893239eb54c939c"),
    ("KEY_CUSTODY_AND_ROTATION.md", 2375, "a3bb1283a04a133b0f32cb8d27d1867bb0cf9543c12976fc31f0827ab9235952c06349a35a81d34972c241f32c1793e87f845a3c2668f02d60f8d9111920167c"),
    ("MONITORING_AUDIT_EVENTS.md", 1643, "d4778636f9f76cc065349c11368aa620cbbf57ab3810677d405e8a8388e5e285c0f9c058b7881f1e12639bec069d0259a77f593d21b8031b77a52dcfc3f38a7f"),
    ("PRODUCTION_CONFIG_CHECKLIST.md", 1080, "afffeff773a00aec7471f2a8fb15d463244e025f2c8928cd76e56e43ab7d7d93938dd63b8cfd71812b38093f9f780aca593eeaf826db566d96040b8fa9842a3a"),
    ("RISK_REGISTER.md", 1278, "d5ad6ac4a0812292df5ea3f8cc754181cc40560831a931f493212cdfa77c52a69be6eb51eabc0907ca23e77385493086ae47e93d8c75e35ecf5d4508d4b243d8"),
    ("governance_config.example.json", 668, "82134027600bdf65ee98ee316fedc7b4ba090177087ace31f5b39b10644c6b7df66a08a44acebb4bd74eb43326c0c3fe331428111b4149d08aa91f49b17695eb"),
    ("launch_blockers.json", 9292, "9e783ae01434c6c3e9b1696cb4a6d91bb3b9c98d2195fe5259aed113775ec6e049ba2e42749ee30e4b76600df070a1c080e1f36f74b5d6ede34a594317ccd4e9"),
    ("monitoring_events.json", 2277, "164929793eed57d5cf30ae953492cb23b1603992ec4c776f0222b30ca462160fd400e3ad2f6fd7ddae0fb7cee45ad2dc44086963aa4f0f15e246a80cf17e3bba"),
    ("native_stark_public_inputs_v2.json", 1807, "cb9e2c4e248f62832f996f4c2a157985643ffef4ff09ab58002f2265cbc97347862093c77361ead8be7ce68dae9a92f9565a133491899dfb130a2f6c4acc122d"),
    ("oracle_source_manifest.example.json", 1062, "2488a56707935bccc892b7dc78cd57c78adccd2348aff2dc75a48a755bb164e8f2a499d52ac896ced70f30cfbfb99181f7b691596b178c7042fcc449b95c98ff"),
    ("policy_spec_v1.yaml", 2006, "86fbce089c246c5631ff824d08af23b9646e6753470a84c9bd810c05c67c9adee4576917fece90d781ffa47e166b500bab9b14720f8511a2474c957a0bceebda"),
    ("production.env.example", 1993, "05d9bf86ef5bfb29660afdcc08f6cf2fb687466a543b169aa34ddbea5d3e6df6e74145bbbb51ecf65a34bc2069c8307fa9357cff86b9fb2238d474be7754f97e"),
    ("verifier_artifact_pin.example.json", 948, "c794de9ec7ad8c7a92f39cabcf786ed62ab3cb710dd9a86e8a10cce2813dd5488d435681255ec4dd94f2db48aeb573d615c6d20d08152d5036564f2bd25aa6e2"),
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
