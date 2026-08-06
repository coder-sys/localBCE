"""Local, synthetic Wave 5 based-validity-rollup boundary.

This module closes the R01-R12 engineering interfaces without opening a network
socket, using a live chain, or selecting a production proof suite.  Every public
object is commitment-shaped: private claims, exact amounts, encrypted records,
and provider payloads cannot enter the boundary.  The local L1/EL/CL model is a
deterministic conformance fixture, not an Ethereum client or a production
verifier.

The module intentionally keeps the outer-chain classical boundary explicit.  The
Blind Ledger-controlled authority port uses the Wave 4 dual-PQ signer interface;
the Ethereum model contributes ordering/finality semantics only and receives no
post-quantum security credit.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import json
import re
from threading import RLock
from typing import Final, Mapping, Protocol, Sequence

from app.batch.poseidon import FIELD_MODULUS
from app.batch.pq_suite_candidate import CandidateSidecarV1
from app.public_inputs import PUBLIC_INPUT_FIELD_NAMES_V2
from app.wave4_adapters import DUAL_PQ_SUITES, DualPqAuthenticator, PqSignature


WAVE5_SCHEMA: Final[str] = "blind_ledger_wave5_rollup_v1"
WAVE5_PROFILE: Final[str] = "SYNTHETIC-BASED-VALIDITY-V1"
WAVE5_L1_CHAIN_ID: Final[int] = 7_531_512
WAVE5_L2_CHAIN_ID: Final[int] = 7_531_513
WAVE5_PUBLIC_FIELD_NAMES: Final[tuple[str, ...]] = tuple(PUBLIC_INPUT_FIELD_NAMES_V2)
WAVE5_PACKAGE_IDS: Final[frozenset[str]] = frozenset(f"R{index:02d}" for index in range(1, 13))
WAVE5_PRODUCTION_USABLE: Final[bool] = False
WAVE5_ACTIVATION_ALLOWED: Final[bool] = False
# The native candidate envelope has the same fixed upper bound.  The local
# rollup claim port carries that encoded envelope as its proof body, so a
# smaller legacy cap would reject a valid native proof before verification.
MAX_PROOF_BODY_BYTES: Final[int] = 512 * 1024 * 1024
MAX_CELLS: Final[int] = 256
MAX_CELL_BYTES: Final[int] = 64
MAX_TRANSACTIONS: Final[int] = 256
MAX_FORCED_INCLUSIONS: Final[int] = 256
MAX_RETENTION_SLOTS: Final[int] = 2**20
MAX_QUEUE_SLOTS: Final[int] = 2**16
_IDENTIFIER = re.compile(r"[A-Z0-9][A-Z0-9_.:/-]{0,127}\Z")


class Wave5RollupError(ValueError):
    """Stable fail-closed error at the local rollup boundary."""


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise Wave5RollupError("wave5_noncanonical_json_value") from exc


def _digest(domain: bytes, *parts: bytes) -> bytes:
    if type(domain) is not bytes or not domain or len(domain) > 128:
        raise Wave5RollupError("wave5_digest_domain_invalid")
    hasher = hashlib.sha3_512()
    hasher.update(b"BL/WAVE5/")
    hasher.update(len(domain).to_bytes(2, "big"))
    hasher.update(domain)
    for part in parts:
        if type(part) is not bytes or len(part) > MAX_PROOF_BODY_BYTES:
            raise Wave5RollupError("wave5_digest_part_invalid")
        hasher.update(len(part).to_bytes(8, "big"))
        hasher.update(part)
    return hasher.digest()


def _bytes(label: str, value: object, length: int, *, nonzero: bool = False) -> bytes:
    if type(value) is not bytes or len(value) != length or (nonzero and not any(value)):
        raise Wave5RollupError(f"{label}_invalid")
    return value


def _u64(label: str, value: object, *, nonzero: bool = False, maximum: int = 2**64 - 1) -> int:
    if type(value) is not int or isinstance(value, bool) or value < 0 or value > maximum:
        raise Wave5RollupError(f"{label}_invalid")
    if nonzero and value == 0:
        raise Wave5RollupError(f"{label}_must_be_nonzero")
    return value


def _identifier(label: str, value: object) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise Wave5RollupError(f"{label}_invalid")
    return value


def _field_alias(value: bytes) -> bytes:
    raw = _bytes("field_alias_source", value, 64, nonzero=True)
    return (int.from_bytes(raw, "big") % (FIELD_MODULUS - 1) + 1).to_bytes(32, "big")


def _canonical_fields(values: Sequence[bytes]) -> tuple[bytes, ...]:
    if type(values) not in (tuple, list) or len(values) != 12:
        raise Wave5RollupError("wave5_public_field_count_invalid")
    result: list[bytes] = []
    for index, value in enumerate(values):
        field = _bytes(f"wave5_public_field_{index}", value, 32)
        if int.from_bytes(field, "big") >= FIELD_MODULUS:
            raise Wave5RollupError(f"wave5_public_field_{index}_not_canonical")
        result.append(field)
    return tuple(result)


def _enum_value(label: str, value: object, allowed: Sequence[str]) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise Wave5RollupError(f"{label}_invalid")
    return value


class FinalityLevel(str, Enum):
    HEAD = "head"
    SAFE = "safe"
    JUSTIFIED = "justified"
    FINALIZED = "finalized"
    REORGED = "reorged"
    RECOVERED = "recovered"


_FINALITY_RANK: Final[Mapping[FinalityLevel, int]] = {
    FinalityLevel.HEAD: 0,
    FinalityLevel.SAFE: 1,
    FinalityLevel.JUSTIFIED: 2,
    FinalityLevel.FINALIZED: 3,
    FinalityLevel.REORGED: -1,
    FinalityLevel.RECOVERED: 3,
}


@dataclass(frozen=True, slots=True)
class EthereumFeature:
    eip: int
    snapshot_status: str
    impact_class: str
    enabled_in_baseline: bool = False

    def __post_init__(self) -> None:
        _u64("ethereum_feature_eip", self.eip)
        if self.eip < 1 or self.eip > 9999:
            raise Wave5RollupError("ethereum_feature_eip_invalid")
        if (
            not isinstance(self.snapshot_status, str)
            or not self.snapshot_status
            or len(self.snapshot_status) > 64
            or any(ord(character) < 32 for character in self.snapshot_status)
        ):
            raise Wave5RollupError("ethereum_feature_status_invalid")
        if self.impact_class not in {
            "INHERIT",
            "INHERIT+L1-COMPAT",
            "L1-COMPAT",
            "L1-COMPAT+L2-PARITY",
            "OPTIONAL",
            "OPTIONAL+L2-PARITY",
            "OPTIONAL/RESEARCH",
            "RESEARCH",
        }:
            raise Wave5RollupError("ethereum_feature_impact_class_invalid")
        if type(self.enabled_in_baseline) is not bool:
            raise Wave5RollupError("ethereum_feature_enabled_flag_invalid")
        if self.enabled_in_baseline and self.snapshot_status not in {"Final", "Scheduled"}:
            raise Wave5RollupError("ethereum_feature_unfinalized_dependency")

    def canonical_dict(self) -> dict[str, object]:
        return {
            "eip": self.eip,
            "snapshot_status": self.snapshot_status,
            "impact_class": self.impact_class,
            "enabled_in_baseline": self.enabled_in_baseline,
        }


@dataclass(frozen=True, slots=True)
class EthereumForkProfile:
    fork_id_512: bytes
    name: str
    maturity: str
    execution_client: str
    consensus_client: str
    execution_client_commit: str
    consensus_client_commit: str
    engine_api_version: str
    evm_revision: str
    semantics_id: str
    slot_seconds: int
    finality_depth_slots: int
    gas_limit: int
    blob_limit: int
    da_modes: tuple[str, ...]
    enabled_eips: tuple[int, ...] = ()

    def __post_init__(self) -> None:
        _bytes("fork_id_512", self.fork_id_512, 64, nonzero=True)
        for label, value in (
            ("fork_name", self.name),
            ("fork_maturity", self.maturity),
            ("execution_client", self.execution_client),
            ("consensus_client", self.consensus_client),
            ("execution_client_commit", self.execution_client_commit),
            ("consensus_client_commit", self.consensus_client_commit),
            ("engine_api_version", self.engine_api_version),
            ("evm_revision", self.evm_revision),
            ("semantics_id", self.semantics_id),
        ):
            _identifier(label, value)
        if self.maturity not in {"PINNED_BASELINE", "SHADOW_FUTURE"}:
            raise Wave5RollupError("fork_maturity_invalid")
        _u64("fork_slot_seconds", self.slot_seconds, nonzero=True, maximum=3_600)
        _u64("fork_finality_depth", self.finality_depth_slots, nonzero=True, maximum=2**20)
        _u64("fork_gas_limit", self.gas_limit, nonzero=True, maximum=2**63)
        _u64("fork_blob_limit", self.blob_limit, maximum=2**20)
        if type(self.da_modes) is not tuple or not self.da_modes or any(
            item not in {"CALLDATA_COMMITMENT", "BLOB_COMMITMENT", "CELL_COMMITMENT"}
            for item in self.da_modes
        ):
            raise Wave5RollupError("fork_da_modes_invalid")
        if tuple(sorted(set(self.enabled_eips))) != self.enabled_eips:
            raise Wave5RollupError("fork_enabled_eips_not_sorted")
        if any(type(item) is not int or item < 1 for item in self.enabled_eips):
            raise Wave5RollupError("fork_enabled_eip_invalid")

    def canonical_dict(self) -> dict[str, object]:
        return {
            "fork_id_512": self.fork_id_512.hex(),
            "name": self.name,
            "maturity": self.maturity,
            "execution_client": self.execution_client,
            "consensus_client": self.consensus_client,
            "execution_client_commit": self.execution_client_commit,
            "consensus_client_commit": self.consensus_client_commit,
            "engine_api_version": self.engine_api_version,
            "evm_revision": self.evm_revision,
            "semantics_id": self.semantics_id,
            "slot_seconds": self.slot_seconds,
            "finality_depth_slots": self.finality_depth_slots,
            "gas_limit": self.gas_limit,
            "blob_limit": self.blob_limit,
            "da_modes": list(self.da_modes),
            "enabled_eips": list(self.enabled_eips),
        }


def _strawmap_features() -> tuple[EthereumFeature, ...]:
    rows = (
        (7503, "Stagnant", "RESEARCH"),
        (7732, "Review", "INHERIT+L1-COMPAT"),
        (7773, "Draft Meta", "L1-COMPAT+L2-PARITY"),
        (7805, "Draft", "INHERIT+L1-COMPAT"),
        (7919, "Stagnant Meta", "RESEARCH"),
        (7928, "Review", "L1-COMPAT+L2-PARITY"),
        (7938, "Stagnant Informational", "RESEARCH"),
        (7999, "Draft", "L1-COMPAT+L2-PARITY"),
        (8007, "Draft Meta", "L1-COMPAT+L2-PARITY"),
        (8025, "Draft", "OPTIONAL"),
        (8070, "Review Networking", "INHERIT+L1-COMPAT"),
        (8077, "Draft", "INHERIT+L1-COMPAT"),
        (8079, "Draft", "OPTIONAL"),
        (8081, "Draft Meta", "L1-COMPAT+L2-PARITY"),
        (8136, "Draft Networking", "INHERIT+L1-COMPAT"),
        (8141, "Draft", "OPTIONAL+L2-PARITY"),
        (8142, "Draft", "L1-COMPAT"),
        (8184, "Draft", "OPTIONAL/RESEARCH"),
        (8198, "Draft", "INHERIT+L1-COMPAT"),
        (8200, "Draft", "L1-COMPAT+L2-PARITY"),
        (8250, "Draft", "OPTIONAL+L2-PARITY"),
        (8272, "Draft", "OPTIONAL+L2-PARITY"),
        (8297, "Draft", "INHERIT+L1-COMPAT"),
    )
    return tuple(EthereumFeature(eip, status, impact) for eip, status, impact in rows)


@dataclass(frozen=True, slots=True)
class EthereumCompatManifest:
    version: int
    l1_chain_id: int
    l2_chain_id: int
    baseline: EthereumForkProfile
    future_shadow: EthereumForkProfile
    strawmap: tuple[EthereumFeature, ...]
    optional_features_disabled: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.version != 1:
            raise Wave5RollupError("ethereum_compat_manifest_version_invalid")
        _u64("ethereum_l1_chain_id", self.l1_chain_id, nonzero=True)
        _u64("ethereum_l2_chain_id", self.l2_chain_id, nonzero=True)
        if self.baseline.maturity != "PINNED_BASELINE" or self.future_shadow.maturity != "SHADOW_FUTURE":
            raise Wave5RollupError("ethereum_compat_manifest_profile_maturity_invalid")
        if self.baseline.enabled_eips:
            raise Wave5RollupError("ethereum_compat_baseline_has_unshipped_eip")
        if self.future_shadow.semantics_id != self.baseline.semantics_id:
            raise Wave5RollupError("ethereum_future_shadow_semantics_changed")
        if type(self.strawmap) is not tuple or len(self.strawmap) != 23:
            raise Wave5RollupError("ethereum_strawmap_count_invalid")
        if tuple(item.eip for item in self.strawmap) != tuple(sorted(item.eip for item in self.strawmap)):
            raise Wave5RollupError("ethereum_strawmap_order_invalid")
        if len({item.eip for item in self.strawmap}) != 23:
            raise Wave5RollupError("ethereum_strawmap_duplicate_eip")
        if type(self.optional_features_disabled) is not tuple or not self.optional_features_disabled:
            raise Wave5RollupError("ethereum_optional_feature_inventory_invalid")
        if tuple(sorted(self.optional_features_disabled)) != self.optional_features_disabled:
            raise Wave5RollupError("ethereum_optional_feature_inventory_order_invalid")

    @property
    def manifest_digest_512(self) -> bytes:
        return _digest(b"ETHEREUM-COMPAT-MANIFEST/V1", self.canonical_bytes())

    def canonical_bytes(self) -> bytes:
        return _canonical_json(
            {
                "schema": "ethereum_compat_manifest_v1",
                "version": self.version,
                "l1_chain_id": self.l1_chain_id,
                "l2_chain_id": self.l2_chain_id,
                "baseline": self.baseline.canonical_dict(),
                "future_shadow": self.future_shadow.canonical_dict(),
                "strawmap": [item.canonical_dict() for item in self.strawmap],
                "optional_features_disabled": list(self.optional_features_disabled),
            }
        )

    def profile_for(self, fork_id_512: bytes) -> EthereumForkProfile:
        if fork_id_512 == self.baseline.fork_id_512:
            return self.baseline
        if fork_id_512 == self.future_shadow.fork_id_512:
            return self.future_shadow
        raise Wave5RollupError("ethereum_unknown_fork_id")


def build_ethereum_compat_manifest() -> EthereumCompatManifest:
    baseline = EthereumForkProfile(
        _digest(b"FORK-ID", b"SYNTHETIC-BASELINE"),
        "SYNTHETIC-BASELINE",
        "PINNED_BASELINE",
        "EL-SANDBOX-V1",
        "CL-SANDBOX-V1",
        "EL-SANDBOX-COMMIT-V1",
        "CL-SANDBOX-COMMIT-V1",
        "ENGINE-SANDBOX-V1",
        "EVM-COMPATIBLE-SANDBOX-V1",
        "BL-L2-EVM-SEMANTICS-V1",
        12,
        2,
        30_000_000,
        6,
        ("CALLDATA_COMMITMENT", "BLOB_COMMITMENT", "CELL_COMMITMENT"),
    )
    future = EthereumForkProfile(
        _digest(b"FORK-ID", b"SYNTHETIC-FUTURE-SHADOW"),
        "SYNTHETIC-FUTURE-SHADOW",
        "SHADOW_FUTURE",
        "EL-SANDBOX-V1",
        "CL-SANDBOX-V1",
        "EL-SANDBOX-COMMIT-V1",
        "CL-SANDBOX-COMMIT-V1",
        "ENGINE-SANDBOX-V1",
        "EVM-COMPATIBLE-SANDBOX-V1",
        "BL-L2-EVM-SEMANTICS-V1",
        12,
        2,
        30_000_000,
        6,
        ("CALLDATA_COMMITMENT", "BLOB_COMMITMENT", "CELL_COMMITMENT"),
    )
    return EthereumCompatManifest(
        1,
        WAVE5_L1_CHAIN_ID,
        WAVE5_L2_CHAIN_ID,
        baseline,
        future,
        _strawmap_features(),
        tuple(
            sorted(
                (
                    "EIP-8025-EXECUTION-PROOFS",
                    "EIP-8079-NATIVE-ROLLUP",
                    "EIP-8141-FRAME-TRANSACTIONS",
                    "EIP-8184-ENCRYPTED-MEMPOOL",
                    "EIP-8250-KEYED-NONCES",
                    "EIP-8272-RECENT-ROOTS",
                    "EIP-8297-L1-TREE-MIRROR",
                )
            )
        ),
    )


@dataclass(frozen=True, slots=True)
class L1Block:
    number: int
    slot: int
    parent_hash_512: bytes
    fork_id_512: bytes
    payload_digest_512: bytes
    da_commitment_512: bytes
    state_root_512: bytes
    finality: FinalityLevel = FinalityLevel.HEAD

    def __post_init__(self) -> None:
        _u64("l1_block_number", self.number)
        _u64("l1_block_slot", self.slot)
        for label, value in (
            ("l1_parent_hash", self.parent_hash_512),
            ("l1_fork_id", self.fork_id_512),
            ("l1_payload_digest", self.payload_digest_512),
            ("l1_da_commitment", self.da_commitment_512),
            ("l1_state_root", self.state_root_512),
        ):
            _bytes(label, value, 64, nonzero=(label != "l1_parent_hash" or self.number != 0))
        if type(self.finality) is not FinalityLevel:
            raise Wave5RollupError("l1_block_finality_invalid")

    def header_bytes(self) -> bytes:
        return _canonical_json(
            {
                "number": self.number,
                "slot": self.slot,
                "parent_hash_512": self.parent_hash_512.hex(),
                "fork_id_512": self.fork_id_512.hex(),
                "payload_digest_512": self.payload_digest_512.hex(),
                "da_commitment_512": self.da_commitment_512.hex(),
                "state_root_512": self.state_root_512.hex(),
            }
        )

    @property
    def block_hash_512(self) -> bytes:
        return _digest(b"L1-BLOCK-HEADER/V1", self.header_bytes())


@dataclass(frozen=True, slots=True)
class DeploymentConfig:
    manifest_digest_512: bytes
    node_count: int = 5
    slot_seconds: int = 12
    gas_limit: int = 30_000_000
    blob_limit: int = 6
    bal_mode: str = "PUBLIC-BAL-V1"
    data_modes: tuple[str, ...] = ("CALLDATA_COMMITMENT", "BLOB_COMMITMENT", "CELL_COMMITMENT")
    transaction_format: str = "OPAQUE-COMMITMENT-TX-V1"

    def __post_init__(self) -> None:
        _bytes("deployment_manifest_digest", self.manifest_digest_512, 64, nonzero=True)
        _u64("deployment_node_count", self.node_count, nonzero=True, maximum=64)
        _u64("deployment_slot_seconds", self.slot_seconds, nonzero=True, maximum=3_600)
        _u64("deployment_gas_limit", self.gas_limit, nonzero=True, maximum=2**63)
        _u64("deployment_blob_limit", self.blob_limit, maximum=2**20)
        _identifier("deployment_bal_mode", self.bal_mode)
        if type(self.data_modes) is not tuple or not self.data_modes:
            raise Wave5RollupError("deployment_data_modes_invalid")
        if any(item not in {"CALLDATA_COMMITMENT", "BLOB_COMMITMENT", "CELL_COMMITMENT"} for item in self.data_modes):
            raise Wave5RollupError("deployment_data_mode_unknown")
        _identifier("deployment_transaction_format", self.transaction_format)

    def canonical_bytes(self) -> bytes:
        return _canonical_json(
            {
                "manifest_digest_512": self.manifest_digest_512.hex(),
                "node_count": self.node_count,
                "slot_seconds": self.slot_seconds,
                "gas_limit": self.gas_limit,
                "blob_limit": self.blob_limit,
                "bal_mode": self.bal_mode,
                "data_modes": list(self.data_modes),
                "transaction_format": self.transaction_format,
            }
        )


@dataclass(frozen=True, slots=True)
class LocalNode:
    node_id: str
    role: str
    client_id: str
    fork_id_512: bytes

    def __post_init__(self) -> None:
        for label, value in (("local_node_id", self.node_id), ("local_node_role", self.role), ("local_node_client", self.client_id)):
            _identifier(label, value)
        if self.role not in {"EL", "CL", "L2"}:
            raise Wave5RollupError("local_node_role_invalid")
        _bytes("local_node_fork_id", self.fork_id_512, 64, nonzero=True)


@dataclass(slots=True)
class LocalDeployment:
    manifest: EthereumCompatManifest
    config: DeploymentConfig
    nodes: tuple[LocalNode, ...]
    genesis: L1Block
    blocks: list[L1Block] = field(default_factory=list)

    def __post_init__(self) -> None:
        if type(self.manifest) is not EthereumCompatManifest or type(self.config) is not DeploymentConfig:
            raise Wave5RollupError("local_deployment_inputs_invalid")
        if self.config.manifest_digest_512 != self.manifest.manifest_digest_512:
            raise Wave5RollupError("local_deployment_manifest_mismatch")
        if type(self.nodes) is not tuple or len(self.nodes) != self.config.node_count:
            raise Wave5RollupError("local_deployment_node_count_invalid")
        if sum(node.role == "EL" for node in self.nodes) < 2 or sum(node.role == "CL" for node in self.nodes) < 2:
            raise Wave5RollupError("local_deployment_multi_node_roles_missing")
        if self.genesis.number != 0 or self.genesis.parent_hash_512 != bytes(64):
            raise Wave5RollupError("local_deployment_genesis_invalid")
        if self.genesis.fork_id_512 != self.manifest.baseline.fork_id_512:
            raise Wave5RollupError("local_deployment_genesis_fork_invalid")
        if type(self.blocks) is not list or self.blocks:
            raise Wave5RollupError("local_deployment_block_history_invalid")

    @classmethod
    def build(cls, manifest: EthereumCompatManifest) -> "LocalDeployment":
        config = DeploymentConfig(manifest.manifest_digest_512)
        fork_id = manifest.baseline.fork_id_512
        nodes = (
            LocalNode("EL-01", "EL", "EL-SANDBOX-V1", fork_id),
            LocalNode("EL-02", "EL", "EL-SANDBOX-V1", fork_id),
            LocalNode("CL-01", "CL", "CL-SANDBOX-V1", fork_id),
            LocalNode("CL-02", "CL", "CL-SANDBOX-V1", fork_id),
            LocalNode("L2-01", "L2", "BL-L2-SANDBOX-V1", fork_id),
        )
        genesis = L1Block(
            0,
            0,
            bytes(64),
            fork_id,
            _digest(b"GENESIS-PAYLOAD", manifest.manifest_digest_512),
            _digest(b"GENESIS-DA", manifest.manifest_digest_512),
            _digest(b"GENESIS-STATE", manifest.manifest_digest_512),
            FinalityLevel.FINALIZED,
        )
        return cls(manifest, config, nodes, genesis)

    @property
    def head(self) -> L1Block:
        return self.blocks[-1] if self.blocks else self.genesis

    def mine_block(
        self,
        *,
        slot: int,
        payload_digest_512: bytes,
        da_commitment_512: bytes,
        state_root_512: bytes,
        finality: FinalityLevel = FinalityLevel.HEAD,
    ) -> L1Block:
        _u64("local_block_slot", slot)
        if slot <= self.head.slot:
            raise Wave5RollupError("local_block_slot_not_monotonic")
        block = L1Block(
            self.head.number + 1,
            slot,
            self.head.block_hash_512,
            self.manifest.baseline.fork_id_512,
            payload_digest_512,
            da_commitment_512,
            state_root_512,
            finality,
        )
        self.blocks.append(block)
        return block

    def canonical_bytes(self) -> bytes:
        return _canonical_json(
            {
                "schema": "local_multi_node_deployment_v1",
                "manifest_digest_512": self.manifest.manifest_digest_512.hex(),
                "config": self.config.canonical_bytes().decode("ascii"),
                "nodes": [
                    {
                        "node_id": node.node_id,
                        "role": node.role,
                        "client_id": node.client_id,
                        "fork_id_512": node.fork_id_512.hex(),
                    }
                    for node in self.nodes
                ],
                "genesis": self.genesis.block_hash_512.hex(),
                "blocks": [block.block_hash_512.hex() for block in self.blocks],
                "network_access": False,
                "live_credentials": False,
            }
        )


@dataclass(frozen=True, slots=True)
class RollupSuiteIdentity:
    profile_id_512: bytes
    candidate_suite_id_512: bytes
    schema_id_512: bytes
    verifier_artifact_identity_512: bytes
    settlement_domain_id_512: bytes
    epoch: int = 1

    def __post_init__(self) -> None:
        for label, value in (
            ("rollup_profile_id", self.profile_id_512),
            ("rollup_candidate_suite_id", self.candidate_suite_id_512),
            ("rollup_schema_id", self.schema_id_512),
            ("rollup_verifier_identity", self.verifier_artifact_identity_512),
            ("rollup_settlement_domain", self.settlement_domain_id_512),
        ):
            _bytes(label, value, 64, nonzero=True)
        _u64("rollup_identity_epoch", self.epoch, nonzero=True)


def make_synthetic_identity() -> RollupSuiteIdentity:
    return RollupSuiteIdentity(
        _digest(b"IDENTITY", b"PROFILE", WAVE5_PROFILE.encode("ascii")),
        _digest(b"IDENTITY", b"CANDIDATE-SUITE", b"H4-H5-H6-REFERENCE"),
        _digest(b"IDENTITY", b"SCHEMA", WAVE5_SCHEMA.encode("ascii")),
        _digest(b"IDENTITY", b"VERIFIER-ARTIFACT", b"WAVE5-REFERENCE-VERIFIER"),
        _digest(b"IDENTITY", b"SETTLEMENT-DOMAIN", b"SYNTHETIC"),
    )


@dataclass(frozen=True, slots=True)
class RollupClaimContext:
    fork_id_512: bytes
    l1_chain_id: int
    l2_chain_id: int
    state_before_digest_512: bytes
    da_commitment_512: bytes
    verifier_artifact_identity_512: bytes
    schema_id_512: bytes
    candidate_suite_id_512: bytes
    settlement_domain_id_512: bytes

    def __post_init__(self) -> None:
        _bytes("claim_context_fork_id", self.fork_id_512, 64, nonzero=True)
        _u64("claim_context_l1_chain_id", self.l1_chain_id, nonzero=True)
        _u64("claim_context_l2_chain_id", self.l2_chain_id, nonzero=True)
        for label, value in (
            ("claim_context_state", self.state_before_digest_512),
            ("claim_context_da", self.da_commitment_512),
            ("claim_context_verifier", self.verifier_artifact_identity_512),
            ("claim_context_schema", self.schema_id_512),
            ("claim_context_suite", self.candidate_suite_id_512),
            ("claim_context_domain", self.settlement_domain_id_512),
        ):
            _bytes(label, value, 64, nonzero=True)

    def canonical_bytes(self) -> bytes:
        return _canonical_json(
            {
                "fork_id_512": self.fork_id_512.hex(),
                "l1_chain_id": self.l1_chain_id,
                "l2_chain_id": self.l2_chain_id,
                "state_before_digest_512": self.state_before_digest_512.hex(),
                "da_commitment_512": self.da_commitment_512.hex(),
                "verifier_artifact_identity_512": self.verifier_artifact_identity_512.hex(),
                "schema_id_512": self.schema_id_512.hex(),
                "candidate_suite_id_512": self.candidate_suite_id_512.hex(),
                "settlement_domain_id_512": self.settlement_domain_id_512.hex(),
            }
        )


@dataclass(frozen=True, slots=True)
class RollupClaimEnvelope:
    public_fields: tuple[bytes, ...]
    encoded_sidecar: bytes
    proof_body: bytes
    context_digest_512: bytes
    claim_proof_digest_512: bytes

    def __post_init__(self) -> None:
        _canonical_fields(self.public_fields)
        _bytes("claim_encoded_sidecar", self.encoded_sidecar, 744, nonzero=True)
        try:
            decoded = CandidateSidecarV1.decode(self.encoded_sidecar)
        except (TypeError, ValueError) as exc:
            raise Wave5RollupError("claim_sidecar_rejected") from exc
        if decoded.encode() != self.encoded_sidecar:
            raise Wave5RollupError("claim_sidecar_noncanonical")
        if type(self.proof_body) is not bytes or not self.proof_body or len(self.proof_body) > MAX_PROOF_BODY_BYTES:
            raise Wave5RollupError("claim_proof_body_invalid")
        _bytes("claim_context_digest", self.context_digest_512, 64, nonzero=True)
        _bytes("claim_proof_digest", self.claim_proof_digest_512, 64, nonzero=True)

    def canonical_bytes(self) -> bytes:
        return b"".join(
            (
                b"BL-WAVE5-CLAIM-ENVELOPE-V1",
                len(self.encoded_sidecar).to_bytes(4, "big"),
                self.encoded_sidecar,
                len(self.public_fields).to_bytes(1, "big"),
                b"".join(self.public_fields),
                len(self.proof_body).to_bytes(4, "big"),
                self.proof_body,
                self.context_digest_512,
                self.claim_proof_digest_512,
            )
        )


@dataclass(frozen=True, slots=True)
class ClaimVerificationReceipt:
    statement_digest_512: bytes
    proof_digest_512: bytes
    verifier_artifact_identity_512: bytes
    sidecar_digest_512: bytes

    def __post_init__(self) -> None:
        for label, value in (
            ("claim_statement_digest", self.statement_digest_512),
            ("claim_receipt_proof_digest", self.proof_digest_512),
            ("claim_receipt_verifier", self.verifier_artifact_identity_512),
            ("claim_receipt_sidecar", self.sidecar_digest_512),
        ):
            _bytes(label, value, 64, nonzero=True)

    def canonical_bytes(self) -> bytes:
        return b"".join(
            (
                b"BL-WAVE5-CLAIM-RECEIPT-V1",
                self.statement_digest_512,
                self.proof_digest_512,
                self.verifier_artifact_identity_512,
                self.sidecar_digest_512,
            )
        )


class ClaimVerifierPort(Protocol):
    def verify(
        self,
        *,
        envelope: RollupClaimEnvelope,
        context: RollupClaimContext,
        identity: RollupSuiteIdentity,
    ) -> ClaimVerificationReceipt: ...


def _reference_proof_body(envelope_sidecar: bytes, fields: tuple[bytes, ...], context: RollupClaimContext) -> bytes:
    return b"BL-WAVE5-REFERENCE-PROOF-V1" + _digest(
        b"REFERENCE-CLAIM-PROOF/V1",
        envelope_sidecar,
        b"".join(fields),
        context.canonical_bytes(),
    )


def build_reference_claim_envelope(
    *,
    sidecar: CandidateSidecarV1,
    public_fields: Sequence[bytes],
    context: RollupClaimContext,
) -> RollupClaimEnvelope:
    fields = _canonical_fields(public_fields)
    body = _reference_proof_body(sidecar.encode(), fields, context)
    return RollupClaimEnvelope(
        fields,
        sidecar.encode(),
        body,
        _digest(b"CLAIM-CONTEXT/V1", context.canonical_bytes()),
        _digest(b"CLAIM-PROOF-DIGEST/V1", body),
    )


class SyntheticReferenceClaimVerifier:
    """A deterministic local proof-boundary verifier, never a production ZK verifier."""

    def verify(
        self,
        *,
        envelope: RollupClaimEnvelope,
        context: RollupClaimContext,
        identity: RollupSuiteIdentity,
    ) -> ClaimVerificationReceipt:
        if type(envelope) is not RollupClaimEnvelope or type(context) is not RollupClaimContext:
            raise Wave5RollupError("claim_verifier_input_type_invalid")
        sidecar = CandidateSidecarV1.decode(envelope.encoded_sidecar)
        expected = (
            ("profile", sidecar.profile_id, identity.profile_id_512),
            ("suite", sidecar.proof_suite_id, identity.candidate_suite_id_512),
            ("schema", sidecar.schema_id, identity.schema_id_512),
            ("verifier", sidecar.verifier_artifact_identity, identity.verifier_artifact_identity_512),
            ("domain", sidecar.strong_settlement_domain_id, identity.settlement_domain_id_512),
        )
        if any(observed != required for _label, observed, required in expected):
            raise Wave5RollupError("claim_verifier_identity_mismatch")
        if sidecar.epoch != identity.epoch:
            raise Wave5RollupError("claim_verifier_epoch_mismatch")
        if context.fork_id_512 == bytes(64) or context.verifier_artifact_identity_512 != identity.verifier_artifact_identity_512:
            raise Wave5RollupError("claim_verifier_context_identity_mismatch")
        if context.schema_id_512 != identity.schema_id_512 or context.candidate_suite_id_512 != identity.candidate_suite_id_512:
            raise Wave5RollupError("claim_verifier_context_suite_mismatch")
        fields = _canonical_fields(envelope.public_fields)
        expected_context_digest = _digest(b"CLAIM-CONTEXT/V1", context.canonical_bytes())
        if envelope.context_digest_512 != expected_context_digest:
            raise Wave5RollupError("claim_verifier_context_digest_mismatch")
        expected_body = _reference_proof_body(envelope.encoded_sidecar, fields, context)
        if envelope.proof_body != expected_body:
            raise Wave5RollupError("claim_verifier_proof_body_mismatch")
        expected_proof_digest = _digest(b"CLAIM-PROOF-DIGEST/V1", expected_body)
        if envelope.claim_proof_digest_512 != expected_proof_digest:
            raise Wave5RollupError("claim_verifier_proof_digest_mismatch")
        statement = _digest(b"CLAIM-STATEMENT/V1", envelope.encoded_sidecar, b"".join(fields), context.canonical_bytes())
        return ClaimVerificationReceipt(
            statement,
            expected_proof_digest,
            identity.verifier_artifact_identity_512,
            _digest(b"CLAIM-SIDECAR/V1", envelope.encoded_sidecar),
        )


@dataclass(frozen=True, slots=True)
class KeyedNonceRecord:
    key_commitment_512: bytes
    next_nonce: int

    def __post_init__(self) -> None:
        _bytes("keyed_nonce_key", self.key_commitment_512, 64, nonzero=True)
        _u64("keyed_nonce_value", self.next_nonce)


class KeyedNonceTable:
    def __init__(self) -> None:
        self._values: dict[bytes, int] = {}

    def consume(self, key_commitment_512: bytes, expected_nonce: int) -> KeyedNonceRecord:
        key = _bytes("keyed_nonce_key", key_commitment_512, 64, nonzero=True)
        expected = _u64("keyed_nonce_expected", expected_nonce)
        observed = self._values.get(key, 0)
        if observed != expected:
            raise Wave5RollupError("keyed_nonce_conflict")
        self._values[key] = observed + 1
        return KeyedNonceRecord(key, observed + 1)

    @property
    def root_512(self) -> bytes:
        records = tuple(KeyedNonceRecord(key, value) for key, value in sorted(self._values.items()))
        encoded = b"".join(item.key_commitment_512 + item.next_nonce.to_bytes(8, "big") for item in records)
        return _digest(b"KEYED-NONCE-ROOT/V1", encoded)


@dataclass(frozen=True, slots=True)
class RecentRootReference:
    source_commitment_512: bytes
    root_512: bytes
    valid_from_slot: int
    valid_until_slot: int
    signed_envelope_digest_512: bytes

    def __post_init__(self) -> None:
        for label, value in (
            ("recent_root_source", self.source_commitment_512),
            ("recent_root", self.root_512),
            ("recent_root_envelope", self.signed_envelope_digest_512),
        ):
            _bytes(label, value, 64, nonzero=True)
        _u64("recent_root_valid_from", self.valid_from_slot)
        _u64("recent_root_valid_until", self.valid_until_slot)
        if self.valid_until_slot < self.valid_from_slot:
            raise Wave5RollupError("recent_root_window_invalid")


class RecentRootAdapter:
    """EIP-8272-style recent roots remain an explicit disabled optional adapter."""

    def __init__(self, *, enabled: bool = False) -> None:
        if type(enabled) is not bool:
            raise Wave5RollupError("recent_root_adapter_enabled_flag_invalid")
        self.enabled = enabled

    def validate(self, reference: RecentRootReference, *, slot: int) -> None:
        if not self.enabled:
            raise Wave5RollupError("recent_root_optional_feature_disabled")
        if type(reference) is not RecentRootReference:
            raise Wave5RollupError("recent_root_reference_invalid")
        _u64("recent_root_slot", slot)
        if not reference.valid_from_slot <= slot <= reference.valid_until_slot:
            raise Wave5RollupError("recent_root_outside_window")


@dataclass(frozen=True, slots=True)
class RollupState:
    sequence: int
    epoch: int
    l2_state_root_512: bytes
    nullifier_root_512: bytes
    payment_state_root_512: bytes
    wide_state_root_512: bytes
    keyed_nonce_root_512: bytes
    recent_root_digest_512: bytes
    l1_anchor_hash_512: bytes

    def __post_init__(self) -> None:
        _u64("rollup_state_sequence", self.sequence)
        _u64("rollup_state_epoch", self.epoch, nonzero=True)
        for label, value in (
            ("rollup_state_l2_root", self.l2_state_root_512),
            ("rollup_state_nullifier_root", self.nullifier_root_512),
            ("rollup_state_payment_root", self.payment_state_root_512),
            ("rollup_state_wide_root", self.wide_state_root_512),
            ("rollup_state_nonce_root", self.keyed_nonce_root_512),
            ("rollup_state_recent_root", self.recent_root_digest_512),
            ("rollup_state_l1_anchor", self.l1_anchor_hash_512),
        ):
            _bytes(label, value, 64, nonzero=True)

    @classmethod
    def genesis(cls, manifest: EthereumCompatManifest, identity: RollupSuiteIdentity) -> "RollupState":
        seed = _digest(b"ROLLUP-GENESIS/V1", manifest.manifest_digest_512, identity.profile_id_512)
        return cls(
            0,
            identity.epoch,
            _digest(b"GENESIS-L2-ROOT", seed),
            _digest(b"GENESIS-NULLIFIER-ROOT", seed),
            _digest(b"GENESIS-PAYMENT-ROOT", seed),
            _digest(b"GENESIS-WIDE-ROOT", seed),
            _digest(b"GENESIS-NONCE-ROOT", seed),
            _digest(b"GENESIS-RECENT-ROOT", seed),
            _digest(b"GENESIS-L1-ANCHOR", seed),
        )

    def canonical_bytes(self) -> bytes:
        return _canonical_json(
            {
                "sequence": self.sequence,
                "epoch": self.epoch,
                "l2_state_root_512": self.l2_state_root_512.hex(),
                "nullifier_root_512": self.nullifier_root_512.hex(),
                "payment_state_root_512": self.payment_state_root_512.hex(),
                "wide_state_root_512": self.wide_state_root_512.hex(),
                "keyed_nonce_root_512": self.keyed_nonce_root_512.hex(),
                "recent_root_digest_512": self.recent_root_digest_512.hex(),
                "l1_anchor_hash_512": self.l1_anchor_hash_512.hex(),
            }
        )

    @property
    def digest_512(self) -> bytes:
        return _digest(b"ROLLUP-STATE-DIGEST/V1", self.canonical_bytes())


@dataclass(frozen=True, slots=True)
class OpaqueTransaction:
    sender_commitment_512: bytes
    nonce: int
    payload_commitment_512: bytes
    attempt_id: str
    origin: str = "USER"

    def __post_init__(self) -> None:
        _bytes("opaque_tx_sender", self.sender_commitment_512, 64, nonzero=True)
        _u64("opaque_tx_nonce", self.nonce)
        _bytes("opaque_tx_payload", self.payload_commitment_512, 64, nonzero=True)
        _identifier("opaque_tx_attempt_id", self.attempt_id)
        if self.origin not in {"USER", "FORCED"}:
            raise Wave5RollupError("opaque_tx_origin_invalid")

    def canonical_bytes(self) -> bytes:
        return _canonical_json(
            {
                "sender_commitment_512": self.sender_commitment_512.hex(),
                "nonce": self.nonce,
                "payload_commitment_512": self.payload_commitment_512.hex(),
                "attempt_id": self.attempt_id,
                "origin": self.origin,
            }
        )

    @property
    def tx_hash_512(self) -> bytes:
        return _digest(b"OPAQUE-TX-HASH/V1", self.canonical_bytes())


@dataclass(frozen=True, slots=True)
class InclusionList:
    slot: int
    view_commitment_512: bytes
    transaction_hashes: tuple[bytes, ...]
    committee_commitment_512: bytes

    def __post_init__(self) -> None:
        _u64("inclusion_list_slot", self.slot)
        _bytes("inclusion_list_view", self.view_commitment_512, 64, nonzero=True)
        _bytes("inclusion_list_committee", self.committee_commitment_512, 64, nonzero=True)
        if type(self.transaction_hashes) is not tuple or len(self.transaction_hashes) > MAX_TRANSACTIONS:
            raise Wave5RollupError("inclusion_list_transaction_count_invalid")
        if tuple(sorted(self.transaction_hashes)) != self.transaction_hashes or len(set(self.transaction_hashes)) != len(self.transaction_hashes):
            raise Wave5RollupError("inclusion_list_transaction_order_invalid")
        for value in self.transaction_hashes:
            _bytes("inclusion_list_transaction_hash", value, 64, nonzero=True)

    @property
    def digest_512(self) -> bytes:
        return _digest(
            b"INCLUSION-LIST/V1",
            self.slot.to_bytes(8, "big"),
            self.view_commitment_512,
            b"".join(self.transaction_hashes),
            self.committee_commitment_512,
        )


@dataclass(frozen=True, slots=True)
class ForcedInclusion:
    transaction: OpaqueTransaction
    due_slot: int
    request_digest_512: bytes

    def __post_init__(self) -> None:
        if type(self.transaction) is not OpaqueTransaction or self.transaction.origin != "FORCED":
            raise Wave5RollupError("forced_inclusion_transaction_invalid")
        _u64("forced_inclusion_due_slot", self.due_slot)
        _bytes("forced_inclusion_request_digest", self.request_digest_512, 64, nonzero=True)


class ForcedInclusionQueue:
    def __init__(self, *, capacity: int = MAX_FORCED_INCLUSIONS) -> None:
        _u64("forced_queue_capacity", capacity, nonzero=True, maximum=MAX_FORCED_INCLUSIONS)
        self._capacity = capacity
        self._entries: dict[bytes, ForcedInclusion] = {}

    def submit(self, transaction: OpaqueTransaction, *, current_slot: int, deadline_slots: int = 2) -> ForcedInclusion:
        if type(transaction) is not OpaqueTransaction or transaction.origin != "FORCED":
            raise Wave5RollupError("forced_queue_requires_opaque_forced_transaction")
        _u64("forced_queue_current_slot", current_slot)
        _u64("forced_queue_deadline_slots", deadline_slots, nonzero=True, maximum=MAX_QUEUE_SLOTS)
        if len(self._entries) >= self._capacity:
            raise Wave5RollupError("forced_queue_full")
        request = _digest(b"FORCED-INCLUSION-REQUEST/V1", transaction.canonical_bytes(), current_slot.to_bytes(8, "big"))
        entry = ForcedInclusion(transaction, current_slot + deadline_slots, request)
        if transaction.tx_hash_512 in self._entries:
            raise Wave5RollupError("forced_queue_replay")
        self._entries[transaction.tx_hash_512] = entry
        return entry

    def due(self, slot: int) -> tuple[ForcedInclusion, ...]:
        _u64("forced_queue_due_slot", slot)
        return tuple(sorted((item for item in self._entries.values() if item.due_slot <= slot), key=lambda item: item.transaction.tx_hash_512))

    def consume(self, transaction_hashes: Sequence[bytes]) -> None:
        for value in transaction_hashes:
            key = _bytes("forced_queue_consume_hash", value, 64, nonzero=True)
            if key not in self._entries:
                raise Wave5RollupError("forced_queue_consume_unknown")
            del self._entries[key]

    @property
    def count(self) -> int:
        return len(self._entries)


@dataclass(frozen=True, slots=True)
class OrderedBatch:
    slot: int
    transactions: tuple[OpaqueTransaction, ...]
    inclusion_list_digest_512: bytes
    forced_inclusion_digests: tuple[bytes, ...]
    batch_commitment_512: bytes

    def __post_init__(self) -> None:
        _u64("ordered_batch_slot", self.slot)
        if type(self.transactions) is not tuple or not self.transactions or len(self.transactions) > MAX_TRANSACTIONS:
            raise Wave5RollupError("ordered_batch_transactions_invalid")
        _bytes("ordered_batch_inclusion_digest", self.inclusion_list_digest_512, 64, nonzero=True)
        for value in self.forced_inclusion_digests:
            _bytes("ordered_batch_forced_digest", value, 64, nonzero=True)
        _bytes("ordered_batch_commitment", self.batch_commitment_512, 64, nonzero=True)

    @property
    def transaction_hashes(self) -> tuple[bytes, ...]:
        return tuple(item.tx_hash_512 for item in self.transactions)


class BasedOrderer:
    """Deterministic L1-origin ordering with no canonical sequencer input."""

    def __init__(self, manifest: EthereumCompatManifest) -> None:
        self.manifest = manifest
        self._pending: dict[bytes, OpaqueTransaction] = {}
        self._sender_nonces: dict[bytes, dict[int, bytes]] = {}

    def submit(self, transaction: OpaqueTransaction) -> None:
        if type(transaction) is not OpaqueTransaction:
            raise Wave5RollupError("based_orderer_transaction_type_invalid")
        tx_hash = transaction.tx_hash_512
        if tx_hash in self._pending:
            raise Wave5RollupError("based_orderer_duplicate_transaction")
        sender = self._sender_nonces.setdefault(transaction.sender_commitment_512, {})
        previous = sender.get(transaction.nonce)
        if previous is not None and previous != tx_hash:
            raise Wave5RollupError("based_orderer_nonce_conflict")
        sender[transaction.nonce] = tx_hash
        self._pending[tx_hash] = transaction

    def order(
        self,
        *,
        slot: int,
        inclusion_list: InclusionList,
        forced_entries: Sequence[ForcedInclusion] = (),
    ) -> OrderedBatch:
        _u64("based_orderer_slot", slot)
        if inclusion_list.slot != slot:
            raise Wave5RollupError("based_orderer_inclusion_slot_mismatch")
        if type(forced_entries) not in (tuple, list):
            raise Wave5RollupError("based_orderer_forced_entries_invalid")
        forced_hashes = {entry.transaction.tx_hash_512 for entry in forced_entries}
        if any(entry.transaction.tx_hash_512 not in self._pending for entry in forced_entries):
            raise Wave5RollupError("based_orderer_forced_transaction_missing")
        required = set(inclusion_list.transaction_hashes)
        if not required.issubset(self._pending):
            raise Wave5RollupError("based_orderer_inclusion_withheld")
        selected = tuple(
            sorted(
                (self._pending[key] for key in required | forced_hashes),
                key=lambda item: item.tx_hash_512,
            )
        )
        if not selected:
            raise Wave5RollupError("based_orderer_empty_batch")
        if len(selected) > MAX_TRANSACTIONS:
            raise Wave5RollupError("based_orderer_batch_limit")
        seen_nonce: set[tuple[bytes, int]] = set()
        for item in selected:
            identity = (item.sender_commitment_512, item.nonce)
            if identity in seen_nonce:
                raise Wave5RollupError("based_orderer_nonce_replay")
            seen_nonce.add(identity)
        batch_commitment = _digest(
            b"BASED-ORDERED-BATCH/V1",
            slot.to_bytes(8, "big"),
            b"".join(item.canonical_bytes() for item in selected),
            inclusion_list.digest_512,
            b"".join(sorted(forced_hashes)),
        )
        for item in selected:
            del self._pending[item.tx_hash_512]
            del self._sender_nonces[item.sender_commitment_512][item.nonce]
        return OrderedBatch(slot, selected, inclusion_list.digest_512, tuple(sorted(forced_hashes)), batch_commitment)

    @staticmethod
    def validate_payload(*, batch: OrderedBatch, inclusion_list: InclusionList, execution_validated: bool) -> None:
        if not execution_validated:
            raise Wave5RollupError("based_orderer_preconfirmation_not_validity")
        if batch.slot != inclusion_list.slot:
            raise Wave5RollupError("based_orderer_payload_slot_mismatch")
        if not set(inclusion_list.transaction_hashes).issubset(set(batch.transaction_hashes)):
            raise Wave5RollupError("based_orderer_payload_withholding")


@dataclass(frozen=True, slots=True)
class DataCell:
    index: int
    total: int
    commitment_512: bytes

    def __post_init__(self) -> None:
        _u64("da_cell_index", self.index, maximum=MAX_CELLS - 1)
        _u64("da_cell_total", self.total, nonzero=True, maximum=MAX_CELLS)
        if self.index >= self.total:
            raise Wave5RollupError("da_cell_index_out_of_range")
        _bytes("da_cell_commitment", self.commitment_512, MAX_CELL_BYTES, nonzero=True)


@dataclass(frozen=True, slots=True)
class DABundle:
    mode: str
    payload_commitment_512: bytes
    reconstruction_proof_512: bytes
    cells: tuple[DataCell, ...]
    retention_until_slot: int
    migration_digest_512: bytes = bytes(64)

    def __post_init__(self) -> None:
        if self.mode not in {"CALLDATA_COMMITMENT", "BLOB_COMMITMENT", "CELL_COMMITMENT"}:
            raise Wave5RollupError("da_mode_unknown")
        _bytes("da_payload_commitment", self.payload_commitment_512, 64, nonzero=True)
        _bytes("da_reconstruction_proof", self.reconstruction_proof_512, 64, nonzero=True)
        if type(self.cells) is not tuple or not self.cells or len(self.cells) > MAX_CELLS:
            raise Wave5RollupError("da_cell_count_invalid")
        if tuple(item.index for item in self.cells) != tuple(range(len(self.cells))):
            raise Wave5RollupError("da_cell_order_invalid")
        if any(item.total != len(self.cells) for item in self.cells):
            raise Wave5RollupError("da_cell_total_mismatch")
        _u64("da_retention_until", self.retention_until_slot, maximum=MAX_RETENTION_SLOTS)
        if self.migration_digest_512 != bytes(64):
            _bytes("da_migration_digest", self.migration_digest_512, 64, nonzero=True)

    @property
    def digest_512(self) -> bytes:
        return _digest(b"DA-BUNDLE/V1", self.canonical_bytes())

    def canonical_bytes(self) -> bytes:
        return _canonical_json(
            {
                "mode": self.mode,
                "payload_commitment_512": self.payload_commitment_512.hex(),
                "reconstruction_proof_512": self.reconstruction_proof_512.hex(),
                "cells": [
                    {"index": item.index, "total": item.total, "commitment_512": item.commitment_512.hex()}
                    for item in self.cells
                ],
                "retention_until_slot": self.retention_until_slot,
                "migration_digest_512": self.migration_digest_512.hex(),
            }
        )


@dataclass(frozen=True, slots=True)
class DAReconstruction:
    bundle_digest_512: bytes
    payload_commitment_512: bytes
    reconstructed_commitments: tuple[bytes, ...]

    def __post_init__(self) -> None:
        _bytes("da_reconstruction_bundle", self.bundle_digest_512, 64, nonzero=True)
        _bytes("da_reconstruction_payload", self.payload_commitment_512, 64, nonzero=True)
        if type(self.reconstructed_commitments) is not tuple or not self.reconstructed_commitments:
            raise Wave5RollupError("da_reconstruction_commitments_invalid")
        for value in self.reconstructed_commitments:
            _bytes("da_reconstructed_commitment", value, 64, nonzero=True)


def build_da_bundle(payload_commitments: Sequence[bytes], *, mode: str, retention_until_slot: int) -> DABundle:
    if type(payload_commitments) not in (tuple, list) or not payload_commitments or len(payload_commitments) > MAX_CELLS:
        raise Wave5RollupError("da_payload_fragment_count_invalid")
    fragments = tuple(_bytes("da_payload_fragment", value, 64, nonzero=True) for value in payload_commitments)
    cells = tuple(DataCell(index, len(fragments), value) for index, value in enumerate(fragments))
    payload = _digest(b"DA-PAYLOAD/V1", b"".join(fragments))
    proof = _digest(b"DA-RECONSTRUCTION-PROOF/V1", payload, b"".join(item.commitment_512 for item in cells))
    return DABundle(mode, payload, proof, cells, retention_until_slot)


class DataAvailabilityStore:
    def __init__(self) -> None:
        self._bundles: dict[bytes, DABundle] = {}

    def publish(self, bundle: DABundle) -> bytes:
        if type(bundle) is not DABundle:
            raise Wave5RollupError("da_publish_bundle_invalid")
        digest = bundle.digest_512
        existing = self._bundles.get(digest)
        if existing is not None and existing != bundle:
            raise Wave5RollupError("da_bundle_digest_collision")
        self._bundles[digest] = bundle
        return digest

    def fetch(self, bundle_digest_512: bytes, indexes: Sequence[int]) -> tuple[DataCell, ...]:
        key = _bytes("da_fetch_bundle_digest", bundle_digest_512, 64, nonzero=True)
        bundle = self._bundles.get(key)
        if bundle is None:
            raise Wave5RollupError("da_bundle_missing")
        if type(indexes) not in (tuple, list) or not indexes:
            raise Wave5RollupError("da_fetch_indexes_invalid")
        if any(type(index) is not int or index < 0 or index >= len(bundle.cells) for index in indexes):
            raise Wave5RollupError("da_fetch_index_invalid")
        if len(set(indexes)) != len(indexes):
            raise Wave5RollupError("da_fetch_duplicate_index")
        return tuple(bundle.cells[index] for index in sorted(indexes))

    def reconstruct(self, bundle_digest_512: bytes, cells: Sequence[DataCell], *, current_slot: int) -> DAReconstruction:
        key = _bytes("da_reconstruct_bundle_digest", bundle_digest_512, 64, nonzero=True)
        bundle = self._bundles.get(key)
        if bundle is None:
            raise Wave5RollupError("da_bundle_missing")
        _u64("da_reconstruct_current_slot", current_slot)
        if current_slot > bundle.retention_until_slot:
            raise Wave5RollupError("da_retention_expired")
        if type(cells) not in (tuple, list) or len(cells) != len(bundle.cells):
            raise Wave5RollupError("da_reconstruction_partial")
        observed = tuple(sorted(cells, key=lambda item: item.index))
        if observed != bundle.cells:
            raise Wave5RollupError("da_reconstruction_cell_mismatch")
        payload = _digest(b"DA-PAYLOAD/V1", b"".join(item.commitment_512 for item in observed))
        proof = _digest(b"DA-RECONSTRUCTION-PROOF/V1", payload, b"".join(item.commitment_512 for item in observed))
        if payload != bundle.payload_commitment_512 or proof != bundle.reconstruction_proof_512:
            raise Wave5RollupError("da_reconstruction_binding_mismatch")
        return DAReconstruction(key, payload, tuple(item.commitment_512 for item in observed))

    def migrate(self, bundle_digest_512: bytes, *, target_mode: str, current_slot: int) -> DABundle:
        key = _bytes("da_migration_bundle_digest", bundle_digest_512, 64, nonzero=True)
        bundle = self._bundles.get(key)
        if bundle is None:
            raise Wave5RollupError("da_bundle_missing")
        if target_mode not in {"CALLDATA_COMMITMENT", "BLOB_COMMITMENT", "CELL_COMMITMENT"}:
            raise Wave5RollupError("da_migration_target_mode_unknown")
        _u64("da_migration_current_slot", current_slot)
        if target_mode == bundle.mode:
            raise Wave5RollupError("da_migration_mode_unchanged")
        migrated = DABundle(
            target_mode,
            bundle.payload_commitment_512,
            bundle.reconstruction_proof_512,
            bundle.cells,
            max(bundle.retention_until_slot, current_slot + 1),
            _digest(b"DA-MIGRATION/V1", bundle.digest_512, target_mode.encode("ascii")),
        )
        self.publish(migrated)
        return migrated


@dataclass(frozen=True, slots=True)
class RollupTransition:
    before: RollupState
    after: RollupState
    attempt_id: str
    batch_nonce: int
    fork_id_512: bytes
    ordered_batch_commitment_512: bytes
    da_commitment_512: bytes
    bal_commitment_512: bytes
    cbam_commitment_512: bytes
    claim_receipt: ClaimVerificationReceipt
    envelope: RollupClaimEnvelope

    def __post_init__(self) -> None:
        if type(self.before) is not RollupState or type(self.after) is not RollupState:
            raise Wave5RollupError("rollup_transition_state_type_invalid")
        if self.after.sequence != self.before.sequence + 1:
            raise Wave5RollupError("rollup_transition_sequence_invalid")
        _identifier("rollup_transition_attempt_id", self.attempt_id)
        _u64("rollup_transition_batch_nonce", self.batch_nonce)
        _bytes("rollup_transition_fork_id", self.fork_id_512, 64, nonzero=True)
        for label, value in (
            ("rollup_transition_ordered_batch", self.ordered_batch_commitment_512),
            ("rollup_transition_da", self.da_commitment_512),
            ("rollup_transition_bal", self.bal_commitment_512),
            ("rollup_transition_cbam", self.cbam_commitment_512),
        ):
            _bytes(label, value, 64, nonzero=True)
        if self.bal_commitment_512 == self.cbam_commitment_512:
            raise Wave5RollupError("rollup_transition_bal_cbam_must_be_separate")
        if type(self.claim_receipt) is not ClaimVerificationReceipt or type(self.envelope) is not RollupClaimEnvelope:
            raise Wave5RollupError("rollup_transition_claim_binding_invalid")
        sidecar = CandidateSidecarV1.decode(self.envelope.encoded_sidecar)
        if sidecar.sequence_before != self.before.sequence or sidecar.sequence_after != self.after.sequence:
            raise Wave5RollupError("rollup_transition_sidecar_sequence_mismatch")
        if sidecar.strong_nullifier_root_before != self.before.nullifier_root_512 or sidecar.strong_nullifier_root_after != self.after.nullifier_root_512:
            raise Wave5RollupError("rollup_transition_nullifier_root_mismatch")
        if sidecar.strong_payment_state_root_before != self.before.payment_state_root_512 or sidecar.strong_payment_state_root_after != self.after.payment_state_root_512:
            raise Wave5RollupError("rollup_transition_payment_root_mismatch")

    def canonical_bytes(self) -> bytes:
        return b"".join(
            (
                b"BL-WAVE5-ROLLUP-TRANSITION-V1",
                self.before.digest_512,
                self.after.digest_512,
                self.attempt_id.encode("ascii"),
                self.batch_nonce.to_bytes(8, "big"),
                self.fork_id_512,
                self.ordered_batch_commitment_512,
                self.da_commitment_512,
                self.bal_commitment_512,
                self.cbam_commitment_512,
                self.claim_receipt.canonical_bytes(),
                self.envelope.canonical_bytes(),
            )
        )

    @property
    def binding_digest_512(self) -> bytes:
        return _digest(b"ROLLUP-TRANSITION-BINDING/V1", self.canonical_bytes())


def build_rollup_transition(
    *,
    before: RollupState,
    envelope: RollupClaimEnvelope,
    claim_receipt: ClaimVerificationReceipt,
    fork_id_512: bytes,
    ordered_batch_commitment_512: bytes,
    da_commitment_512: bytes,
    bal_commitment_512: bytes,
    cbam_commitment_512: bytes,
    attempt_id: str,
    batch_nonce: int,
) -> RollupTransition:
    sidecar = CandidateSidecarV1.decode(envelope.encoded_sidecar)
    if sidecar.strong_nullifier_root_before != before.nullifier_root_512 or sidecar.strong_payment_state_root_before != before.payment_state_root_512:
        raise Wave5RollupError("rollup_transition_before_root_mismatch")
    wide_after = _digest(
        b"WIDE-STATE-SUCCESSOR/V1",
        before.wide_state_root_512,
        envelope.canonical_bytes(),
        da_commitment_512,
        ordered_batch_commitment_512,
        bal_commitment_512,
        cbam_commitment_512,
    )
    after = RollupState(
        before.sequence + 1,
        before.epoch,
        _digest(b"L2-STATE-SUCCESSOR/V1", before.canonical_bytes(), wide_after),
        sidecar.strong_nullifier_root_after,
        sidecar.strong_payment_state_root_after,
        wide_after,
        _digest(b"NONCE-SUCCESSOR/V1", before.keyed_nonce_root_512, batch_nonce.to_bytes(8, "big")),
        _digest(b"RECENT-ROOT-SUCCESSOR/V1", before.recent_root_digest_512, before.sequence.to_bytes(8, "big")),
        before.l1_anchor_hash_512,
    )
    return RollupTransition(
        before,
        after,
        attempt_id,
        batch_nonce,
        fork_id_512,
        ordered_batch_commitment_512,
        da_commitment_512,
        bal_commitment_512,
        cbam_commitment_512,
        claim_receipt,
        envelope,
    )


@dataclass(frozen=True, slots=True)
class L2ExecutionVector:
    profile_name: str
    semantics_id: str
    transition_digest_512: bytes
    before_state_digest_512: bytes
    after_state_digest_512: bytes
    trace_digest_512: bytes

    def __post_init__(self) -> None:
        _identifier("l2_vector_profile", self.profile_name)
        _identifier("l2_vector_semantics", self.semantics_id)
        for label, value in (
            ("l2_vector_transition", self.transition_digest_512),
            ("l2_vector_before", self.before_state_digest_512),
            ("l2_vector_after", self.after_state_digest_512),
            ("l2_vector_trace", self.trace_digest_512),
        ):
            _bytes(label, value, 64, nonzero=True)


@dataclass(frozen=True, slots=True)
class L2TransitionProof:
    fork_id_512: bytes
    transition_digest_512: bytes
    before_state_digest_512: bytes
    after_state_digest_512: bytes
    claim_proof_digest_512: bytes
    da_commitment_512: bytes
    trace_digest_512: bytes
    verifier_artifact_identity_512: bytes
    proof_body: bytes

    def __post_init__(self) -> None:
        for label, value in (
            ("l2_proof_fork", self.fork_id_512),
            ("l2_proof_transition", self.transition_digest_512),
            ("l2_proof_before", self.before_state_digest_512),
            ("l2_proof_after", self.after_state_digest_512),
            ("l2_proof_claim", self.claim_proof_digest_512),
            ("l2_proof_da", self.da_commitment_512),
            ("l2_proof_trace", self.trace_digest_512),
            ("l2_proof_verifier", self.verifier_artifact_identity_512),
        ):
            _bytes(label, value, 64, nonzero=True)
        if type(self.proof_body) is not bytes or len(self.proof_body) != 64 or not any(self.proof_body):
            raise Wave5RollupError("l2_proof_body_invalid")

    def canonical_bytes(self) -> bytes:
        return b"".join(
            (
                b"BL-WAVE5-L2-TRANSITION-PROOF-V1",
                self.fork_id_512,
                self.transition_digest_512,
                self.before_state_digest_512,
                self.after_state_digest_512,
                self.claim_proof_digest_512,
                self.da_commitment_512,
                self.trace_digest_512,
                self.verifier_artifact_identity_512,
                self.proof_body,
            )
        )

    @property
    def proof_digest_512(self) -> bytes:
        return _digest(b"L2-TRANSITION-PROOF-DIGEST/V1", self.canonical_bytes())

    @property
    def expected_l1_state_root_512(self) -> bytes:
        return _digest(b"L1-ROLLUP-STATE-ROOT/V1", self.proof_digest_512)


class L2StateTransitionProver:
    def __init__(self, manifest: EthereumCompatManifest) -> None:
        self.manifest = manifest

    def execute_vector(self, transition: RollupTransition, profile: EthereumForkProfile) -> L2ExecutionVector:
        if profile.fork_id_512 not in {self.manifest.baseline.fork_id_512, self.manifest.future_shadow.fork_id_512}:
            raise Wave5RollupError("l2_vector_profile_unknown")
        trace = _digest(
            b"L2-EXECUTION-TRACE/V1",
            profile.semantics_id.encode("ascii"),
            transition.before.canonical_bytes(),
            transition.after.canonical_bytes(),
            transition.envelope.canonical_bytes(),
            transition.da_commitment_512,
        )
        return L2ExecutionVector(
            profile.name,
            profile.semantics_id,
            transition.binding_digest_512,
            transition.before.digest_512,
            transition.after.digest_512,
            trace,
        )

    def differential(self, transition: RollupTransition) -> tuple[L2ExecutionVector, ...]:
        vectors = (
            self.execute_vector(transition, self.manifest.baseline),
            self.execute_vector(transition, self.manifest.future_shadow),
        )
        if vectors[0].after_state_digest_512 != vectors[1].after_state_digest_512 or vectors[0].trace_digest_512 != vectors[1].trace_digest_512:
            raise Wave5RollupError("l2_differential_semantics_mismatch")
        return vectors

    def prove(self, transition: RollupTransition) -> L2TransitionProof:
        vector = self.execute_vector(transition, self.manifest.baseline)
        body = _digest(
            b"L2-TRANSITION-PROOF-BODY/V1",
            vector.trace_digest_512,
            transition.claim_receipt.proof_digest_512,
            transition.da_commitment_512,
            transition.binding_digest_512,
        )
        return L2TransitionProof(
            transition.fork_id_512,
            transition.binding_digest_512,
            transition.before.digest_512,
            transition.after.digest_512,
            transition.claim_receipt.proof_digest_512,
            transition.da_commitment_512,
            vector.trace_digest_512,
            transition.claim_receipt.verifier_artifact_identity_512,
            body,
        )

    def verify(self, proof: L2TransitionProof, transition: RollupTransition) -> None:
        expected = self.prove(transition)
        if proof != expected:
            raise Wave5RollupError("l2_transition_proof_rejected")


@dataclass(frozen=True, slots=True)
class GovernanceApproval:
    manifest_digest_512: bytes
    verifier_artifact_identity_512: bytes
    signatures: tuple[PqSignature, ...]

    def __post_init__(self) -> None:
        _bytes("governance_manifest_digest", self.manifest_digest_512, 64, nonzero=True)
        _bytes("governance_verifier_identity", self.verifier_artifact_identity_512, 64, nonzero=True)
        if type(self.signatures) is not tuple or len(self.signatures) != 2 or tuple(item.suite_id for item in self.signatures) != DUAL_PQ_SUITES:
            raise Wave5RollupError("governance_dual_pq_signature_set_invalid")

    def message(self) -> bytes:
        return _digest(b"GOVERNANCE-APPROVAL/V1", self.manifest_digest_512, self.verifier_artifact_identity_512)


class PqGovernance:
    def __init__(self, authority: DualPqAuthenticator) -> None:
        if type(authority) is not DualPqAuthenticator:
            raise Wave5RollupError("governance_dual_pq_authority_required")
        self.authority = authority

    def approve(self, manifest_digest_512: bytes, verifier_artifact_identity_512: bytes) -> GovernanceApproval:
        approval = GovernanceApproval(
            _bytes("governance_manifest_digest", manifest_digest_512, 64, nonzero=True),
            _bytes("governance_verifier_identity", verifier_artifact_identity_512, 64, nonzero=True),
            self.authority.sign(_digest(b"GOVERNANCE-APPROVAL/V1", manifest_digest_512, verifier_artifact_identity_512)),
        )
        self.verify(approval)
        return approval

    def verify(self, approval: GovernanceApproval) -> None:
        if type(approval) is not GovernanceApproval or not self.authority.verify(message=approval.message(), signatures=approval.signatures):
            raise Wave5RollupError("governance_approval_rejected")


@dataclass(frozen=True, slots=True)
class SettlementReceipt:
    l1_block_hash_512: bytes
    l1_state_root_512: bytes
    proof_digest_512: bytes
    transition_binding_512: bytes
    governance_manifest_digest_512: bytes
    finality: FinalityLevel

    def __post_init__(self) -> None:
        for label, value in (
            ("settlement_block_hash", self.l1_block_hash_512),
            ("settlement_state_root", self.l1_state_root_512),
            ("settlement_proof_digest", self.proof_digest_512),
            ("settlement_transition_binding", self.transition_binding_512),
            ("settlement_governance_manifest", self.governance_manifest_digest_512),
        ):
            _bytes(label, value, 64, nonzero=True)
        if self.finality is not FinalityLevel.FINALIZED:
            raise Wave5RollupError("settlement_receipt_not_finalized")


class FinalityTracker:
    def __init__(self, manifest: EthereumCompatManifest) -> None:
        self.manifest = manifest
        self._blocks: dict[bytes, L1Block] = {}
        self._levels: dict[bytes, FinalityLevel] = {}
        self._head: bytes = bytes(64)
        self._finalized: bytes = bytes(64)

    def observe(self, block: L1Block) -> None:
        if type(block) is not L1Block:
            raise Wave5RollupError("finality_observed_block_invalid")
        self.manifest.profile_for(block.fork_id_512)
        if block.number == 0:
            self._blocks[block.block_hash_512] = block
            self._levels[block.block_hash_512] = FinalityLevel.FINALIZED
            self._head = block.block_hash_512
            self._finalized = block.block_hash_512
            return
        if block.parent_hash_512 not in self._blocks:
            raise Wave5RollupError("finality_parent_unknown")
        self._blocks[block.block_hash_512] = block
        observed = self._levels.get(block.block_hash_512, FinalityLevel.HEAD)
        level = block.finality if _FINALITY_RANK[block.finality] > _FINALITY_RANK[observed] else observed
        self._levels[block.block_hash_512] = level
        self._head = block.block_hash_512
        if level in {FinalityLevel.FINALIZED, FinalityLevel.RECOVERED}:
            if self._finalized != bytes(64):
                previous = self._blocks[self._finalized]
                if block.number < previous.number:
                    raise Wave5RollupError("finality_regressed")
            self._finalized = block.block_hash_512

    def is_finalized(self, block_hash_512: bytes) -> bool:
        key = _bytes("finality_query_hash", block_hash_512, 64, nonzero=True)
        return key == self._finalized or self._levels.get(key) in {FinalityLevel.FINALIZED, FinalityLevel.RECOVERED}

    def level(self, block_hash_512: bytes) -> FinalityLevel:
        key = _bytes("finality_level_hash", block_hash_512, 64, nonzero=True)
        if key not in self._levels:
            raise Wave5RollupError("finality_block_unknown")
        return self._levels[key]

    @property
    def finalized_hash_512(self) -> bytes:
        return self._finalized

    @property
    def head_hash_512(self) -> bytes:
        return self._head


class SettlementEngine:
    def __init__(self, manifest: EthereumCompatManifest, tracker: FinalityTracker, governance: PqGovernance) -> None:
        self.manifest = manifest
        self.tracker = tracker
        self.governance = governance

    def settle(
        self,
        *,
        proof: L2TransitionProof,
        transition: RollupTransition,
        block: L1Block,
        approval: GovernanceApproval,
    ) -> SettlementReceipt:
        L2StateTransitionProver(self.manifest).verify(proof, transition)
        self.governance.verify(approval)
        if approval.manifest_digest_512 != self.manifest.manifest_digest_512:
            raise Wave5RollupError("settlement_governance_manifest_mismatch")
        if approval.verifier_artifact_identity_512 != proof.verifier_artifact_identity_512:
            raise Wave5RollupError("settlement_governance_verifier_mismatch")
        if block.fork_id_512 != self.manifest.baseline.fork_id_512:
            raise Wave5RollupError("settlement_fork_not_baseline")
        if not self.tracker.is_finalized(block.block_hash_512):
            raise Wave5RollupError("settlement_requires_l1_finality")
        expected_root = proof.expected_l1_state_root_512
        if block.state_root_512 != expected_root:
            raise Wave5RollupError("settlement_state_root_mismatch")
        return SettlementReceipt(
            block.block_hash_512,
            block.state_root_512,
            proof.proof_digest_512,
            transition.binding_digest_512,
            approval.manifest_digest_512,
            FinalityLevel.FINALIZED,
        )


class AtomicRollupState:
    def __init__(self, initial: RollupState) -> None:
        if type(initial) is not RollupState:
            raise Wave5RollupError("atomic_rollup_initial_state_invalid")
        self._state = initial
        self._attempts: set[str] = set()
        self._batch_nonces: set[int] = set()
        self._history: list[bytes] = [initial.digest_512]
        self._lock = RLock()

    @property
    def snapshot(self) -> RollupState:
        with self._lock:
            return self._state

    @property
    def history(self) -> tuple[bytes, ...]:
        with self._lock:
            return tuple(self._history)

    def apply(self, *, transition: RollupTransition, proof: L2TransitionProof, settlement: SettlementReceipt) -> RollupState:
        with self._lock:
            if transition.attempt_id in self._attempts or transition.batch_nonce in self._batch_nonces:
                raise Wave5RollupError("atomic_rollup_replay")
            if transition.before != self._state:
                raise Wave5RollupError("atomic_rollup_stale_before_state")
            if proof.transition_digest_512 != transition.binding_digest_512:
                raise Wave5RollupError("atomic_rollup_proof_transition_mismatch")
            if settlement.proof_digest_512 != proof.proof_digest_512 or settlement.transition_binding_512 != transition.binding_digest_512:
                raise Wave5RollupError("atomic_rollup_settlement_binding_mismatch")
            if settlement.finality is not FinalityLevel.FINALIZED:
                raise Wave5RollupError("atomic_rollup_settlement_not_finalized")
            if proof.before_state_digest_512 != transition.before.digest_512 or proof.after_state_digest_512 != transition.after.digest_512:
                raise Wave5RollupError("atomic_rollup_state_digest_mismatch")
            self._attempts.add(transition.attempt_id)
            self._batch_nonces.add(transition.batch_nonce)
            self._state = transition.after
            self._history.append(self._state.digest_512)
            return self._state


@dataclass(frozen=True, slots=True)
class DepositReceipt:
    deposit_id_512: bytes
    value_commitment_512: bytes
    recipient_commitment_512: bytes
    finalized_l1_block_hash_512: bytes
    fork_id_512: bytes
    accounting_digest_512: bytes

    def __post_init__(self) -> None:
        for label, value in (
            ("deposit_id", self.deposit_id_512),
            ("deposit_value_commitment", self.value_commitment_512),
            ("deposit_recipient_commitment", self.recipient_commitment_512),
            ("deposit_l1_block", self.finalized_l1_block_hash_512),
            ("deposit_fork", self.fork_id_512),
            ("deposit_accounting", self.accounting_digest_512),
        ):
            _bytes(label, value, 64, nonzero=True)


@dataclass(frozen=True, slots=True)
class WithdrawalRequest:
    withdrawal_id_512: bytes
    deposit_id_512: bytes
    value_commitment_512: bytes
    recipient_commitment_512: bytes
    settlement_receipt_digest_512: bytes
    ready_slot: int
    replay_domain_512: bytes

    def __post_init__(self) -> None:
        for label, value in (
            ("withdrawal_id", self.withdrawal_id_512),
            ("withdrawal_deposit_id", self.deposit_id_512),
            ("withdrawal_value_commitment", self.value_commitment_512),
            ("withdrawal_recipient_commitment", self.recipient_commitment_512),
            ("withdrawal_settlement_receipt", self.settlement_receipt_digest_512),
            ("withdrawal_replay_domain", self.replay_domain_512),
        ):
            _bytes(label, value, 64, nonzero=True)
        _u64("withdrawal_ready_slot", self.ready_slot)


@dataclass(frozen=True, slots=True)
class FinalizedWithdrawal:
    request: WithdrawalRequest
    finalized_l1_block_hash_512: bytes
    accounting_digest_512: bytes

    def __post_init__(self) -> None:
        if type(self.request) is not WithdrawalRequest:
            raise Wave5RollupError("finalized_withdrawal_request_invalid")
        _bytes("finalized_withdrawal_block", self.finalized_l1_block_hash_512, 64, nonzero=True)
        _bytes("finalized_withdrawal_accounting", self.accounting_digest_512, 64, nonzero=True)


class BridgeEscrow:
    def __init__(self, *, manifest: EthereumCompatManifest, tracker: FinalityTracker, withdrawal_delay_slots: int = 2) -> None:
        self.manifest = manifest
        self.tracker = tracker
        _u64("bridge_withdrawal_delay", withdrawal_delay_slots, nonzero=True, maximum=MAX_QUEUE_SLOTS)
        self.withdrawal_delay_slots = withdrawal_delay_slots
        self._deposits: dict[bytes, DepositReceipt] = {}
        self._requests: dict[bytes, WithdrawalRequest] = {}
        self._finalized: dict[bytes, FinalizedWithdrawal] = {}

    def _accounting_digest(self) -> bytes:
        return _digest(
            b"BRIDGE-ACCOUNTING/V1",
            b"".join(
                item.deposit_id_512 + item.value_commitment_512 + item.recipient_commitment_512
                for item in sorted(self._deposits.values(), key=lambda value: value.deposit_id_512)
            ),
            b"".join(
                item.request.withdrawal_id_512 + item.request.value_commitment_512
                for item in sorted(self._finalized.values(), key=lambda value: value.request.withdrawal_id_512)
            ),
        )

    def deposit(
        self,
        *,
        value_commitment_512: bytes,
        recipient_commitment_512: bytes,
        block: L1Block,
    ) -> DepositReceipt:
        if block.fork_id_512 != self.manifest.baseline.fork_id_512 or not self.tracker.is_finalized(block.block_hash_512):
            raise Wave5RollupError("bridge_deposit_requires_finalized_l1")
        value = _bytes("bridge_deposit_value_commitment", value_commitment_512, 64, nonzero=True)
        recipient = _bytes("bridge_deposit_recipient_commitment", recipient_commitment_512, 64, nonzero=True)
        deposit_id = _digest(b"BRIDGE-DEPOSIT-ID/V1", block.block_hash_512, value, recipient)
        if deposit_id in self._deposits:
            raise Wave5RollupError("bridge_deposit_replay")
        provisional = DepositReceipt(
            deposit_id,
            value,
            recipient,
            block.block_hash_512,
            block.fork_id_512,
            _digest(b"BRIDGE-PENDING-ACCOUNTING/V1", deposit_id),
        )
        self._deposits[deposit_id] = provisional
        receipt = DepositReceipt(
            provisional.deposit_id_512,
            provisional.value_commitment_512,
            provisional.recipient_commitment_512,
            provisional.finalized_l1_block_hash_512,
            provisional.fork_id_512,
            self._accounting_digest(),
        )
        self._deposits[deposit_id] = receipt
        return receipt

    def request_withdrawal(
        self,
        *,
        deposit_id_512: bytes,
        settlement: SettlementReceipt,
        recipient_commitment_512: bytes,
        current_slot: int,
    ) -> WithdrawalRequest:
        deposit_id = _bytes("bridge_withdrawal_deposit_id", deposit_id_512, 64, nonzero=True)
        deposit = self._deposits.get(deposit_id)
        if deposit is None:
            raise Wave5RollupError("bridge_withdrawal_deposit_unknown")
        if type(settlement) is not SettlementReceipt or settlement.finality is not FinalityLevel.FINALIZED:
            raise Wave5RollupError("bridge_withdrawal_settlement_not_finalized")
        _u64("bridge_withdrawal_current_slot", current_slot)
        recipient = _bytes("bridge_withdrawal_recipient", recipient_commitment_512, 64, nonzero=True)
        if recipient != deposit.recipient_commitment_512:
            raise Wave5RollupError("bridge_withdrawal_recipient_mismatch")
        request_id = _digest(b"BRIDGE-WITHDRAWAL-ID/V1", deposit_id, settlement.proof_digest_512, recipient)
        if request_id in self._requests:
            raise Wave5RollupError("bridge_withdrawal_replay")
        request = WithdrawalRequest(
            request_id,
            deposit_id,
            deposit.value_commitment_512,
            recipient,
            _digest(b"BRIDGE-SETTLEMENT-RECEIPT/V1", settlement.proof_digest_512, settlement.l1_block_hash_512),
            current_slot + self.withdrawal_delay_slots,
            _digest(b"BRIDGE-REPLAY-DOMAIN/V1", self.manifest.manifest_digest_512, deposit_id),
        )
        self._requests[request_id] = request
        return request

    def finalize_withdrawal(self, request: WithdrawalRequest, *, block: L1Block) -> FinalizedWithdrawal:
        if type(request) is not WithdrawalRequest or request.withdrawal_id_512 not in self._requests:
            raise Wave5RollupError("bridge_withdrawal_request_unknown")
        if block.fork_id_512 != self.manifest.baseline.fork_id_512 or not self.tracker.is_finalized(block.block_hash_512):
            raise Wave5RollupError("bridge_withdrawal_requires_finalized_l1")
        if block.slot < request.ready_slot:
            raise Wave5RollupError("bridge_withdrawal_delay_incomplete")
        if request.withdrawal_id_512 in self._finalized:
            raise Wave5RollupError("bridge_withdrawal_already_finalized")
        deposit = self._deposits[request.deposit_id_512]
        if request.value_commitment_512 != deposit.value_commitment_512:
            raise Wave5RollupError("bridge_value_conservation_mismatch")
        provisional = FinalizedWithdrawal(
            request,
            block.block_hash_512,
            _digest(b"BRIDGE-PENDING-ACCOUNTING/V1", request.withdrawal_id_512),
        )
        self._finalized[request.withdrawal_id_512] = provisional
        receipt = FinalizedWithdrawal(request, block.block_hash_512, self._accounting_digest())
        self._finalized[request.withdrawal_id_512] = receipt
        return receipt

    @property
    def accounting_digest_512(self) -> bytes:
        return self._accounting_digest()


class ForkAdapterController:
    def __init__(self, manifest: EthereumCompatManifest, governance: PqGovernance, *, timelock_slots: int = 2) -> None:
        self.manifest = manifest
        self.governance = governance
        _u64("fork_controller_timelock", timelock_slots, nonzero=True, maximum=MAX_QUEUE_SLOTS)
        self.timelock_slots = timelock_slots
        self.active = manifest.baseline
        self.paused = False
        self._pending: tuple[EthereumForkProfile, GovernanceApproval, int] | None = None
        self._history: list[bytes] = [self.active.fork_id_512]

    def request_activation(self, profile: EthereumForkProfile, approval: GovernanceApproval, *, current_slot: int) -> None:
        if profile != self.manifest.future_shadow:
            raise Wave5RollupError("fork_activation_profile_not_manifest_bound")
        self.governance.verify(approval)
        if approval.manifest_digest_512 != self.manifest.manifest_digest_512:
            raise Wave5RollupError("fork_activation_manifest_mismatch")
        _u64("fork_activation_current_slot", current_slot)
        if profile.enabled_eips:
            raise Wave5RollupError("fork_activation_unshipped_features")
        self._pending = (profile, approval, current_slot + self.timelock_slots)

    def activate(self, *, current_slot: int, finality: FinalityLevel) -> EthereumForkProfile:
        if self._pending is None:
            raise Wave5RollupError("fork_activation_not_pending")
        profile, _approval, ready_slot = self._pending
        _u64("fork_activation_slot", current_slot)
        if current_slot < ready_slot:
            raise Wave5RollupError("fork_activation_timelock_incomplete")
        if finality is not FinalityLevel.FINALIZED:
            raise Wave5RollupError("fork_activation_requires_finality")
        self.active = profile
        self._history.append(profile.fork_id_512)
        self._pending = None
        self.paused = False
        return self.active

    def observe_fork(self, fork_id_512: bytes) -> None:
        _bytes("fork_observed_id", fork_id_512, 64, nonzero=True)
        if fork_id_512 != self.active.fork_id_512:
            self.paused = True

    def emergency_rollback(
        self,
        *,
        target: EthereumForkProfile,
        approval: GovernanceApproval,
        current_slot: int,
        finality: FinalityLevel,
    ) -> EthereumForkProfile:
        self.governance.verify(approval)
        _u64("fork_rollback_slot", current_slot)
        if not self.paused:
            raise Wave5RollupError("fork_rollback_requires_pause")
        if finality is not FinalityLevel.FINALIZED:
            raise Wave5RollupError("fork_rollback_requires_finalized_anchor")
        if approval.manifest_digest_512 != self.manifest.manifest_digest_512 or target != self.manifest.baseline:
            raise Wave5RollupError("fork_rollback_target_not_governed")
        if self.active != self.manifest.future_shadow:
            raise Wave5RollupError("fork_rollback_not_previous_profile")
        self.active = target
        self._history.append(target.fork_id_512)
        self.paused = False
        return target

    @property
    def history(self) -> tuple[bytes, ...]:
        return tuple(self._history)


@dataclass(frozen=True, slots=True)
class Wave5ConformanceReceipt:
    package_status: Mapping[str, str]
    manifest_digest_sha3_512: str
    deployment_digest_sha3_512: str
    claim_proof_digest_sha3_512: str
    l2_proof_digest_sha3_512: str
    finalized_l1_block_sha3_512: str
    bridge_accounting_digest_sha3_512: str
    da_bundle_digest_sha3_512: str
    rollback_ok: bool
    network_access: bool = False
    live_credentials: bool = False
    production_usable: bool = False
    activation_allowed: bool = False
    proofSuiteId: None = None

    def __post_init__(self) -> None:
        if dict(self.package_status) != {key: "complete_internal_nonactivating" for key in sorted(WAVE5_PACKAGE_IDS)}:
            raise Wave5RollupError("wave5_package_status_invalid")
        for label, value in (
            ("wave5_receipt_manifest", self.manifest_digest_sha3_512),
            ("wave5_receipt_deployment", self.deployment_digest_sha3_512),
            ("wave5_receipt_claim", self.claim_proof_digest_sha3_512),
            ("wave5_receipt_l2", self.l2_proof_digest_sha3_512),
            ("wave5_receipt_l1", self.finalized_l1_block_sha3_512),
            ("wave5_receipt_bridge", self.bridge_accounting_digest_sha3_512),
            ("wave5_receipt_da", self.da_bundle_digest_sha3_512),
        ):
            if not isinstance(value, str) or len(value) != 128 or any(char not in "0123456789abcdef" for char in value):
                raise Wave5RollupError(f"{label}_invalid")
        if self.rollback_ok is not True or self.network_access is not False or self.live_credentials is not False:
            raise Wave5RollupError("wave5_receipt_safety_flags_invalid")
        if self.production_usable is not False or self.activation_allowed is not False or self.proofSuiteId is not None:
            raise Wave5RollupError("wave5_receipt_must_remain_nonactivating")

    def as_dict(self) -> dict[str, object]:
        return {
            "schema": WAVE5_SCHEMA,
            "wave": 5,
            "package_status": dict(sorted(self.package_status.items())),
            "manifest_digest_sha3_512": self.manifest_digest_sha3_512,
            "deployment_digest_sha3_512": self.deployment_digest_sha3_512,
            "claim_proof_digest_sha3_512": self.claim_proof_digest_sha3_512,
            "l2_proof_digest_sha3_512": self.l2_proof_digest_sha3_512,
            "finalized_l1_block_sha3_512": self.finalized_l1_block_sha3_512,
            "bridge_accounting_digest_sha3_512": self.bridge_accounting_digest_sha3_512,
            "da_bundle_digest_sha3_512": self.da_bundle_digest_sha3_512,
            "rollback_ok": self.rollback_ok,
            "network_access": self.network_access,
            "live_credentials": self.live_credentials,
            "production_usable": self.production_usable,
            "activation_allowed": self.activation_allowed,
            "proofSuiteId": self.proofSuiteId,
        }


def run_wave5_conformance(governance: PqGovernance) -> Wave5ConformanceReceipt:
    """Run all twelve R-package obligations against the local synthetic baseline."""

    manifest = build_ethereum_compat_manifest()
    deployment = LocalDeployment.build(manifest)
    identity = make_synthetic_identity()
    initial = RollupState.genesis(manifest, identity)

    orderer = BasedOrderer(manifest)
    sender = _digest(b"SENDER", b"SYNTHETIC")
    tx = OpaqueTransaction(sender, 0, _digest(b"OPAQUE-PAYLOAD", b"TX-1"), "ATTEMPT-0001")
    forced_tx = OpaqueTransaction(sender, 1, _digest(b"OPAQUE-PAYLOAD", b"FORCED-1"), "ATTEMPT-0002", "FORCED")
    orderer.submit(tx)
    orderer.submit(forced_tx)
    forced_queue = ForcedInclusionQueue()
    forced_entry = forced_queue.submit(forced_tx, current_slot=1, deadline_slots=1)
    inclusion = InclusionList(
        1,
        _digest(b"INCLUSION-VIEW", b"VIEW-1"),
        tuple(sorted((tx.tx_hash_512, forced_tx.tx_hash_512))),
        _digest(b"INCLUSION-COMMITTEE", b"COMMITTEE-1"),
    )
    ordered = orderer.order(slot=1, inclusion_list=inclusion, forced_entries=(forced_entry,))
    BasedOrderer.validate_payload(batch=ordered, inclusion_list=inclusion, execution_validated=True)
    forced_queue.consume((forced_tx.tx_hash_512,))

    da_store = DataAvailabilityStore()
    da = build_da_bundle(
        (tx.tx_hash_512, forced_tx.tx_hash_512, ordered.batch_commitment_512),
        mode="CELL_COMMITMENT",
        retention_until_slot=32,
    )
    da_digest = da_store.publish(da)
    da_store.reconstruct(da_digest, da.cells, current_slot=1)
    migrated_da = da_store.migrate(da_digest, target_mode="BLOB_COMMITMENT", current_slot=1)
    if migrated_da.payload_commitment_512 != da.payload_commitment_512:
        raise Wave5RollupError("wave5_da_migration_payload_changed")

    sidecar_before = initial.nullifier_root_512
    sidecar_after = _digest(b"NULLIFIER-SUCCESSOR/V1", sidecar_before, tx.tx_hash_512, forced_tx.tx_hash_512)
    payment_after = _digest(b"PAYMENT-SUCCESSOR/V1", initial.payment_state_root_512, ordered.batch_commitment_512)
    governance_commitment = manifest.manifest_digest_512
    public_fields = (
        (2).to_bytes(32, "big"),
        _field_alias(identity.settlement_domain_id_512),
        _field_alias(_digest(b"BATCH-NONCE", b"0")),
        _field_alias(sidecar_before),
        _field_alias(sidecar_after),
        _field_alias(_digest(b"CLAIM-SOURCE", b"SYNTHETIC")),
        _field_alias(_digest(b"ORACLE-FACTS", b"SYNTHETIC")),
        _field_alias(_digest(b"POLICY", b"SYNTHETIC")),
        _field_alias(_digest(b"RULESET", b"SYNTHETIC")),
        _field_alias(ordered.batch_commitment_512),
        _field_alias(_digest(b"VALUE-CONSERVATION", ordered.batch_commitment_512)),
        _field_alias(_digest(b"SETTLEMENT", ordered.batch_commitment_512)),
    )
    if tuple(WAVE5_PUBLIC_FIELD_NAMES) != tuple(PUBLIC_INPUT_FIELD_NAMES_V2):
        raise Wave5RollupError("wave5_public_abi_drift")
    sidecar = CandidateSidecarV1(
        identity.profile_id_512,
        identity.candidate_suite_id_512,
        identity.schema_id_512,
        identity.verifier_artifact_identity_512,
        identity.settlement_domain_id_512,
        identity.epoch,
        initial.sequence,
        initial.sequence + 1,
        sidecar_before,
        sidecar_after,
        governance_commitment,
        initial.payment_state_root_512,
        payment_after,
        _digest(b"BATCH-COMMITMENT", ordered.batch_commitment_512, da_digest),
    )
    context = RollupClaimContext(
        manifest.baseline.fork_id_512,
        manifest.l1_chain_id,
        manifest.l2_chain_id,
        initial.digest_512,
        da_digest,
        identity.verifier_artifact_identity_512,
        identity.schema_id_512,
        identity.candidate_suite_id_512,
        identity.settlement_domain_id_512,
    )
    envelope = build_reference_claim_envelope(sidecar=sidecar, public_fields=public_fields, context=context)
    claim_receipt = SyntheticReferenceClaimVerifier().verify(envelope=envelope, context=context, identity=identity)
    transition = build_rollup_transition(
        before=initial,
        envelope=envelope,
        claim_receipt=claim_receipt,
        fork_id_512=manifest.baseline.fork_id_512,
        ordered_batch_commitment_512=ordered.batch_commitment_512,
        da_commitment_512=da_digest,
        bal_commitment_512=_digest(b"PUBLIC-BAL", ordered.batch_commitment_512),
        cbam_commitment_512=_digest(b"PRIVATE-CBAM-COMMITMENT", ordered.batch_commitment_512),
        attempt_id=tx.attempt_id,
        batch_nonce=0,
    )
    prover = L2StateTransitionProver(manifest)
    vectors = prover.differential(transition)
    proof = prover.prove(transition)
    governance_approval = governance.approve(manifest.manifest_digest_512, proof.verifier_artifact_identity_512)
    tracker = FinalityTracker(manifest)
    tracker.observe(deployment.genesis)
    head = deployment.mine_block(
        slot=2,
        payload_digest_512=ordered.batch_commitment_512,
        da_commitment_512=da_digest,
        state_root_512=proof.expected_l1_state_root_512,
        finality=FinalityLevel.HEAD,
    )
    tracker.observe(head)
    settlement_engine = SettlementEngine(manifest, tracker, governance)
    try:
        settlement_engine.settle(proof=proof, transition=transition, block=head, approval=governance_approval)
    except Wave5RollupError as exc:
        if str(exc) != "settlement_requires_l1_finality":
            raise
    finalized = L1Block(
        head.number,
        head.slot,
        head.parent_hash_512,
        head.fork_id_512,
        head.payload_digest_512,
        head.da_commitment_512,
        head.state_root_512,
        FinalityLevel.FINALIZED,
    )
    tracker.observe(finalized)
    settlement = settlement_engine.settle(proof=proof, transition=transition, block=finalized, approval=governance_approval)
    AtomicRollupState(initial).apply(transition=transition, proof=proof, settlement=settlement)

    bridge = BridgeEscrow(manifest=manifest, tracker=tracker)
    value_commitment = _digest(b"VALUE-COMMITMENT", b"SYNTHETIC-VALUE")
    recipient_commitment = _digest(b"RECIPIENT-COMMITMENT", b"SYNTHETIC-RECIPIENT")
    deposit = bridge.deposit(value_commitment_512=value_commitment, recipient_commitment_512=recipient_commitment, block=finalized)
    request = bridge.request_withdrawal(
        deposit_id_512=deposit.deposit_id_512,
        settlement=settlement,
        recipient_commitment_512=recipient_commitment,
        current_slot=2,
    )
    exit_block = deployment.mine_block(
        slot=request.ready_slot,
        payload_digest_512=_digest(b"EXIT-PAYLOAD", request.withdrawal_id_512),
        da_commitment_512=da_digest,
        state_root_512=proof.expected_l1_state_root_512,
        finality=FinalityLevel.FINALIZED,
    )
    tracker.observe(exit_block)
    bridge.finalize_withdrawal(request, block=exit_block)

    controller = ForkAdapterController(manifest, governance)
    future_approval = governance.approve(manifest.manifest_digest_512, identity.verifier_artifact_identity_512)
    controller.request_activation(manifest.future_shadow, future_approval, current_slot=exit_block.slot)
    try:
        controller.activate(current_slot=exit_block.slot, finality=FinalityLevel.FINALIZED)
    except Wave5RollupError as exc:
        if str(exc) != "fork_activation_timelock_incomplete":
            raise
    controller.activate(current_slot=exit_block.slot + 2, finality=FinalityLevel.FINALIZED)
    controller.observe_fork(_digest(b"UNKNOWN-FORK", b"NOT-SUPPORTED"))
    base_approval = governance.approve(manifest.manifest_digest_512, identity.verifier_artifact_identity_512)
    controller.emergency_rollback(
        target=manifest.baseline,
        approval=base_approval,
        current_slot=exit_block.slot + 3,
        finality=FinalityLevel.FINALIZED,
    )
    if controller.active != manifest.baseline or controller.paused:
        raise Wave5RollupError("wave5_rollback_not_recovered")

    return Wave5ConformanceReceipt(
        {key: "complete_internal_nonactivating" for key in sorted(WAVE5_PACKAGE_IDS)},
        manifest.manifest_digest_512.hex(),
        _digest(b"DEPLOYMENT-DIGEST", deployment.canonical_bytes()).hex(),
        claim_receipt.proof_digest_512.hex(),
        proof.proof_digest_512.hex(),
        finalized.block_hash_512.hex(),
        bridge.accounting_digest_512.hex(),
        da_digest.hex(),
        True,
    )


__all__ = (
    "AtomicRollupState",
    "BasedOrderer",
    "BridgeEscrow",
    "ClaimVerificationReceipt",
    "DataAvailabilityStore",
    "DataCell",
    "DABundle",
    "DAReconstruction",
    "DeploymentConfig",
    "EthereumCompatManifest",
    "EthereumFeature",
    "EthereumForkProfile",
    "FinalityLevel",
    "FinalityTracker",
    "ForkAdapterController",
    "ForcedInclusion",
    "ForcedInclusionQueue",
    "GovernanceApproval",
    "InclusionList",
    "L1Block",
    "L2ExecutionVector",
    "L2StateTransitionProver",
    "L2TransitionProof",
    "LocalDeployment",
    "OpaqueTransaction",
    "PqGovernance",
    "RecentRootAdapter",
    "RecentRootReference",
    "RollupClaimContext",
    "RollupClaimEnvelope",
    "RollupState",
    "RollupSuiteIdentity",
    "RollupTransition",
    "SettlementEngine",
    "SettlementReceipt",
    "SyntheticReferenceClaimVerifier",
    "WAVE5_ACTIVATION_ALLOWED",
    "WAVE5_PACKAGE_IDS",
    "WAVE5_PRODUCTION_USABLE",
    "WAVE5_PUBLIC_FIELD_NAMES",
    "WAVE5_SCHEMA",
    "Wave5ConformanceReceipt",
    "Wave5RollupError",
    "build_da_bundle",
    "build_ethereum_compat_manifest",
    "build_reference_claim_envelope",
    "build_rollup_transition",
    "make_synthetic_identity",
    "run_wave5_conformance",
)
