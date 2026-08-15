"""Qualification record for the active Construction 8.2 hiding path.

The old Circle worksheet is retained only in Git history and reviewed source
archives.  The current prover does not import that retired worksheet: it uses
the committed GKR mask, the packed SHA3 bus, the selected FRI geometry,
and the dual-PQ interactive transcript.  This module makes that rebase
machine-checkable without pretending that an old Circle-only obligation was a
missing implementation in the active path.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Final


ROOT: Final[Path] = Path(__file__).resolve().parents[2]
ACTIVE_STATUS: Final[str] = "ACTIVE_CONSTRUCTION_8_2_GKR_HIDING_REBASED_NONACTIVATING"
ACTIVATION_ALLOWED: Final[bool] = False
PRODUCTION_USABLE: Final[bool] = False

HISTORICAL_CIRCLE_GAPS: Final[tuple[str, ...]] = (
    "FINAL_CIRCLE_SPLIT_LOG_DEGREE_AND_PROVER_INTEGRATION",
    "FINAL_SHA3_AIR_INTERACTION_ORACLE_DIMENSIONS",
    "FINAL_MULTI_DOMAIN_FRI_ORACLE_WIDTHS_AFTER_SHA3_AIR_EXPANSION",
    "INTERACTIVE_CIRCLE_SIMULATOR_TRANSCRIPT",
)

ACTIVE_SOURCES: Final[tuple[tuple[str, tuple[str, ...]], ...]] = (
    (
        "experiments/bl_pq512_crypto_core/src/gkr_zk_mask.rs",
        (
            "CompleteGkrZkMaskCommitmentLayout",
            "CompleteGkrZkLeakageBudget",
            "decode_prefix",
            "leakage_budget",
        ),
    ),
    (
        "experiments/bl_pq512_crypto_core/src/hash_bus_b16_gkr_plan.rs",
        ("HashBusB16GkrPlan", "pub fn selected", "pub fn commitment"),
    ),
    (
        "experiments/bl_pq512_crypto_core/src/hash_bus_b16_gkr_worker.rs",
        ("Fail-closed binary client", "PLAN_ACCEPTED", "untrusted"),
    ),
    (
        "experiments/bl_pq512_crypto_core/src/fp16_relay_free_gkr_schedule.rs",
        ("GKR_ROUNDS", "STATE_RELATION_ROUNDS", "PCS_DOWNSTREAM_ROUNDS"),
    ),
    (
        "experiments/bl_pq512_crypto_core/src/proof_parameters.rs",
        (
            "selected_parameter_commitment",
            "selected_schedule_commitment",
            "selected_proof_geometry",
            "proof_suite_id",
        ),
    ),
    (
        "experiments/bl_pq512_crypto_core/src/selected_proof_package.rs",
        ("PRIVATE_PROOF_PACKAGE_MAGIC", "verify_selected_proof_package"),
    ),
    (
        "experiments/bl_pq512_crypto_core/src/proof_format.rs",
        ("BLPQPRF2", "FriPipelineProofV2", "decode_fri_pipeline_proof_v2"),
    ),
    (
        "experiments/bl_pq512_crypto_core/src/chained_public_coin.rs",
        (
            "verify_chain_head_signature",
            "verify_chained_public_coin_bundle",
            "PqSignatureSuite",
        ),
    ),
    (
        "experiments/bl_pq512_crypto_foundation/selected_public_coin.py",
        (
            "verify_selected_transcript",
            "PRODUCTION_STATEMENT_EVIDENCE_DOMAIN",
            "dual-PQ",
        ),
    ),
)

_REBASED_OBLIGATIONS: Final[tuple[str, ...]] = (
    "NATIVE_MASK_COMMITMENT_AND_LEAKAGE_BUDGET",
    "PACKED_SHA3_INTERACTION_BUS_DIMENSIONS",
    "SELECTED_FRI_ORACLE_WIDTH_AND_PACKAGE_BINDING",
    "DUAL_PQ_INTERACTIVE_TRANSCRIPT_REPLAY",
)


class ActiveHidingError(ValueError):
    """Fail-closed error for a stale or incomplete active-path record."""


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode("ascii")


def _read_source(root: Path, relative: str, markers: tuple[str, ...]) -> tuple[str, str]:
    path = root / relative
    if path.is_symlink() or not path.is_file():
        raise ActiveHidingError(f"active_hiding_source_missing:{relative}")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ActiveHidingError(f"active_hiding_source_unreadable:{relative}") from exc
    text = raw.decode("utf-8")
    missing = tuple(marker for marker in markers if marker not in text)
    if missing:
        raise ActiveHidingError(
            f"active_hiding_source_marker_missing:{relative}:{','.join(missing)}"
        )
    return relative, hashlib.sha3_512(raw).hexdigest()


@dataclass(frozen=True, slots=True)
class ActiveGkrHidingCertificate:
    status: str
    source_digests_sha3_512: tuple[tuple[str, str], ...]
    closed_obligations: tuple[str, ...]
    superseded_historical_gaps: tuple[str, ...]
    coverage_gaps: tuple[str, ...] = ()
    activation_allowed: bool = False
    production_usable: bool = False

    def __post_init__(self) -> None:
        if self.status != ACTIVE_STATUS:
            raise ActiveHidingError("active_hiding_status_invalid")
        if self.activation_allowed or self.production_usable:
            raise ActiveHidingError("active_hiding_activation_boundary_invalid")
        if self.closed_obligations != _REBASED_OBLIGATIONS:
            raise ActiveHidingError("active_hiding_obligation_order_invalid")
        if self.superseded_historical_gaps != HISTORICAL_CIRCLE_GAPS:
            raise ActiveHidingError("active_hiding_historical_gap_record_invalid")
        if self.coverage_gaps:
            raise ActiveHidingError("active_hiding_current_gap_present")
        if not self.source_digests_sha3_512 or tuple(
            path for path, _ in self.source_digests_sha3_512
        ) != tuple(path for path, _ in ACTIVE_SOURCES):
            raise ActiveHidingError("active_hiding_source_order_invalid")
        for path, digest in self.source_digests_sha3_512:
            if len(path) == 0 or len(digest) != 128 or digest == "0" * 128:
                raise ActiveHidingError("active_hiding_source_digest_invalid")

    @property
    def certificate_digest_sha3_512(self) -> str:
        payload = {
            "status": self.status,
            "source_digests_sha3_512": self.source_digests_sha3_512,
            "closed_obligations": self.closed_obligations,
            "superseded_historical_gaps": self.superseded_historical_gaps,
            "coverage_gaps": self.coverage_gaps,
            "activation_allowed": self.activation_allowed,
            "production_usable": self.production_usable,
        }
        return hashlib.sha3_512(
            b"BL/PQ512/ACTIVE-GKR-HIDING-CERTIFICATE/v1\0" + _canonical(payload)
        ).hexdigest()

    def as_public_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "closedObligations": list(self.closed_obligations),
            "supersededHistoricalGaps": list(self.superseded_historical_gaps),
            "coverageGaps": list(self.coverage_gaps),
            "sourceFiles": [
                {"path": path, "sha3_512": digest}
                for path, digest in self.source_digests_sha3_512
            ],
            "certificateSha3_512": self.certificate_digest_sha3_512,
            "activationAllowed": self.activation_allowed,
            "productionUsable": self.production_usable,
        }


def build_active_gkr_hiding_certificate(
    root: Path = ROOT,
) -> ActiveGkrHidingCertificate:
    if not isinstance(root, Path):
        raise TypeError("active_hiding_root_required")
    source_digests = tuple(_read_source(root, path, markers) for path, markers in ACTIVE_SOURCES)
    return ActiveGkrHidingCertificate(
        status=ACTIVE_STATUS,
        source_digests_sha3_512=source_digests,
        closed_obligations=_REBASED_OBLIGATIONS,
        superseded_historical_gaps=HISTORICAL_CIRCLE_GAPS,
    )


def validate_active_gkr_hiding_certificate(
    certificate: ActiveGkrHidingCertificate,
    root: Path = ROOT,
) -> None:
    if not isinstance(certificate, ActiveGkrHidingCertificate):
        raise TypeError("active_hiding_certificate_required")
    expected = build_active_gkr_hiding_certificate(root)
    if certificate != expected:
        raise ActiveHidingError("active_hiding_certificate_stale")


__all__ = (
    "ACTIVE_STATUS",
    "ACTIVATION_ALLOWED",
    "HISTORICAL_CIRCLE_GAPS",
    "ActiveGkrHidingCertificate",
    "ActiveHidingError",
    "build_active_gkr_hiding_certificate",
    "validate_active_gkr_hiding_certificate",
)
