"""Fail-closed H6 qualification preflight.

This module records the twelve H6 qualification obligations without claiming
that any of them are closed.  It independently replays the blocked H5
preflight, re-reads the candidate suite registry, and emits bounded public
identities plus explicit blockers.  It never launches a prover, accepts a
cached proof, selects a state or commitment backend, assigns ``proofSuiteId``,
or enables activation.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from hashlib import sha3_512
from pathlib import Path
from typing import Any, Final

from app.batch.pq_tree_reference import require_synthetic_reference_enabled
from experiments.bl_pq512_crypto_foundation.benchmark_evidence import (
    canonical_json_bytes,
)
from experiments.bl_pq512_crypto_foundation.gate_2e_terminal_ledger import (
    TerminalLedger,
    TerminalLedgerContext,
)
from experiments.bl_pq512_crypto_foundation.h5_qualification_preflight import (
    CAMPAIGN_NOT_STARTED,
    EXTERNAL_MONITOR_NOT_CONFIGURED,
    FRESH_LAUNCH_COUNT,
    H5Preflight,
    H5PreflightContext,
    MEASURED_REPETITIONS,
    PREFLIGHT_BLOCKED as H5_PREFLIGHT_BLOCKED,
    PROFILE_IDS,
    WARMUP_COUNT,
    independently_verify_h5_preflight,
)


ROOT: Final[Path] = Path(__file__).resolve().parents[2]
DEFAULT_SUITE_REGISTRY_PATH: Final[Path] = (
    ROOT / "docs" / "bl_pq512_suite_candidate_v1.json"
)

STATUS: Final[str] = "H6_QUALIFICATION_PREFLIGHT_V1_SYNTHETIC_REFERENCE_NONPRODUCTION"
PREFLIGHT_BLOCKED: Final[str] = "BLOCKED_H6_PREFLIGHT"
SUITE_REGISTRY_STATUS: Final[str] = "CANDIDATE_UNQUALIFIED"
MODULE_COUNT: Final[int] = 8

H6_OBLIGATION_IDS: Final[tuple[str, ...]] = (
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

REFERENCE_ONLY: Final[str] = "REFERENCE_ONLY"
OPEN: Final[str] = "OPEN"
BLOCKED: Final[str] = "BLOCKED"
CLOSED: Final[str] = "CLOSED"
EVIDENCE_STATUSES: Final[tuple[str, ...]] = (REFERENCE_ONLY, OPEN, BLOCKED, CLOSED)

OBSERVED: Final[str] = "OBSERVED"
DERIVED: Final[str] = "DERIVED"
INFERRED: Final[str] = "INFERRED"
UNKNOWN: Final[str] = "UNKNOWN"
EVIDENCE_CLASSES: Final[tuple[str, ...]] = (OBSERVED, DERIVED, INFERRED, UNKNOWN)

_PREFLIGHT_DOMAIN = b"BL/PQ512/H6/QUALIFICATION-PREFLIGHT/v1\x00"
_RECORD_DOMAIN = b"BL/PQ512/H6/QUALIFICATION-RECORD/v1\x00"
_EVIDENCE_DOMAIN = b"BL/PQ512/H6/EVIDENCE-IDENTITY/v1\x00"
_DIGEST_LENGTH = 64
_MAX_REGISTRY_BYTES = 256 * 1024


class H6PreflightError(ValueError):
    """Stable fail-closed error for malformed or contradictory H6 state."""


def _synthetic() -> None:
    require_synthetic_reference_enabled()


def _text(value: object, label: str, maximum: int = 192) -> bytes:
    if type(value) is not str or not value or len(value) > maximum:
        raise H6PreflightError(f"h6_preflight_{label}_invalid")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise H6PreflightError(f"h6_preflight_{label}_not_ascii") from exc
    if b"\x00" in encoded:
        raise H6PreflightError(f"h6_preflight_{label}_nul")
    return encoded


def _digest(value: object, label: str) -> bytes:
    if type(value) is not bytes or len(value) != _DIGEST_LENGTH or not any(value):
        raise H6PreflightError(f"h6_preflight_{label}_digest_invalid")
    return value


def _hash(domain: bytes, *parts: bytes) -> bytes:
    hasher = sha3_512(domain)
    for part in parts:
        if type(part) is not bytes or len(part) > 0xFFFFFFFF:
            raise H6PreflightError("h6_preflight_hash_part_invalid")
        hasher.update(len(part).to_bytes(4, "big"))
        hasher.update(part)
    return hasher.digest()


def _encode_strings(values: tuple[str, ...], label: str) -> bytes:
    encoded: list[bytes] = []
    for value in values:
        item = _text(value, label)
        encoded.append(len(item).to_bytes(4, "big") + item)
    return b"".join(encoded)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise H6PreflightError("h6_preflight_suite_duplicate_key")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    raise H6PreflightError(f"h6_preflight_suite_nonfinite:{value}")


@dataclass(frozen=True, slots=True)
class _SuiteRegistryFacts:
    raw_digest_512: bytes
    canonical_digest_512: bytes
    status: str
    module_count: int
    proof_suite_id: None
    activation_allowed: bool


def _read_suite_registry(path: Path) -> _SuiteRegistryFacts:
    if not isinstance(path, Path):
        raise TypeError("h6_preflight_suite_registry_path_required")
    if path.is_symlink() or not path.is_file():
        raise H6PreflightError("h6_preflight_suite_registry_missing")
    try:
        size = path.stat().st_size
        raw = path.read_bytes()
    except OSError as exc:
        raise H6PreflightError("h6_preflight_suite_registry_read_failed") from exc
    if size != len(raw) or size < 3 or size > _MAX_REGISTRY_BYTES:
        raise H6PreflightError("h6_preflight_suite_registry_size_invalid")
    try:
        registry = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except H6PreflightError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise H6PreflightError("h6_preflight_suite_registry_json_invalid") from exc
    if type(registry) is not dict:
        raise H6PreflightError("h6_preflight_suite_registry_object_required")

    if registry.get("registryVersion") != 1:
        raise H6PreflightError("h6_preflight_suite_registry_version_invalid")
    if registry.get("status") != SUITE_REGISTRY_STATUS:
        raise H6PreflightError("h6_preflight_suite_registry_status_invalid")
    if registry.get("proofSuiteId") is not None:
        raise H6PreflightError("h6_preflight_suite_registry_suite_must_be_null")
    if registry.get("activationAllowed") is not False:
        raise H6PreflightError("h6_preflight_suite_registry_activation_invalid")
    if registry.get("syntheticOnly") is not True:
        raise H6PreflightError("h6_preflight_suite_registry_synthetic_only_required")

    external_abi = registry.get("externalAbi")
    if type(external_abi) is not dict:
        raise H6PreflightError("h6_preflight_suite_external_abi_invalid")
    if (
        external_abi.get("fieldCount") != 12
        or external_abi.get("fieldWidthBytes") != 32
        or external_abi.get("changeAllowed") is not False
    ):
        raise H6PreflightError("h6_preflight_suite_external_abi_boundary_invalid")

    current_disposition = registry.get("currentSuiteDisposition")
    if (
        type(current_disposition) is not dict
        or current_disposition.get("disposition") != "REJECTED"
    ):
        raise H6PreflightError("h6_preflight_current_suite_disposition_invalid")

    transcript = registry.get("candidateTranscript")
    if type(transcript) is not dict:
        raise H6PreflightError("h6_preflight_candidate_transcript_invalid")
    if (
        transcript.get("fiatShamirAllowed") is not False
        or transcript.get("qromReductionRequired") is not False
        or transcript.get("grindingCreditBits") != 0
    ):
        raise H6PreflightError("h6_preflight_candidate_transcript_boundary_invalid")

    candidate_fri = registry.get("candidateFri")
    if type(candidate_fri) is not dict or candidate_fri.get("status") != "UNSELECTED":
        raise H6PreflightError("h6_preflight_candidate_fri_status_invalid")
    for key in (
        "codeRate",
        "distanceParameter",
        "foldSchedule",
        "queryCount",
        "queryReplacementPolicy",
        "listBound",
    ):
        if candidate_fri.get(key) is not None:
            raise H6PreflightError("h6_preflight_candidate_fri_parameter_must_be_null")

    transport = registry.get("transport")
    if type(transport) is not dict:
        raise H6PreflightError("h6_preflight_transport_invalid")
    if (
        transport.get("proofLength") is not None
        or transport.get("proofSections") is not None
        or transport.get("trailingBytesAllowed") is not False
        or transport.get("parseBeforeAllocate") is not True
    ):
        raise H6PreflightError("h6_preflight_transport_boundary_invalid")

    modules = registry.get("modules")
    if type(modules) is not list or len(modules) != MODULE_COUNT:
        raise H6PreflightError("h6_preflight_module_count_invalid")
    expected_kinds = {
        "ENCODING_FRAMING",
        "APPLICATION_SHA3_STATE",
        "CHALLENGE_FIELD_ALGEBRA",
        "PCS_CIRCLE_FRI",
        "PUBLIC_COIN_INTERACTIVE_TRANSCRIPT",
        "NATIVE_WITNESS_HIDING",
        "SECURITY_BUDGET",
        "PROOF_BODY_FORMAT",
    }
    actual_kinds: set[str] = set()
    for module in modules:
        if type(module) is not dict:
            raise H6PreflightError("h6_preflight_module_object_invalid")
        kind = module.get("kind")
        if type(kind) is not str or kind in actual_kinds or kind not in expected_kinds:
            raise H6PreflightError("h6_preflight_module_kind_invalid")
        if module.get("moduleId") is not None:
            raise H6PreflightError("h6_preflight_module_id_must_be_null")
        actual_kinds.add(kind)
    if actual_kinds != expected_kinds:
        raise H6PreflightError("h6_preflight_module_set_invalid")

    blocked_by = registry.get("blockedBy")
    if (
        type(blocked_by) is not list
        or not blocked_by
        or any(type(item) is not str or not item for item in blocked_by)
        or len(blocked_by) != len(set(blocked_by))
    ):
        raise H6PreflightError("h6_preflight_suite_blocker_inventory_invalid")

    return _SuiteRegistryFacts(
        raw_digest_512=sha3_512(raw).digest(),
        canonical_digest_512=sha3_512(canonical_json_bytes(registry)).digest(),
        status=registry["status"],
        module_count=len(modules),
        proof_suite_id=registry["proofSuiteId"],
        activation_allowed=registry["activationAllowed"],
    )


@dataclass(frozen=True, slots=True)
class H6EvidenceRecord:
    """One H6 obligation with explicit, nonqualifying evidence strength."""

    obligation_id: str
    status: str
    evidence_class: str
    source_id: str
    evidence_identity_512: bytes
    blockers: tuple[str, ...]
    record_digest_512: bytes = b""

    def __post_init__(self) -> None:
        _synthetic()
        _text(self.obligation_id, "obligation_id", 64)
        if self.obligation_id not in H6_OBLIGATION_IDS:
            raise H6PreflightError("h6_preflight_unknown_obligation")
        if self.status not in EVIDENCE_STATUSES:
            raise H6PreflightError("h6_preflight_evidence_status_invalid")
        if self.status == CLOSED:
            raise H6PreflightError("h6_preflight_closed_record_forbidden")
        if self.evidence_class not in EVIDENCE_CLASSES:
            raise H6PreflightError("h6_preflight_evidence_class_invalid")
        _text(self.source_id, "source_id")
        _digest(self.evidence_identity_512, "evidence_identity")
        if type(self.blockers) is not tuple or not self.blockers:
            raise H6PreflightError("h6_preflight_record_blockers_required")
        if len(self.blockers) != len(set(self.blockers)):
            raise H6PreflightError("h6_preflight_record_blockers_duplicate")
        for blocker in self.blockers:
            _text(blocker, "blocker", 128)

        expected = _hash(
            _RECORD_DOMAIN,
            _text(self.obligation_id, "obligation_id", 64),
            _text(self.status, "evidence_status"),
            _text(self.evidence_class, "evidence_class"),
            _text(self.source_id, "source_id"),
            _digest(self.evidence_identity_512, "evidence_identity"),
            _encode_strings(self.blockers, "blocker"),
        )
        if self.record_digest_512 not in (b"", expected):
            raise H6PreflightError("h6_preflight_record_digest_mismatch")
        object.__setattr__(self, "record_digest_512", expected)

    @property
    def canonical_bytes(self) -> bytes:
        return b"".join(
            (
                _text(self.obligation_id, "obligation_id", 64),
                _text(self.status, "evidence_status"),
                _text(self.evidence_class, "evidence_class"),
                _text(self.source_id, "source_id"),
                _digest(self.evidence_identity_512, "evidence_identity"),
                _encode_strings(self.blockers, "blocker"),
                self.record_digest_512,
            )
        )

    def as_public_dict(self) -> dict[str, object]:
        return {
            "obligation_id": self.obligation_id,
            "status": self.status,
            "evidence_class": self.evidence_class,
            "source_id": self.source_id,
            "blockers": self.blockers,
            "evidence_identity_sha3_512_hex": self.evidence_identity_512.hex(),
            "record_digest_sha3_512_hex": self.record_digest_512.hex(),
        }


@dataclass(frozen=True, slots=True)
class H6PreflightContext:
    """Private inputs used for independent H6 preflight verification."""

    h5_preflight: H5Preflight
    h5_context: H5PreflightContext
    suite_registry_path: Path = DEFAULT_SUITE_REGISTRY_PATH

    def __post_init__(self) -> None:
        _synthetic()
        if type(self.h5_preflight) is not H5Preflight:
            raise H6PreflightError("h6_preflight_h5_type_invalid")
        if type(self.h5_context) is not H5PreflightContext:
            raise H6PreflightError("h6_preflight_h5_context_type_invalid")
        if not isinstance(self.suite_registry_path, Path):
            raise H6PreflightError("h6_preflight_suite_registry_path_required")


@dataclass(frozen=True, slots=True)
class H6Preflight:
    """Public, blocked H6 record; no obligation may be marked closed."""

    h5_preflight_digest_512: bytes
    suite_registry_digest_512: bytes
    suite_registry_canonical_digest_512: bytes
    suite_registry_status: str
    suite_registry_module_count: int
    h5_profile_ids: tuple[str, ...]
    h5_warmup_count: int
    h5_measured_repetitions: int
    h5_fresh_launch_count: int
    h5_campaign_status: str
    h5_external_monitor_status: str
    records: tuple[H6EvidenceRecord, ...]
    blockers: tuple[str, ...]
    source_git_clean: bool
    protected_paths_clean: bool
    suite_registry_proof_suite_id: None = None
    suite_registry_activation_allowed: bool = False
    status: str = PREFLIGHT_BLOCKED
    proof_suite_id: None = None
    activation_allowed: bool = False
    preflight_digest_512: bytes = b""

    def __post_init__(self) -> None:
        _synthetic()
        _digest(self.h5_preflight_digest_512, "h5_preflight")
        _digest(self.suite_registry_digest_512, "suite_registry")
        _digest(self.suite_registry_canonical_digest_512, "suite_registry_canonical")
        if self.suite_registry_status != SUITE_REGISTRY_STATUS:
            raise H6PreflightError("h6_preflight_suite_status_invalid")
        if (
            type(self.suite_registry_module_count) is not int
            or self.suite_registry_module_count != MODULE_COUNT
        ):
            raise H6PreflightError("h6_preflight_suite_module_count_invalid")
        if self.suite_registry_proof_suite_id is not None:
            raise H6PreflightError("h6_preflight_suite_id_must_remain_null")
        if self.suite_registry_activation_allowed is not False:
            raise H6PreflightError("h6_preflight_suite_activation_must_remain_false")
        if self.status != PREFLIGHT_BLOCKED:
            raise H6PreflightError("h6_preflight_status_must_remain_blocked")
        if self.h5_profile_ids != PROFILE_IDS:
            raise H6PreflightError("h6_preflight_h5_profile_shape_invalid")
        if (
            type(self.h5_warmup_count) is not int
            or self.h5_warmup_count != WARMUP_COUNT
            or type(self.h5_measured_repetitions) is not int
            or self.h5_measured_repetitions != MEASURED_REPETITIONS
            or type(self.h5_fresh_launch_count) is not int
            or self.h5_fresh_launch_count != FRESH_LAUNCH_COUNT
        ):
            raise H6PreflightError("h6_preflight_h5_campaign_shape_invalid")
        if self.h5_campaign_status != CAMPAIGN_NOT_STARTED:
            raise H6PreflightError("h6_preflight_h5_campaign_status_invalid")
        if self.h5_external_monitor_status != EXTERNAL_MONITOR_NOT_CONFIGURED:
            raise H6PreflightError("h6_preflight_h5_monitor_status_invalid")
        if type(self.records) is not tuple or len(self.records) != len(H6_OBLIGATION_IDS):
            raise H6PreflightError("h6_preflight_record_count_invalid")
        if any(type(record) is not H6EvidenceRecord for record in self.records):
            raise H6PreflightError("h6_preflight_record_type_invalid")
        if tuple(record.obligation_id for record in self.records) != H6_OBLIGATION_IDS:
            raise H6PreflightError("h6_preflight_record_order_invalid")
        if any(record.status == CLOSED for record in self.records):
            raise H6PreflightError("h6_preflight_closed_record_forbidden")
        if type(self.blockers) is not tuple or not self.blockers:
            raise H6PreflightError("h6_preflight_blockers_required")
        if len(self.blockers) != len(set(self.blockers)):
            raise H6PreflightError("h6_preflight_blockers_duplicate")
        for blocker in self.blockers:
            _text(blocker, "blocker", 128)
        if type(self.source_git_clean) is not bool or type(self.protected_paths_clean) is not bool:
            raise H6PreflightError("h6_preflight_source_flags_boolean_required")
        if self.proof_suite_id is not None or self.activation_allowed is not False:
            raise H6PreflightError("h6_preflight_activation_boundary_invalid")

        expected = _hash(
            _PREFLIGHT_DOMAIN,
            _digest(self.h5_preflight_digest_512, "h5_preflight"),
            _digest(self.suite_registry_digest_512, "suite_registry"),
            _digest(self.suite_registry_canonical_digest_512, "suite_registry_canonical"),
            _text(self.status, "status"),
            _text(self.suite_registry_status, "suite_status"),
            self.suite_registry_module_count.to_bytes(4, "big"),
            _encode_strings(self.h5_profile_ids, "profile_id"),
            self.h5_warmup_count.to_bytes(4, "big"),
            self.h5_measured_repetitions.to_bytes(4, "big"),
            self.h5_fresh_launch_count.to_bytes(4, "big"),
            _text(self.h5_campaign_status, "h5_campaign_status"),
            _text(self.h5_external_monitor_status, "h5_monitor_status"),
            b"".join(record.canonical_bytes for record in self.records),
            _encode_strings(self.blockers, "blocker"),
            bytes(
                (
                    int(self.source_git_clean),
                    int(self.protected_paths_clean),
                    int(self.suite_registry_activation_allowed),
                    int(self.activation_allowed),
                )
            ),
        )
        if self.preflight_digest_512 not in (b"", expected):
            raise H6PreflightError("h6_preflight_digest_mismatch")
        object.__setattr__(self, "preflight_digest_512", expected)

    def as_public_dict(self) -> dict[str, object]:
        """Return only bounded status, evidence identities, and blockers."""

        return {
            "status": STATUS,
            "preflight_status": self.status,
            "h5_preflight_digest_sha3_512_hex": self.h5_preflight_digest_512.hex(),
            "suite_registry_digest_sha3_512_hex": self.suite_registry_digest_512.hex(),
            "suite_registry_canonical_digest_sha3_512_hex": (
                self.suite_registry_canonical_digest_512.hex()
            ),
            "suite_registry_status": self.suite_registry_status,
            "suite_registry_module_count": self.suite_registry_module_count,
            "suite_registry_proofSuiteId": self.suite_registry_proof_suite_id,
            "suite_registry_activation_allowed": self.suite_registry_activation_allowed,
            "h5_profiles": self.h5_profile_ids,
            "h5_warmup_count_per_profile": self.h5_warmup_count,
            "h5_measured_repetitions_per_profile": self.h5_measured_repetitions,
            "h5_fresh_launch_count": self.h5_fresh_launch_count,
            "h5_campaign_status": self.h5_campaign_status,
            "h5_external_monitor_status": self.h5_external_monitor_status,
            "source_git_clean": self.source_git_clean,
            "protected_paths_clean": self.protected_paths_clean,
            "records": tuple(record.as_public_dict() for record in self.records),
            "blockers": self.blockers,
            "proofSuiteId": self.proof_suite_id,
            "activation_allowed": self.activation_allowed,
            "preflight_digest_sha3_512_hex": self.preflight_digest_512.hex(),
        }


def _append_unique(values: list[str], value: str) -> None:
    if value not in values:
        values.append(value)


def _record(
    *,
    obligation_id: str,
    status: str,
    evidence_class: str,
    source_id: str,
    h5_digest: bytes,
    suite_digest: bytes,
    evidence_parts: tuple[bytes, ...],
    blockers: tuple[str, ...],
) -> H6EvidenceRecord:
    identity = _hash(
        _EVIDENCE_DOMAIN,
        h5_digest,
        suite_digest,
        _text(obligation_id, "obligation_id", 64),
        _text(source_id, "source_id"),
        *evidence_parts,
        _encode_strings(blockers, "blocker"),
    )
    return H6EvidenceRecord(
        obligation_id=obligation_id,
        status=status,
        evidence_class=evidence_class,
        source_id=source_id,
        evidence_identity_512=identity,
        blockers=blockers,
    )


def _terminal_record(ledger: TerminalLedger, obligation_id: str) -> bytes:
    for record in ledger.records:
        if record.obligation_id == obligation_id:
            return record.record_digest_512
    raise H6PreflightError("h6_preflight_terminal_record_missing")


def build_h6_preflight(context: H6PreflightContext) -> H6Preflight:
    """Replay H5/2E and construct a blocked, non-launching H6 record."""

    _synthetic()
    if type(context) is not H6PreflightContext:
        raise H6PreflightError("h6_preflight_context_type_invalid")
    try:
        independently_verify_h5_preflight(
            context.h5_preflight,
            context.h5_context,
        )
    except (ValueError, TypeError) as exc:
        raise H6PreflightError("h6_preflight_h5_replay_failed") from exc

    h5 = context.h5_preflight
    if (
        h5.status != H5_PREFLIGHT_BLOCKED
        or h5.proof_suite_id is not None
        or h5.activation_allowed is not False
    ):
        raise H6PreflightError("h6_preflight_h5_activation_boundary_invalid")
    suite = _read_suite_registry(context.suite_registry_path)
    ledger = context.h5_context.terminal_ledger

    records: list[H6EvidenceRecord] = []
    blockers: list[str] = []

    def add(record: H6EvidenceRecord) -> None:
        records.append(record)
        for blocker in record.blockers:
            _append_unique(blockers, blocker)

    add(
        _record(
            obligation_id="STRICT_PQ_SECURITY_LEDGER",
            status=BLOCKED,
            evidence_class=UNKNOWN,
            source_id="gate_2e_terminal_ledger.py+bl_pq512_suite_candidate_v1.json",
            h5_digest=h5.preflight_digest_512,
            suite_digest=suite.raw_digest_512,
            evidence_parts=(
                ledger.ledger_digest_512,
                _terminal_record(ledger, "STRICT_PQ_SECURITY_LEDGER"),
            ),
            blockers=(
                "no_backend_admitted",
                "proof_suite_unselected",
                "strict_pq_security_ledger_open",
            ),
        )
    )
    add(
        _record(
            obligation_id="COMPLETE_SIMULATOR",
            status=REFERENCE_ONLY,
            evidence_class=DERIVED,
            source_id="gate_2e_terminal_ledger.py+fp16_zk_rs_hiding_simulator_kat.py",
            h5_digest=h5.preflight_digest_512,
            suite_digest=suite.raw_digest_512,
            evidence_parts=(
                ledger.ledger_digest_512,
                _terminal_record(ledger, "SEMANTIC_STATE_SIMULATOR"),
            ),
            blockers=("h6_simulator_qualification_pending",),
        )
    )
    add(
        _record(
            obligation_id="PROOF_RECEIPT_GRAMMAR",
            status=OPEN,
            evidence_class=DERIVED,
            source_id="docs/bl_pq512_suite_candidate_v1.json+proof_body_reference.py",
            h5_digest=h5.preflight_digest_512,
            suite_digest=suite.canonical_digest_512,
            evidence_parts=(
                ledger.ledger_digest_512,
                _terminal_record(ledger, "STATE_PROOF_RECEIPT"),
            ),
            blockers=("proof_grammar_unselected", "h4_atomic_binding_deferred"),
        )
    )
    add(
        _record(
            obligation_id="ATTACK_CORPUS",
            status=REFERENCE_ONLY,
            evidence_class=OBSERVED,
            source_id="tests/attacks/gate_2e_and_h5_current_slices",
            h5_digest=h5.preflight_digest_512,
            suite_digest=suite.raw_digest_512,
            evidence_parts=(ledger.ledger_digest_512,),
            blockers=("attack_corpus_incomplete",),
        )
    )
    add(
        _record(
            obligation_id="CROSS_LANGUAGE_VERIFIER_KATS",
            status=OPEN,
            evidence_class=UNKNOWN,
            source_id="gate_2e_terminal_ledger.py+independent_verifier",
            h5_digest=h5.preflight_digest_512,
            suite_digest=suite.raw_digest_512,
            evidence_parts=(
                ledger.ledger_digest_512,
                _terminal_record(ledger, "INDEPENDENT_VERIFIER"),
            ),
            blockers=("cross_language_verifier_kats_open", "h4_atomic_binding_deferred"),
        )
    )
    add(
        _record(
            obligation_id="SOURCE_TOOLCHAIN_SBOM",
            status=OPEN,
            evidence_class=UNKNOWN,
            source_id="docs/BL_PQ512_S07_S12_PREIMPLEMENTATION_FREEZE.md",
            h5_digest=h5.preflight_digest_512,
            suite_digest=suite.raw_digest_512,
            evidence_parts=(suite.canonical_digest_512,),
            blockers=("source_toolchain_dependency_sbom_open",),
        )
    )
    add(
        _record(
            obligation_id="REPRODUCIBLE_BUILDS",
            status=OPEN,
            evidence_class=UNKNOWN,
            source_id="docs/DEPLOYMENT_READY_BUILD_CONTRACT.md+current_build_evidence",
            h5_digest=h5.preflight_digest_512,
            suite_digest=suite.raw_digest_512,
            evidence_parts=(suite.canonical_digest_512,),
            blockers=("offline_reproducible_builds_open",),
        )
    )
    add(
        _record(
            obligation_id="H5_RESOURCE_EVIDENCE",
            status=BLOCKED,
            evidence_class=UNKNOWN,
            source_id="h5_qualification_preflight.py",
            h5_digest=h5.preflight_digest_512,
            suite_digest=suite.raw_digest_512,
            evidence_parts=(h5.preflight_digest_512,),
            blockers=tuple(h5.blockers),
        )
    )
    add(
        _record(
            obligation_id="SIDE_CHANNEL_UNLINKABILITY",
            status=BLOCKED,
            evidence_class=UNKNOWN,
            source_id="gate_2e_terminal_ledger.py+H5_campaign",
            h5_digest=h5.preflight_digest_512,
            suite_digest=suite.raw_digest_512,
            evidence_parts=(
                ledger.ledger_digest_512,
                _terminal_record(ledger, "FIXED_SHAPE_LEAKAGE"),
            ),
            blockers=("complete_leakage_scan_missing", "side_channel_unlinkability_open"),
        )
    )
    add(
        _record(
            obligation_id="ROLLBACK_RECOVERY",
            status=REFERENCE_ONLY,
            evidence_class=DERIVED,
            source_id="state_migration_recovery.py",
            h5_digest=h5.preflight_digest_512,
            suite_digest=suite.raw_digest_512,
            evidence_parts=(
                ledger.ledger_digest_512,
                _terminal_record(ledger, "MIGRATION_RECOVERY"),
            ),
            blockers=("production_migration_theorem_open",),
        )
    )
    add(
        _record(
            obligation_id="COMPLETE_EVIDENCE_MANIFEST",
            status=BLOCKED,
            evidence_class=UNKNOWN,
            source_id="H6_qualification_evidence_manifest",
            h5_digest=h5.preflight_digest_512,
            suite_digest=suite.raw_digest_512,
            evidence_parts=(ledger.ledger_digest_512, suite.canonical_digest_512),
            blockers=("complete_evidence_manifest_missing", "h6_no_qualified_evidence"),
        )
    )
    add(
        _record(
            obligation_id="WAVE3_NONACTIVATING_BOUNDARY",
            status=OPEN,
            evidence_class=UNKNOWN,
            source_id="docs/IMPLEMENTATION_ROADMAP.md+Wave_3_reference_boundary",
            h5_digest=h5.preflight_digest_512,
            suite_digest=suite.raw_digest_512,
            evidence_parts=(ledger.ledger_digest_512,),
            blockers=("wave3_verifier_state_custody_open",),
        )
    )

    if h5.source_git_clean is not True:
        _append_unique(blockers, "git_dirty")
    if h5.protected_paths_clean is not True:
        _append_unique(blockers, "protected_path_changed")
    _append_unique(blockers, "h6_no_qualified_evidence")

    return H6Preflight(
        h5_preflight_digest_512=h5.preflight_digest_512,
        suite_registry_digest_512=suite.raw_digest_512,
        suite_registry_canonical_digest_512=suite.canonical_digest_512,
        suite_registry_status=suite.status,
        suite_registry_module_count=suite.module_count,
        h5_profile_ids=h5.profile_ids,
        h5_warmup_count=h5.warmup_count,
        h5_measured_repetitions=h5.measured_repetitions,
        h5_fresh_launch_count=h5.fresh_launch_count,
        h5_campaign_status=h5.campaign_status,
        h5_external_monitor_status=h5.external_monitor_status,
        records=tuple(records),
        blockers=tuple(blockers),
        source_git_clean=h5.source_git_clean,
        protected_paths_clean=h5.protected_paths_clean,
        suite_registry_proof_suite_id=suite.proof_suite_id,
        suite_registry_activation_allowed=suite.activation_allowed,
    )


def independently_verify_h6_preflight(
    preflight: H6Preflight,
    context: H6PreflightContext,
) -> None:
    """Rebuild every public field; never trust a supplied H6 digest."""

    _synthetic()
    if type(preflight) is not H6Preflight:
        raise H6PreflightError("h6_preflight_verifier_type_invalid")
    expected = build_h6_preflight(context)
    if preflight != expected:
        raise H6PreflightError("h6_preflight_verifier_replay_mismatch")


__all__: tuple[str, ...] = (
    "BLOCKED",
    "CLOSED",
    "DEFAULT_SUITE_REGISTRY_PATH",
    "DERIVED",
    "EVIDENCE_CLASSES",
    "EVIDENCE_STATUSES",
    "H6EvidenceRecord",
    "H6Preflight",
    "H6PreflightContext",
    "H6PreflightError",
    "H6_OBLIGATION_IDS",
    "INFERRED",
    "OBSERVED",
    "OPEN",
    "PREFLIGHT_BLOCKED",
    "REFERENCE_ONLY",
    "STATUS",
    "SUITE_REGISTRY_STATUS",
    "UNKNOWN",
    "build_h6_preflight",
    "independently_verify_h6_preflight",
)
