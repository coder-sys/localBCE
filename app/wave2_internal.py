"""Local, synthetic Wave 2 Privacy V2 and proof-boundary reference.

This module is the small integration seam that was missing between the fixed-K
privacy reference, the 12-field public ABI, the 744-byte candidate sidecar,
and the bounded proof-body grammar.  It is deliberately not a production
prover or a zero-knowledge proof system.  The reference proof body commits to
private synthetic witness material and proves only its transport grammar and
public binding; the semantic witness-hiding and soundness gates remain closed.

The module is useful because it makes the internal boundary executable without
silently promoting a hash-and-commitment fixture into a production proof.  All
private material is guarded by an explicit local/test environment, all public
records have exactly twelve fields, and every rejection is fail-closed.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from hashlib import sha3_512
import hmac
import os
import secrets
from typing import Final, Iterator, Sequence

from app.batch.poseidon import FIELD_MODULUS
from app.batch.pq_suite_candidate import (
    ActiveSuiteIdentityV1,
    CandidateSidecarV1,
    validate_active_binding,
)
from experiments.bl_pq512_crypto_foundation.proof_body_reference import (
    NONACTIVATING_REFERENCE_STATUS,
    ParsedProofBody,
    ProofGrammar,
    ProofIdentity,
    SectionPayload,
    SectionRule,
    encode_reference_proof_body,
    parse_proof_body,
)


MODULE_STATUS: Final[str] = "WAVE2_INTERNAL_REFERENCE_BOUNDARY_NONACTIVATING"
SCHEMA_VERSION: Final[str] = "blind_ledger_wave2_internal_reference_v1"
ACTIVATION_ALLOWED: Final[bool] = False
PRODUCTION_USABLE: Final[bool] = False
NETWORK_ACCESS: Final[bool] = False
LIVE_CREDENTIALS: Final[bool] = False
PROOF_SUITE_ID: None = None

PUBLIC_FIELD_COUNT: Final[int] = 12
SIDECAR_BYTES: Final[int] = 744
REFERENCE_SECTION_COUNT: Final[int] = 4
REFERENCE_SECTION_BYTES: Final[int] = 64
MAX_FIXED_K: Final[int] = 512
MAX_SYNTHETIC_CENTS: Final[int] = 10_000_000_000
PRIVATE_SLOT_BYTES: Final[int] = 182
# Public fields are transported separately from the private witness.  Keeping
# them out of this private wire makes the commitment independent of its own
# public projection and prevents circular construction.
PRIVATE_HEADER_BYTES: Final[int] = 8 + 64 + 4 + 32 + 32 + 64

SYNTHETIC_ENABLE_ENV: Final[str] = "BL_ALLOW_WAVE2_INTERNAL_REFERENCE"
SYNTHETIC_ENVIRONMENTS: Final[frozenset[str]] = frozenset({"local", "test", "unit", "ci"})

PUBLIC_FIELD_NAMES: Final[tuple[str, ...]] = (
    "protocolVersion",
    "settlementDomain",
    "batchNonce",
    "nullifierRootBefore",
    "nullifierRootAfter",
    "claimSourceRoot",
    "oracleFactsRoot",
    "policyRoot",
    "rulesetRoot",
    "opaqueBatchCommitment",
    "valueConservationCommitment",
    "settlementCommitment",
)

_SCHEDULE_MAGIC: Final[bytes] = b"BLW2SCH1"
_DOMAIN_PREFIX: Final[bytes] = b"BL/PQ512/WAVE2/INTERNAL/"
_REFERENCE_SECTION_NAMES: Final[tuple[str, ...]] = (
    "STATEMENT",
    "RELATION_COMMITMENT",
    "MASK_COMMITMENT",
    "TRANSCRIPT_COMMITMENT",
)


class Wave2InternalError(ValueError):
    """Stable fail-closed error for the local Wave 2 reference boundary."""


def _require_synthetic_environment() -> None:
    environment = os.environ.get("BL_ENV", "").strip().lower()
    if (
        environment not in SYNTHETIC_ENVIRONMENTS
        or os.environ.get("BL_DEV") != "1"
        or os.environ.get(SYNTHETIC_ENABLE_ENV) != "1"
    ):
        raise RuntimeError(
            "wave2_internal_reference_forbidden:requires_local_test_environment_and_explicit_dev_flag"
        )


@contextmanager
def synthetic_reference_environment(*, environment: str = "test") -> Iterator[None]:
    """Temporarily enable only the synthetic reference path.

    The context manager is for local conformance and tests.  It never changes
    the activation flags and restores the caller's environment exactly.
    """

    if environment not in SYNTHETIC_ENVIRONMENTS:
        raise Wave2InternalError("wave2_internal_environment_invalid")
    names = ("BL_ENV", "BL_DEV", SYNTHETIC_ENABLE_ENV)
    previous = {name: os.environ.get(name) for name in names}
    os.environ["BL_ENV"] = environment
    os.environ["BL_DEV"] = "1"
    os.environ[SYNTHETIC_ENABLE_ENV] = "1"
    try:
        yield
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def _bytes(label: str, value: object, length: int, *, nonzero: bool = False) -> bytes:
    if type(value) is not bytes or len(value) != length:
        raise Wave2InternalError(f"wave2_{label}_must_be_{length}_bytes")
    if nonzero and not any(value):
        raise Wave2InternalError(f"wave2_{label}_must_be_nonzero")
    return value


def _u32(label: str, value: object, *, nonzero: bool = False) -> int:
    if type(value) is not int or value < 0 or value >= 1 << 32:
        raise Wave2InternalError(f"wave2_{label}_not_u32")
    if nonzero and value == 0:
        raise Wave2InternalError(f"wave2_{label}_must_be_nonzero")
    return value


def _felt_bytes(label: str, value: object, *, nonzero: bool = False) -> bytes:
    checked = _bytes(label, value, 32)
    integer = int.from_bytes(checked, "big")
    if integer >= FIELD_MODULUS:
        raise Wave2InternalError(f"wave2_{label}_not_canonical_felt")
    if nonzero and integer == 0:
        raise Wave2InternalError(f"wave2_{label}_must_be_nonzero")
    return checked


def _cents(label: str, value: object) -> int:
    if type(value) is not int or value < 0 or value >= MAX_SYNTHETIC_CENTS:
        raise Wave2InternalError(f"wave2_{label}_out_of_range")
    return value


def _frame(domain: bytes, *parts: bytes) -> bytes:
    if type(domain) is not bytes or not domain or len(domain) > 0xFFFF:
        raise Wave2InternalError("wave2_digest_domain_invalid")
    encoded = bytearray(domain)
    for part in parts:
        if type(part) is not bytes or len(part) > 0xFFFFFFFF:
            raise Wave2InternalError("wave2_digest_part_invalid")
        encoded.extend(len(part).to_bytes(4, "big"))
        encoded.extend(part)
    return bytes(encoded)


def _digest(label: bytes, *parts: bytes) -> bytes:
    return sha3_512(_frame(_DOMAIN_PREFIX + label, *parts)).digest()


def _field_alias(value: bytes) -> bytes:
    wide = _bytes("field_alias_source", value, 64, nonzero=True)
    return (int.from_bytes(wide, "big") % (FIELD_MODULUS - 1) + 1).to_bytes(32, "big")


def _canonical_public_fields(values: Sequence[bytes]) -> tuple[bytes, ...]:
    if type(values) not in (tuple, list) or len(values) != PUBLIC_FIELD_COUNT:
        raise Wave2InternalError("wave2_public_field_count_invalid")
    return tuple(
        _felt_bytes(f"public_field_{index}", value)
        for index, value in enumerate(values)
    )


@dataclass(frozen=True, slots=True)
class SyntheticPrivateSlotV1:
    """One private synthetic fixed-width slot; never a public record."""

    kind: str
    approved: bool
    slot_index: int
    legacy_nullifier: bytes
    strong_nullifier: bytes = field(repr=False)
    private_claim_commitment: bytes = field(repr=False)
    allowed_cents: int = field(repr=False)
    payment_cents: int = field(repr=False)

    def __post_init__(self) -> None:
        if self.kind not in {"COVER", "REAL"}:
            raise Wave2InternalError("wave2_slot_kind_invalid")
        if type(self.approved) is not bool:
            raise Wave2InternalError("wave2_slot_approved_not_bool")
        _u32("slot_index", self.slot_index)
        _felt_bytes("slot_legacy_nullifier", self.legacy_nullifier, nonzero=True)
        _bytes("slot_strong_nullifier", self.strong_nullifier, 64, nonzero=True)
        _bytes("slot_claim_commitment", self.private_claim_commitment, 64)
        allowed = _cents("slot_allowed_cents", self.allowed_cents)
        payment = _cents("slot_payment_cents", self.payment_cents)
        if self.kind == "COVER":
            if self.approved or self.private_claim_commitment != bytes(64) or allowed or payment:
                raise Wave2InternalError("wave2_cover_slot_not_inert")
        elif self.private_claim_commitment == bytes(64):
            raise Wave2InternalError("wave2_real_slot_claim_commitment_missing")
        elif self.approved and (allowed == 0 or payment != allowed):
            raise Wave2InternalError("wave2_approved_slot_value_mismatch")
        elif not self.approved and payment != 0:
            raise Wave2InternalError("wave2_denied_slot_payment_nonzero")

    def private_bytes(self) -> bytes:
        _require_synthetic_environment()
        encoded = b"".join(
            (
                (0 if self.kind == "COVER" else 1).to_bytes(1, "big"),
                int(self.approved).to_bytes(1, "big"),
                self.slot_index.to_bytes(4, "big"),
                self.legacy_nullifier,
                self.strong_nullifier,
                self.private_claim_commitment,
                self.allowed_cents.to_bytes(8, "big"),
                self.payment_cents.to_bytes(8, "big"),
            )
        )
        if len(encoded) != PRIVATE_SLOT_BYTES:
            raise AssertionError("wave2_private_slot_width_mismatch")
        return encoded


@dataclass(frozen=True, slots=True)
class Wave2PrivateScheduleV1:
    """Private fixed-K witness schedule used by the local reference only."""

    fixed_k: int
    profile_digest_512: bytes
    settlement_domain: bytes
    batch_nonce: bytes
    fresh_private_salt_512: bytes = field(repr=False)
    slots: tuple[SyntheticPrivateSlotV1, ...] = field(repr=False)
    public_fields: tuple[bytes, ...]

    def __post_init__(self) -> None:
        _require_synthetic_environment()
        if type(self.fixed_k) is not int or self.fixed_k not in {128, 512}:
            raise Wave2InternalError("wave2_fixed_k_profile_invalid")
        _bytes("profile_digest", self.profile_digest_512, 64, nonzero=True)
        _felt_bytes("settlement_domain", self.settlement_domain, nonzero=True)
        _felt_bytes("batch_nonce", self.batch_nonce, nonzero=True)
        _bytes("fresh_private_salt", self.fresh_private_salt_512, 64, nonzero=True)
        fields = _canonical_public_fields(self.public_fields)
        if fields[0] != (2).to_bytes(32, "big"):
            raise Wave2InternalError("wave2_protocol_version_invalid")
        if fields[1] != self.settlement_domain:
            raise Wave2InternalError("wave2_public_settlement_domain_mismatch")
        if fields[2] != self.batch_nonce:
            raise Wave2InternalError("wave2_public_batch_nonce_mismatch")
        slots = tuple(self.slots)
        if len(slots) != self.fixed_k:
            raise Wave2InternalError("wave2_fixed_shape_slot_count_mismatch")
        legacy: set[bytes] = set()
        strong: set[bytes] = set()
        for expected_index, slot in enumerate(slots):
            if type(slot) is not SyntheticPrivateSlotV1:
                raise Wave2InternalError("wave2_slot_type_invalid")
            if slot.slot_index != expected_index:
                raise Wave2InternalError("wave2_slot_order_invalid")
            if slot.legacy_nullifier in legacy:
                raise Wave2InternalError("wave2_duplicate_legacy_nullifier")
            if slot.strong_nullifier in strong:
                raise Wave2InternalError("wave2_duplicate_strong_nullifier")
            legacy.add(slot.legacy_nullifier)
            strong.add(slot.strong_nullifier)
        object.__setattr__(self, "slots", slots)
        object.__setattr__(self, "public_fields", fields)

    @property
    def private_wire_length(self) -> int:
        return PRIVATE_HEADER_BYTES + self.fixed_k * PRIVATE_SLOT_BYTES

    def private_bytes(self) -> bytes:
        _require_synthetic_environment()
        encoded = b"".join(
            (
                _SCHEDULE_MAGIC,
                self.profile_digest_512,
                self.fixed_k.to_bytes(4, "big"),
                self.settlement_domain,
                self.batch_nonce,
                self.fresh_private_salt_512,
                b"".join(slot.private_bytes() for slot in self.slots),
            )
        )
        if len(encoded) != self.private_wire_length:
            raise AssertionError("wave2_private_schedule_width_mismatch")
        return encoded

    @property
    def commitment_512(self) -> bytes:
        _require_synthetic_environment()
        return _digest(b"PRIVATE-SCHEDULE", self.private_bytes())

    @property
    def shape_digest_512(self) -> bytes:
        return _digest(
            b"FIXED-SHAPE",
            self.fixed_k.to_bytes(4, "big"),
            PRIVATE_SLOT_BYTES.to_bytes(4, "big"),
            PUBLIC_FIELD_COUNT.to_bytes(2, "big"),
            self.private_wire_length.to_bytes(8, "big"),
        )

    @property
    def approved_slot_count(self) -> int:
        _require_synthetic_environment()
        return sum(slot.kind == "REAL" and slot.approved for slot in self.slots)

    @property
    def total_allowed_cents(self) -> int:
        _require_synthetic_environment()
        return sum(slot.allowed_cents for slot in self.slots)

    @property
    def total_payment_cents(self) -> int:
        _require_synthetic_environment()
        return sum(slot.payment_cents for slot in self.slots)


def deterministic_test_salt_512(label: str) -> bytes:
    """Return a deterministic salt only inside the explicit synthetic guard."""

    _require_synthetic_environment()
    if type(label) is not str or not label:
        raise Wave2InternalError("wave2_test_salt_label_invalid")
    try:
        encoded = label.encode("ascii")
    except UnicodeEncodeError as exc:
        raise Wave2InternalError("wave2_test_salt_label_not_ascii") from exc
    if len(encoded) > 128:
        raise Wave2InternalError("wave2_test_salt_label_invalid")
    return _digest(b"DETERMINISTIC-TEST-SALT", encoded)


def fresh_synthetic_salt_512() -> bytes:
    """Use the OS CSPRNG for a local synthetic run; never accept caller salts in production."""

    _require_synthetic_environment()
    try:
        salt = secrets.token_bytes(64)
    except Exception as exc:
        raise Wave2InternalError("wave2_entropy_failure_closed") from exc
    return _bytes("fresh_synthetic_salt", salt, 64, nonzero=True)


def build_synthetic_schedule(
    fixed_k: int,
    *,
    real_slot_indices: Sequence[int] = (),
    label: str = "case",
    fresh_private_salt_512: bytes | None = None,
) -> Wave2PrivateScheduleV1:
    """Build synthetic slots for conformance tests without accepting external data."""

    _require_synthetic_environment()
    if type(fixed_k) is not int or fixed_k not in {128, 512}:
        raise Wave2InternalError("wave2_fixed_k_profile_invalid")
    if type(label) is not str or not label:
        raise Wave2InternalError("wave2_synthetic_label_invalid")
    if type(real_slot_indices) not in (tuple, list):
        raise Wave2InternalError("wave2_real_slot_indices_invalid")
    real = set()
    for index in real_slot_indices:
        if type(index) is not int or index < 0 or index >= fixed_k:
            raise Wave2InternalError("wave2_real_slot_index_invalid")
        if index in real:
            raise Wave2InternalError("wave2_real_slot_index_duplicate")
        real.add(index)
    domain = _field_alias(_digest(b"SETTLEMENT-DOMAIN", label.encode("ascii")))
    nonce = _field_alias(_digest(b"BATCH-NONCE", label.encode("ascii")))
    profile = _digest(b"PROFILE", f"K{fixed_k}".encode("ascii"))
    salt = (
        deterministic_test_salt_512(f"{label}/salt")
        if fresh_private_salt_512 is None
        else _bytes("provided_synthetic_salt", fresh_private_salt_512, 64, nonzero=True)
    )
    slots: list[SyntheticPrivateSlotV1] = []
    for index in range(fixed_k):
        strong = _digest(b"SYNTHETIC-STRONG-NULLIFIER", profile, index.to_bytes(4, "big"))
        legacy = _field_alias(strong)
        if index in real:
            slots.append(
                SyntheticPrivateSlotV1(
                    "REAL",
                    True,
                    index,
                    legacy,
                    strong,
                    _digest(b"SYNTHETIC-CLAIM", profile, index.to_bytes(4, "big")),
                    12_500,
                    12_500,
                )
            )
        else:
            slots.append(
                SyntheticPrivateSlotV1(
                    "COVER",
                    False,
                    index,
                    legacy,
                    strong,
                    bytes(64),
                    0,
                    0,
                )
            )
    placeholder_public = [
        (2).to_bytes(32, "big"),
        domain,
        nonce,
        *((1).to_bytes(32, "big") for _ in range(9)),
    ]
    schedule = Wave2PrivateScheduleV1(
        fixed_k,
        profile,
        domain,
        nonce,
        salt,
        tuple(slots),
        tuple(placeholder_public),
    )
    identity = _identity_for_schedule(schedule)
    _sidecar, public = _reference_sidecar_and_public(schedule, identity)
    return replace(schedule, public_fields=public)


def _identity_for_schedule(schedule: Wave2PrivateScheduleV1) -> ActiveSuiteIdentityV1:
    profile = schedule.profile_digest_512
    suite = _digest(b"REFERENCE-SUITE", profile)
    schema = _digest(b"SCHEMA", SCHEMA_VERSION.encode("ascii"))
    verifier = _digest(b"REFERENCE-VERIFIER", profile)
    domain = _digest(b"WIDE-SETTLEMENT-DOMAIN", schedule.settlement_domain)
    return ActiveSuiteIdentityV1(
        profile,
        suite,
        schema,
        verifier,
        domain,
        1,
        (2).to_bytes(32, "big"),
        schedule.settlement_domain,
    )


def _reference_sidecar_and_public(
    schedule: Wave2PrivateScheduleV1,
    identity: ActiveSuiteIdentityV1,
) -> tuple[CandidateSidecarV1, tuple[bytes, ...]]:
    commitment = schedule.commitment_512
    batch = _digest(b"BATCH-COMMITMENT", commitment, schedule.shape_digest_512)
    before = _digest(b"NULLIFIER-BEFORE", identity.profile_id, schedule.batch_nonce)
    after = _digest(b"NULLIFIER-AFTER", before, commitment)
    payment_before = _digest(b"PAYMENT-BEFORE", identity.profile_id, schedule.batch_nonce)
    payment_after = _digest(b"PAYMENT-AFTER", payment_before, commitment)
    governance = _digest(b"GOVERNANCE", identity.profile_id, identity.schema_id)
    value = _digest(
        b"VALUE-CONSERVATION",
        commitment,
        schedule.total_allowed_cents.to_bytes(8, "big"),
        schedule.total_payment_cents.to_bytes(8, "big"),
    )
    sidecar = CandidateSidecarV1(
        identity.profile_id,
        identity.proof_suite_id,
        identity.schema_id,
        identity.verifier_artifact_identity,
        identity.strong_settlement_domain_id,
        identity.epoch,
        0,
        1,
        before,
        after,
        governance,
        payment_before,
        payment_after,
        batch,
    )
    public = [
        (2).to_bytes(32, "big"),
        identity.legacy_settlement_domain_alias,
        schedule.batch_nonce,
        _field_alias(before),
        _field_alias(after),
        _field_alias(_digest(b"CLAIM-SOURCE", identity.profile_id)),
        _field_alias(_digest(b"ORACLE-FACTS", identity.profile_id)),
        _field_alias(_digest(b"POLICY", identity.profile_id)),
        _field_alias(_digest(b"RULESET", identity.profile_id)),
        _field_alias(batch),
        _field_alias(value),
        _field_alias(_digest(b"SETTLEMENT", sidecar.encode(), value)),
    ]
    return sidecar, _canonical_public_fields(public)


def build_reference_proof_grammar(identity: ActiveSuiteIdentityV1) -> ProofGrammar:
    if type(identity) is not ActiveSuiteIdentityV1:
        raise TypeError("wave2_reference_identity_required")
    proof_identity = ProofIdentity(
        identity.profile_id,
        identity.proof_suite_id,
        identity.schema_id,
        identity.verifier_artifact_identity,
    )
    sections = tuple(
        SectionRule(code, name, REFERENCE_SECTION_BYTES, REFERENCE_SECTION_BYTES)
        for code, name in enumerate(_REFERENCE_SECTION_NAMES, start=1)
    )
    grammar = ProofGrammar(
        proof_identity,
        sections,
        88 + (88 * REFERENCE_SECTION_COUNT) + (REFERENCE_SECTION_BYTES * REFERENCE_SECTION_COUNT),
        NONACTIVATING_REFERENCE_STATUS,
    )
    return grammar


def _statement_digest(public_fields: Sequence[bytes], sidecar: CandidateSidecarV1) -> bytes:
    return _digest(b"PUBLIC-STATEMENT", b"".join(_canonical_public_fields(public_fields)), sidecar.encode())


@dataclass(frozen=True, slots=True)
class Wave2ReferenceArtifactV1:
    """One in-memory synthetic candidate artifact; private schedule is hidden from repr."""

    fixed_k: int
    identity: ActiveSuiteIdentityV1
    sidecar: CandidateSidecarV1
    public_fields: tuple[bytes, ...]
    proof_body: bytes = field(repr=False)
    grammar: ProofGrammar = field(repr=False)
    schedule: Wave2PrivateScheduleV1 = field(repr=False)

    def __post_init__(self) -> None:
        if type(self.identity) is not ActiveSuiteIdentityV1:
            raise TypeError("wave2_artifact_identity_invalid")
        if type(self.sidecar) is not CandidateSidecarV1:
            raise TypeError("wave2_artifact_sidecar_invalid")
        fields = _canonical_public_fields(self.public_fields)
        if type(self.proof_body) is not bytes or not self.proof_body:
            raise Wave2InternalError("wave2_artifact_proof_body_invalid")
        if type(self.grammar) is not ProofGrammar or not self.grammar.selected_for_reference_parsing:
            raise Wave2InternalError("wave2_artifact_grammar_invalid")
        if type(self.schedule) is not Wave2PrivateScheduleV1 or self.schedule.fixed_k != self.fixed_k:
            raise Wave2InternalError("wave2_artifact_schedule_invalid")
        validate_active_binding(self.sidecar.encode(), fields, self.identity)
        object.__setattr__(self, "public_fields", fields)

    @property
    def proof_digest_512(self) -> bytes:
        return _digest(b"PROOF-DIGEST", self.proof_body, self.sidecar.encode(), b"".join(self.public_fields))

    @property
    def sidecar_digest_512(self) -> bytes:
        return sha3_512(self.sidecar.encode()).digest()

    @property
    def public_output(self) -> dict[str, str]:
        return {
            name: "0x" + value.hex()
            for name, value in zip(PUBLIC_FIELD_NAMES, self.public_fields)
        }

    def public_receipt(self) -> dict[str, object]:
        """Return only commitment-shaped output; no private schedule or amounts."""

        return {
            "schema_version": SCHEMA_VERSION,
            "module_status": MODULE_STATUS,
            "profile": f"K{self.fixed_k}_LOCAL_SYNTHETIC",
            "public_fields": self.public_output,
            "public_field_count": PUBLIC_FIELD_COUNT,
            "sidecar_bytes": SIDECAR_BYTES,
            "sidecar_sha3_512": self.sidecar_digest_512.hex(),
            "proof_body_bytes": len(self.proof_body),
            "proof_body_sha3_512": sha3_512(self.proof_body).hexdigest(),
            "private_wire_bytes": self.schedule.private_wire_length,
            "fixed_shape": True,
            "private_witness_published": False,
            "private_amounts_published": False,
            "proof_suite_id": None,
            "activation_allowed": ACTIVATION_ALLOWED,
            "production_usable": PRODUCTION_USABLE,
            "network_access": NETWORK_ACCESS,
            "live_credentials": LIVE_CREDENTIALS,
        }


class Wave2ReferenceProofVerifierV1:
    """Structural/public-binding verifier for the nonactivating reference body."""

    def __init__(self, identity: ActiveSuiteIdentityV1) -> None:
        if type(identity) is not ActiveSuiteIdentityV1:
            raise TypeError("wave2_reference_verifier_identity_required")
        self.identity = identity
        self.grammar = build_reference_proof_grammar(identity)

    def verify(
        self,
        *,
        proof: bytes,
        public_fields: tuple[bytes, ...],
        sidecar: CandidateSidecarV1,
    ) -> bytes:
        _require_synthetic_environment()
        if type(sidecar) is not CandidateSidecarV1:
            raise Wave2InternalError("wave2_reference_verifier_sidecar_invalid")
        fields = _canonical_public_fields(public_fields)
        try:
            validate_active_binding(sidecar.encode(), fields, self.identity)
            parsed = parse_proof_body(
                proof,
                grammar=self.grammar,
                active_identity=self.grammar.identity,
            )
        except (TypeError, ValueError) as exc:
            raise Wave2InternalError("wave2_reference_proof_rejected") from exc
        if len(parsed.sections) != REFERENCE_SECTION_COUNT:
            raise Wave2InternalError("wave2_reference_section_count_invalid")
        statement, relation, mask, transcript = (item.data for item in parsed.sections)
        if not hmac.compare_digest(statement, _statement_digest(fields, sidecar)):
            raise Wave2InternalError("wave2_reference_statement_binding_mismatch")
        expected_transcript = _digest(
            b"TRANSCRIPT",
            statement,
            relation,
            mask,
        )
        if not hmac.compare_digest(transcript, expected_transcript):
            raise Wave2InternalError("wave2_reference_transcript_binding_mismatch")
        return _digest(b"VERIFIED-REFERENCE-PROOF", proof, sidecar.encode(), b"".join(fields))

    def verify_activation(self, *, proof: bytes, public_fields: tuple[bytes, ...], sidecar: CandidateSidecarV1) -> bytes:
        del proof, public_fields, sidecar
        raise Wave2InternalError("wave2_reference_activation_closed")


def build_reference_artifact(schedule: Wave2PrivateScheduleV1) -> Wave2ReferenceArtifactV1:
    """Build a bounded, commitment-only synthetic candidate proof body."""

    _require_synthetic_environment()
    if type(schedule) is not Wave2PrivateScheduleV1:
        raise TypeError("wave2_reference_schedule_required")
    identity = _identity_for_schedule(schedule)
    sidecar, public_fields = _reference_sidecar_and_public(schedule, identity)
    grammar = build_reference_proof_grammar(identity)
    statement = _statement_digest(public_fields, sidecar)
    relation = _digest(b"PRIVATE-RELATION-COMMITMENT", schedule.commitment_512, schedule.shape_digest_512)
    mask = _digest(b"PRIVATE-MASK-COMMITMENT", schedule.commitment_512, secrets.token_bytes(64))
    transcript = _digest(b"TRANSCRIPT", statement, relation, mask)
    proof_body = encode_reference_proof_body(
        tuple(
            SectionPayload(code, payload)
            for code, payload in zip(
                range(1, REFERENCE_SECTION_COUNT + 1),
                (statement, relation, mask, transcript),
            )
        ),
        grammar=grammar,
        active_identity=grammar.identity,
    )
    return Wave2ReferenceArtifactV1(
        schedule.fixed_k,
        identity,
        sidecar,
        public_fields,
        proof_body,
        grammar,
        schedule,
    )


def verify_reference_artifact(artifact: Wave2ReferenceArtifactV1) -> bytes:
    if type(artifact) is not Wave2ReferenceArtifactV1:
        raise TypeError("wave2_reference_artifact_required")
    return Wave2ReferenceProofVerifierV1(artifact.identity).verify(
        proof=artifact.proof_body,
        public_fields=artifact.public_fields,
        sidecar=artifact.sidecar,
    )


def assert_activation_closed() -> None:
    if ACTIVATION_ALLOWED or PRODUCTION_USABLE or PROOF_SUITE_ID is not None:
        raise AssertionError("wave2_internal_activation_flags_changed")


__all__: tuple[str, ...] = (
    "ACTIVATION_ALLOWED",
    "LIVE_CREDENTIALS",
    "MODULE_STATUS",
    "NETWORK_ACCESS",
    "PRODUCTION_USABLE",
    "PROOF_SUITE_ID",
    "PUBLIC_FIELD_COUNT",
    "PUBLIC_FIELD_NAMES",
    "REFERENCE_SECTION_COUNT",
    "REFERENCE_SECTION_BYTES",
    "SCHEMA_VERSION",
    "SIDECAR_BYTES",
    "SyntheticPrivateSlotV1",
    "Wave2InternalError",
    "Wave2PrivateScheduleV1",
    "Wave2ReferenceArtifactV1",
    "Wave2ReferenceProofVerifierV1",
    "assert_activation_closed",
    "build_reference_artifact",
    "build_reference_proof_grammar",
    "build_synthetic_schedule",
    "deterministic_test_salt_512",
    "fresh_synthetic_salt_512",
    "synthetic_reference_environment",
    "verify_reference_artifact",
)
