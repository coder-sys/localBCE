"""Synthetic-only reference parser for the unqualified BL-PQ512 candidate.

This module makes the R24 registry and 744-byte sidecar grammar executable. It
does not implement or identify a proof suite, verify a proof, or authorize
activation. Production code must not promote this reference by renaming it.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha3_512
import json
from typing import Any, Mapping

from app.batch.poseidon import FIELD_MODULUS


SIDECAR_MAGIC = b"BLPQSC01"
SIDECAR_VERSION = 1
SIDECAR_FLAGS = 0
SIDECAR_LENGTH = 744
_UINT64_MAX = (1 << 64) - 1
SALT_USE_MAGIC = b"BLPQSALT"
SALT_USE_VERSION = 1
SALT_USE_DOMAIN_CODE = 259
SALT_USE_LENGTH = 78

# Filled from the canonical JSON instance after every reviewed registry change.
EXPECTED_REGISTRY_CANONICAL_SHA3_512 = (
    "d082aaec00392f6ae7c7c37a52b6b18ab0fccd5fb08654ec9e326d8c20dd355e"
    "13f02b240577823f18b06f50aa165d25f5479d2ba1067beb80dd20ab9d6724e0"
)

SIDECAR_LAYOUT_SPEC = (
    ("magic", 0, 8, "ASCII_FIXED"),
    ("encodingVersion", 8, 2, "U16BE"),
    ("flags", 10, 2, "U16BE"),
    ("encodedLength", 12, 4, "U32BE"),
    ("profileId", 16, 64, "NONZERO_BYTES64"),
    ("proofSuiteId", 80, 64, "NONZERO_BYTES64"),
    ("schemaId", 144, 64, "NONZERO_BYTES64"),
    ("verifierArtifactIdentity", 208, 64, "NONZERO_BYTES64"),
    ("strongSettlementDomainId", 272, 64, "NONZERO_BYTES64"),
    ("epoch", 336, 8, "NONZERO_U64BE"),
    ("sequenceBefore", 344, 8, "U64BE"),
    ("sequenceAfter", 352, 8, "U64BE_SUCCESSOR"),
    ("strongNullifierRootBefore", 360, 64, "NONZERO_BYTES64"),
    ("strongNullifierRootAfter", 424, 64, "NONZERO_BYTES64"),
    ("strongGovernanceCommitment", 488, 64, "NONZERO_BYTES64"),
    ("strongPaymentStateRootBefore", 552, 64, "NONZERO_BYTES64"),
    ("strongPaymentStateRootAfter", 616, 64, "NONZERO_BYTES64"),
    ("strongBatchCommitment", 680, 64, "NONZERO_BYTES64"),
)
SIDECAR_LAYOUT = tuple((name, offset, length) for name, offset, length, _ in SIDECAR_LAYOUT_SPEC)

EXPECTED_MODULE_STATUS = (
    ("ENCODING_FRAMING", "LOCAL_CANDIDATE"),
    ("APPLICATION_SHA3_STATE", "LOCAL_CANDIDATE"),
    ("CHALLENGE_FIELD_ALGEBRA", "LOCAL_REFERENCE_KAT_PASSED_NOT_PRODUCTION"),
    ("PCS_CIRCLE_FRI", "UNSELECTED"),
    ("PUBLIC_COIN_INTERACTIVE_TRANSCRIPT", "LOCAL_REFERENCE_KAT_PASSED_NOT_INTEGRATED"),
    ("NATIVE_WITNESS_HIDING", "SIMULATOR_REVIEW_REQUIRED"),
    ("SECURITY_BUDGET", "EXTERNAL_REVIEW_REQUIRED"),
    ("PROOF_BODY_FORMAT", "UNSELECTED"),
)

EXPECTED_A12_DERIVATION = {
    "status": "A12_APPLICATION_REFERENCE_FROZEN_NOT_AIR",
    "encodingMagicAscii": "BLPQNF01",
    "encodingVersion": 1,
    "integerEncoding": "BIG_ENDIAN",
    "attemptDomainCode": 257,
    "coverDomainCode": 258,
    "legacyFunction": "POSEIDON_NULLIFIER_DOMAIN_30_BYTE_CHUNK_CHAIN",
    "strongFunction": "SHA3_512_DIRECT_CANONICAL_PREIMAGE",
    "independentLanesFromSamePreimage": True,
    "realAttemptIdentityFields": [
        "sourceAuthorityId",
        "sourceClaimId",
        "attemptVersion",
        "revisionKind",
        "parentAttemptVersion",
    ],
    "realAttemptExcludedFields": [
        "batchNonce",
        "slotRandomness",
        "sourceTransportSequence",
        "payerProviderMemberFields",
        "claimFactsAndAmounts",
        "decision",
        "policyAndOracleFacts",
        "epochDomainProfileSchemaSuite",
        "proofRandomness",
    ],
    "blPq512V1RevisionPolicy": "ORIGINAL_ONLY_REJECT_BEFORE_DERIVATION",
    "coverContextFields": [
        "profileId",
        "strongSettlementDomainId",
        "epoch",
        "batchNonce",
        "slotIndex",
        "privateCoverNonce512",
    ],
    "pepperCommitmentMagicAscii": "BLPQPEP1",
    "pepperCommitmentVersion": 1,
    "pepperLength": 64,
    "pepperLifecycle": "REPLAY_REGISTRY_LIFETIME",
    "governanceBindsAuthorityIdAndPepperCommitment": True,
    "batchLevelRotationAllowed": False,
    "rotationRequiresAtomicFullRegistryMigration": True,
}

EXPECTED_NATIVE_HIDING_CANDIDATE = {
    "status": "INTERFACE_SCHEDULE_SUPERSEDED_PACKED_SHA3_RERUN_REQUIRED",
    "profileId": "K512_CALIBRATION",
    "interfaceScheduleCurrent": False,
    "supersededByDenseSharedScheduleSha3_512": (
        "b25f5122554354b37b45eaeeca67fc78eeb0197ec258e55af10ff5922c667a0c"
        "d5ac04b9d8e01271564df046ef87c5b220e04492119cf0532f074c3841771e28"
    ),
    "logBlowup": 1,
    "friQueryCount": 926,
    "traceMaskDegreeFreedom": 4694,
    "nativeHidingPlanSha3_512": (
        "7e83a20f7125fe21985daca5cd063e4b63f0e7d839fce8075f3a16286f581b9b9"
        "ef3b193b01cf2ea34f40288e4151a1bfae12ea1f39eb44ea5fdeb6ea4b0515f"
    ),
    "directEvaluationMapSha3_512": (
        "79148ba5b5ee6655478cd478cf3dd159bb8d458d1b6dad0245ee2db0ba223d4c7"
        "66e0764f9909d05cba9efd0ea98329f53a70618553bf53ea1cd3ead86b6fb04"
    ),
    "directEvaluationRank": 958,
    "directEvaluationFreeDimension": 3736,
    "quotientMaskDegreeFreedom": 927,
    "quotientMaskPlanSha3_512": (
        "8b577a857db1f9ae09b0382039bf1af47bd7fbd0b4f42fb3643039233852b1ac"
        "d56887c45710fb42e733d12024c48ee0c6a334aebdc064fd86d341f1896e6f3a"
    ),
    "quotientSplitLogReduction": 1,
    "quotientSplitFactorRule": (
        "REPEATED_DOUBLE_OODS_X_AT_MAX_LOG_DEGREE_BOUND_MINUS_ONE"
    ),
    "quotientSplitFactorLog21KatHex": (
        "2c2ef3f200470e3f16a140270c1f9e9a451cfd791cc2587f63d18d395ece5473"
        "2ccf39e70f9ab53e19e773cc623a1da32a4355f83810202c14a20e304f577f9e"
    ),
    "quotientClosureProved": False,
    "simulatorComplete": False,
    "coverageGaps": [
        "RERUN_AFTER_PACKED_SHA3_SCHEDULE_SUBSTITUTION",
        "FINAL_CIRCLE_SPLIT_LOG_DEGREE_AND_PROVER_INTEGRATION",
        "FINAL_SHA3_AIR_INTERACTION_ORACLE_DIMENSIONS",
        "FINAL_MULTI_DOMAIN_FRI_ORACLE_WIDTHS_AFTER_SHA3_AIR_EXPANSION",
        "INTERACTIVE_CIRCLE_SIMULATOR_TRANSCRIPT",
    ],
    "vector": "test_data/bl_pq512_wave1b_hiding_vectors_v1.json",
}

EXPECTED_SHA3_AIR_CANDIDATE = {
    "status": "BYTE_LOOKUP_AIR_KAT_PASSED_INTERACTION_PACKING_UNSELECTED",
    "stateBytes": 200,
    "rateBytes": 72,
    "capacityBytes": 128,
    "permutationRounds": 24,
    "coreRoundBaseColumns": 1_632,
    "spongeBlockColumns": 72,
    "traceBaseColumns": 1_704,
    "coreRoundLookupMessages": 1_024,
    "absorbXorLookups": 72,
    "firstRoundLookupMessages": 1_096,
    "roundXorLookups": 608,
    "roundAndNotLookups": 200,
    "roundSplitLookups": 216,
    "directMaximumDegree": 2,
    "composedMaximumDegree": 3,
    "shapeSha3_512": (
        "824d0d5adb44dc5a7f61960f7ad61ccb5a34aff177a51616afd0de6b49bbb4ad"
        "ea54e216cb0d0ea5bbe59f4818468e6bc3deafec21bdeddb4db797d899784e1c"
    ),
    "applicationPortInventoryStatus": (
        "HISTORICAL_51XK_MEASUREMENT_SUPERSEDED_BY_PACKED_SCHEDULE"
    ),
    "applicationPortInventoryCurrent": True,
    "applicationPortComprehensiveSourceScopeCurrent": True,
    "applicationPortGovernedSourceDirectories": [
        "app/batch",
        "experiments/fixed_shape_claim_air",
    ],
    "applicationPortHistoricalMeasurementCurrent": False,
    "applicationPortReconciledAdditionMeasurementCurrent": True,
    "applicationPortReconciledAdditionCount": 5,
    "applicationPortInventoryProfileId": "K128_CALIBRATION",
    "applicationPortStaticCallsites": 79,
    "applicationPortAirCallsites": 39,
    "applicationPortPublicPrecomputedCallsites": 5,
    "applicationPortHostEvidenceOnlyCallsites": 21,
    "applicationPortWave1cVerifierStateCallsites": 11,
    "applicationPortSupersededReferenceCallsites": 3,
    "applicationPortObservedInvocations": 404_482,
    "applicationPortConservativeInvocations": 401_275,
    "applicationPortConservativePermutations": 1_205_016,
    "applicationPortConservativeKeccakRoundRows": 28_920_384,
    "applicationPortInventorySha3_512": (
        "618c06447efc67bca80ca9bb4c59a89970e7c42a26ea6a45a298c8dc8e1e8b2"
        "643f3c51a923d1b89ebb6a2311dc22edfffeea70471a9f97c5378b8a43fb607c2"
    ),
    "applicationPortFinalScheduleSelected": False,
    "applicationPortInventoryImplementation": (
        "experiments/bl_pq512_crypto_foundation/application_sha3_port_inventory.py"
    ),
    "denseSharedScheduleStatus": (
        "COMPACT_CLAIM_TREE_AND_PACKED_ORACLE_BUNDLE_SCHEDULE_PROVED_"
        "INTERACTION_PACKING_OPEN"
    ),
    "denseSharedSchedulePackedOracleBundlesPerSlot": 1,
    "denseSharedScheduleK128HashInvocations": 385,
    "denseSharedScheduleK256HashInvocations": 769,
    "denseSharedScheduleK512HashInvocations": 1_537,
    "denseSharedScheduleK128Permutations": 14_322,
    "denseSharedScheduleK256Permutations": 28_644,
    "denseSharedScheduleK512Permutations": 57_288,
    "denseSharedScheduleK128KeccakRoundRows": 343_728,
    "denseSharedScheduleK256KeccakRoundRows": 687_456,
    "denseSharedScheduleK512KeccakRoundRows": 1_374_912,
    "denseSharedScheduleK128MembershipLinks": 896,
    "denseSharedScheduleK256MembershipLinks": 2_048,
    "denseSharedScheduleK512MembershipLinks": 4_608,
    "denseSharedSchedulePreimageWidthsSelected": True,
    "denseSharedScheduleSha3_512": (
        "b25f5122554354b37b45eaeeca67fc78eeb0197ec258e55af10ff5922c667a0c"
        "d5ac04b9d8e01271564df046ef87c5b220e04492119cf0532f074c3841771e28"
    ),
    "denseSharedScheduleImplementation": (
        "experiments/bl_pq512_crypto_foundation/"
        "application_sha3_shared_schedule.py"
    ),
    "economicMapScheduleStatus": (
        "SHARD24_FIXED_PRIVACY_BOUNDS_SELECTED_PADDED_AIR_OPEN"
    ),
    "economicMapShardIndexBits": 24,
    "economicMapShardAllocatedCapacity": 16_777_214,
    "economicMapK128OperationRows": 512,
    "economicMapK128PositionRows": 1_024,
    "economicMapK128MemoryRows": 1_024,
    "economicMapK128ProofNodeRows": 18_034,
    "economicMapK128NodeHashRows": 34_026,
    "economicMapK128LeafHashRows": 2_048,
    "economicMapK128HeaderHashRows": 6,
    "economicMapK128Sha3Calls": 36_080,
    "economicMapK128Sha3Permutations": 74_208,
    "economicMapK128KeccakRoundRows": 1_780_992,
    "economicMapPaddingMaterialized": False,
    "economicMapScheduleImplementation": (
        "experiments/fixed_shape_claim_air/ordered_map_batch_reference.py"
    ),
    "interactionPackingSelected": False,
    "proofSuiteId": None,
    "activationAllowed": False,
    "implementation": (
        "experiments/bl_pq512_crypto_foundation/sha3_512_air_reference.py"
    ),
}


def _bytes64(label: str, value: object) -> bytes:
    if not isinstance(value, bytes) or len(value) != 64:
        raise ValueError(f"candidate_sidecar_{label}_must_be_64_bytes")
    if not any(value):
        raise ValueError(f"candidate_sidecar_{label}_must_be_nonzero")
    return value


def _u64(label: str, value: object, *, nonzero: bool = False) -> int:
    if type(value) is not int or value < 0 or value > _UINT64_MAX:
        raise ValueError(f"candidate_sidecar_{label}_not_u64")
    if nonzero and value == 0:
        raise ValueError(f"candidate_sidecar_{label}_must_be_nonzero")
    return value


def candidate_salt_use_tag(master_salt: bytes) -> bytes:
    """Return the context-free hidden replay tag for one raw master salt."""

    salt = _bytes64("master_salt", master_salt)
    preimage = b"".join(
        (
            SALT_USE_MAGIC,
            SALT_USE_VERSION.to_bytes(2, "big"),
            SALT_USE_DOMAIN_CODE.to_bytes(2, "big"),
            len(salt).to_bytes(2, "big"),
            salt,
        )
    )
    if len(preimage) != SALT_USE_LENGTH:
        raise AssertionError("candidate_salt_use_internal_length_mismatch")
    return sha3_512(preimage).digest()


def canonical_registry_sha3_512(registry: Mapping[str, Any]) -> str:
    try:
        encoded = json.dumps(
            registry,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("candidate_registry_not_canonical_json_value") from exc
    return sha3_512(encoded).hexdigest()


@dataclass(frozen=True)
class CandidateSidecarV1:
    profile_id: bytes
    proof_suite_id: bytes
    schema_id: bytes
    verifier_artifact_identity: bytes
    strong_settlement_domain_id: bytes
    epoch: int
    sequence_before: int
    sequence_after: int
    strong_nullifier_root_before: bytes
    strong_nullifier_root_after: bytes
    strong_governance_commitment: bytes
    strong_payment_state_root_before: bytes
    strong_payment_state_root_after: bytes
    strong_batch_commitment: bytes

    def __post_init__(self) -> None:
        for label, value in (
            ("profile_id", self.profile_id),
            ("proof_suite_id", self.proof_suite_id),
            ("schema_id", self.schema_id),
            ("verifier_artifact_identity", self.verifier_artifact_identity),
            ("strong_settlement_domain_id", self.strong_settlement_domain_id),
            ("strong_nullifier_root_before", self.strong_nullifier_root_before),
            ("strong_nullifier_root_after", self.strong_nullifier_root_after),
            ("strong_governance_commitment", self.strong_governance_commitment),
            ("strong_payment_state_root_before", self.strong_payment_state_root_before),
            ("strong_payment_state_root_after", self.strong_payment_state_root_after),
            ("strong_batch_commitment", self.strong_batch_commitment),
        ):
            _bytes64(label, value)
        _u64("epoch", self.epoch, nonzero=True)
        before = _u64("sequence_before", self.sequence_before)
        after = _u64("sequence_after", self.sequence_after)
        if before == _UINT64_MAX or after != before + 1:
            raise ValueError("candidate_sidecar_sequence_transition_invalid")
        if self.strong_nullifier_root_before == self.strong_nullifier_root_after:
            raise ValueError("candidate_sidecar_nullifier_root_unchanged")
        if self.strong_payment_state_root_before == self.strong_payment_state_root_after:
            raise ValueError("candidate_sidecar_payment_state_root_unchanged")

    def encode(self) -> bytes:
        encoded = b"".join(
            (
                SIDECAR_MAGIC,
                SIDECAR_VERSION.to_bytes(2, "big"),
                SIDECAR_FLAGS.to_bytes(2, "big"),
                SIDECAR_LENGTH.to_bytes(4, "big"),
                self.profile_id,
                self.proof_suite_id,
                self.schema_id,
                self.verifier_artifact_identity,
                self.strong_settlement_domain_id,
                self.epoch.to_bytes(8, "big"),
                self.sequence_before.to_bytes(8, "big"),
                self.sequence_after.to_bytes(8, "big"),
                self.strong_nullifier_root_before,
                self.strong_nullifier_root_after,
                self.strong_governance_commitment,
                self.strong_payment_state_root_before,
                self.strong_payment_state_root_after,
                self.strong_batch_commitment,
            )
        )
        if len(encoded) != SIDECAR_LENGTH:
            raise AssertionError("candidate_sidecar_internal_length_mismatch")
        return encoded

    @classmethod
    def decode(cls, encoded: bytes) -> "CandidateSidecarV1":
        if not isinstance(encoded, bytes):
            raise TypeError("candidate_sidecar_must_be_bytes")
        if len(encoded) != SIDECAR_LENGTH:
            raise ValueError("candidate_sidecar_length_mismatch")
        if encoded[0:8] != SIDECAR_MAGIC:
            raise ValueError("candidate_sidecar_magic_mismatch")
        if int.from_bytes(encoded[8:10], "big") != SIDECAR_VERSION:
            raise ValueError("candidate_sidecar_version_mismatch")
        if int.from_bytes(encoded[10:12], "big") != SIDECAR_FLAGS:
            raise ValueError("candidate_sidecar_flags_mismatch")
        if int.from_bytes(encoded[12:16], "big") != SIDECAR_LENGTH:
            raise ValueError("candidate_sidecar_declared_length_mismatch")
        return cls(
            profile_id=encoded[16:80],
            proof_suite_id=encoded[80:144],
            schema_id=encoded[144:208],
            verifier_artifact_identity=encoded[208:272],
            strong_settlement_domain_id=encoded[272:336],
            epoch=int.from_bytes(encoded[336:344], "big"),
            sequence_before=int.from_bytes(encoded[344:352], "big"),
            sequence_after=int.from_bytes(encoded[352:360], "big"),
            strong_nullifier_root_before=encoded[360:424],
            strong_nullifier_root_after=encoded[424:488],
            strong_governance_commitment=encoded[488:552],
            strong_payment_state_root_before=encoded[552:616],
            strong_payment_state_root_after=encoded[616:680],
            strong_batch_commitment=encoded[680:744],
        )


@dataclass(frozen=True)
class ActiveSuiteIdentityV1:
    profile_id: bytes
    proof_suite_id: bytes
    schema_id: bytes
    verifier_artifact_identity: bytes
    strong_settlement_domain_id: bytes
    epoch: int
    legacy_protocol_version_alias: bytes
    legacy_settlement_domain_alias: bytes

    def __post_init__(self) -> None:
        for label, value in (
            ("profile_id", self.profile_id),
            ("proof_suite_id", self.proof_suite_id),
            ("schema_id", self.schema_id),
            ("verifier_artifact_identity", self.verifier_artifact_identity),
            ("strong_settlement_domain_id", self.strong_settlement_domain_id),
        ):
            _bytes64(label, value)
        _u64("epoch", self.epoch, nonzero=True)
        if self.legacy_protocol_version_alias != (2).to_bytes(32, "big"):
            raise ValueError("active_legacy_protocol_version_alias_invalid")
        _canonical_felt_alias("legacy_settlement_domain_alias", self.legacy_settlement_domain_alias, nonzero=True)


def _canonical_felt_alias(label: str, value: object, *, nonzero: bool = False) -> bytes:
    if not isinstance(value, bytes) or len(value) != 32:
        raise ValueError(f"{label}_must_be_32_bytes")
    integer = int.from_bytes(value, "big")
    if integer >= FIELD_MODULUS or (nonzero and integer == 0):
        raise ValueError(f"{label}_not_canonical_stark_felt")
    return value


def validate_active_binding(
    encoded_sidecar: bytes,
    public_outputs: object,
    active: ActiveSuiteIdentityV1,
) -> CandidateSidecarV1:
    """Validate structural bytes and the indivisible authenticated ACTIVE identity tuple."""

    if not isinstance(active, ActiveSuiteIdentityV1):
        raise TypeError("candidate_active_identity_required")
    sidecar = CandidateSidecarV1.decode(encoded_sidecar)
    for label, observed, expected in (
        ("profile_id", sidecar.profile_id, active.profile_id),
        ("proof_suite_id", sidecar.proof_suite_id, active.proof_suite_id),
        ("schema_id", sidecar.schema_id, active.schema_id),
        ("verifier_artifact_identity", sidecar.verifier_artifact_identity, active.verifier_artifact_identity),
        ("strong_settlement_domain_id", sidecar.strong_settlement_domain_id, active.strong_settlement_domain_id),
        ("epoch", sidecar.epoch, active.epoch),
    ):
        if observed != expected:
            raise ValueError(f"candidate_active_{label}_mismatch")
    if not isinstance(public_outputs, (tuple, list)) or len(public_outputs) != 12:
        raise ValueError("candidate_public_outputs_must_have_12_fields")
    canonical = tuple(
        _canonical_felt_alias(f"public_output_{index}", value)
        for index, value in enumerate(public_outputs)
    )
    if canonical[0] != active.legacy_protocol_version_alias:
        raise ValueError("candidate_active_protocol_alias_mismatch")
    if canonical[1] != active.legacy_settlement_domain_alias:
        raise ValueError("candidate_active_settlement_domain_alias_mismatch")
    return sidecar


def validate_unqualified_registry(registry: Mapping[str, Any]) -> None:
    if registry.get("status") != "CANDIDATE_UNQUALIFIED":
        raise ValueError("candidate_registry_status_invalid")
    if registry.get("activationAllowed") is not False:
        raise ValueError("candidate_registry_activation_must_be_false")
    if registry.get("proofSuiteId") is not None:
        raise ValueError("candidate_registry_suite_id_must_be_unset")
    if registry.get("syntheticOnly") is not True:
        raise ValueError("candidate_registry_synthetic_only_required")

    abi = registry.get("externalAbi")
    if not isinstance(abi, Mapping) or abi.get("fieldCount") != 12 or abi.get("changeAllowed") is not False:
        raise ValueError("candidate_registry_abi_invalid")

    sidecar = registry.get("sidecar")
    if not isinstance(sidecar, Mapping):
        raise ValueError("candidate_registry_sidecar_missing")
    if (
        sidecar.get("magicAscii") != SIDECAR_MAGIC.decode("ascii")
        or sidecar.get("encodingVersion") != SIDECAR_VERSION
        or sidecar.get("flags") != SIDECAR_FLAGS
        or sidecar.get("encodedLength") != SIDECAR_LENGTH
        or sidecar.get("integerEncoding") != "BIG_ENDIAN"
    ):
        raise ValueError("candidate_registry_sidecar_header_invalid")
    fields = sidecar.get("fields")
    if not isinstance(fields, list) or len(fields) != len(SIDECAR_LAYOUT):
        raise ValueError("candidate_registry_sidecar_layout_invalid")
    if any(not isinstance(field, Mapping) for field in fields):
        raise ValueError("candidate_registry_sidecar_field_invalid")
    observed_spec = tuple(
        (field.get("name"), field.get("offset"), field.get("length"), field.get("type"))
        for field in fields
    )
    if observed_spec != SIDECAR_LAYOUT_SPEC:
        raise ValueError("candidate_registry_sidecar_layout_invalid")
    observed = tuple((name, offset, length) for name, offset, length, _ in observed_spec)
    if sum(length for _, _, length in observed) != SIDECAR_LENGTH:
        raise ValueError("candidate_registry_sidecar_length_invalid")

    modules = registry.get("modules")
    if not isinstance(modules, list) or len(modules) != 8:
        raise ValueError("candidate_registry_modules_invalid")
    if any(not isinstance(module, Mapping) for module in modules):
        raise ValueError("candidate_registry_module_entry_invalid")
    module_status = tuple((module.get("kind"), module.get("status")) for module in modules)
    if module_status != EXPECTED_MODULE_STATUS:
        raise ValueError("candidate_registry_module_status_invalid")
    if any(module.get("moduleId") is not None for module in modules):
        raise ValueError("candidate_registry_module_id_must_be_unset")

    native_hiding = registry.get("candidateNativeHiding")
    if not isinstance(native_hiding, Mapping):
        raise ValueError("candidate_registry_native_hiding_missing")
    if dict(native_hiding) != EXPECTED_NATIVE_HIDING_CANDIDATE:
        raise ValueError("candidate_registry_native_hiding_mismatch")

    sha3_air = registry.get("candidateSha3Air")
    if not isinstance(sha3_air, Mapping):
        raise ValueError("candidate_registry_sha3_air_missing")
    if dict(sha3_air) != EXPECTED_SHA3_AIR_CANDIDATE:
        raise ValueError("candidate_registry_sha3_air_mismatch")

    replay = registry.get("strongReplayRegistry")
    if not isinstance(replay, Mapping):
        raise ValueError("candidate_registry_strong_replay_missing")
    if replay.get("attemptNullifierDerivation") != EXPECTED_A12_DERIVATION:
        raise ValueError("candidate_registry_a12_derivation_mismatch")

    domains = registry.get("domainRegistry")
    if not isinstance(domains, list) or not domains:
        raise ValueError("candidate_registry_domains_missing")
    if any(not isinstance(entry, Mapping) for entry in domains):
        raise ValueError("candidate_registry_domain_entry_invalid")
    codes = [entry.get("code") for entry in domains]
    names = [entry.get("name") for entry in domains]
    if len(codes) != len(set(codes)):
        raise ValueError("candidate_registry_domain_code_duplicate")
    if len(names) != len(set(names)):
        raise ValueError("candidate_registry_domain_name_duplicate")

    if canonical_registry_sha3_512(registry) != EXPECTED_REGISTRY_CANONICAL_SHA3_512:
        raise ValueError("candidate_registry_canonical_digest_mismatch")
