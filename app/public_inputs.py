from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from app.batch.poseidon import FIELD_MODULUS


@dataclass(frozen=True)
class PublicInputField:
    index: int
    name: str
    solidity_type: str
    submission_field: str
    batch_attr: str


PUBLIC_INPUT_FIELDS: tuple[PublicInputField, ...] = (
    PublicInputField(0, "batchId", "bytes32", "batchId", "batch_id"),
    PublicInputField(1, "nullifierRootBefore", "bytes32", "nullifierRootBefore", "duplicate_check_before"),
    PublicInputField(2, "nullifierRootAfter", "bytes32", "nullifierRootAfter", "duplicate_check_after"),
    PublicInputField(3, "claimRoot", "bytes32", "claimRoot", "claim_batch_record"),
    PublicInputField(4, "resultRoot", "bytes32", "resultRoot", "adjudication_batch_record"),
    PublicInputField(5, "paymentRoot", "bytes32", "paymentRoot", "payment_batch_record"),
    PublicInputField(6, "batchNullifierCommitment", "bytes32", "batchNullifierCommitment", "batch_nullifier_commitment"),
    PublicInputField(7, "rulesetRoot", "bytes32", "rulesetRoot", "ruleset_record"),
    PublicInputField(8, "claimSourceRoot", "bytes32", "claimSourceRoot", "claim_source_root"),
    PublicInputField(9, "oracleFactsRoot", "bytes32", "oracleFactsRoot", "oracle_facts_root"),
    PublicInputField(10, "oracleSignerRoot", "bytes32", "oracleSignerRoot", "oracle_signer_root"),
    PublicInputField(11, "policyRoot", "bytes32", "policyRoot", "policy_root"),
    PublicInputField(12, "addressBookRoot", "bytes32", "addressBookRoot", "address_book_root"),
    PublicInputField(13, "dataAvailabilityRoot", "bytes32", "dataAvailabilityRoot", "data_availability_root"),
    PublicInputField(14, "encryptedClaimDataRoot", "bytes32", "encryptedClaimDataRoot", "encrypted_claim_data_root"),
    PublicInputField(15, "combinedBatchCommitment", "bytes32", "combinedBatchCommitment", "combined_batch_commitment"),
    PublicInputField(16, "accumulatorRootBefore", "bytes32", "accumulatorRootBefore", "accumulator_root_before"),
    PublicInputField(17, "accumulatorRootAfter", "bytes32", "accumulatorRootAfter", "accumulator_root_after"),
    PublicInputField(18, "valueConservationCommitment", "bytes32", "valueConservationCommitment", "value_conservation_commitment"),
    PublicInputField(19, "approvedAmountCents", "uint256_as_bytes32", "approvedAmountCents", "approved_amount_cents"),
    PublicInputField(20, "paymentAmountCents", "uint256_as_bytes32", "paymentAmountCents", "payment_amount_cents"),
)
PUBLIC_INPUT_FIELD_NAMES: tuple[str, ...] = tuple(field.name for field in PUBLIC_INPUT_FIELDS)

PUBLIC_INPUT_FIELDS_V2: tuple[PublicInputField, ...] = (
    PublicInputField(0, "protocolVersion", "bytes32", "protocolVersion", "protocol_version"),
    PublicInputField(1, "settlementDomain", "bytes32", "settlementDomain", "settlement_domain"),
    PublicInputField(2, "batchNonce", "bytes32", "batchNonce", "batch_nonce"),
    PublicInputField(3, "nullifierRootBefore", "bytes32", "nullifierRootBefore", "nullifier_root_before"),
    PublicInputField(4, "nullifierRootAfter", "bytes32", "nullifierRootAfter", "nullifier_root_after"),
    PublicInputField(5, "claimSourceRoot", "bytes32", "claimSourceRoot", "claim_source_root"),
    PublicInputField(6, "oracleFactsRoot", "bytes32", "oracleFactsRoot", "oracle_facts_root"),
    PublicInputField(7, "policyRoot", "bytes32", "policyRoot", "policy_root"),
    PublicInputField(8, "rulesetRoot", "bytes32", "rulesetRoot", "ruleset_root"),
    PublicInputField(9, "opaqueBatchCommitment", "bytes32", "opaqueBatchCommitment", "opaque_batch_commitment"),
    PublicInputField(10, "valueConservationCommitment", "bytes32", "valueConservationCommitment", "value_conservation_commitment"),
    PublicInputField(11, "settlementCommitment", "bytes32", "settlementCommitment", "settlement_commitment"),
)
PUBLIC_INPUT_FIELD_NAMES_V2: tuple[str, ...] = tuple(field.name for field in PUBLIC_INPUT_FIELDS_V2)


def _object_get(source: Any, attr: str) -> Any:
    if isinstance(source, Mapping):
        return source[attr]
    return getattr(source, attr)


def bytes32_hex(value: str) -> str:
    text = str(value).lower().removeprefix("0x")
    if len(text) != 64 or any(ch not in "0123456789abcdef" for ch in text):
        raise ValueError(f"public_input_not_bytes32:{value}")
    return text


def uint256_as_bytes32(value: int | str) -> str:
    integer = int(value)
    if integer < 0 or integer >= 2**256:
        raise ValueError(f"public_input_uint256_out_of_range:{value}")
    return f"{integer:064x}"


def build_native_stark_public_inputs(batch: Any) -> list[str]:
    values: list[str] = []
    for field in PUBLIC_INPUT_FIELDS:
        value = _object_get(batch, field.batch_attr)
        if field.solidity_type == "uint256_as_bytes32":
            values.append(uint256_as_bytes32(value))
        else:
            values.append(bytes32_hex(value))
    return values


def build_native_stark_public_inputs_v2(output: Any) -> list[str]:
    values: list[str] = []
    for field in PUBLIC_INPUT_FIELDS_V2:
        value = _object_get(output, field.batch_attr)
        if type(value) is not int:
            raise ValueError(f"public_input_v2_not_exact_integer:{field.name}")
        if value < 0 or value >= FIELD_MODULUS:
            raise ValueError(f"public_input_v2_not_stark_field:{field.name}:{value}")
        values.append(bytes32_hex(f"{value:064x}"))
    return values


def manifest_fields() -> list[dict[str, str | int]]:
    return [
        {
            "index": field.index,
            "name": field.name,
            "solidity_type": field.solidity_type,
            "submission_field": field.submission_field,
        }
        for field in PUBLIC_INPUT_FIELDS
    ]


def manifest_fields_v2() -> list[dict[str, str | int]]:
    return [
        {
            "index": field.index,
            "name": field.name,
            "solidity_type": field.solidity_type,
            "submission_field": field.submission_field,
        }
        for field in PUBLIC_INPUT_FIELDS_V2
    ]


def assert_public_input_names(names: Sequence[str]) -> None:
    if tuple(names) != PUBLIC_INPUT_FIELD_NAMES:
        raise ValueError(f"public_input_schema_mismatch:{list(names)}")


def assert_public_input_names_v2(names: Sequence[str]) -> None:
    if tuple(names) != PUBLIC_INPUT_FIELD_NAMES_V2:
        raise ValueError(f"public_input_v2_schema_mismatch:{list(names)}")
