from __future__ import annotations

import ast
from hashlib import sha3_512
import inspect

import pytest

from experiments.bl_pq512_crypto_foundation import state_interface
from experiments.bl_pq512_crypto_foundation.state_interface import (
    ACTIVATION_ALLOWED,
    INTERFACE_DESCRIPTORS,
    PROOF_SUITE_ID,
    StateTransitionV1,
    decode_interface_envelope,
    decode_transition_envelope,
    derive_sha3_512_public_identifier,
    encode_interface_envelope,
    encode_transition_envelope,
    interface_descriptor,
)


EXPECTED_IDS = (
    "state_layout",
    "key_value_encoding",
    "membership",
    "absence",
    "ordered_access_manifest",
    "memory_consistency",
    "commitment_opening",
    "old_new_transition",
    "sha3_512_public_identifier",
    "migration_rollback",
    "transcript_contribution",
    "independent_verification",
    "atomic_receipt",
)


def _digest(label: str) -> bytes:
    return sha3_512(label.encode("ascii")).digest()


def _transition() -> StateTransitionV1:
    return StateTransitionV1(
        "K128_CALIBRATION",
        "BL-PQ512-STATE-C0-PARAM-V1",
        7,
        11,
        12,
        _digest("old-root"),
        _digest("new-root"),
        _digest("manifest"),
        _digest("public-projection"),
    )


def test_all_required_ports_have_bounded_descriptor_contracts() -> None:
    assert tuple(item.interface_id for item in INTERFACE_DESCRIPTORS) == EXPECTED_IDS
    assert tuple(item.wire_code for item in INTERFACE_DESCRIPTORS) == tuple(range(1, 14))
    assert len({item.domain for item in INTERFACE_DESCRIPTORS}) == len(INTERFACE_DESCRIPTORS)
    for item in INTERFACE_DESCRIPTORS:
        assert item.version == 1
        assert item.max_payload_length <= 4096
        assert item.public_fields and item.private_fields
        assert set(item.public_fields).isdisjoint(item.private_fields)
        assert item.grammar and item.canonical_decode_rule
        assert item.error_family and item.retry_behavior and item.crash_behavior
        assert item.mutation_cases
    assert PROOF_SUITE_ID is None
    assert ACTIVATION_ALLOWED is False


def test_envelope_roundtrip_is_canonical_and_domain_selected() -> None:
    payload = b"layout-v1"
    encoded = encode_interface_envelope("state_layout", payload)
    assert encoded == encode_interface_envelope("state_layout", payload)
    decoded = decode_interface_envelope(encoded)
    assert decoded.interface_id == "state_layout"
    assert decoded.version == 1
    assert decoded.payload == payload
    assert decoded.descriptor.domain.endswith(b"\x00")


def test_transition_roundtrip_is_atomic_and_deterministic() -> None:
    transition = _transition()
    encoded = encode_transition_envelope(transition)
    assert encoded == encode_transition_envelope(transition)
    assert decode_transition_envelope(encoded) == transition
    assert transition.sequence_after == transition.sequence_before + 1


def test_sha3_public_identifier_is_fixed_width_and_input_bound() -> None:
    first = derive_sha3_512_public_identifier(b"source-a")
    second = derive_sha3_512_public_identifier(b"source-b")
    assert len(first) == len(second) == 64
    assert first != second
    assert first == derive_sha3_512_public_identifier(b"source-a")


def test_interface_module_does_not_import_claim_or_settlement_implementation() -> None:
    source = inspect.getsource(state_interface)
    tree = ast.parse(source)
    imported_modules = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    }
    imported_modules.update(
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    )
    assert not any(
        forbidden in module
        for module in imported_modules
        for forbidden in (
            "claim_batch_access_manifest",
            "authenticated_payment_maps_reference",
            "app.public_inputs",
            "settlement",
        )
    )


@pytest.mark.parametrize("interface_id", EXPECTED_IDS)
def test_descriptor_lookup_rejects_unknown_ids_without_fallback(interface_id: str) -> None:
    assert interface_descriptor(interface_id).interface_id == interface_id
    with pytest.raises(ValueError, match="state_interface_id_unknown"):
        interface_descriptor(interface_id + "-unknown")
