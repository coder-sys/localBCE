from __future__ import annotations

from dataclasses import replace
from hashlib import sha3_512

import pytest

from experiments.bl_pq512_crypto_foundation.state_interface import (
    InterfaceEnvelope,
    StateTransitionV1,
    decode_interface_envelope,
    decode_transition_envelope,
    derive_sha3_512_public_identifier,
    encode_interface_envelope,
    encode_transition_envelope,
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
        _digest("old"),
        _digest("new"),
        _digest("manifest"),
        _digest("projection"),
    )


def test_envelope_rejects_magic_version_code_length_and_trailing_mutations() -> None:
    encoded = bytearray(encode_interface_envelope("state_layout", b"payload"))
    encoded[0] ^= 1
    with pytest.raises(ValueError, match="state_interface_envelope_magic_invalid"):
        decode_interface_envelope(bytes(encoded))
    encoded = bytearray(encode_interface_envelope("state_layout", b"payload"))
    encoded[4] = 2
    with pytest.raises(ValueError, match="state_interface_envelope_version_unsupported"):
        decode_interface_envelope(bytes(encoded))
    encoded = bytearray(encode_interface_envelope("state_layout", b"payload"))
    encoded[5] = 255
    with pytest.raises(ValueError, match="state_interface_wire_code_unknown"):
        decode_interface_envelope(bytes(encoded))
    encoded = bytearray(encode_interface_envelope("state_layout", b"payload"))
    encoded[7] ^= 1
    with pytest.raises(ValueError, match="state_interface_envelope_length_mismatch"):
        decode_interface_envelope(bytes(encoded))
    with pytest.raises(ValueError, match="state_interface_envelope_length_mismatch"):
        decode_interface_envelope(encode_interface_envelope("state_layout", b"payload") + b"x")


def test_envelope_rejects_payload_over_descriptor_bound() -> None:
    with pytest.raises(ValueError, match="state_interface_envelope_payload_length_invalid"):
        InterfaceEnvelope("state_layout", 1, b"")
    with pytest.raises(ValueError, match="state_interface_envelope_payload_length_invalid"):
        InterfaceEnvelope("state_layout", 1, b"x" * 129)

    with pytest.raises(ValueError, match="state_interface_public_identifier_source_length_invalid"):
        derive_sha3_512_public_identifier(b"")


def test_transition_rejects_sequence_root_parameter_and_trailing_mutations() -> None:
    transition = _transition()
    with pytest.raises(ValueError, match="state_interface_sequence_not_sequential"):
        replace(transition, sequence_after=13)
    with pytest.raises(ValueError, match="state_interface_old_root_digest_invalid"):
        replace(transition, old_root=b"\x00" * 64)
    with pytest.raises(ValueError, match="state_interface_parameter_identity_invalid"):
        replace(transition, parameter_identity="x" * 49)
    with pytest.raises(ValueError, match="state_interface_transition_trailing_bytes"):
        StateTransitionV1.decode(transition.encoded + b"x")


def test_transition_cannot_be_retyped_as_another_interface() -> None:
    encoded = encode_transition_envelope(_transition())
    forged = bytearray(encoded)
    forged[5] = 7
    with pytest.raises(ValueError, match="state_interface_transition_interface_mismatch"):
        decode_transition_envelope(bytes(forged))
