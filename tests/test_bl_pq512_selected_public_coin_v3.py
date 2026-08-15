from __future__ import annotations

from dataclasses import dataclass, fields, replace
from hashlib import sha3_512

import pytest

import experiments.bl_pq512_crypto_foundation.selected_public_coin_v3 as v3
from experiments.bl_pq512_crypto_foundation.field16_reference import Fp16
from experiments.bl_pq512_crypto_foundation.oods_reference import CirclePoint
from experiments.bl_pq512_crypto_foundation.pq_signature_adapters import (
    MlDsa87PqcryptoAdapter,
    SphincsShake256fSimplePqcryptoAdapter,
)
from experiments.bl_pq512_crypto_foundation.public_coin_reference import Contributor
from experiments.bl_pq512_crypto_foundation.selected_public_coin_v3 import (
    SemanticV3Geometry,
    SemanticV3GovernedContext,
    SemanticV3ParentAnchorFrame,
    SemanticV3ParentAnchorState,
    SemanticV3ParentProducerState,
    SemanticV3TranscriptEvidence,
    SemanticV3TranscriptProducer,
    replay_semantic_v3_producer_evidence,
    semantic_v3_contributor_set_commitment,
    verify_semantic_v3_continuation,
    verify_semantic_v3_prefix,
)
from experiments.fixed_shape_claim_air.semantics import StructuralError


def _wide(label: str) -> bytes:
    return sha3_512(label.encode("ascii")).digest()


@dataclass(frozen=True, slots=True)
class _SignedFixture:
    context: SemanticV3GovernedContext
    parent: SemanticV3ParentProducerState
    adapters: dict[str, object]
    evidence: SemanticV3TranscriptEvidence


@pytest.fixture(scope="module")
def signed_fixture() -> _SignedFixture:
    ml = MlDsa87PqcryptoAdapter()
    slh = SphincsShake256fSimplePqcryptoAdapter()
    adapters = {ml.suite_id: ml, slh.suite_id: slh}
    material = []
    for ordinal, adapter in enumerate((ml, slh), 1):
        public_key, secret_key = adapter.generate_keypair()
        contributor = Contributor(
            _wide(f"semantic-v3-contributor-{ordinal}"),
            _wide(f"semantic-v3-key-{ordinal}"),
            adapter.suite_id,
            public_key,
        )
        material.append((contributor, secret_key))
    material.sort(key=lambda value: value[0].contributor_id)
    contributors = tuple(value[0] for value in material)
    secrets = {value[0].contributor_id: value[1] for value in material}
    context = SemanticV3GovernedContext(
        profile_code=1,
        semantic_program_commitment=_wide("semantic-v3-program"),
        parameter_commitment=_wide("semantic-v3-parameters"),
        statement_commitment=_wide("semantic-v3-statement"),
        composite_parent_schedule_commitment=_wide("semantic-v3-parent-schedule"),
        contributor_set_commitment=semantic_v3_contributor_set_commitment(
            contributors
        ),
        geometry=SemanticV3Geometry(
            fold_round_count=1,
            query_domain_log_size=2,
            log_blowup=1,
        ),
    )
    producer = SemanticV3TranscriptProducer(
        context=context,
        session_id=_wide("semantic-v3-session"),
        contributors=contributors,
        adapters=adapters,
        secret_keys=secrets,
        reveal_source=lambda round_index, contributor: _wide(
            f"semantic-v3-reveal-{round_index}-{contributor.contributor_id.hex()}"
        ),
    )
    producer.record_main_root(_wide("semantic-v3-main-root"))
    producer.record_interaction_root(_wide("semantic-v3-interaction-root"))
    producer.finish_prefix()
    parent = SemanticV3ParentProducerState(
        parent_bundle=b"authenticated-parent-bundle-fixture",
        parent_session_id=_wide("semantic-v3-parent-session"),
        parent_round_901_transcript_root=_wide("semantic-v3-parent-round-901"),
        composition_root=_wide("semantic-v3-composition-root"),
        z=CirclePoint(Fp16.zero(), Fp16.one()),
        bridge_program_commitment=_wide("semantic-v3-bridge-program"),
        answer_aggregate_root=_wide("semantic-v3-answer-aggregate"),
        message_direct_q_commitment=_wide("semantic-v3-message-q"),
        digest_direct_q_commitment=_wide("semantic-v3-digest-q"),
    )
    producer.bind_parent_anchor(
        parent.anchor_state,
        worker_composition_root=parent.composition_root,
    )
    producer.record_continuation_message(
        _wide("semantic-v3-oods-claims") + _wide("semantic-v3-fri-mask")
    )
    producer.record_continuation_message(_wide("semantic-v3-batch-derivation"))
    producer.record_continuation_message(_wide("semantic-v3-final-layer"))
    producer.finalize_parent(parent)
    evidence = producer.finish_evidence()
    return _SignedFixture(context, parent, adapters, evidence)


def test_real_dual_pq_prefix_parent_continuation_replays(
    signed_fixture: _SignedFixture,
) -> None:
    replayed = replay_semantic_v3_producer_evidence(
        signed_fixture.evidence,
        context=signed_fixture.context,
        parent=signed_fixture.parent,
        adapters=signed_fixture.adapters,
    )
    assert replayed == signed_fixture.evidence
    assert len(replayed.prefix.rounds) == 2
    assert len(replayed.continuation.rounds) == 3
    assert replayed.parent_bundle == signed_fixture.parent.parent_bundle
    assert replayed.continuation.fri_fold_coefficients


def test_local_oods_resampling_is_not_a_continuation_authority(
    signed_fixture: _SignedFixture,
) -> None:
    locally_resampled = replace(
        signed_fixture.parent,
        z=CirclePoint(Fp16.one(), Fp16.zero()),
    )
    with pytest.raises(StructuralError, match="anchor_mismatch"):
        replay_semantic_v3_producer_evidence(
            signed_fixture.evidence,
            context=signed_fixture.context,
            parent=locally_resampled,
            adapters=signed_fixture.adapters,
        )
    changed_frame = SemanticV3ParentAnchorFrame.from_parent(
        signed_fixture.evidence.prefix,
        locally_resampled,
    )
    with pytest.raises(StructuralError, match="continuation_context_invalid"):
        verify_semantic_v3_continuation(
            signed_fixture.evidence.continuation.encoded,
            prefix=signed_fixture.evidence.prefix,
            frame=changed_frame,
            geometry=signed_fixture.context.geometry,
            adapters=signed_fixture.adapters,
        )


def test_cross_parent_and_cross_session_evidence_is_rejected(
    signed_fixture: _SignedFixture,
) -> None:
    cross_parent = replace(
        signed_fixture.parent,
        parent_session_id=_wide("semantic-v3-other-parent-session"),
    )
    with pytest.raises(StructuralError, match="anchor_mismatch"):
        replay_semantic_v3_producer_evidence(
            signed_fixture.evidence,
            context=signed_fixture.context,
            parent=cross_parent,
            adapters=signed_fixture.adapters,
        )

    cross_session_prefix = bytearray(signed_fixture.evidence.prefix.encoded)
    cross_session_prefix[12] ^= 1
    with pytest.raises(StructuralError):
        verify_semantic_v3_prefix(
            bytes(cross_session_prefix),
            signed_fixture.context,
            signed_fixture.adapters,
        )
    cross_session_continuation = bytearray(
        signed_fixture.evidence.continuation.encoded
    )
    cross_session_continuation[12] ^= 1
    with pytest.raises(StructuralError, match="continuation_context_invalid"):
        verify_semantic_v3_continuation(
            bytes(cross_session_continuation),
            prefix=signed_fixture.evidence.prefix,
            frame=signed_fixture.evidence.parent_anchor,
            geometry=signed_fixture.context.geometry,
            adapters=signed_fixture.adapters,
        )


def test_reordered_continuation_rounds_are_rejected(
    signed_fixture: _SignedFixture,
) -> None:
    rounds = signed_fixture.evidence.continuation.rounds
    reordered = v3._encode_continuation(
        signed_fixture.evidence.parent_anchor,
        signed_fixture.evidence.prefix,
        (rounds[1], rounds[0], *rounds[2:]),
    )
    with pytest.raises(StructuralError):
        verify_semantic_v3_continuation(
            reordered,
            prefix=signed_fixture.evidence.prefix,
            frame=signed_fixture.evidence.parent_anchor,
            geometry=signed_fixture.context.geometry,
            adapters=signed_fixture.adapters,
        )


def test_parent_frame_cross_language_kat_and_strict_grammar() -> None:
    first = (
        *(bytes((value,)) * 64 for value in range(1, 8)),
        Fp16.zero().encode(),
        Fp16.one().encode(),
        *(bytes((value,)) * 64 for value in range(10, 14)),
    )
    frame = SemanticV3ParentAnchorFrame(
        (*first, v3._continuation_initial_root(first))
    )
    assert frame.continuation_initial_root.hex() == (
        "2ffa158f08d8bdf6dedf610f2f362f62f794bf3a4643a2f901a68c30fd4eecac"
        "0a84b3c958708279b5fa02f61d079e917e43d823ae2c86cb89c40e4a2392f881"
    )
    assert frame.commitment.hex() == (
        "99b6b9259ec33c33c60731b10fc33bf36fd6102e44df3ba45e368887b8648325"
        "c0b251dc2760e15c239f24ec268d406477a2cf3ddc39b0b7dd19dbb4fb646473"
    )
    command = frame.command_fields
    assert command[0] == "V3_PARENT_ANCHOR"
    assert SemanticV3ParentAnchorFrame.from_command_tokens(command[1:]) == frame

    with pytest.raises(StructuralError):
        SemanticV3ParentAnchorFrame.from_command_tokens(command[1:-1])
    with pytest.raises(StructuralError):
        SemanticV3ParentAnchorFrame.from_command_tokens(
            (*command[1:-1], command[-1].upper())
        )
    with pytest.raises(StructuralError):
        SemanticV3ParentAnchorFrame.from_command_tokens(
            (command[1][:64], *command[2:])
        )
    with pytest.raises(StructuralError, match="circle_invalid"):
        SemanticV3ParentAnchorFrame.from_command_tokens(
            (*command[1:9], "0" * 128, *command[10:])
        )
    changed_root = (*command[1:-1], ("0" if command[-1][0] != "0" else "1") + command[-1][1:])
    with pytest.raises(StructuralError, match="root_invalid"):
        SemanticV3ParentAnchorFrame.from_command_tokens(changed_root)


def test_parent_producer_state_cannot_supply_q_coefficients_or_receipts() -> None:
    names = {field.name for field in fields(SemanticV3ParentProducerState)}
    assert "message_q_coefficients" not in names
    assert "digest_q_coefficients" not in names
    assert "verified" not in names
    assert "receipt" not in names


def test_parent_anchor_state_matches_complete_parent_without_bundle(
    signed_fixture: _SignedFixture,
) -> None:
    parent = signed_fixture.parent
    anchor = parent.anchor_state
    assert type(anchor) is SemanticV3ParentAnchorState
    assert anchor.composition_root == parent.composition_root
    assert SemanticV3ParentAnchorFrame.from_anchor(
        signed_fixture.evidence.prefix, anchor
    ) == SemanticV3ParentAnchorFrame.from_parent(
        signed_fixture.evidence.prefix, parent
    )


def test_governed_context_encoding_matches_the_native_transport() -> None:
    context = SemanticV3GovernedContext(
        profile_code=3,
        semantic_program_commitment=bytes((1,)) * 64,
        parameter_commitment=bytes((2,)) * 64,
        statement_commitment=bytes((3,)) * 64,
        composite_parent_schedule_commitment=bytes((4,)) * 64,
        contributor_set_commitment=bytes((5,)) * 64,
        geometry=SemanticV3Geometry(
            fold_round_count=0x1234,
            query_domain_log_size=26,
            log_blowup=2,
        ),
    )
    encoded = context.encode()
    assert len(encoded) == v3.SEMANTIC_V3_CONTEXT_BYTES == 348
    assert encoded == b"".join(
        (
            b"BLV3CX01",
            b"\x00\x01\x00\x00\x03",
            bytes(7),
            bytes((1,)) * 64,
            bytes((2,)) * 64,
            bytes((3,)) * 64,
            bytes((4,)) * 64,
            bytes((5,)) * 64,
            b"\x12\x34\x1a\x02",
            bytes(4),
        )
    )
    assert sha3_512(encoded).hexdigest() == (
        "759567cab18fd0d42aa48a63299c75bf5fee60eb9f85e684c4e81c88324fd11f"
        "413427cf8c5264ae4cdaf8da12a1691988085b7e1a49d1d8425491aba38073de"
    )
