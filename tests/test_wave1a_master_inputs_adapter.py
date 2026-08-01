from __future__ import annotations

from hashlib import sha3_512
import os
from unittest import mock

import pytest

from app.batch.pq_nullifier_derivation import (
    AttemptReplayIdentityV1,
    CoverReplayContextV2,
    NullifierDerivationAuthorityV1,
    REVISION_KIND_ORIGINAL,
)
from experiments.bl_pq512_crypto_foundation.claim_truth_pq_authority import (
    ClaimTruthAuthorityRegistryV1,
    ClaimTruthRootsV1,
    sign_claim_truth_roots,
)
from experiments.bl_pq512_crypto_foundation.pq_signature_adapters import (
    MlDsa87PqcryptoAdapter,
    SphincsShake256fSimplePqcryptoAdapter,
)
from experiments.fixed_shape_claim_air.a12_nullifier_executable_air import (
    AttemptNullifierAirRequest,
    CoverNullifierAirRequest,
    build_a12_nullifier_executable_air,
)
from experiments.fixed_shape_claim_air.claim_truth_authority_executable_air import (
    build_claim_truth_authority_executable_air,
)
from experiments.fixed_shape_claim_air.master_inputs_adapter import (
    build_master_commitment_inputs_v2,
)
from experiments.fixed_shape_claim_air.profile import get_profile
from experiments.fixed_shape_claim_air.replay_ordered_map_executable_air import (
    build_replay_ordered_map_executable_air,
)
from experiments.fixed_shape_claim_air.salt_use_tag_executable_air import (
    build_salt_use_tag_executable_air,
)
from experiments.fixed_shape_claim_air.semantics import SlotKind, StructuralError
from tests.test_wave1a_authenticated_payment_maps_reference import FLAGS
from tests.test_wave1a_payment_log_cross_language import _transition


def _components():
    profile = get_profile("K128_CALIBRATION")
    with mock.patch.dict(os.environ, FLAGS, clear=False):
        slots, _, payment = _transition()
        domain = payment.before.strong_settlement_domain_id_512
        batch_nonce = sha3_512(b"BL-WAVE1A-ADAPTER-BATCH-NONCE").digest()
        nullifier_authority = NullifierDerivationAuthorityV1.from_secret(
            sha3_512(b"BL-WAVE1A-ADAPTER-NULLIFIER-AUTHORITY").digest(),
            sha3_512(b"BL-WAVE1A-ADAPTER-PEPPER").digest(),
        )
        requests = []
        for slot in slots:
            if slot.slot_kind is SlotKind.REAL:
                request = AttemptNullifierAirRequest(
                    f"slot-{slot.slot_index}",
                    AttemptReplayIdentityV1(
                        slot.source_authority_id,
                        slot.claim_id,
                        slot.attempt_version,
                        REVISION_KIND_ORIGINAL,
                        slot.parent_attempt_version,
                    ),
                )
            else:
                request = CoverNullifierAirRequest(
                    f"slot-{slot.slot_index}",
                    CoverReplayContextV2(
                        profile.profile_id,
                        domain,
                        payment.before.epoch,
                        batch_nonce,
                        slot.slot_index,
                    ),
                    sha3_512(
                        b"BL-WAVE1A-ADAPTER-COVER-NONCE"
                        + slot.slot_index.to_bytes(2, "big")
                    ).digest(),
                )
            requests.append(request)
        a12 = build_a12_nullifier_executable_air(tuple(requests), nullifier_authority)
        salt = build_salt_use_tag_executable_air(
            sha3_512(b"BL-WAVE1A-ADAPTER-MASTER-SALT").digest()
        )
        replay = build_replay_ordered_map_executable_air(
            (), (*a12.strong_nullifiers, salt.tag_512)
        )

        roots = ClaimTruthRootsV1(
            *(sha3_512(f"adapter-root-{index}".encode()).digest() for index in range(6))
        )
        ml = MlDsa87PqcryptoAdapter()
        slh = SphincsShake256fSimplePqcryptoAdapter()
        ml_public, ml_secret = ml.generate_keypair()
        slh_public, slh_secret = slh.generate_keypair()
        registry = ClaimTruthAuthorityRegistryV1(
            profile.profile_id,
            "BL-SYNTH-GOV-INTAKE-V1",
            payment.before.epoch,
            sha3_512(b"BL-WAVE1A-ADAPTER-SNAPSHOT").digest(),
            ml_public,
            slh_public,
        )
        envelope = sign_claim_truth_roots(
            registry,
            roots,
            ml_adapter=ml,
            ml_secret_key=ml_secret,
            slh_adapter=slh,
            slh_secret_key=slh_secret,
        )
        authority = build_claim_truth_authority_executable_air(
            registry, envelope, ml_adapter=ml, slh_adapter=slh
        )
    return profile, slots, payment, domain, batch_nonce, authority, a12, salt, replay


@pytest.fixture(scope="module")
def components():
    return _components()


def test_actual_components_build_one_authoritative_master_input(components) -> None:
    profile, slots, payment, domain, nonce, authority, a12, salt, replay = components
    value = build_master_commitment_inputs_v2(
        profile,
        slots,
        authority,
        a12,
        salt,
        replay,
        payment,
        epoch=payment.before.epoch,
        strong_settlement_domain_id_512=domain,
        strong_batch_nonce_512=nonce,
    )
    replay_state = replay.traces["replay_map__ordered_map_state"]
    assert value.claim_truth_roots_512 == authority.envelope.roots.ordered()
    assert value.claim_truth_authority_digest_512 == authority.envelope.message_digest
    assert tuple(slot.strong_nullifier_512 for slot in value.slots) == (
        a12.strong_nullifiers
    )
    assert value.replay_root_before_512 == bytes(
        replay_state.columns[f"root_before_{byte}"][0] for byte in range(64)
    )
    assert value.replay_root_after_512 == bytes(
        replay_state.columns[f"root_after_{byte}"][0] for byte in range(64)
    )
    assert value.payment_lane_roots_after_512 == (
        payment.after.benefit_root_512,
        payment.after.obligation_root_512,
        payment.after.private_asset_ledger_root_512,
    )
    assert value.operation_log_root_after_512 == payment.after.operation_log_root_512
    assert value.salt_use_tag_512 == salt.tag_512


def test_master_adapter_rejects_cross_epoch_assembly(components) -> None:
    profile, slots, payment, domain, nonce, authority, a12, salt, replay = components
    with pytest.raises(StructuralError, match="authority_context_mismatch"):
        build_master_commitment_inputs_v2(
            profile,
            slots,
            authority,
            a12,
            salt,
            replay,
            payment,
            epoch=payment.before.epoch + 1,
            strong_settlement_domain_id_512=domain,
            strong_batch_nonce_512=nonce,
        )
