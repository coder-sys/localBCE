from __future__ import annotations

from hashlib import sha3_512

import pytest

from experiments.bl_pq512_crypto_foundation.pq_signature_adapters import (
    INTERNAL_REFERENCE_NOTICE,
    ML_DSA_87_SUITE_ID,
    SPHINCS_SHAKE_256F_SIMPLE_SUITE_ID,
    MlDsa87PqcryptoAdapter,
    SphincsShake256fSimplePqcryptoAdapter,
)
from experiments.bl_pq512_crypto_foundation.public_coin_reference import Contributor


@pytest.fixture(scope="module")
def cryptographic_material():
    ml = MlDsa87PqcryptoAdapter()
    slh = SphincsShake256fSimplePqcryptoAdapter()
    adapters = {ml.suite_id: ml, slh.suite_id: slh}
    entries = []
    for label, adapter in ((b"ML-A", ml), (b"ML-B", ml), (b"SLH-A", slh)):
        public_key, secret_key = adapter.generate_keypair()
        contributor = Contributor(
            sha3_512(b"CONTRIBUTOR/" + label).digest(),
            sha3_512(b"KEY/" + label).digest(),
            adapter.suite_id,
            public_key,
        )
        entries.append((contributor, secret_key))
    entries.sort(key=lambda item: item[0].contributor_id)
    return adapters, tuple(item[0] for item in entries), {
        item[0].contributor_id: item[1] for item in entries
    }


def test_exact_locked_adapters_sign_verify_and_expose_nonqualification(cryptographic_material) -> None:
    adapters, contributors, secret_keys = cryptographic_material
    expected = {
        ML_DSA_87_SUITE_ID: ("ML-DSA-87", 2592, 4896, 4627),
        SPHINCS_SHAKE_256F_SIMPLE_SUITE_ID: (
            "SPHINCS+-SHAKE-256f-simple",
            64,
            128,
            49856,
        ),
    }
    for contributor in contributors:
        adapter = adapters[contributor.suite_id]
        message = b"PQ-ADAPTER-KAT/" + contributor.contributor_id
        signature = adapter.sign(
            secret_key=secret_keys[contributor.contributor_id], message=message
        )
        assert (
            adapter.algorithm_name,
            adapter.public_key_size,
            adapter.secret_key_size,
            adapter.signature_size,
        ) == expected[adapter.suite_id]
        assert len(signature) == adapter.signature_size
        assert adapter.verify(
            public_key=contributor.public_key, message=message, signature=signature
        )
        assert adapter.synthetic_only is False
        assert adapter.internal_reference_only is True
        assert adapter.software_only is True
        assert adapter.hsm_backed is False
        assert adapter.fips_validation_evidence is False
        assert adapter.qualification_notice == INTERNAL_REFERENCE_NOTICE
