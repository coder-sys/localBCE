from __future__ import annotations

import pytest

from experiments.bl_pq512_crypto_foundation.pq_signature_adapters import (
    MlDsa87PqcryptoAdapter,
    PqSignatureAdapterError,
)


def test_adapters_reject_wrong_types_lengths_mutation_and_runtime_exception(monkeypatch) -> None:
    ml = MlDsa87PqcryptoAdapter()
    public_key, secret_key = ml.generate_keypair()
    signature = ml.sign(secret_key=secret_key, message=b"MESSAGE")
    assert not ml.verify(public_key=public_key[:-1], message=b"MESSAGE", signature=signature)
    assert not ml.verify(public_key=public_key, message="MESSAGE", signature=signature)
    assert not ml.verify(public_key=public_key, message=b"MESSAGE", signature=signature[:-1])
    mutated = bytes([signature[0] ^ 1]) + signature[1:]
    assert not ml.verify(public_key=public_key, message=b"MESSAGE", signature=mutated)
    with pytest.raises(PqSignatureAdapterError, match="secret_key_size_invalid"):
        ml.sign(secret_key=secret_key[:-1], message=b"MESSAGE")
    monkeypatch.setattr(ml._module, "verify", lambda *_: (_ for _ in ()).throw(RuntimeError("boom")))
    assert not ml.verify(public_key=public_key, message=b"MESSAGE", signature=signature)
