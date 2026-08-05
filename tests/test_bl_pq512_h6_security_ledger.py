from __future__ import annotations

from experiments.bl_pq512_crypto_foundation.h6_security_ledger import (
    TARGET_BITS,
    TARGET_COUNT,
    build_h6_security_ledger,
    require_h6_security_ledger,
)


def test_h6_composed_security_ledger_covers_retry_abort_and_targets() -> None:
    ledger = require_h6_security_ledger()
    assert ledger.target_bits == TARGET_BITS == 256
    assert ledger.target_count == TARGET_COUNT == 22
    assert ledger.minimum_term_bits >= 392.0
    assert ledger.composed_iopp_bits >= 392.0
    assert ledger.multi_target_bits >= TARGET_BITS
    assert ledger.retry_bits >= TARGET_BITS
    assert ledger.abort_error == 0
    assert ledger.qualifies
    assert ledger.ledger_digest_sha3_512


def test_h6_security_ledger_is_recomputed_not_caller_supplied() -> None:
    first = build_h6_security_ledger()
    second = build_h6_security_ledger()
    assert first == second
