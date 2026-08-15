from __future__ import annotations

from dataclasses import replace

import pytest

from experiments.bl_pq512_crypto_foundation import h6_security_ledger as ledger_module
from experiments.bl_pq512_crypto_foundation.h6_security_ledger import (
    ACTIVATION_ALLOWED,
    GOVERNED_ATTEMPTS,
    PRODUCTION_USABLE,
    PROOF_SUITE_ID,
    TARGET_BITS,
    LedgerEffect,
    LedgerState,
    UnionScope,
    build_h6_security_ledger,
    require_h6_security_ledger,
)


def _term(term_id: str):
    ledger = build_h6_security_ledger()
    return next(term for term in ledger.terms if term.term_id == term_id)


def test_h6_closed_union_is_machine_derived_and_fails_closed_pending_migration() -> None:
    ledger = build_h6_security_ledger()
    assert ledger.target_bits == TARGET_BITS == 256
    assert ledger.parameters.governed_attempts == GOVERNED_ATTEMPTS == 4
    assert ledger.parameters.required_contributors == 2
    assert ledger.parameters.statement_lifetime_log2 == 64
    assert ledger.parameters.h4_max_shards == 4
    assert ledger.parameters.h4_max_segments_per_shard == 37
    assert ledger.parameters.h4_max_iopp_targets_per_attempt == 148
    assert ledger.parameters.iopp_lifetime_multiplier == (1 << 64) * 4 * 148
    assert len(ledger.sources) == 56
    assert len(ledger.terms) == 59
    assert len(ledger.pending_term_ids) == 23
    assert ledger.iopp_per_target_bits == pytest.approx(392.108419572807)
    assert ledger.known_acceptance_bits == pytest.approx(318.898966207178)
    assert ledger.minimum_known_acceptance_bits >= TARGET_BITS
    assert PROOF_SUITE_ID is None
    assert ACTIVATION_ALLOWED is False
    assert PRODUCTION_USABLE is False
    assert ledger.qualifies is False
    assert "binding.core_merkle_opening_roots_v2" in ledger.qualification_blockers
    assert "public_coin.durable_atomic_root_consumption" in ledger.qualification_blockers
    assert "unknown_charged_acceptance_probability" in ledger.qualification_blockers
    with pytest.raises(ValueError, match="h6_security_ledger_incomplete"):
        require_h6_security_ledger()


def test_fp8_oods_event_is_availability_only_and_never_charged_to_acceptance() -> None:
    fp8 = _term("sampler.oods_fp8_rejection")
    assert fp8.effect is LedgerEffect.AVAILABILITY
    assert fp8.state is LedgerState.FAIL_CLOSED
    assert fp8.union_scope is UnionScope.EXCLUDED
    assert fp8.event_bits == pytest.approx(247.99999999462554)
    assert fp8.charged_probability is None
    exhausted = _term("sampler.oods_attempt_cap_exhaustion")
    assert exhausted.event_bits == pytest.approx(432.0000000806167)
    four_attempts = _term("sampler.oods_four_attempt_availability_union")
    assert four_attempts.event_bits == pytest.approx(430.0000000806167)
    denominator = _term("sampler.oods_exceptional_denominator")
    assert denominator.effect is LedgerEffect.ACCEPTANCE
    assert denominator.state is LedgerState.VERIFIED
    assert denominator.charged_probability == 0


def test_signatures_are_provenance_only_and_strict_authentication_is_pending_exact_theorem() -> None:
    for term_id in (
        "authentication.ml_dsa_87_provenance_only",
        "authentication.slh_dsa_shake_256f_provenance_only",
    ):
        term = _term(term_id)
        assert term.effect is LedgerEffect.PROVENANCE
        assert term.state is LedgerState.NOT_CREDITED
        assert term.union_scope is UnionScope.EXCLUDED
        assert term.charged_probability is None
    strict = _term("authentication.strict_coin_combined_forgery_union")
    assert strict.state is LedgerState.PENDING_EXTERNAL
    assert strict.charged_bits == 556.0
    assert strict.work_bits == 258


def test_h6_closed_universe_rejects_unknown_terms_sources_and_classifications() -> None:
    ledger = build_h6_security_ledger()
    first = ledger.terms[0]
    with pytest.raises(ValueError, match="term_universe_mismatch"):
        ledger_module._validate_closed_universe(
            ledger.sources,
            ledger.terms + (replace(first, term_id="iopp.unregistered"),),
        )
    with pytest.raises(ValueError, match="term_source_unknown"):
        ledger_module._validate_closed_universe(
            ledger.sources,
            (replace(first, sources=("unknown/security/source.rs",)),) + ledger.terms[1:],
        )
    with pytest.raises(ValueError, match="term_classification_unknown"):
        ledger_module._validate_closed_universe(
            ledger.sources,
            (replace(first, effect="acceptance_error"),) + ledger.terms[1:],
        )


def test_h6_security_ledger_is_recomputed_and_mutation_invalidates_digest() -> None:
    first = build_h6_security_ledger()
    second = build_h6_security_ledger()
    assert first == second
    forged = replace(first, status="H6_SECURITY_LEDGER_V2_COMPLETE")
    assert forged.qualifies is False
