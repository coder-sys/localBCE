"""Composed, nonactivating H6 security/error ledger.

The IOPP arithmetic is reused from the exact theorem-parameter script.  H6
adds the bounded union terms that the earlier ledger deliberately left out:
the exact campaign target count, one bounded retry, and fail-closed aborts.
No retry or target count can silently raise the acceptance probability above
the frozen 256-bit floor.
"""

from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
import hashlib
import math
from pathlib import Path
from typing import Final

from experiments.bl_pq512_crypto_core.cuda import fp16_zk_rs_security_ledger as base


ROOT: Final[Path] = Path(__file__).resolve().parents[2]
TARGET_BITS: Final[int] = 256
TARGET_COUNT: Final[int] = 22
MAX_RETRIES: Final[int] = 1
STATUS: Final[str] = "H6_SECURITY_LEDGER_V1_NONACTIVATING"
_DOMAIN = b"BL/PQ512/H6/COMPOSED-SECURITY-LEDGER/v1\x00"
_SOURCE_FILES: Final[tuple[str, ...]] = (
    "experiments/bl_pq512_crypto_core/cuda/fp16_zk_rs_security_ledger.py",
    "experiments/bl_pq512_crypto_core/cuda/fp16_zk_rs_hiding_simulator_kat.py",
    "experiments/bl_pq512_crypto_foundation/h6_security_ledger.py",
)


@dataclass(frozen=True, slots=True)
class LedgerTerm:
    label: str
    probability: Fraction
    bits: float


@dataclass(frozen=True, slots=True)
class H6SecurityLedger:
    status: str
    theorem_source: str
    mca_assumption: str
    target_bits: int
    target_count: int
    max_retries: int
    terms: tuple[LedgerTerm, ...]
    composed_iopp_error: Fraction
    composed_iopp_bits: float
    multi_target_error: Fraction
    multi_target_bits: float
    retry_error: Fraction
    retry_bits: float
    abort_error: Fraction
    abort_bits: float
    source_manifest_sha3_512: bytes
    ledger_digest_sha3_512: bytes

    @property
    def minimum_term_bits(self) -> float:
        return min(term.bits for term in self.terms)

    @property
    def qualifies(self) -> bool:
        return (
            self.target_bits == TARGET_BITS
            and self.target_count == TARGET_COUNT
            and self.max_retries == MAX_RETRIES
            and self.minimum_term_bits >= TARGET_BITS
            and self.composed_iopp_bits >= TARGET_BITS
            and self.multi_target_bits >= TARGET_BITS
            and self.retry_bits >= TARGET_BITS
            and self.abort_error == 0
            and all(path.is_file() and not path.is_symlink() for path in self._source_paths())
        )

    def _source_paths(self) -> tuple[Path, ...]:
        return tuple(ROOT / Path(relative) for relative in _SOURCE_FILES)

    def as_public_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "theorem_source": self.theorem_source,
            "mca_assumption": self.mca_assumption,
            "target_error_bits": self.target_bits,
            "target_count": self.target_count,
            "max_retries": self.max_retries,
            "minimum_independent_error_bits": self.minimum_term_bits,
            "composed_iopp_error_bits": self.composed_iopp_bits,
            "multi_target_error_bits": self.multi_target_bits,
            "retry_error_bits": self.retry_bits,
            "abort_error_bits": self.abort_bits,
            "abort_is_fail_closed": self.abort_error == 0,
            "terms": tuple(
                {
                    "label": term.label,
                    "error_bits": term.bits,
                }
                for term in self.terms
            ),
            "source_manifest_sha3_512": self.source_manifest_sha3_512.hex(),
            "ledger_digest_sha3_512": self.ledger_digest_sha3_512.hex(),
            "proofSuiteId": None,
            "activationAllowed": False,
            "qualifies": self.qualifies,
        }


def _bits(probability: Fraction) -> float:
    if probability == 0:
        return math.inf
    return math.log2(probability.denominator) - math.log2(probability.numerator)


def _source_manifest() -> tuple[bytes, tuple[Path, ...]]:
    hasher = hashlib.sha3_512(_DOMAIN + b"sources\x00")
    paths = tuple(ROOT / Path(relative) for relative in _SOURCE_FILES)
    for relative, path in zip(_SOURCE_FILES, paths, strict=True):
        if path.is_symlink() or not path.is_file():
            raise ValueError("h6_security_source_missing")
        data = path.read_bytes()
        encoded = relative.encode("ascii")
        hasher.update(len(encoded).to_bytes(4, "big"))
        hasher.update(encoded)
        hasher.update(len(data).to_bytes(8, "big"))
        hasher.update(hashlib.sha3_512(data).digest())
    return hasher.digest(), paths


def _iopp_terms() -> tuple[tuple[str, Fraction], ...]:
    field_inverse = Fraction(1, base.FIELD_CARDINALITY)
    nonzero_field_inverse = Fraction(1, base.FIELD_CARDINALITY - 1)
    errors: list[tuple[str, Fraction]] = [
        ("gkr_claim_batch", Fraction(base.GKR_CLAIMS - 1, base.FIELD_CARDINALITY)),
        (
            "packed_coordinate_batch",
            Fraction(base.PACKED_COORDINATES - 1, base.FIELD_CARDINALITY),
        ),
        ("source_mask_batch", field_inverse),
        (
            "quadratic_row_sumcheck",
            Fraction(
                base.SUMCHECK_ROUNDS * base.SUMCHECK_DEGREE,
                base.FIELD_CARDINALITY,
            ),
        ),
        (
            "state_key_compression_collision",
            Fraction(
                base.STATE_PHASES * base.STATE_CAPACITY * (base.STATE_CAPACITY - 1) // 2,
                base.FIELD_CARDINALITY,
            ),
        ),
        (
            "state_squarefree_identity",
            Fraction(
                base.STATE_PHASES * (2 * base.STATE_CAPACITY - 1),
                base.FIELD_CARDINALITY,
            ),
        ),
        ("state_squarefree_sumchecks", Fraction(base.STATE_SUMCHECK_DEGREE_BUDGET, base.FIELD_CARDINALITY)),
        (
            "state_squarefree_claim_combinations",
            base.STATE_CLAIM_COMBINATIONS * nonzero_field_inverse,
        ),
        (
            "state_coefficient_claim_combination",
            base.STATE_COEFFICIENT_CLAIM_COMBINATIONS * nonzero_field_inverse,
        ),
        ("initial_list_field", field_inverse),
    ]
    for round_index in range(1, base.SUMCHECK_ROUNDS + 1):
        remaining_interleaving = 1 << (base.SUMCHECK_ROUNDS - round_index)
        errors.append(
            (
                f"sumcheck_round_{round_index}_mca_plus_field",
                Fraction(remaining_interleaving * base.MAIN_BLOCK, base.FIELD_CARDINALITY)
                + Fraction(base.MASK_MESSAGE, base.FIELD_CARDINALITY),
            )
        )
    base_error = Fraction(base.MAIN_BLOCK, base.FIELD_CARDINALITY)
    base_error += Fraction(base.SUMCHECK_ROUNDS * base.MASK_BLOCK, base.FIELD_CARDINALITY)
    base_error += field_inverse
    errors.append(("base_combination", base_error))
    query_error = max(
        (1 - base.MAIN_DELTA) ** base.MAIN_QUERIES,
        (1 - base.MASK_DELTA) ** base.MASK_QUERIES,
    )
    errors.append(("spotcheck_max", query_error))
    return tuple(errors)


def build_h6_security_ledger() -> H6SecurityLedger:
    source_manifest, _ = _source_manifest()
    terms = tuple(
        LedgerTerm(label, probability, _bits(probability))
        for label, probability in _iopp_terms()
    )
    composed = sum((term.probability for term in terms), Fraction(0, 1))
    multi_target = composed * TARGET_COUNT
    retry = multi_target * (MAX_RETRIES + 1)
    abort = Fraction(0, 1)
    minimum = min(term.bits for term in terms)
    if minimum < base.TARGET_BITS or _bits(composed) < base.TARGET_BITS:
        raise ValueError("h6_security_iopp_floor_failed")
    digest = hashlib.sha3_512(_DOMAIN)

    def append_integer(value: int) -> None:
        width = max(1, (value.bit_length() + 7) // 8)
        digest.update(width.to_bytes(4, "big"))
        digest.update(value.to_bytes(width, "big"))

    for term in terms:
        digest.update(term.label.encode("ascii"))
        append_integer(term.probability.numerator)
        append_integer(term.probability.denominator)
    for probability in (composed, multi_target, retry, abort):
        append_integer(probability.numerator)
        append_integer(probability.denominator)
    digest.update(source_manifest)
    return H6SecurityLedger(
        status=STATUS,
        theorem_source="eprint_2026_391_theorem_8_1",
        mca_assumption="unconditional_unique_decoding_regime",
        target_bits=TARGET_BITS,
        target_count=TARGET_COUNT,
        max_retries=MAX_RETRIES,
        terms=terms,
        composed_iopp_error=composed,
        composed_iopp_bits=_bits(composed),
        multi_target_error=multi_target,
        multi_target_bits=_bits(multi_target),
        retry_error=retry,
        retry_bits=_bits(retry),
        abort_error=abort,
        abort_bits=math.inf,
        source_manifest_sha3_512=source_manifest,
        ledger_digest_sha3_512=digest.digest(),
    )


def require_h6_security_ledger() -> H6SecurityLedger:
    ledger = build_h6_security_ledger()
    if not ledger.qualifies:
        raise ValueError("h6_security_ledger_floor_failed")
    return ledger


__all__: tuple[str, ...] = (
    "H6SecurityLedger",
    "LedgerTerm",
    "MAX_RETRIES",
    "STATUS",
    "TARGET_BITS",
    "TARGET_COUNT",
    "build_h6_security_ledger",
    "require_h6_security_ledger",
)
