from __future__ import annotations

from dataclasses import replace

import pytest

from experiments.bl_pq512_crypto_foundation.hash_pad_security_review import (
    hash_pad_security_review,
)


def test_review_metadata_mutation_cannot_change_the_rejection_digest() -> None:
    review = hash_pad_security_review()
    with pytest.raises(ValueError, match="hash_pad_review_digest_mismatch"):
        replace(review, review_digest_512=b"\x01" * 64)


def test_review_is_not_promoted_by_removing_one_rejection_reason() -> None:
    review = hash_pad_security_review()
    with pytest.raises(ValueError, match="hash_pad_review_digest_mismatch"):
        replace(review, rejection_reasons=review.rejection_reasons[1:])
