from __future__ import annotations

from pathlib import Path

import pytest

from experiments.bl_pq512_crypto_foundation.internal_completion import (
    InternalCompletionError,
    build_internal_completion_receipt,
)


def test_wrong_repository_root_fails_closed() -> None:
    with pytest.raises(InternalCompletionError, match="wrong_repository_root"):
        build_internal_completion_receipt(Path(__file__).resolve().parent)
