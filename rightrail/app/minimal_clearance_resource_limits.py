"""Single production authority for the native Queue resource boundary."""

from __future__ import annotations

from typing import Final


ADMISSION_CAP_BYTES: Final[int] = 4_500_000_000
ACTIVE_PROCESS_LIMIT: Final[int] = 1
