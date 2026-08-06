"""Print the fail-closed all-internal Blind Ledger qualification receipt."""

from __future__ import annotations

import sys
from pathlib import Path

# Executing ``py tools/internal_completion.py`` places only ``tools/`` on
# sys.path.  The receipt imports repository packages, so make the documented
# repository-root invocation deterministic without changing package behavior.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from experiments.bl_pq512_crypto_foundation.internal_completion import main


if __name__ == "__main__":
    raise SystemExit(main())
