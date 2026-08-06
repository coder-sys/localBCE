"""Run the complete local/synthetic R01-R12 Wave 5 boundary.

The runner is offline and uses software-only PQ signers solely to exercise the
provider-neutral dual-PQ governance port.  It never enables a production suite,
opens a network connection, or emits private claim/payment data.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.wave4_adapters import (  # noqa: E402
    DualPqAuthenticator,
    ML_DSA_87,
    PqcryptoSoftwareSigner,
    SLH_DSA_SHAKE_256F,
)
from app.wave5_rollup import PqGovernance, run_wave5_conformance  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.parse_args()
    ml = PqcryptoSoftwareSigner.generate(ML_DSA_87)
    slh = PqcryptoSoftwareSigner.generate(SLH_DSA_SHAKE_256F)
    try:
        receipt = run_wave5_conformance(PqGovernance(DualPqAuthenticator((ml, slh))))
        print(json.dumps(receipt.as_dict(), sort_keys=True, separators=(",", ":")))
        return 0
    finally:
        ml.destroy()
        slh.destroy()


if __name__ == "__main__":
    raise SystemExit(main())
