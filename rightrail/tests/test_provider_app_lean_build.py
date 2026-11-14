"""The provider app's pinned Lean build must be present and unchanged.

The provider app's own tests (provider_app/tests) compare Python with this build.
Build it with: lake -d provider_app/lean/ProviderApp build providerAppLean
"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class ProviderAppLeanBuildTests(unittest.TestCase):
    def test_pinned_toolchain_sources_and_executable_match(self):
        sys.path.insert(0, str(ROOT / "provider_app"))
        try:
            from provider_app.lean_compare import LeanCompareError, _verify_identity
        finally:
            sys.path.pop(0)
        try:  # build it with: lake -d lean/ProviderApp build providerAppLean
            _verify_identity()
        except LeanCompareError as error:
            self.fail(f"provider app Lean build is not usable: {error.code}")


if __name__ == "__main__":
    unittest.main()
