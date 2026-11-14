import os
from pathlib import Path
import tempfile

os.environ.setdefault("RIGHTRAIL_CHECK_ROW_CACHE", "1")  # the Owner recounts every history table after each write and compares its cache

# One scratch root for every test store: RR_TEST_SCRATCH, else a short folder in the home directory, never the system Temp folder and never inside the repo
# (a nested Lean build under a long or in-repo path fails).
# Each process imports this once, and it always points tempfile at the root (so a temp dir made without dir= lands here and a failing run's
# stores stay for the founder to empty), sets TEMP/TMP there unless they already are, and records the root in RR_TEST_SCRATCH.
try:
    _default = Path.home() / "rr-test-scratch"
except (RuntimeError, KeyError, OSError):  # no home directory: the system temp folder is better than no tests
    _default = Path(tempfile.gettempdir()) / "rr-test-scratch"
SCRATCH_ROOT = Path(os.environ.get("RR_TEST_SCRATCH") or _default).resolve()
SCRATCH_ROOT.mkdir(parents=True, exist_ok=True)
os.environ["RR_TEST_SCRATCH"] = str(SCRATCH_ROOT)
for _name in ("TEMP", "TMP"):
    _value = os.environ.get(_name)
    if not _value or SCRATCH_ROOT not in (Path(_value).resolve(), *Path(_value).resolve().parents):
        os.environ[_name] = str(SCRATCH_ROOT)
tempfile.tempdir = os.environ["TEMP"]  # under the root: a test may point a child at a folder inside it
