"""Size budget for the trunk (CONSTITUTION Art. IX, X.1, XI).

Ceilings only ratchet down. Raising one needs a commit message that names the
felt effect (Art. XII) the extra size buys; lower them whenever work shrinks
the code (the core-v8 merge must lower the core-file ceilings).
"""

import hashlib
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKIP_DIRS = {".git", ".lake", "__pycache__", "node_modules", "target", "parked", ".venv", "build"}
CODE_EXTS = {".py", ".lean", ".js", ".rs", ".c", ".h", ".cpp", ".ps1", ".css", ".html"}

LIVE_CODE_LINES = 88_000
MARKDOWN_FILES = 20
MARKDOWN_BYTES = 180_000
STATUS_BYTES = 40_000
CORE_FILE_LINES = {
    "app/right_rail_financial_owner.py": 7_220,
    "app/right_rail_financial_owner_independent.py": 4_957,
    "app/right_rail_financial_semantic_adapter.py": 2_250,
    "app/right_rail_financial_mirror.py": 1_750,
    "app/right_rail_financial_engine.py": 1_520,
    "app/right_rail_financial_switch.py": 1_400,
    "tools/continuity_successor_v7.py": 2_400,
}
FORBIDDEN_NAMES = {"CURRENT_TASK.md", "STATE.md", "AGENTS.override.md"}
# Copy-paste: repeated 6-line windows (>=120 chars) across product Python.
# Independent checkers may restate a small shared schema by design; the rest
# is duplication to delete.
PRODUCT_DIRS = ("app", "tools", os.path.join("provider_app", "provider_app"))
DUPLICATED_WINDOWS = 870


def _live_files():
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            yield os.path.join(dirpath, name)


def _lines(path):
    with open(path, "rb") as handle:
        return handle.read().count(b"\n")


class BloatBudgetTest(unittest.TestCase):
    def test_live_code_stays_under_ceiling(self):
        total = sum(_lines(p) for p in _live_files() if os.path.splitext(p)[1].lower() in CODE_EXTS)
        self.assertLessEqual(total, LIVE_CODE_LINES)

    def test_core_files_stay_under_ceiling(self):
        for rel, ceiling in CORE_FILE_LINES.items():
            with self.subTest(rel):
                self.assertLessEqual(_lines(os.path.join(ROOT, rel)), ceiling)

    def test_markdown_stays_small(self):
        docs = [p for p in _live_files() if p.endswith(".md")]
        self.assertLessEqual(len(docs), MARKDOWN_FILES)
        self.assertLessEqual(sum(os.path.getsize(p) for p in docs), MARKDOWN_BYTES)
        self.assertLessEqual(os.path.getsize(os.path.join(ROOT, "STATUS.md")), STATUS_BYTES)

    def test_no_per_team_status_files(self):
        found = [os.path.relpath(p, ROOT) for p in _live_files() if os.path.basename(p) in FORBIDDEN_NAMES]
        self.assertEqual(found, [])

    def test_no_exact_duplicate_code_files(self):
        seen = {}
        duplicates = []
        for path in _live_files():
            if os.path.splitext(path)[1].lower() not in CODE_EXTS:
                continue
            with open(path, "rb") as handle:
                data = handle.read()
            if len(data) <= 200:
                continue
            digest = hashlib.sha256(data).hexdigest()
            if digest in seen:
                duplicates.append((os.path.relpath(seen[digest], ROOT), os.path.relpath(path, ROOT)))
            else:
                seen[digest] = path
        self.assertEqual(duplicates, [])

    def test_copy_paste_stays_under_ceiling(self):
        windows = {}
        for top in PRODUCT_DIRS:
            for dirpath, dirnames, filenames in os.walk(os.path.join(ROOT, top)):
                dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
                for name in filenames:
                    if not name.endswith(".py"):
                        continue
                    with open(os.path.join(dirpath, name), encoding="utf-8") as handle:
                        lines = [line.strip() for line in handle]
                    lines = [line for line in lines if line and not line.startswith("#")]
                    for start in range(len(lines) - 5):
                        text = "\n".join(lines[start:start + 6])
                        if len(text) >= 120:
                            windows[text] = windows.get(text, 0) + 1
        repeated = sum(count for count in windows.values() if count > 1)
        self.assertLessEqual(repeated, DUPLICATED_WINDOWS)


if __name__ == "__main__":
    unittest.main()
