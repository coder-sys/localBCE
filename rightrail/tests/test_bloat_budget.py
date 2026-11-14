"""Duplication checks for the trunk: no copied code files, a bounded amount of copy-paste,
no per-team status files. Neither code nor documents have a line limit: size is judged by
the design (fewer parts, one copy of each rule), not by a count.
"""

import hashlib
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKIP_DIRS = {".git", ".lake", "__pycache__", "node_modules", "target", "parked", ".venv", "build", ".pytest_cache"}
CODE_EXTS = {".py", ".lean", ".js", ".rs", ".c", ".h", ".cpp", ".ps1", ".css", ".html"}
FORBIDDEN_NAMES = {"CURRENT_TASK.md", "STATE.md", "AGENTS.override.md"}
# Copy-paste: repeated 6-line windows (>=120 chars) across product Python.
# Independent checkers may restate a small shared schema by design; the rest
# is duplication to delete.
PRODUCT_DIRS = ("app", "tools", os.path.join("provider_app", "provider_app"))
DUPLICATED_WINDOWS = 210


def _live_files():
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            yield os.path.join(dirpath, name)


class BloatBudgetTest(unittest.TestCase):

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
