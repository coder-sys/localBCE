import hashlib
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONF = os.path.join(ROOT, "conformance")
# The README indexes the kit and the manifest cannot list itself; every other file is pinned.
UNPINNED = {"README.md", "MANIFEST.sha256"}


def listed():
    with open(os.path.join(CONF, "MANIFEST.sha256"), encoding="utf-8") as f:
        return dict(line.split("  ", 1)[::-1] for line in f.read().splitlines())


class ConformanceManifest(unittest.TestCase):
    def test_every_conformance_file_is_pinned_with_its_digest(self):
        pins = listed()
        found = []
        for base, dirs, names in os.walk(CONF):
            dirs[:] = [d for d in dirs if d != "__pycache__"]  # Python's own byte-code cache from running a reference reader, not a kit file
            for n in names:
                rel = os.path.relpath(os.path.join(base, n), ROOT).replace(os.sep, "/")
                if rel[len("conformance/"):] not in UNPINNED:
                    found.append(rel)
        self.assertTrue(found)
        for rel in sorted(found):
            self.assertIn(rel, pins, f"{rel} is not listed in conformance/MANIFEST.sha256")
            with open(os.path.join(ROOT, rel), "rb") as g:
                self.assertEqual(hashlib.sha256(g.read()).hexdigest(), pins[rel], rel)


if __name__ == "__main__":
    unittest.main()
