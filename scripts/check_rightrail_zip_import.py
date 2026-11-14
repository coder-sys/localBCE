#!/usr/bin/env python3
"""Compare rightrail/ with the RightRail trunk zip it was imported from (docs/integration/RIGHTRAIL_IMPORTED_FROM.md).

Usage: python3 scripts/check_rightrail_zip_import.py PATH/TO/rightrail-rightrail-main.zip
Exits 0 when the zip hash and archive comment match the record and every file matches byte for byte, except the
local changes listed in LOCAL_CHANGES.
"""
import hashlib
import pathlib
import sys
import zipfile

ZIP_SHA256 = "1afbc74dc3cf3f5a97c494a196f0c0e0a2d3938abdd16c76b8ce09d36ba0ab71"
COMMIT = "fc89f9e5ceaacfbfb0cb50173a4fd870e3872a3f"
PREFIX = "rightrail-rightrail-main/"
LOCAL_CHANGES = {"tests/test_privacy_artifact_scan.py"}


def main(zip_path: str) -> int:
    root = pathlib.Path(__file__).resolve().parents[1] / "rightrail"
    data = pathlib.Path(zip_path).read_bytes()
    if hashlib.sha256(data).hexdigest() != ZIP_SHA256:
        print("FAIL: zip SHA-256 does not match the record")
        return 1
    z = zipfile.ZipFile(zip_path)
    if z.comment.decode() != COMMIT:
        print("FAIL: archive comment is not", COMMIT)
        return 1
    zipped = {i.filename[len(PREFIX):]: i for i in z.infolist() if not i.is_dir()}
    local = {str(p.relative_to(root)).replace("\\", "/") for p in root.rglob("*") if p.is_file()
             and not str(p.relative_to(root)).replace("\\", "/").startswith("lean/.lake/")}
    problems = sorted(f"missing: {f}" for f in zipped.keys() - local)
    problems += sorted(f"extra: {f}" for f in local - zipped.keys())
    for name in sorted(zipped.keys() & local):
        if (root / name).read_bytes() != z.read(zipped[name]) and name not in LOCAL_CHANGES:
            problems.append(f"differs: {name}")
    changed = sorted(n for n in LOCAL_CHANGES if (root / n).read_bytes() != z.read(zipped[n]))
    for p in problems:
        print(p)
    print(f"{len(zipped)} zip files; local changes present: {', '.join(changed) or 'none'}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
