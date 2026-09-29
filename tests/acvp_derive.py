"""Derive the committed ML-DSA-87 ACVP line files from NIST's ACVP-Server JSON.

    python -m tests.acvp_derive <directory holding the nine JSON files named <set>.<prompt|expectedResults>.json>

Source: https://github.com/usnistgov/ACVP-Server, ``gen-val/json-files/ML-DSA-{keyGen,sigGen,sigVer}-FIPS204/``
{prompt,expectedResults}.json at commit ``COMMIT``.  Only ML-DSA-87 groups are read.  Every message is
M' (FIPS 204's input to Sign_internal / Verify_internal): an external pure case has ``0 || |ctx| || ctx || msg``.
HashML-DSA (``preHash``) and ``externalMu`` groups are excluded, since the gate uses neither; the headers count them.
Writes ``gate_vectors/mldsa87_acvp_gen.vectors`` (keygen, siggen: the worker, Python) and
``gate_vectors/mldsa87_acvp.vectors`` (sigVer: the worker and the Lean ``gate_vectors``).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

COMMIT = "975de31eb83d87039ec88934fdc47d8c312b892d"
OUT = Path(__file__).resolve().parent / "gate_vectors"
BASE = f"https://raw.githubusercontent.com/usnistgov/ACVP-Server/{COMMIT}/gen-val/json-files"


def _load(source: Path, name: str, header: list[str]) -> tuple[list[dict], dict[tuple[int, int], dict]]:
    sets = []
    for kind in ("prompt", "expectedResults"):
        data = (source / f"ML-DSA-{name}-FIPS204.{kind}.json").read_bytes()
        header.append(f"# {BASE}/ML-DSA-{name}-FIPS204/{kind}.json sha256 {hashlib.sha256(data).hexdigest()} bytes {len(data)}")
        sets.append(json.loads(data))
    expected = {(g["tgId"], t["tcId"]): t for g in sets[1]["testGroups"] for t in g["tests"]}
    return [g for g in sets[0]["testGroups"] if g["parameterSet"] == "ML-DSA-87"], expected


def _kind(group: dict) -> str:
    if group["signatureInterface"] == "internal":
        return "internal-externalMu" if group["externalMu"] else "internal"
    return "external-" + group["preHash"]


def _message(group: dict, test: dict) -> str:
    kind = _kind(group)
    if kind == "internal":
        return test["message"].lower()
    context = bytes.fromhex(test["context"])
    return (bytes([0, len(context)]) + context + bytes.fromhex(test["message"])).hex()


def derive(source: Path) -> tuple[str, str]:
    gen = [f"# ML-DSA-87 ACVP keyGen and sigGen vectors (FIPS 204), derived by tests/acvp_derive.py; upstream commit {COMMIT}"]
    ver = [f"# ML-DSA-87 ACVP sigVer vectors (FIPS 204), derived by tests/acvp_derive.py; upstream commit {COMMIT}"]
    for name, header, lines in (("keyGen", gen, gen), ("sigGen", gen, gen), ("sigVer", ver, ver)):
        groups, expected = _load(source, name, header)
        for group in groups:
            included = name == "keyGen" or _kind(group) in ("internal", "external-pure")
            header.append(f"# {'included' if included else 'excluded'} {name} tgId={group['tgId']} {_kind(group) if name != 'keyGen' else 'aft'} tests={len(group['tests'])}")
            for test in group["tests"] if included else ():
                answer = expected[(group["tgId"], test["tcId"])]
                if name == "keyGen":
                    lines.append(f"keygen {test['seed'].lower()} {answer['pk'].lower()} {answer['sk'].lower()}")
                elif name == "sigGen":
                    rnd = "00" * 32 if group["deterministic"] else test["rnd"].lower()
                    lines.append(f"siggen {test['sk'].lower()} {rnd} {_message(group, test)} {answer['signature'].lower()}")
                else:
                    lines.append(f"mldsa87 {'accept' if answer['testPassed'] else 'reject'} {test['pk'].lower()} {_message(group, test)} {test['signature'].lower()}")
    ver.append(f"end {sum(line.startswith('mldsa87 ') for line in ver)}")
    return "\n".join(gen) + "\n", "\n".join(ver) + "\n"


if __name__ == "__main__":
    gen, ver = derive(Path(sys.argv[1]))
    (OUT / "mldsa87_acvp_gen.vectors").write_text(gen, "ascii", newline="\n")
    (OUT / "mldsa87_acvp.vectors").write_text(ver, "ascii", newline="\n")
