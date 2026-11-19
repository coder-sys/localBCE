"""Synthetic data for the gate rules vectors (test-only; invented IDs, no PHI).

``pin FILE`` replaces each ``snap KIND ASOF COUNT ?`` with the pin of the KIND
rows after it (``pinInput`` in ``lean/BlindLedger/Gate/Rules/Spec.lean``); the
author declares COUNT.  Each ``anchor ?`` becomes the state digest (``stateDigest``
in ``lean/BlindLedger/Gate/Spec.lean``) of the latest released and unresolved snaps.  No rule is evaluated here; the
Lean runner decides and compares every line.  The generator of the retired ``demo_zz.vectors`` was deleted (git keeps
it); ``demo_zz_v2.vectors`` is that file with one fixed ``elig`` row per member inserted.
"""

import hashlib
import sys

KINDS = ("dmf", "pdeath", "excl", "span", "released", "unresolved", "elig")  # kind = position + 1: elig is kind 7
FLOWS = ("FFS_CYCLE", "FFS_CLAIM", "CAP_820")
ID, PAY = 129, 261
LINE = (ID, PAY, 1, ID, ID, ID, 4, ID, 4, 8)
WIDTHS = {"dmf": (ID, 4), "pdeath": (ID, 4), "excl": (ID, 4, 4), "span": (ID, ID, 4, 4), "released": LINE,
          "unresolved": LINE, "elig": (ID, ID, 1, 4, 4)}


def row(kind, fields):
    if WIDTHS[kind] is LINE:
        i, _, p = fields[0].partition(":")
        fields = [i, p or i, FLOWS.index(fields[1]) + 1] + fields[2:]
    return b"".join(int(v).to_bytes(w, "big") for w, v in zip(WIDTHS[kind], fields, strict=True))


def pin(lines):
    out = list(lines)
    for i, line in enumerate(out):
        f = line.split()
        if f[:1] == ["snap"] and f[4] == "?":
            rows = []
            for later in out[i + 1:]:
                g = later.split()
                if g[:2] in (["snap", f[1]], ["drop", f[1]]):
                    break
                if g[:1] == [f[1]]:
                    rows.append(row(f[1], g[1:]))
            domain = f"RR/GATE/{f[1].upper()}/v1" if f[1] in ("released", "unresolved") else "RR/GATE/SNAPSHOT/v1"
            head = b"".join(int(v).to_bytes(4, "big") for v in (KINDS.index(f[1]) + 1, f[2], f[3]))
            data = domain.encode() + b"\0" + head + b"".join(sorted(rows))
            out[i] = " ".join(f[:4] + [hashlib.sha3_512(data).hexdigest()])
        elif f == ["anchor", "?"]:
            pins = {g[1]: bytes.fromhex(g[4]) for g in map(str.split, out[:i]) if g[:1] == ["snap"]}
            out[i] = "anchor " + hashlib.sha3_512(b"RR/GATE/STATE/v1\0" + pins["released"] + pins["unresolved"]).hexdigest()
    return out


def main(command, path):
    if command != "pin":
        return 2
    with open(path, encoding="utf-8") as f:
        lines = pin(f.read().splitlines())
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
