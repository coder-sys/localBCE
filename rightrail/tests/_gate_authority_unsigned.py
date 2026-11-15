"""Test-only, signer-free authority fixture (docs/integration/TRUNK_STEP2_FRAME_DESIGN.md 7.1): the KEYSET/v2 genesis key set
and the APPROVAL/v2 TRANSFER grant of ``_gate_authority.standing()``, the same shape and the same fields, with placeholder
public keys (SHAKE-256 of the key's name, at the ML-DSA-87 public key size) and all-zero signatures of the ML-DSA-87
signature size.  Nothing here runs the signer.  Only ``gate_engine_unsigned`` (whose check accepts every signature)
admits it; the pinned ``gate_engine`` refuses it.  Selected only by ``RR_GATE_UNSIGNED=1`` (``_gate_shards._authority``).
Synthetic, non-PHI."""

from __future__ import annotations

from functools import lru_cache
import hashlib

from app import right_rail_gate_codec as gate
from app import right_rail_gate_decide as decider
from tests import _gate_authority as au
from tests import test_right_rail_gate_formats as fx

be, ident, H = au.be, au.ident, au.H


@lru_cache(maxsize=None)
def pk(name: str) -> bytes:
    """A placeholder public key: distinct per name, the ML-DSA-87 size, never a key anything can sign under."""
    return hashlib.shake_256(b"RR/TEST/UNSIGNED-PK\x00" + name.encode()).digest(gate.ML_DSA_87_PUBLIC_KEY)


def key_id(name: str) -> bytes:
    return H(b"RR/KEY/v1\x00" + pk(name))


def sig_block(signers: tuple[str, ...]) -> bytes:
    """``au.sig_block``'s layout (a count byte, then key id and signature, sorted) with zero signatures."""
    recs = sorted((key_id(n), bytes(gate.ML_DSA_87_SIGNATURE)) for n in set(signers))
    return be(len(recs), 1) + b"".join(k + s for k, s in recs)


def entry(name: str, revoked: int = au.LIVE) -> bytes:
    """``au.entry`` over the placeholder key."""
    role, emp, idp = au.KEYS[name]
    src = role == au.SOURCE
    return (key_id(name) + H(b"TEST/EMPLOYEE\x00" + emp.encode()) + H(b"TEST/IDP\x00" + idp.encode()) + be(role, 1)
            + be(1 if src else 0, 1) + be(1 if src else 0, 1) + be(20270101, 4) + be(20271231, 4) + be(revoked, 4)
            + be(0, 2) + be(0, 8) + be(len(pk(name)), 2) + pk(name))


def keyset_body(epoch: int = 0, prev: bytes = bytes(64), nb: int = au.NB, na: int = au.NA) -> bytes:
    """``au.keyset_body`` over the placeholder keys: roster r1, r2 (quorum 2), approvers a1..a3, sources s1, s2."""
    names = sorted(au.KEYS, key=key_id)
    return (b"RR/KEYSET/v2\x00" + au.STATE + be(epoch, 4) + prev + be(nb, 4) + be(na, 4) + be(2, 1) + be(2, 1) + be(len(names), 4)
            + b"".join(entry(n) for n in names))


def genesis() -> tuple[bytes, bytes]:
    """(pin, document) as ``au.genesis``: the pin is the SHA3-512 of the key-set body; the document is signed by r1, r2 (zeros)."""
    body = keyset_body()
    return H(body), body + sig_block(("r1", "r2"))


def grant(entries: list[tuple[str, int, int, int]], serial: int = 1) -> bytes:
    """``au.grant`` with its defaults (tenant, window, signers r1, r2, state), zero signatures."""
    body = be(serial, 8) + be(len(entries), 1) + b"".join(ident(p) + be(f, 1) + be(a, 1) + be(h, 4) for p, f, a, h in entries)
    return au._doc(1, au.TENANT, au.NB, au.NA, body, au.STATE) + sig_block(("r1", "r2"))


def grant_id(doc: bytes) -> bytes:
    """The grant id as Lean's ``encDoc`` digest: the SHA3-512 of the document before its signature block, found by parsing the
    document from the front (the host's ``_approval``).  Not ``au.grant_id``: its ``fx.unsigned`` finds the block from the end
    by its count byte, and a zero signature's last byte reads as a count of 0, so it would cut one byte."""
    got = decider._approval(doc)
    if got is None or got[0] != 1:
        raise ValueError("not an APPROVAL/v2 grant")
    if H(doc[:len(doc) - len(sig_block(("r1", "r2")))]) != got[1]:
        raise ValueError("the parsed grant id is not the digest of the document before its signature block")
    return got[1]


def standing() -> tuple[bytes, decider.Keys]:
    """``au.standing()``'s authority: a TRANSFER grant (holds 0) for the harness program (claims and SDP) and the genesis key set."""
    return grant([(fx.PROGRAM, 1 << 1 | 1 << 3, 3, 0)]), decider.Keys(genesis()[1])
