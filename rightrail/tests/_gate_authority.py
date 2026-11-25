"""Signed authority fixtures: a key set, its successor, and APPROVAL/v2 grants and bypasses, all from fixed test-only seeds
(``fx.det_sign``: ML-DSA-87, rnd = 0, so every byte is reproducible).  Synthetic, non-PHI."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from app import right_rail_deployment_slots as slots
from app import right_rail_gate_codec as gate
from app import right_rail_gate_decide as decider
from tests import test_right_rail_gate_formats as fx

H = gate.sha3_512
LIVE = 0xFFFFFFFF
TENANT = fx.TENANT
STATE = H(b"TEST/STATE")
TODAY = 20270315
NB, NA = 20270301, 20270331  # the genesis key set's life; the grant and bypass windows default to it
SOURCE, APPROVER, ROSTER, POLICY = 1, 2, 5, 6
# name -> (role, employee, identity-provider subject); a3 shares a1's subject
KEYS = {"r1": (ROSTER, "ann", "ann"), "r2": (ROSTER, "bo", "bo"), "a1": (APPROVER, "cy", "sso-cy"),
        "a2": (APPROVER, "di", "sso-di"), "a3": (APPROVER, "ed", "sso-cy"), "s1": (SOURCE, "fay", "fay"),
        "s2": (SOURCE, "gus", "gus")}


def be(n: int, w: int) -> bytes:
    return n.to_bytes(w, "big")


def ident(b: str | bytes) -> bytes:
    b = b.encode() if isinstance(b, str) else b
    return be(len(b), 2) + b


@lru_cache(maxsize=None)
def pk(name: str) -> bytes:
    return fx.keypair("authority-" + name)[0]


def key_id(name: str) -> bytes:
    return H(b"RR/KEY/v1\x00" + pk(name))


def sig_block(signers: tuple[str, ...], msg: bytes) -> bytes:
    recs = sorted((key_id(n), fx.det_sign("authority-" + n, msg)) for n in set(signers))
    return be(len(recs), 1) + b"".join(k + s for k, s in recs)


def entry(name: str, revoked: int = LIVE, keys: dict = KEYS) -> bytes:
    """A key's entry; `keys[name]` is (role, employee, subject) or, with its own validity window, (role, employee,
    subject, valid_from, valid_until)."""
    role, emp, idp, *window = keys[name]
    valid_from, valid_until = window or (20270101, 20271231)
    src = role == SOURCE
    return (key_id(name) + H(b"TEST/EMPLOYEE\x00" + emp.encode()) + H(b"TEST/IDP\x00" + idp.encode()) + be(role, 1)
            + be(1 if src else 0, 1) + be(1 if src else 0, 1) + be(valid_from, 4) + be(valid_until, 4) + be(revoked, 4)
            + be(0, 2) + be(0, 8) + be(len(pk(name)), 2) + pk(name))


def keyset_body(epoch: int = 0, prev: bytes = bytes(64), nb: int = NB, na: int = NA, revoked: dict | None = None,
                extra: dict | None = None, k_policy: int = 2) -> bytes:
    """KEYSET/v2 body: roster keys r1, r2 (employees ann, bo; quorum 2), approvers a1..a3, sources s1, s2, and the keys
    `extra` names (as KEYS does).  The POLICY threshold byte `k_policy` follows the entries only when some key is POLICY,
    so without `extra` the body is the one every gate suite signs."""
    keys = KEYS | (extra or {})
    names = sorted(keys, key=key_id)
    tail = be(k_policy, 1) if any(keys[n][0] == POLICY for n in names) else b""
    return (b"RR/KEYSET/v2\x00" + STATE + be(epoch, 4) + prev + be(nb, 4) + be(na, 4) + be(2, 1) + be(2, 1) + be(len(names), 4)
            + b"".join(entry(n, (revoked or {}).get(n, LIVE), keys) for n in names) + tail)


def keyset_doc(body: bytes, signers: tuple[str, ...] = ("r1", "r2")) -> bytes:
    return body + sig_block(signers, H(b"RR/KEYSET/v2/SIG\x00" + body))


def genesis() -> tuple[bytes, bytes]:
    """(pin, document): the pin is the genesis key set's digest, which `flat init` takes."""
    body = keyset_body()
    return H(body), keyset_doc(body)


def kstep(revoked: dict | None = None, day: int = TODAY, nb: int = 20270310, na: int = 20270409) -> tuple[int, bytes]:
    """(day, document) of the epoch-1 key set that succeeds the genesis one."""
    return day, keyset_doc(keyset_body(1, genesis()[0], nb, na, revoked))


def _doc(kind: int, tenant: str, nb: int, na: int, body: bytes, state: bytes) -> bytes:
    return b"RR/GATE/APPROVAL/v2\x00" + be(kind, 1) + state + ident(tenant) + be(nb, 4) + be(na, 4) + body


def _signed(unsigned: bytes, signers: tuple[str, ...]) -> bytes:
    return unsigned + sig_block(signers, H(b"RR/GATE/APPROVAL/v2/SIG\x00" + unsigned))


def grant(entries: list[tuple[str, int, int, int]], serial: int = 1, tenant: str = TENANT, nb: int = NB, na: int = NA,
          signers: tuple[str, ...] = ("r1", "r2"), state: bytes = STATE) -> bytes:
    """A grant; each entry is (program, flow mask, authority byte 1 OBSERVE / 2 HOLD / 3 TRANSFER, holds mask)."""
    body = be(serial, 8) + be(len(entries), 1) + b"".join(ident(p) + be(f, 1) + be(a, 1) + be(h, 4) for p, f, a, h in entries)
    return _signed(_doc(1, tenant, nb, na, body, state), signers)


def bypass(program: str, payment: str, request: bytes, overrides: int, tenant: str = TENANT, nb: int = NB, na: int = NA,
           signers: tuple[str, ...] = ("a1", "a2"), state: bytes = STATE) -> bytes:
    """A bypass of one payment; `request` is the 64-byte digest of the DECIDE-REQUEST bytes it was signed for."""
    return _signed(_doc(2, tenant, nb, na, ident(program) + ident(payment) + request + be(overrides, 4), state), signers)


def cause(reason: int, entries: list[tuple[str, bytes, int]], flows: int = 1 << 1, dates: tuple[int, int] = (NB, NA),
          total: int | None = None, tenant: str = TENANT, nb: int = NB, na: int = NA, signers: tuple[str, ...] = ("a1", "a2"),
          state: bytes = STATE) -> bytes:
    """A release by cause of the harness program: the reason's fixed bit number, the flow mask, the service-date range, the
    total (the amounts' sum unless given) and the entries (payment id, request digest, amount in cents) in the order given."""
    body = (be(reason, 1) + ident(fx.PROGRAM) + be(flows, 1) + be(dates[0], 4) + be(dates[1], 4)
            + be(sum(a for _, _, a in entries) if total is None else total, 8) + be(len(entries), 2)
            + b"".join(ident(p) + d + be(a, 8) for p, d, a in entries))
    return _signed(_doc(3, tenant, nb, na, body, state), signers)


def grant_id(doc: bytes) -> bytes:
    """A grant's id: the digest of its unsigned bytes (the id Lean prints in each `RULES_PAY` line)."""
    return H(fx.unsigned(doc))


def standing() -> tuple[bytes, decider.Keys]:
    """The one authority the batch tests decide under: a TRANSFER grant for the harness program (claims and SDP) and the genesis key set."""
    return grant([(fx.PROGRAM, 1 << 1 | 1 << 3, 3, 0)]), decider.Keys(genesis()[1])


def tenant(floor_path, shards, pin: bytes | None = None, tenant_id: str = TENANT, rulesets=(),
           ruleset_folder=None) -> decider.TenantAuthority:
    """The tenant's authority over ``shards`` (every shard of the tenant, open): its deployment slot naming the genesis key
    set's pin (or ``pin``), its grant floor file (provisioned the first time), and its signed rule-set records (given, and
    in ``ruleset_folder``)."""
    pack = {"GATE_KEYSET_PIN": [[tenant_id, (genesis()[0] if pin is None else pin).hex()]]}
    if not Path(floor_path).exists():
        decider.TenantAuthority.provision(floor_path, tenant_id, shards)
    return decider.TenantAuthority(slots.Slots(pack), tenant_id, floor_path, shards, rulesets, ruleset_folder)


def digest(request_bytes: bytes) -> bytes:
    return H(request_bytes)
