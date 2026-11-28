"""Gate formats #1-#4 and #12: encoder laws, batch builder, golden vectors.

``tests/gate_vectors/gate_v1.vectors`` is produced by ``build_vectors`` with the
worker's deterministic known-answer signer (``python -m tests.test_right_rail_gate_formats``: every key is
a test-only seed, every signature has rnd = 0) and judged by the Lean ``gate_vectors`` executable, the only
decoder and verifier.  Here Python must reproduce every byte of it, Lean must accept it, and ``seal`` must
release a signature only when the pinned Lean ``gate_verify`` accepts.  Synthetic, non-PHI.
"""

from __future__ import annotations

import contextlib
import functools
import itertools
from dataclasses import replace
import hashlib
from itertools import count, permutations
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from app import right_rail_gate_chain as flatchain
from app import right_rail_gate_codec as gate
from app import right_rail_gate_payer as payer
from app import right_rail_gate_signer as signer
from tools import gate_rules_data

VECTORS = Path(__file__).resolve().parent / "gate_vectors" / "gate_v1.vectors"
RULES = VECTORS.parents[1] / "gate_rules" / "rules_v1.vectors"
TENANT, OTHER, STANDBY, SELF, PROGRAM, PERIOD = "nc-dhhs", "nc-other", "nc-standby", "nc-self", "medicaid-ffs", "2026-09"
EPOCH, NOW, EXPIRES = 7, 1_790_000_000, 1_790_086_400
DECIDED = NOW - 3600
D = [gate.sha3_512(bytes([i])) for i in range(17)]
SHARDS, SHARD, OTHER_SHARDS = 8, 3, 4  # shard counts, and the shard of the main batch
# Epoch certificates: epoch, tenant, shard count.  Each has its own test-only key; each tenant's root key signs them.
CERTS = {"e7": (EPOCH, TENANT, SHARDS), "e6": (EPOCH - 1, TENANT, SHARDS), "other": (EPOCH, OTHER, OTHER_SHARDS),
         "bad": (EPOCH, TENANT, SHARDS), "reshard": (EPOCH - 2, TENANT, 2 * SHARDS), "other8": (EPOCH + 1, OTHER, OTHER_SHARDS),
         "e8": (EPOCH + 1, TENANT, SHARDS), "reshard-e9": (EPOCH + 2, TENANT, 2 * SHARDS),
         "reshard-other9": (EPOCH + 2, OTHER, 2 * OTHER_SHARDS), "twin": (EPOCH + 1, OTHER, OTHER_SHARDS),
         "sb1": (1, STANDBY, OTHER_SHARDS), "sb2": (2, STANDBY, OTHER_SHARDS), "eq5": (5, STANDBY, OTHER_SHARDS),
         "sf1": (1, SELF, OTHER_SHARDS), "sf4": (4, SELF, OTHER_SHARDS), "e0": (0, TENANT, SHARDS)}
CHECKED = ("cert", "payment", "checkpoint", "token", "release", "request", "response", "reissue", "redecide",
           "decision-id", "input", "lines-root", "state", "context", "input7", "batch-input", "answer")
# The rules' empty released and unresolved sets, pinned as tests/gate_rules/rules_v1.vectors pins them
PINS = tuple(bytes.fromhex(gate_rules_data.pin([f"snap {kind} 20270315 0 ?"])[0].split()[4])
             for kind in ("released", "unresolved"))
STATE = gate.sha3_512(b"RR/GATE/STATE/v1\x00" + b"".join(PINS))  # Lean checks the STATE/v1 digest; the app no longer builds it


def input_v1(request, read_set: bytes) -> bytes:  # INPUT/v1, kept only as a Lean vector input
    body = gate.encode_decide_request(request)
    return gate.sha3_512(b"RR/GATE/INPUT/v1\x00" + len(body).to_bytes(4, "big") + body + read_set)

def synthetic_input(request, head: bytes) -> bytes:
    """A stand-in input commitment for a hand-made token (the real one is Lean's INPUT/v6; ``frame_inputs`` recomputes it)."""
    return gate.sha3_512(b"RR/GATE/TEST-ONLY-INPUT/v4\x00" + gate.encode_decide_request(request) + head)


def request_parts(x: bytes) -> tuple[bytes, list[bytes], bytes]:
    """DECIDE-REQUEST/v2 bytes cut as the payment digest reads them: the bytes before the lines (the domain, the fields
    and the line count), each line's bytes, then the bytes after the lines (the evidence count and references, then the
    contest flag)."""
    ident = lambda a: a + 2 + int.from_bytes(x[a:a + 2], "big")
    at = ident(ident(len(gate.DECIDE_REQUEST)))  # tenant, program
    at = ident(ident(at + 1)) + 32  # flow tag, command key, payment id, member key
    at = ident(ident(at) + 8)  # payee, amount, period
    n, at = int.from_bytes(x[at:at + 2], "big"), at + 2
    head, lines = x[:at], []
    for _ in range(n):
        ln = int.from_bytes(x[at:at + 2], "big")
        lines.append(x[at + 2:at + 2 + ln])
        at += 2 + ln
    return head, lines, x[at:]


def input_v7(ctx: bytes, request: bytes) -> bytes:
    """INPUT/v7, written out again from the format: the context digest, the request's bytes before its lines after a
    4-byte length, the root of its lines, then its bytes after them."""
    head, lines, tail = request_parts(request)
    return gate.sha3_512(b"RR/GATE/INPUT/v7\x00" + ctx + len(head).to_bytes(4, "big") + head + gate.lines_root(lines) + tail)


def batch_input(ctx: bytes, rqs: list[bytes]) -> bytes:
    return gate.sha3_512(b"RR/GATE/BATCH-INPUT/v1\x00" + ctx + b"".join(rqs))


def answer_frame(status: int, shard: int, batch: int, digest: bytes, recs: list[tuple[int, int, int, int, int, int]] = (),
                 leaves: list[tuple[int, int, int, int, bytes, bytes]] = (), notes: list[bytes] = (), adds: list[bytes] = (),
                 grant: bytes = bytes(64), auth: bytes = bytes(flatchain.AUTH)) -> bytes:
    """An engine answer, written out again from conformance/FRAME_V1.md section 4 and ENGINE_V3.md section 17: the 87-byte
    header (version 4), then (status 0 only) the 20-byte records (index, outcome, rule, u64 reasons, chunk, row), head,
    root and the
    extension (hold word, grant id, the ``flatchain.AUTH``-byte authority record, notes), each leaf ``(outcome, reasons, authority, flag,
    bypass id or earlier list, input)`` with u64 reasons: flag 1 carries the bypass id, flag 2 the earlier list after a
    2-byte length."""
    le = lambda n, w: n.to_bytes(w, "little")
    out = b"RRDA" + le(4, 2) + le(status, 1) + le(shard, 4) + le(batch, 8) + le(len(recs), 4) + digest
    if status:
        return out
    out += b"".join(le(i, 3) + le(o, 1) + le(u, 1) + le(m, 8) + le(c, 4) + le(w, 3) for i, o, u, m, c, w in recs)
    out += D[13] + D[14] + bytes(16) + grant + auth + le(len(notes), 4) + b"".join(le(len(n), 2) + n for n in notes)
    out += le(len(leaves), 4) + b"".join(le(o, 1) + le(m, 8) + le(a, 1) + le(f, 1) + (b if f == 1 else le(len(b), 2) + b if f == 2 else b"") + x
                                         for o, m, a, f, b, x in leaves)
    return out + le(len(adds), 4) + b"".join(le(len(r), 2) + r for r in adds)


def unsigned(doc: bytes) -> bytes:
    """An APPROVAL/v2 or KEYSET/v2 document without its signature block (a count byte, then key id and signature each)."""
    for n in range(10):
        cut = len(doc) - 1 - n * (64 + gate.ML_DSA_87_SIGNATURE)
        if cut > 0 and doc[cut] == n:
            return doc[:cut]
    raise ValueError("no signature block")


def frame_commitments(frame: bytes) -> tuple[bytes, dict[bytes, bytes]]:
    """The batch identity and, by request bytes, each request's INPUT/v7, read from the binary request frame the way
    conformance/FRAME_V1.md says: the context is CONTEXT/v1 over the body before its request count."""
    body, at = frame[82:], 0

    def take(n: int) -> bytes:
        nonlocal at
        at += n
        assert at <= len(body)
        return body[at - n:at]

    num = lambda n: int.from_bytes(take(n), "little")
    blob = lambda: take(num(4))
    _, _, _, nredo = num(4), num(4), take(64), num(4)
    descs = [take(77) for _ in range(4)]
    for d, width in zip(descs, (37, 25, 29, 62)):
        take(int.from_bytes(d[9:13], "little") * width)
    take(261 * nredo)
    take(64 + 13 + 4 + 64)  # pin, floors (serial, epoch), rsv and rs
    blob(), blob(), blob()
    for _ in range(num(4)):
        take(4)
        blob()
    for _ in range(2):  # the bypasses, then the rule-set records
        for _ in range(num(4)):
            blob()
    ctx = gate.sha3_512(b"RR/GATE/CONTEXT/v1\x00" + body[:at])
    reqs = [blob() for _ in range(num(4))]
    assert at == len(body)
    rqs = [input_v7(ctx, r) for r in reqs]
    return batch_input(ctx, rqs), dict(zip(reqs, rqs))


def frame_inputs(frame: bytes) -> dict[bytes, bytes]:
    return frame_commitments(frame)[1]


PROCS = ("99213", "99214", "99215")


def seed(name: str) -> bytes:
    return gate.sha3_512(b"RR/GATE/TEST-ONLY-SEED/v1\x00" + name.encode())[:32]


def _kat(mode: str, data: bytes, size: int) -> bytes:
    return signer._run(signer.BINARY, signer.PIN, (mode,), data, size)


@functools.cache
def keypair(name: str) -> tuple[bytes, bytes]:
    """(public key, secret key) of a test-only key: ``name`` is a certificate name or ``root-<tenant>``."""
    pair = _kat("kat-keygen", seed(name), gate.ML_DSA_87_PUBLIC_KEY + 4896)
    return pair[: gate.ML_DSA_87_PUBLIC_KEY], pair[gate.ML_DSA_87_PUBLIC_KEY :]


def det_sign(name: str, message: bytes, rnd: bytes = bytes(32)) -> bytes:
    """Deterministic (rnd = 0 unless given) pure ML-DSA-87 with an empty context: M' = 00 00 || message."""
    return _kat("kat-sign", keypair(name)[1] + rnd + b"\x00\x00" + message, gate.ML_DSA_87_SIGNATURE)


def _blob(x: bytes) -> bytes:
    return len(x).to_bytes(2, "big") + x


@functools.cache
def link(tenant: str) -> bytes:
    """The tenant's test-only AUTHORITY-LINK/v1, generation 0: root key ``root-<tenant>``, witness key ``witness-<tenant>``,
    each committing to a next key, signed by both."""
    key = lambda name: gate.encode_key(keypair(f"{name}-{tenant}")[0])
    body = (gate.LINK + _blob(tenant.encode()) + bytes(8) + bytes(64) + b"\x00" + key("root") + gate.sha3_512(key("root-next"))
            + key("witness") + gate.sha3_512(key("witness-next")) + bytes(9) + gate.sha3_512(b"RR/GATE/TEST-ONLY-APPROVAL/v1\x00"))
    return body + _blob(det_sign(f"root-{tenant}", body)) + _blob(det_sign(f"witness-{tenant}", body))


def link_digest(tenant: str) -> bytes:
    return gate.sha3_512(gate.read_link(link(tenant)).body)


VREL = gate.sha3_512(b"RR/GATE/TEST-ONLY-VERIFIER-RELEASE/v1\x00")


def cosign_record(header: bytes, tenant: str = TENANT) -> bytes:
    """The tenant's test verifier's cosign record for a checkpoint ``header`` (its release VREL)."""
    return gate.encode_cosign(VREL, det_sign(f"verifier-{tenant}", gate.cosign_message(header, VREL)))


def cosigner(tenant: str = TENANT):
    """The cosign callable ``signer.seal`` takes: a signed checkpoint (header and signature) to its cosign record."""
    return lambda signed_header: cosign_record(signed_header[: -2 - gate.ML_DSA_87_SIGNATURE], tenant)


def cert_body(name: str, public_key: bytes | None = None) -> bytes:
    """The body the root and witness keys sign for certificate ``name``: its epoch key (``name``'s test key unless given),
    its tenant's verifier key and its one shard count, under its tenant's link."""
    epoch, tenant, shards = CERTS[name]
    return gate.encode_key_cert(tenant, epoch, link_digest(tenant), (shards,), public_key or keypair(name)[0], keypair(f"verifier-{tenant}")[0])


def certify(body: bytes, tenant: str, rnd: bytes = bytes(32)) -> bytes:
    """A certificate body signed by ``tenant``'s root key and countersigned by its witness key."""
    return gate.attach_signatures(body, det_sign(f"root-{tenant}", body, rnd), det_sign(f"witness-{tenant}", body, rnd))


def key_cert(name: str, root: str = "", edit=lambda body: body, rnd: bytes = bytes(32)) -> bytes:
    """The certificate ``name`` signed by ``root``'s keys (default its tenant's); ``edit`` changes the body first."""
    return certify(edit(cert_body(name)), root or CERTS[name][1], rnd)


def member(n: int, shard: int = SHARD) -> bytes:
    """A synthetic member key for payment ``n`` that routes to ``shard``, and to ``shard`` mod 4 for the
    other tenant, so a swapped tenant is caught by the tenant compare and not by routing."""
    return next(key for i in count() if (
        key := gate.sha3_512(b"RR/GATE/TEST-ONLY-MEMBER/v1\x00" + f"{n}/{i}".encode())[:gate.MEMBER_KEY]) and
        gate.shard_of(TENANT, key, SHARDS) == shard and gate.shard_of(OTHER, key, OTHER_SHARDS) == shard % OTHER_SHARDS)


def _request(flow: str = "FFS_CYCLE", n: int = 0, lines: tuple[bytes, ...] = (), key: int | None = None,
             member_key: bytes | None = None) -> gate.DecideRequest:
    return gate.DecideRequest(TENANT, PROGRAM, flow, f"cmd-{n if key is None else key:04d}", f"pay-{n:04d}",
                              member_key or member(n), f"payee-{n % 3}", 125_000 + n, PERIOD, lines,
                              tuple(sorted((D[2], D[5]))))


def _lines(n: int, flow: str = "FFS_CLAIM", key: bytes | None = None, **change) -> tuple[bytes, ...]:
    """Payment ``n``'s ``n % 4 + 1`` canonical lines (none unruled), summing to its amount; ``change`` edits
    every line."""
    count, total = n % 4 + 1 if flow in gate.RULED else 0, 125_000 + n
    return tuple(gate.encode_line(**{
        "flow": flow, "line_id": f"line-{n}-{k}", "member_key": key or member(n), "payee_ref": f"payee-{n % 3}",
        "rendering": f"npi-{n}", "service_date": 20_260_901 + k, "procedure": PROCS[k % 3], "units": 1,
        "cents": total // count + (total % count if k == 0 else 0), **change}) for k in range(count))


def _leaf(n: int, seq: int, outcome: str = "ALLOW", flow: str = "", shard: int = SHARD,
          member_key: bytes | None = None, head: bytes | None = None) -> gate.TokenLeaf:
    """Payment ``n`` (per claim when it has lines) decided by engine release D[6] on ``shard``; with ``head``, on the
    history index from that chain head (a stand-in input)."""
    flow = flow or ("FFS_CLAIM" if n % 4 else "FFS_CYCLE")
    member_key = member_key or member(n)
    lines = _lines(n, flow, member_key)
    request = _request(flow, n, lines, member_key=member_key)
    return gate.TokenLeaf(
        TENANT, PROGRAM, shard, flow, n % 2, request.payment_id, request.member_key, request.payee_ref,
        request.amount_cents, PERIOD, gate.lines_root(lines), outcome,
        ("ELIGIBLE", "RATE_OK") if outcome == "ALLOW" else ("PA_MISSING",), "TRANSFER", D[3], bytes(64), D[4], D[6],
        synthetic_input(request, head) if head else input_v1(request, D[1]), DECIDED, EPOCH, seq,
        NOW - 5, EXPIRES,
    )


_COUNTERS = itertools.count(2, 2)


def _auto_counter() -> int:
    """Vector building: each checkpoint takes its own even counter, so two never share one and none follows another by accident."""
    return next(_COUNTERS)


def _batch(leaves, sign, prev: bytes = D[0], counter: int | None = None) -> tuple[gate.Checkpoint, bytes, list[gate.Token]]:
    cp, tokens = gate.build_batch(leaves, prev_checkpoint_digest=prev, event_head=D[1], evidence_root=D[2],
                                  state_digest=STATE, created_at=NOW, counter=counter or _auto_counter())
    return cp, sign(gate.encode_checkpoint_header(cp)), tokens


def _flip(data: bytes, at: int, bit: int = 0x80) -> bytes:
    return data[:at] + bytes([data[at] ^ bit]) + data[at + 1 :]


def _header_of(signed_bytes: bytes) -> bytes:
    """The header of a signed checkpoint, with or without its cosign record."""
    if signed_bytes[-gate.COSIGN_RECORD :].startswith(gate.VCOSIGN):
        signed_bytes = signed_bytes[: -gate.COSIGN_RECORD]
    return signed_bytes[: -2 - gate.ML_DSA_87_SIGNATURE]


def _tpm_seal(*args, tpm: int | None = None, tenant: str | None = None) -> bytes:
    """``signer.seal`` (arguments from the handle to the tokens) with the counter value given, else read from the chain: the
    signed ``last`` header's own counter, or, for a first checkpoint, the value just before the header's (the shard's armed
    value).  The new header's counter is never the source of a successor's ``tpm``, so the ``counter == tpm + 1`` check can
    fail.  The cosigner is the verifier of ``tenant``, by default of the certificate's.  Returns the signature."""
    header, last = args[-2], args[3]
    if tpm is None:
        tpm = int.from_bytes((_header_of(last) if last else header)[-8:], "big") - (0 if last else 1)
    if tenant is None:
        try:
            tenant = gate.read_key_cert(args[2]).tenant_id
        except ValueError:
            tenant = TENANT
    return signer.seal(*args, tpm, cosigner(tenant))[0]


def hexes(values) -> str:
    return ",".join(map(bytes.hex, values)) or "-"


def signed(c: gate.Checkpoint, key: str = "e7", sig: bytes | None = None, cosigned: bool = True) -> bytes:
    """The signed checkpoint under certificate ``key``'s key, with its tenant's verifier's cosign record (``cosigned``)."""
    header = gate.encode_checkpoint_header(c)
    sig = sig if sig is not None else det_sign(key, header)
    return gate.encode_checkpoint(c, sig) + (cosign_record(header, CERTS[key][1] if key in CERTS else TENANT) if cosigned else b"")


def sign_header(header: bytes, key: str = "e7") -> bytes:
    """A checkpoint header signed by certificate ``key``'s key and cosigned by its tenant's verifier."""
    return gate.attach_signature(header, det_sign(key, header)) + cosign_record(header, CERTS[key][1])


def resigned(header: bytes) -> bytes:
    """A changed header signed and cosigned again, so it is refused for the change itself."""
    sig = det_sign("e7", header)
    return header + len(sig).to_bytes(2, "big") + sig + cosign_record(header)


def checkpoint_record(name: str, c: gate.Checkpoint, data: bytes) -> str:
    """A ``checkpoint`` line; an accepted one lists the decoded fields."""
    h = bytes.hex
    fields = [c.tenant_id, c.program_id, *map(str, (c.shard_id, c.seq_from, c.seq_to, c.epoch)),
              *(h(getattr(c, n)) for n in gate._CHECKPOINT_DIGESTS), str(c.count), str(c.created_at), str(c.counter),
              h(gate.checkpoint_digest(c))]
    return f"checkpoint accept {name} {h(data)} {' '.join(fields)}"


def payment_record(name: str, leaf: gate.TokenLeaf, verdict: str = "accept", lines: tuple[bytes, ...] | None = None) -> str:
    lines = _lines(int(leaf.payment_id[4:]), leaf.flow, leaf.member_key) if lines is None else lines
    return (f"payment {verdict} {name} {leaf.tenant_id} {leaf.program_id} {leaf.flow} {leaf.payment_id} {bytes.hex(leaf.member_key)} "
            f"{leaf.payee_ref} {leaf.amount_cents} {PERIOD} {hexes(lines)}")


def build_vectors() -> str:
    """Every vector; all keys and signatures are deterministic."""
    global _COUNTERS
    _COUNTERS = itertools.count(2, 2)
    sign = det_sign
    out = ["# RR/GATE formats #1-#4, #12 golden vectors. Synthetic, non-PHI, activation=false."]
    add = out.append
    h = bytes.hex

    # #12 digests: the decision id has no flow and no command key
    for n in (0, 1):
        add(f"decision-id d{n} {TENANT} {PROGRAM} pay-{n:04d} {n} {h(gate.decision_id(TENANT, PROGRAM, f'pay-{n:04d}', n))}")
    request = _request("FFS_CLAIM", 3, _lines(3))
    add(f"input i0 {h(gate.encode_decide_request(request))} {h(D[1])} {h(input_v1(request, D[1]))}")
    for n in (0, 1, 3, 5):
        lines = tuple(f"l{k}".encode() for k in range(n))
        add(f"lines-root r{n} {hexes(lines)} {h(gate.lines_root(lines))}")
    add(f"state s0 {h(PINS[0])} {h(PINS[1])} {h(STATE)}")
    # the commitments of a batch: its context, each payment's input, and the batch's identity
    body = bytes(range(256)) + bytes(9)
    ctx = gate.sha3_512(b"RR/GATE/CONTEXT/v1\x00" + body)
    add(f"context c0 {h(body)} {h(ctx)}")
    rqs = []
    for n, r in enumerate((request, _request("SDP", 1))):
        x = gate.encode_decide_request(r)
        rqs.append(input_v7(ctx, x))
        add(f"input7 v{n} {h(ctx)} {h(x)} {h(rqs[-1])}")
    add(f"batch-input b0 {h(ctx)} {hexes(rqs)} {h(batch_input(ctx, rqs))}")
    add(f"batch-input b1 {h(ctx)} - {h(batch_input(ctx, []))}")

    # Engine answers: the request digest is read from bytes 23-86 of the header, and the bytes are canonical.  Records
    # (index, outcome, rule, reasons, chunk, row): line 1 HOLD decided with a counterpart, line 0 released.  Leaves: an
    # ALLOW under TRANSFER, and a HOLD under HOLD with bit 62 (UNENCODABLE_PAYMENT) that a bypass released; then an
    # ANSWERED leaf (bit 4, an exact repeat) with its earlier list.  Rejected: other answer versions (1 had u32 reasons),
    # a bit past the 29 rule reasons, and bits 60 and 61, which no code names yet.
    none_ref = (2**32 - 1, 2**24 - 1)
    recs = [(1, 1, 0, 1 << 4, 7, 5), (0, 0, 1, 0, *none_ref)]
    leaves = [(0, 0, 2, 0, b"", D[15]), (1, 1 << 62, 1, 1, D[16], D[10])]
    ok = lambda recs=recs, leaves=leaves: answer_frame(0, SHARD, 9, D[11], recs, leaves, [b"bypass note"], [b"row-0"], D[3])
    add(f"answer accept a0 {h(ok())} 0 {SHARD} 9 {h(D[11])} 2 {h(gate.ZERO_DIGEST)},{h(D[16])}")
    ident = lambda t: len(t).to_bytes(2, "big") + t.encode()  # RR/GATE/EARLIER/v1: a count, then per entry four identifiers
    earlier = (1).to_bytes(2, "big") + b"".join(map(ident, ("line-8-0", PROGRAM, "pay-0000", "line-0-0")))
    answered = (3, 1 << 4, 2, 2, earlier, D[12])
    add(f"answer accept a-answered {h(ok(leaves=[*leaves, answered]))} 0 {SHARD} 9 {h(D[11])} 2 "
        f"{h(gate.ZERO_DIGEST)},{h(D[16])},{h(gate.ZERO_DIGEST)}")
    add(f"answer accept a-not-next {h(answer_frame(5, SHARD, 10, D[11]))} 5 {SHARD} 10 {h(D[11])} 0 -")
    flag = lambda f: [leaves[0], (*leaves[1][:3], f, *leaves[1][4:])]
    leaf = lambda i, v: [(*leaves[0][:i], v, *leaves[0][i + 1:]), leaves[1]]
    rec = lambda m: ok(recs=[(*recs[0][:3], m, *recs[0][4:]), recs[1]])
    for name, data in (("truncated", ok()[:-1]), ("trailing", ok() + b"\x00"), ("version-1", ok()[:4] + b"\x01" + ok()[5:]),
                       ("version-2", ok()[:4] + b"\x02" + ok()[5:]), ("version-3", ok()[:4] + b"\x03" + ok()[5:]),
                       ("record-reason-bit-29", rec(1 << 29)), ("record-reason-bit-62", rec(1 << 62)),
                       ("bypass-flag-3", ok(leaves=flag(3))), ("earlier-on-hold", ok(leaves=flag(2))),
                       ("answered-without-earlier", ok(leaves=[*leaves, (*answered[:3], 0, b"", D[12])])),
                       ("answered-empty-earlier", ok(leaves=[*leaves, (*answered[:4], b"", D[12])])), ("zero-bypass-flagged", ok(leaves=[leaves[0], (*leaves[1][:4], gate.ZERO_DIGEST, D[10])])),
                       ("leaf-outcome-3", ok(leaves=leaf(0, 3))), ("leaf-reason-bit-29", ok(leaves=leaf(1, 1 << 29))),
                       ("leaf-reason-bit-60", ok(leaves=leaf(1, 1 << 60))), ("leaf-reason-bit-61", ok(leaves=leaf(1, 1 << 61))),
                       ("leaf-authority-3", ok(leaves=leaf(2, 3))), ("index-twice", ok(recs=[recs[0], (1, *recs[1][1:])])),
                       ("refusal-with-records", answer_frame(5, SHARD, 10, D[11])[:19] + (1).to_bytes(4, "little") + D[11])):
        add(f"answer reject {name} {h(data)}")

    # #1 DECIDE-REQUEST/v2; accepted requests are named for the responses below
    def request_line(name: str, r: gate.DecideRequest) -> None:
        fields = [r.tenant_id, r.program_id, r.flow, r.command_key, r.payment_id, h(r.member_key), r.payee_ref,
                  str(r.amount_cents), r.period, hexes(r.lines), hexes(r.evidence_refs), "1" if r.contest else "0"]
        add(f"request accept {name} {h(gate.encode_decide_request(r))} {' '.join(fields)}")

    req, sdp = gate.encode_decide_request(request), gate.encode_decide_request(_request("SDP", 0))
    flow_at = len(gate.DECIDE_REQUEST) + 2 + len(TENANT) + 2 + len(PROGRAM)
    request_line("claim", request)
    request_line("sdp-without-lines", _request("SDP", 0))
    # The largest canonical line (four 128-byte identifiers) is 569 bytes; one byte more is refused
    big = gate.encode_line("FFS_CLAIM", "l" * 128, member(8), "p" * 128, "r" * 128, 20_260_901, "9" * 128, 1, 125_008)
    request_line("line-569-bytes", replace(_request("FFS_CLAIM", 8), payee_ref="p" * 128, lines=(big,)))
    line = gate.encode_line("FFS_CLAIM", "line-6", member(6), "payee-0", "npi-6", 20_260_901, "99213", 1, 62_503)
    request_line("duplicate-line", _request("FFS_CLAIM", 6, (line, line)))  # the rules hold it
    enc_request = gate.encode_decide_request
    big_req = enc_request(replace(_request("FFS_CLAIM", 8), payee_ref="p" * 128, lines=(big,)))
    for name, data in (
        ("truncated", req[:-1]),
        ("trailing", req + b"\x00"),
        ("contest-flag-2", req[:-1] + b"\x02"),  # the contest flag, last, is 0 or 1
        ("wrong-domain", gate.DECIDE_RESPONSE + req[len(gate.DECIDE_REQUEST) :]),
        ("flipped-flow-bit", _flip(req, flow_at)),
        *((f"{flow}-without-lines", sdp[:flow_at] + bytes([tag]) + sdp[flow_at + 1 :])
          for tag, flow in enumerate(gate.RULED, 1)),
        ("line-570-bytes", big_req.replace(b"\x02\x39" + big, b"\x02\x3a" + big + b"\x00", 1)),
        ("refs-unsorted", req[:-128] + req[-64:] + req[-128:-64]),
        ("bad-identifier", req.replace(TENANT.encode(), b"-" + TENANT[1:].encode(), 1)),
        # Each line is canonical, of the payment's flow, member and payee, and the lines sum to its amount
        ("line-noncanonical", enc_request(_request("FFS_CLAIM", 3, _lines(3) + (_lines(3)[0] + b"\x00",)))),
        ("line-other-flow", enc_request(_request("FFS_CLAIM", 1, _lines(1, "FFS_CYCLE")))),
        ("line-other-member", enc_request(_request("FFS_CLAIM", 1, _lines(1, key=member(90))))),
        ("line-other-payee", enc_request(_request("FFS_CLAIM", 1, _lines(1, payee_ref="payee-9")))),
        ("lines-sum-off", enc_request(_request("FFS_CLAIM", 1, _lines(1, cents=124_000)))),
    ):
        add(f"request reject {name} {h(data)}")

    # Payer setup: each tenant's authority link (the payer holds it), certificates (checked installs) and one active grant
    def link_line(tenant: str) -> None:
        held = gate.read_link(link(tenant))
        key = lambda name: h(gate.encode_key(keypair(f"{name}-{tenant}")[0]))
        add(f"link {tenant} {held.gen} {h(gate.sha3_512(held.body))} {key('root')} {h(gate.sha3_512(bytes.fromhex(key('root-next'))))} "
            f"{key('witness')} {h(gate.sha3_512(bytes.fromhex(key('witness-next'))))} -")

    for tenant in (TENANT, OTHER, STANDBY):
        link_line(tenant)

    def cert(name: str, verdict: str = "accept") -> None:
        add(f"cert {verdict} {h(key_cert(name))}")

    for name in ("e7", "e6", "other"):
        cert(name)
    add(f"cert reject {h(key_cert('bad', root=OTHER))}")  # another tenant's keys signed it
    cert("reshard", "reject")  # a second shard count for the tenant that does not continue the first
    # The root signs every field: shard count 9 under e7's own signatures has no valid chain
    good = key_cert("e7")
    epoch_at = len(gate.KEY_CERT) + 2 + len(TENANT)
    counts_at = epoch_at + 8 + gate.DIGEST + 1  # epoch, link, chain length, then the shard counts
    add(f"cert reject {h(good[:counts_at] + (SHARDS + 1).to_bytes(4, 'big') + good[counts_at + 4 :])}")
    # Signed by the root and witness but not canonical: the decoder refuses each
    for name, data in (
        ("shard-count-zero", key_cert("e7", edit=lambda b: b[:counts_at] + bytes(4) + b[counts_at + 4 :])),
        ("epoch-over-2^63", key_cert("e7", edit=lambda b: b[:epoch_at] + (2**63).to_bytes(8, "big") + b[epoch_at + 8 :])),
        # e8 is not installed yet, so the scheme byte is this certificate's only defect
        ("other-scheme", key_cert("e8", edit=lambda b: b[: len(b) - 2 * gate.KEY_BYTES] + b"\x02" + b[len(b) - 2 * gate.KEY_BYTES + 1 :])),
        ("trailing", good + b"\x00"),
        ("short-signature", good[: -gate.ML_DSA_87_SIGNATURE - 2] + (gate.ML_DSA_87_SIGNATURE - 1).to_bytes(2, "big") + good[-gate.ML_DSA_87_SIGNATURE : -1]),
        ("wrong-domain", gate.CHECKPOINT + good[len(gate.KEY_CERT) :]),
    ):
        add(f"cert reject {h(data)}")
    tenants = (TENANT, OTHER, STANDBY, SELF)  # one grant per tenant, all with id D[3]: a grant is its tenant's alone (check 9)
    grants = lambda rule=D[4], release=D[6], grant_id=D[3], of=tenants: add(f"grants {','.join(of)} {h(grant_id)} {h(rule)} {h(release)}")
    grants()
    add(f"now {NOW}")

    # #4 CHECKPOINT/v3: one signed batch plus single-field variants, each signed
    # by the key of the certificate for its tenant and epoch
    cp, signature, tokens = _batch([_leaf(n, 40 + n, "HOLD" if n == 4 else "ALLOW") for n in range(5)],
                                   lambda m: sign("e7", m))

    def checkpoint_line(name: str, c: gate.Checkpoint, data: bytes) -> None:
        add(checkpoint_record(name, c, data))

    signed_cp = signed(cp, sig=signature)
    checkpoint_line("batch", cp, signed_cp)
    checkpoint_line("batch-fetched-again", cp, signed_cp)
    # Stored checkpoints that differ from a token's batch in one field.  The
    # program and seq variants commit to a lone leaf at a fresh seq, since a
    # variant of the batch at its own seqs would fork it.
    lone = {name: _batch([_leaf(n, seq)], lambda m: b"") for name, n, seq in (("program", 2, 60), ("seq", 3, 70))}
    variants = {
        "other-tenant": (replace(cp, tenant_id=OTHER), "other", tokens[0]),
        "epoch-6": (replace(cp, epoch=EPOCH - 1, counter=_auto_counter()), "e6", tokens[0]),
        "second-shard-same-seq": (replace(cp, shard_id=1), "e7", tokens[0]),
        "other-program": (replace(lone["program"][0], program_id="medicaid-cap"), "e7", lone["program"][2][0]),
        "seq-from-past-leaf": (replace(lone["seq"][0], seq_from=71, seq_to=71), "e7", lone["seq"][2][0]),
    }
    for name, (c, key, _) in variants.items():
        checkpoint_line(name, c, signed(c, key))
    header = gate.encode_checkpoint_header(cp)
    seq_at = len(gate.CHECKPOINT) + 1 + 2 + len(TENANT) + 2 + len(PROGRAM) + 4  # seq_from, seq_to, epoch, prev
    for name, data in (
        ("truncated", signed_cp[:-1]),
        ("trailing", signed_cp + b"\x00"),
        ("wrong-domain", gate.TOKEN + signed_cp[len(gate.CHECKPOINT) :]),
        ("variant-2", resigned(_flip(header, len(gate.CHECKPOINT), 0x03))),
        *((f"magic-v{v}", resigned(gate.CHECKPOINT[:-2] + str(v).encode() + b"\x00" + header[len(gate.CHECKPOINT) :])) for v in (1, 2)),
        ("flipped-count-bit", resigned(_flip(header, len(header) - 17, 0x01))),
        ("flipped-signature-bit", _flip(signed_cp, len(signed_cp) - gate.COSIGN_RECORD - 100)),
        # The verifier's cosign record: required, and each of its parts is checked
        ("uncosigned", signed(cp, sig=signature, cosigned=False)),
        ("flipped-cosignature-bit", _flip(signed_cp, len(signed_cp) - 100)),
        ("cosigned-another-checkpoint", signed(cp, sig=signature, cosigned=False) + cosign_record(_flip(header, len(header) - 1, 0x01))),
        ("cosigned-by-the-epoch-key",
         signed(cp, sig=signature, cosigned=False) + gate.encode_cosign(VREL, det_sign("e7", gate.cosign_message(header, VREL)))),
        ("cosigned-by-another-tenants-verifier", signed(cp, sig=signature, cosigned=False) + cosign_record(header, OTHER)),        ("retired-epoch-key", signed(cp, "e6")),
        ("other-tenant-key", signed(cp, "other")),
        ("state-digest-zero", resigned(header[:-82] + gate.ZERO_DIGEST + header[-18:])),
        # An epoch's first checkpoint, and only it, starts at seq 0 with an all-zero prev
        ("first-with-prev", resigned(header[:seq_at] + bytes(8) + (4).to_bytes(8, "big") + header[seq_at + 16 :])),
        ("zero-prev-not-first", resigned(header[: seq_at + 24] + gate.ZERO_DIGEST + header[seq_at + 88 :])),
    ):
        add(f"checkpoint reject {name} {h(data)}")
    # A second decision for pay-0004 and pay-0000 under CAP_820, as a gate that
    # keyed decisions by flow would sign it (review scenarios A and B), one
    # for pay-0001 under an edited member key that routes to the same shard, and
    # pay-0008 answered as an exact repeat of pay-0000's paid line
    answered_leaf = replace(_leaf(8, 48, "ANSWERED"), reason_codes=("FFS_DUPLICATE_LINE",),
                            earlier_root=gate.earlier_root((("line-8-0", PROGRAM, "pay-0000", "line-0-0"),)))
    rogue_cp, _, rogue = _batch([_leaf(4, 45, flow="CAP_820"), _leaf(0, 46, flow="CAP_820"),
                                 _leaf(1, 47, member_key=member(91)), answered_leaf],
                                lambda m: sign("e7", m), gate.checkpoint_digest(cp))
    checkpoint_line("cross-flow", rogue_cp, signed(rogue_cp))
    # Shard 7 decides pay-0004 again under a mistyped member key that routes
    # there, and signs pay-0001 although its member routes to shard 3 (a gate
    # whose producer skipped the publish check)
    typo_leaves = [_leaf(4, 1, shard=7, member_key=member(4, 7)), _leaf(1, 2, shard=7)]
    typo_cp, _, typo = _batch(typo_leaves, lambda m: sign("e7", m))
    checkpoint_line("shard-7", typo_cp, signed(typo_cp))
    # A gate-signed batch of seqs 90-91 whose first leaf claims seq 92: its
    # path folds to the root at position 2 too, so only index < count refuses it
    stray = [_leaf(5, 92), _leaf(6, 91)]
    stray_root, stray_paths = gate.merkle_tree(gate.MERKLE_NODE, [gate.encode_token_leaf(x) for x in stray])
    stray_cp = gate.Checkpoint(TENANT, PROGRAM, SHARD, 90, 91, EPOCH, D[0], D[1], stray_root, D[2], STATE, 2, NOW, _auto_counter())
    checkpoint_line("seq-outside-batch", stray_cp, signed(stray_cp))

    # #3 TOKEN/v3: the batch, then one reject per check, each one field away
    def payment_line(name: str, leaf: gate.TokenLeaf, verdict: str = "accept", lines: tuple[bytes, ...] | None = None) -> None:
        add(payment_record(name, leaf, verdict, lines))

    def token(verdict: str, name: str, payment: str, t: gate.Token) -> None:
        """A token that decodes, with the fields it must decode to."""
        x = t.leaf
        fields = [x.tenant_id, x.program_id, str(x.shard_id), x.flow, str(x.revision), x.payment_id, h(x.member_key),
                  x.payee_ref, str(x.amount_cents), x.period, h(x.lines_root), x.outcome, ",".join(x.reason_codes) or "-",
                  x.authority, h(x.grant_id), h(x.bypass), h(x.earlier_root), h(x.rule_version), h(x.engine_release), h(x.input_commitment),
                  *map(str, (x.decided_at, x.epoch, x.seq, x.issued_at, x.expires_at)), hexes(t.siblings),
                  h(t.checkpoint_digest)]
        add(f"token {verdict} decode-ok {name} {payment} {h(gate.encode_token(t))} {' '.join(fields)}")

    raw = [gate.encode_token(t) for t in tokens]
    for n, t in enumerate(tokens):
        payment_line(f"p{n}", t.leaf)
        token("reject" if t.leaf.outcome != "ALLOW" else "accept", f"t{n}-{t.leaf.outcome.lower()}", f"p{n}", t)
    p0 = [TENANT, PROGRAM, "FFS_CYCLE", "pay-0000", h(member(0)), "payee-0", "125000", PERIOD,
          hexes(_lines(0, "FFS_CYCLE"))]
    for name, index, value in (("tenant", 0, OTHER), ("program", 1, "medicaid-cap"), ("flow", 2, "FFS_CLAIM"),
                               ("payment-id", 3, "pay-0009"), ("member-key", 4, h(member(90))),
                               ("payee", 5, "payee-9"), ("amount", 6, "124999"), ("period", 7, "2026-10")):
        verdict = "member_key_changed" if name == "member-key" else "accept"
        add(f"payment {verdict} p0-{name} {' '.join(p0[:index] + [value] + p0[index + 1 :])}")
    payment_line("p0-cap", rogue[1].leaf)
    # The same claim line with another procedure: same count and total, another lines root
    payment_line("p1-swapped-procedure", tokens[1].leaf, lines=_lines(1, procedure="99214"))
    t0, leaf0 = tokens[0], gate.encode_token_leaf(tokens[0].leaf)

    def lifetime(expires: int) -> bytes:
        return leaf0[:-8] + expires.to_bytes(8, "big") + raw[0][len(leaf0) :]

    token_flow_at = flow_at - len(gate.DECIDE_REQUEST) + len(gate.TOKEN) + 4  # after the u32 shard_id
    # An unruled flow's decision has no lines and is HUMAN_REVIEW; a ruled flow's has lines
    sdp_token = replace(t0, leaf=_leaf(7, 0, "HUMAN_REVIEW", flow="SDP"))
    sdp_raw = gate.encode_token(sdp_token)
    outcome_at = sdp_raw.index(gate.ZERO_DIGEST) + gate.DIGEST
    def with_bypass(data: bytes, at: int = 64) -> bytes:  # grant_id, bypass (at 64), earlier_root (at 128), rule_version
        at += data.index(D[3] + bytes(128) + D[4])
        return data[:at] + D[5] + data[at + 64 :]

    leaf_outcome_at = raw[0].index(t0.leaf.lines_root) + gate.DIGEST

    hold_raw = next(gate.encode_token(t) for t in tokens if t.leaf.outcome == "HOLD")
    for name, data in (
        ("truncated", raw[0][:-1]),
        ("trailing", raw[0] + b"\x00"),
        ("wrong-domain", gate.CHECKPOINT + raw[0][len(gate.TOKEN) :]),
        ("flipped-flow-bit", _flip(raw[0], token_flow_at)),
        *((f"{flow}-zero-lines-root", sdp_raw[:token_flow_at] + bytes([tag]) + sdp_raw[token_flow_at + 1 :])
          for tag, flow in enumerate(gate.RULED, 1)),
        *((f"unruled-{name}", sdp_raw[:outcome_at] + bytes([tag]) + sdp_raw[outcome_at + 1 :])
          for tag, name in ((1, "allow"), (2, "hold"))),
        ("bypass-on-hold", with_bypass(hold_raw)),
        ("bypass-on-unruled-flow", with_bypass(sdp_raw)),
        # an earlier list exactly on ANSWERED
        ("earlier-on-allow", with_bypass(raw[0], 128)),
        ("answered-without-earlier", raw[0][:leaf_outcome_at] + bytes([gate.OUTCOMES.index("ANSWERED") + 1]) + raw[0][leaf_outcome_at + 1 :]),
        ("reasons-unsorted", raw[0].replace(b"\x00\x08ELIGIBLE\x00\x07RATE_OK", b"\x00\x07RATE_OK\x00\x08ELIGIBLE", 1)),
        ("decided-after-issue", leaf0[:-40] + (NOW - 4).to_bytes(8, "big") + raw[0][len(leaf0) - 32 :]),
        ("expires-before-issue", lifetime(NOW - 6)),
        ("lifetime-over-7-days", lifetime(NOW - 5 + gate.MAX_TOKEN_LIFETIME + 1)),
    ):
        add(f"token reject decode-bad {name} p0 {h(data)}")
    payment_line("p5", stray[0])
    isolated = [
        ("checkpoint-not-stored", "p0", replace(t0, checkpoint_digest=D[11])),
        ("bypassed-leaf-decodes", "p0", replace(t0, leaf=replace(t0.leaf, bypass=D[5]))),
        ("bypassed-leaf-without-reasons-decodes", "p0", replace(t0, leaf=replace(t0.leaf, bypass=D[5], reason_codes=()))),
        *((f"checkpoint-{name}", f"p{int(t.leaf.payment_id[-1])}", replace(t, checkpoint_digest=gate.checkpoint_digest(c)))
          for name, (c, _, t) in variants.items()),
        ("wrong-path", "p0", replace(t0, siblings=tokens[1].siblings)),
        ("seq-outside-batch", "p5", gate.Token(stray[0], tuple(stray_paths[0]), gate.checkpoint_digest(stray_cp))),
        *((f"payment-{name}", f"p0-{name}", t0)
          for name in ("tenant", "program", "flow", "payment-id", "member-key", "payee", "amount", "period")),
        ("payment-swapped-procedure", "p1-swapped-procedure", tokens[1]),
        ("hold-escape-other-flow", "p4", rogue[0]),
        ("hold-escape-mistyped-member", "p4", typo[0]),
        ("wrong-shard", "p1", typo[1]),
    ]
    for name, payment, t in isolated:
        token("reject", name, payment, t)
    # Each payment's member key was pinned at its first command.  The payer's
    # record edited to another key is refused, and a token under that key never
    # verifies, whether it routes elsewhere (pay-0004's HOLD on shard 3 re-decided
    # ALLOW on shard 7) or to the same shard
    for name, t in (("other-shard", typo[0]), ("same-shard", rogue[2])):
        payment_line(f"member-changed-{name}", t.leaf, "member_key_changed")
        token("reject", f"member-changed-{name}", f"member-changed-{name}", t)
    for name, kw in (("grant-id", {"grant_id": D[0]}), ("grant-rule", {"rule": D[0]}), ("grant-release", {"release": D[0]}),
                     ("grant-tenant", {"of": tenants[1:]})):
        grants(**kw)
        token("reject", name, "p1", tokens[1])
    grants()
    for now, verdict, name in ((NOW - 5 - 300, "accept", "issue-skew-edge"), (NOW - 5 - 301, "reject", "not-yet-issued"),
                               (EXPIRES + 299, "accept", "expiry-skew-edge"), (EXPIRES + 300, "reject", "expired")):
        add(f"now {now}")
        token(verdict, name, "p1", tokens[1])
    add(f"now {NOW}")
    token("accept", "cross-flow-before-release", "p0-cap", rogue[1])
    # an ANSWERED decision decodes and is never released
    payment_line("p8", answered_leaf)
    token("reject", "t8-answered", "p8", rogue[3])
    add(f"release accept t0 p0 {h(raw[0])}")
    token("reject", "released", "p0", t0)
    add(f"release reject t0-again p0 {h(raw[0])}")
    token("reject", "cross-flow-after-release", "p0-cap", rogue[1])
    # Tenant OTHER's batch: a command was sent for pay-0030, while pay-0031 is on
    # the payer's books but was never sent, so its token fails check 12 alone
    other_cp, _, other = _batch([replace(_leaf(n, 20 + n), tenant_id=OTHER) for n in (30, 31)],
                                lambda m: sign("other", m))
    checkpoint_line("other-tenant-batch", other_cp, other_signed := signed(other_cp, "other"))
    payment_line("p30", other[0].leaf)
    payment_line("p31", other[1].leaf, "unsent")
    token("reject", "unsent", "p31", other[1])
    # A fork on shard 5 (overlapping seqs, a neighbour on either side that does
    # not link to it, or a link to it from a non-adjacent seq) blocks tenant and
    # epoch on every shard: no later checkpoint of the epoch is stored and shard
    # 3 releases nothing more
    fork_cp, _, fork = _batch([_leaf(20, 1, shard=5, member_key=member(20, 5)),
                               _leaf(21, 2, shard=5, member_key=member(21, 5))], lambda m: sign("e7", m))
    later_cp = _batch([_leaf(22, 3, shard=5, member_key=member(22, 5))], lambda m: b"",
                      gate.checkpoint_digest(fork_cp))[0]
    earlier_cp = _batch([_leaf(23, 0, shard=5, member_key=member(23, 5))], lambda m: b"", gate.ZERO_DIGEST)[0]
    checkpoint_line("fork-base", fork_cp, signed(fork_cp))
    payment_line("p20", fork[0].leaf)
    token("accept", "before-fork", "p20", fork[0])
    for name, c in (("fork-unlinked-next", replace(later_cp, prev_checkpoint_digest=D[0])),
                    ("fork-unlinked-previous", earlier_cp),
                    ("fork-non-adjacent-link", replace(later_cp, seq_from=5, seq_to=5)),
                    ("fork-same-seq", replace(fork_cp, token_root=_flip(fork_cp.token_root, 0, 0x01))),
                    ("fork-overlapping-seq", replace(fork_cp, seq_from=2, seq_to=3))):
        add(f"checkpoint fork {name} {h(signed(c))}")
    # Forks by counter: one counter value twice; the next counter value not naming the stored checkpoint; and the same in
    # another epoch (signed by that epoch's key), which no seq comparison can see
    flipped, after = _flip(fork_cp.token_root, 0, 0x01), fork_cp.counter + 1
    for name, key, c in (
            ("fork-same-counter", "e7", replace(fork_cp, seq_from=40, seq_to=41, token_root=flipped)),
            ("fork-unlinked-counter", "e7", replace(fork_cp, seq_from=60, seq_to=61, token_root=flipped, counter=after)),
            ("fork-unlinked-counter-before", "e7", replace(fork_cp, seq_from=80, seq_to=81, token_root=flipped, counter=fork_cp.counter - 1)),
            ("fork-cross-epoch", "e6", replace(fork_cp, epoch=EPOCH - 1, seq_from=0, seq_to=1, prev_checkpoint_digest=gate.ZERO_DIGEST,
                                               token_root=flipped, counter=after))):
        add(f"checkpoint fork {name} {h(signed(c, key))}")
    token("reject", "forked-batch", "p20", fork[0])
    add(f"checkpoint reject linked-after-fork {h(signed(later_cp))}")
    token("reject", "shard-3-after-fork", "p2", tokens[2])
    add(f"release reject shard-3-after-fork p3 {h(raw[3])}")
    token("accept", "other-tenant-after-fork", "p30", other[0])
    # Failover recovers: epoch 8 is not blocked, and fences only its own tenant
    cert("e8")
    token("accept", "other-tenant-fence", "p30", other[0])

    def reissued(leaf: gate.TokenLeaf, seq: int, issued_at: int = NOW) -> gate.TokenLeaf:
        return replace(leaf, epoch=EPOCH + 1, seq=seq, issued_at=issued_at, expires_at=issued_at + 2 * 86_400)

    # Re-issue: the fenced, unreleased t1 comes back as the same decision at
    # epoch 8, whose seq counter restarts at 0 with an all-zero prev; the
    # released t0 comes back too and fails check 10 alone
    new = reissued(tokens[1].leaf, 0)
    e8_cp, _, (t1_e8, t0_e8) = _batch([new, reissued(tokens[0].leaf, 1)], lambda m: sign("e8", m), gate.ZERO_DIGEST)
    checkpoint_line("reissue-e8", e8_cp, e8_signed := signed(e8_cp, "e8"))
    token("accept", "reissued-e8", "p1", t1_e8)
    token("reject", "released-before-failover", "p0", t0_e8)
    # The grant moves to engine D[7]: the re-issued leaf still carries D[6], its deciding release
    grants(release=D[7])
    token("reject", "reissued-revoked-engine", "p1", t1_e8)
    grants()
    # A re-issue keeps the decision time, so a decision older than its flow's
    # maximum age is refused however fresh its token (check 5)
    age = gate.MAX_DECISION_AGE
    old = [tokens[2].leaf, _leaf(8, 0, flow="FFS_CYCLE"), _leaf(10, 0, flow="CAP_820")]
    late_cp, _, lates = _batch([reissued(x, 2 + k, DECIDED + age[x.flow]) for k, x in enumerate(old)],
                               lambda m: sign("e8", m), gate.checkpoint_digest(e8_cp))
    checkpoint_line("late-reissue-e8", late_cp, signed(late_cp, "e8"))
    for x in lates:
        name = f"p{int(x.leaf.payment_id[4:])}"
        if name != "p2":
            payment_line(name, x.leaf)
        for skew, verdict in ((299, "accept"), (300, "reject")):
            add(f"now {DECIDED + age[x.leaf.flow] + skew}")
            token(verdict, f"{x.leaf.flow.lower()}-age-plus-{skew}", name, x)
    add(f"now {NOW}")
    # Clean failover of tenant OTHER (no fork): its epoch-8 certificate fences
    # its epoch-7 token by check 4 alone, and the epoch-8 re-issue is accepted
    cert("other8")
    token("reject", "fenced-other-e7", "p30", other[0])
    other_e8_cp, _, (p30_e8,) = _batch([reissued(other[0].leaf, 0)], lambda m: sign("other8", m), gate.ZERO_DIGEST)
    checkpoint_line("other-reissue-e8", other_e8_cp, signed(other_e8_cp, "other8"))
    token("accept", "other-reissued-e8", "p30", p30_e8)
    # A newer certificate with a valid chain raises its tenant's fence even when refused
    for name, payment, t in (("reshard-e9", "p1", t1_e8), ("reshard-other9", "p30", p30_e8)):
        cert(name, "reject")
        token("reject", f"fenced-by-{name}", payment, t)
    for verdict, name, latest, leaf in (
        ("accept", "same-decision-e8", 1, new), ("accept", "same-epoch-later-seq", 1, replace(new, epoch=EPOCH, seq=48)),
        ("reject", "re-decided", 1, replace(new, outcome="HOLD")),
        ("reject", "other-engine", 1, replace(new, engine_release=D[7])),
        ("reject", "decision-time-changed", 1, replace(new, decided_at=DECIDED + 1)),
        ("reject", "older-epoch", 1, replace(new, epoch=EPOCH - 1, seq=48)),
        ("reject", "older-seq", 1, replace(new, epoch=EPOCH, seq=40)), ("reject", "not-latest-revision", 2, new),
    ):
        add(f"reissue {verdict} {name} {latest} {h(raw[1])} {h(gate.encode_token(replace(t1_e8, leaf=leaf)))}")
    # Re-decision: an ALLOW past its flow's age by both skews, decided again as
    # the next revision of the same payment, on current data (any outcome)
    for x in lates:
        at = DECIDED + age[x.leaf.flow] + 2 * 300
        for verdict, when in (("accept", at), ("reject", at - 1)):
            new = replace(x.leaf, revision=x.leaf.revision + 1, decided_at=when, issued_at=when, expires_at=when + 86_400)
            add(f"redecide {verdict} {x.leaf.flow.lower()}-at-{when - DECIDED} {x.leaf.revision} "
                f"{h(gate.encode_token(x))} {h(gate.encode_token(replace(x, leaf=new)))}")
    at = DECIDED + age["FFS_CLAIM"] + 2 * 300
    base = replace(lates[0].leaf, revision=1, decided_at=at, issued_at=at, expires_at=at + 86_400)
    for verdict, name, latest, old, new in (
        ("accept", "held-on-current-data", 0, lates[0].leaf, replace(base, outcome="HOLD", reason_codes=("PA_MISSING",))),
        ("reject", "not-latest", 1, lates[0].leaf, replace(base, revision=2)), ("reject", "same-revision", 0, lates[0].leaf, replace(base, revision=0)),
        ("reject", "skips-revision", 0, lates[0].leaf, replace(base, revision=2)),
        ("reject", "old-not-allow", 0, replace(lates[0].leaf, outcome="HOLD", reason_codes=("PA_MISSING",)), base),
        *(("reject", f"other-{f.replace('_', '-')}", 0, lates[0].leaf, replace(base, **{f: v})) for f, v in (
            ("tenant_id", OTHER), ("program_id", "medicaid-cap"), ("shard_id", 5), ("flow", "FFS_CYCLE"),
            ("payment_id", "pay-0009"), ("member_key", member(90)), ("payee_ref", "payee-9"), ("amount_cents", 124_999),
            ("period", "2026-10"), ("lines_root", D[7]))),
    ):
        add(f"redecide {verdict} {name} {latest} {h(gate.encode_token(replace(lates[0], leaf=old)))} "
            f"{h(gate.encode_token(replace(lates[0], leaf=new)))}")
    # Equivocation: the same certificate again changes nothing; a second one
    # for OTHER's epoch 8 is refused, recorded with it, and blocks that tenant
    # and epoch (only them), so no later checkpoint of it is stored
    eq = []
    for n in (32, 33):
        eq.append(_batch([reissued(replace(_leaf(n, 0), tenant_id=OTHER), n - 31)], lambda m: sign("other8", m),
                         gate.checkpoint_digest(eq[-1] if eq else other_e8_cp))[0])
    cert("other8", "reject")
    add(f"cert reject {h(key_cert('other8', rnd=bytes([1]) * 32))}")  # the same body signed again: no equivocation
    checkpoint_line("other8-same-cert-again", eq[0], signed(eq[0], "other8"))
    cert("twin", "reject")
    add(f"checkpoint reject other8-after-twin {h(signed(eq[1], 'other8'))}")
    checkpoint_line("e8-after-twin", e8_cp, e8_signed)
    checkpoint_line("other-tenant-after-twin", other_cp, other_signed)

    # A fenced standby (tenant nc-standby, 4 shards): epoch 2's certificate fences epoch 1, whose late
    # checkpoints are stored as evidence but release nothing, and whose fork blocks epoch 1 alone
    member_sb = next(k for i in count() if (k := gate.sha3_512(b"RR/GATE/TEST-ONLY-MEMBER/v1\x00sb" + bytes([i]))[:gate.MEMBER_KEY])
                     and gate.shard_of(STANDBY, k, OTHER_SHARDS) == 0)

    def standby(n: int, seq: int, epoch: int) -> gate.TokenLeaf:
        return replace(_leaf(n, seq, shard=0, member_key=member_sb), tenant_id=STANDBY, epoch=epoch)

    e1_cp, _, (e1_t,) = _batch([standby(41, 0, 1)], lambda m: sign("sb1", m), gate.ZERO_DIGEST)
    cert("sb1")
    checkpoint_line("standby-e1", e1_cp, signed(e1_cp, "sb1"))
    payment_line("p41", e1_t.leaf)
    token("accept", "standby-before-fence", "p41", e1_t)
    cert("sb2")
    token("reject", "standby-fenced", "p41", e1_t)
    late_cp, _, (late_t,) = _batch([standby(42, 1, 1)], lambda m: sign("sb1", m), gate.checkpoint_digest(e1_cp))
    checkpoint_line("standby-late-e1", late_cp, signed(late_cp, "sb1"))
    payment_line("p42", late_t.leaf)
    token("reject", "standby-late-e1-fenced", "p42", late_t)
    e2_cp, _, (e2_t,) = _batch([standby(41, 0, 2)], lambda m: sign("sb2", m), gate.ZERO_DIGEST)
    add(f"checkpoint reject standby-e2-signed-by-e1 {h(signed(e2_cp, 'sb1'))}")
    add(f"checkpoint fork standby-e1-fork {h(signed(replace(e1_cp, token_root=_flip(e1_cp.token_root, 0, 0x01)), 'sb1'))}")
    next_cp = _batch([standby(43, 2, 1)], lambda m: b"", gate.checkpoint_digest(late_cp))[0]
    add(f"checkpoint reject standby-e1-after-fork {h(signed(next_cp, 'sb1'))}")
    add(f"checkpoint reject standby-e2-after-fork {h(signed(e2_cp, 'sb2'))}")  # the fork pins shard 0 in every epoch
    token("reject", "standby-reissued-e2-after-fork", "p41", e2_t)
    add(f"release reject standby-e2-after-fork p41 {h(gate.encode_token(e2_t))}")
    add(f"release reject standby-e2-again p41 {h(gate.encode_token(e2_t))}")
    # Epoch 2 on a shard the fork did not pin is not blocked: its payment releases once, and the second release is refused
    member_sb1 = next(k for i in count() if (k := gate.sha3_512(b"RR/GATE/TEST-ONLY-MEMBER/v1\x00sc" + bytes([i]))[:gate.MEMBER_KEY])
                      and gate.shard_of(STANDBY, k, OTHER_SHARDS) == 1)
    s1_cp, _, (s1_t,) = _batch([replace(_leaf(44, 0, shard=1, member_key=member_sb1), tenant_id=STANDBY, epoch=2)], lambda m: sign("sb2", m), gate.ZERO_DIGEST, counter=1)
    checkpoint_line("standby-e2-other-shard", s1_cp, signed(s1_cp, "sb2"))
    payment_line("p44", s1_t.leaf)
    add(f"release accept standby-e2-other-shard p44 {h(gate.encode_token(s1_t))}")
    add(f"release reject standby-e2-other-shard-again p44 {h(gate.encode_token(s1_t))}")
    # Equivocation by shard count alone: epoch 5's same key with 8 shards, root-signed, is recorded and blocks epoch 5
    cert("eq5")
    shards_at = len(gate.KEY_CERT) + 2 + len(STANDBY) + 8 + gate.DIGEST + 1
    add(f"cert reject {h(key_cert('eq5', edit=lambda b: b[:shards_at] + (2 * OTHER_SHARDS).to_bytes(4, 'big') + b[shards_at + 4 :]))}")
    eq5_cp = _batch([standby(44, 0, 5)], lambda m: sign("eq5", m), gate.ZERO_DIGEST)[0]
    add(f"checkpoint reject eq5-after-shard-count-equivocation {h(signed(eq5_cp, 'eq5'))}")

    # A self-certified key (the tenant's root key, or its witness key, certified as its own epoch key or verifier key):
    # one key per purpose, so its key never verifies a checkpoint
    root_sf = f"root-{SELF}"
    link_line(SELF)

    def self_cert(epoch: int, public_key: bytes | None = None, verifier_key: bytes | None = None) -> bytes:
        body = gate.encode_key_cert(SELF, epoch, link_digest(SELF), (OTHER_SHARDS,), public_key or keypair(root_sf)[0],
                                    verifier_key or keypair(f"verifier-{SELF}")[0])
        return certify(body, SELF)

    member_sf = next(k for i in count() if (k := gate.sha3_512(b"RR/GATE/TEST-ONLY-MEMBER/v1\x00sf" + bytes([i]))[:gate.MEMBER_KEY])
                     and gate.shard_of(SELF, k, OTHER_SHARDS) == 0)

    def self_leaf(n: int, epoch: int) -> gate.TokenLeaf:
        return replace(_leaf(n, 0, shard=0, member_key=member_sf), tenant_id=SELF, epoch=epoch)

    f1_cp, _, (f1_t,) = _batch([self_leaf(51, 1)], lambda m: sign("sf1", m), gate.ZERO_DIGEST)
    cert("sf1")
    checkpoint_line("self-e1", f1_cp, signed(f1_cp, "sf1"))
    payment_line("p51", f1_t.leaf)
    token("accept", "self-before-fence", "p51", f1_t)
    # A certificate may not name a key of its own link (KEY_REUSE): it is refused, installs nothing and fences nothing
    add(f"cert reject {h(self_cert(2))}")  # the root key as the epoch key
    add(f"cert reject {h(self_cert(2, verifier_key=keypair(f'witness-{SELF}')[0]))}")  # the witness key as the verifier key
    token("accept", "self-cert-refused-fences-nothing", "p51", f1_t)
    add(f"cert reject {h(self_cert(3))}")
    cert("sf4")
    f4_cp = _batch([self_leaf(52, 4)], lambda m: b"", gate.ZERO_DIGEST)[0]
    add(f"checkpoint reject self-e4-signed-by-root {h(signed(f4_cp, 'sf4', det_sign(root_sf, gate.encode_checkpoint_header(f4_cp))))}")

    # #2 DECIDE-RESPONSE/v2, each judged against the request it answers
    requests = {"r0": _request("FFS_CYCLE", 0, _lines(0, "FFS_CYCLE")), "r1": _request("FFS_CLAIM", 1, _lines(1)),
                "r0-new-key": _request("FFS_CYCLE", 0, _lines(0, "FFS_CYCLE"), key=100),
                "r4-cap": _request("CAP_820", 4, _lines(4, "CAP_820"), key=104),
                "r9": _request("FFS_CYCLE", 9, _lines(9, "FFS_CYCLE")), "r7-plan": _request("PLAN_PAY", 7, key=107),
                "r8": _request("FFS_CYCLE", 8, _lines(8, "FFS_CYCLE"))}
    for name, r in requests.items():
        request_line(name, r)
    R = gate.DecideResponse
    decided = R(TENANT, PROGRAM, "cmd-0000", "DECIDED", token=t0)
    refused = R(TENANT, PROGRAM, "cmd-0009", "REJECTED", reject_code="COMMAND_KEY_CONFLICT")
    accepted = (
        ("decided", "r0", decided),
        ("duplicate", "r1", R(TENANT, PROGRAM, "cmd-0001", "DUPLICATE", token=tokens[1])),
        ("duplicate-reissued", "r1", R(TENANT, PROGRAM, "cmd-0001", "DUPLICATE", token=t1_e8)),
        ("already-decided", "r0-new-key", R(TENANT, PROGRAM, "cmd-0100", "PAYMENT_ALREADY_DECIDED", token=t0)),
        ("already-decided-unruled-other-flow", "r7-plan",
         R(TENANT, PROGRAM, "cmd-0107", "PAYMENT_ALREADY_DECIDED", token=sdp_token)),
        ("rejected", "r9", refused),
        ("unavailable", "r9", R(TENANT, PROGRAM, "cmd-0009", "UNAVAILABLE", retry_after_ms=2_000)),
        ("answered", "r8", R(TENANT, PROGRAM, "cmd-0008", "DECIDED", token=rogue[3],
                             earlier=(("line-8-0", PROGRAM, "pay-0000", "line-0-0"),))),
    )
    for name, request_name, r in accepted:
        payload = h(gate.encode_token(r.token)) if r.token else r.reject_code or str(r.retry_after_ms)
        listed = ",".join("/".join(e) for e in r.earlier) or "-"
        add(f"response accept {name} {request_name} {h(gate.encode_decide_response(r))} {r.tenant_id} {r.program_id} {r.command_key} {r.status} {payload} {listed}")
    enc = gate.encode_decide_response
    ok, no = enc(decided), enc(refused)

    def leaf_of(response: gate.DecideResponse = decided, **change) -> gate.DecideResponse:
        return replace(response, token=replace(response.token, leaf=replace(response.token.leaf, **change)))

    for name, request_name, data in (
        ("truncated", "r0", ok[:-1]),
        ("trailing", "r0", ok + b"\x00"),
        ("wrong-domain", "r0", gate.DECIDE_REQUEST + ok[len(gate.DECIDE_RESPONSE) :]),
        ("head-tenant", "r9", enc(replace(refused, tenant_id=OTHER))),
        ("head-program", "r9", enc(replace(refused, program_id="medicaid-cap"))),
        ("head-command-key", "r9", enc(replace(refused, command_key="cmd-0008"))),
        ("leaf-tenant", "r0", enc(leaf_of(tenant_id=OTHER))),
        ("leaf-program", "r0", enc(leaf_of(program_id="medicaid-cap"))),
        ("leaf-member-key", "r0", enc(leaf_of(member_key=member(90)))),
        ("leaf-payee", "r0", enc(leaf_of(payee_ref="payee-9"))),
        ("leaf-amount", "r0", enc(leaf_of(amount_cents=124_999))),
        ("leaf-period", "r0", enc(leaf_of(period="2026-10"))),
        ("leaf-lines-root", "r1", enc(leaf_of(accepted[1][2], lines_root=D[7]))),
        ("leaf-payment", "r0", enc(leaf_of(payment_id="pay-0009"))),
        ("already-decided-other-flow", "r4-cap",
         enc(R(TENANT, PROGRAM, "cmd-0104", "PAYMENT_ALREADY_DECIDED", token=tokens[4]))),
        ("decided-other-flow", "r7-plan", enc(R(TENANT, PROGRAM, "cmd-0107", "DECIDED", token=sdp_token))),
        ("retry-zero", "r9", enc(accepted[6][2])[:-4] + bytes(4)),
        ("flipped-status-bit", "r9", _flip(no, len(no) - 2)),
        # the answered response's earlier list (the bytes `earlier` above): only with its token's root, never left out
        ("answered-without-earlier", "r8", enc(accepted[7][2])[: -len(earlier)] + bytes(2)),
        ("earlier-on-allow", "r0", ok[:-2] + earlier),
        ("earlier-other-line", "r8", enc(accepted[7][2]).replace(b"line-0-0", b"line-0-1")),
    ):
        add(f"response reject {name} {request_name} {h(data)}")
    add(f"end {sum(line.split(' ', 1)[0] in CHECKED for line in out)}")
    return "\n".join(out) + "\n"


LEAN_VECTORS = signer.ROOT / "lean" / ".lake" / "build" / "bin" / "gate_vectors.exe"


class GoldenVectorTests(unittest.TestCase):
    def test_python_reproduces_every_vector_byte(self) -> None:
        self.assertEqual(build_vectors(), VECTORS.read_text("ascii"))

    def test_lean_judges_every_golden_vector(self) -> None:
        for path in (VECTORS,):
            done = subprocess.run([str(LEAN_VECTORS), str(path)], capture_output=True, text=True, timeout=1800, check=False)
            self.assertRegex(done.stdout.strip(), r"^GATE_VECTORS=PASS checked=(\d+) expected=\1 failed=0$", path.name)

    def test_state_digest_commits_to_the_rules_pins(self) -> None:
        rules = RULES.read_text("ascii")
        for kind, pin in zip(("released", "unresolved"), PINS):
            self.assertIn(f"\nsnap {kind} 20270315 0 {pin.hex()}\n", rules)

    def test_signer_refuses_an_unpinned_or_missing_binary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            handle, wrong, absent = str(Path(tmp) / "k"), Path(tmp) / "pin", Path(tmp) / "absent.exe"
            signer.keygen(handle)  # a real key, so each refusal is the one under test and not a missing key
            wrong.write_text("0" * 64 + "\n", "ascii")
            for name, value, refusal in (("PIN", wrong, "rr_gate_mldsa87_pin_mismatch"), ("BINARY", absent, "absent_failed"),
                                         ("VERIFY_PIN", wrong, "gate_verify_pin_mismatch"), ("VERIFY", absent, "absent_failed")):
                with self.subTest(name), mock.patch.object(signer, name, value), self.assertRaisesRegex(signer.GateSignerError, refusal):
                    signer.seal(handle, b"", b"", None, b"header", [], 0, lambda signed: b"")

    def test_the_hashed_copy_cannot_be_written_or_deleted(self) -> None:
        copy = signer._private_copy(signer.BINARY)[0]
        with self.assertRaises(PermissionError):
            copy.write_bytes(b"x")
        with self.assertRaises(PermissionError):
            copy.unlink()

    def test_the_in_tree_gate_verify_build_is_the_pinned_exe(self) -> None:
        built = signer.ROOT / "lean" / ".lake" / "build" / "bin" / "gate_verify.exe"  # this tree's build is the pinned exe; the sources it came from are tools/tcb_report.txt's manifest line
        self.assertEqual(hashlib.sha256(built.read_bytes()).hexdigest(), signer.VERIFY_PIN.read_text("ascii").strip())

    def test_signing_is_hedged(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            handle = str(Path(tmp) / "k")
            pk = signer.keygen(handle)
            first, second = signer.sign(handle, b"same message"), signer.sign(handle, b"same message")
            self.assertNotEqual(first, second)
            for sig in (first, second):
                self.assertEqual(_kat("kat-verify", pk + sig + b"\x00\x00same message", 1), b"\x01")


class Scratch(unittest.TestCase):
    """A temp directory whose tracked stores close first (Windows will not delete an open SQLite file)."""

    def setUp(self) -> None:
        self._stores: list = []

    def track(self, store):
        self._stores.append(store)
        return store

    @contextlib.contextmanager
    def scratch(self):
        with tempfile.TemporaryDirectory() as tmp:
            try:
                yield tmp
            finally:
                for store in self._stores:
                    store.close()


def custody(tmp: str, name: str = "e7") -> tuple[str, bytes, bytes]:
    """A fresh epoch key file, the tenant's test-only authority link, and the certificate for it its root and witness keys signed."""
    handle = str(Path(tmp) / f"{name}.key")
    return handle, link(CERTS[name][1]), certify(cert_body(name, signer.keygen(handle)), CERTS[name][1])


def batch_leaves(first_seq: int, n: int, start: int = 0) -> list[gate.TokenLeaf]:
    """``n`` leaves of the main shard, payment ids ascending, seq consecutive from ``first_seq``."""
    return sorted((_leaf(start + k, first_seq + k) for k in range(n)), key=lambda leaf: leaf.payment_id.encode())


def payment_request(n: int) -> gate.DecideRequest:
    """The payer's own request for payment ``n``, exactly as ``_leaf(n, ...)`` decided it."""
    flow = "FFS_CLAIM" if n % 4 else "FFS_CYCLE"
    return _request(flow, n, _lines(n, flow))


def batch_pays(n: int, start: int = 0) -> list:
    """``n`` Lean payment answers (``decide.Pay``: the leaf fields Lean printed, ALLOW with two reasons under a TRANSFER grant, a stand-in input over the request
    and the head ``D[1]``), as a decide prepares them, for payments ``start`` on."""
    from app import right_rail_gate_decide as decide
    return [decide.Pay("ALLOW", ("ELIGIBLE", "RATE_OK"), r.tenant_id, r.program_id, r.flow, r.payment_id, r.member_key, r.payee_ref,
                       r.amount_cents, r.period, gate.lines_root(r.lines), synthetic_input(r, D[1]), "TRANSFER", D[3], bytes(64))
            for r in map(payment_request, range(start, start + n))]


def build(leaves, prev: bytes = gate.ZERO_DIGEST, head: bytes = gate.ZERO_DIGEST, counter: int | None = None):
    """A batch of ``leaves`` (re-numbered from the first one's seq) linked to ``prev`` and ``head``."""
    leaves = [replace(leaf, seq=leaves[0].seq + i) for i, leaf in enumerate(leaves)]
    return gate.build_batch(leaves, prev_checkpoint_digest=prev, event_head=head, evidence_root=gate.ZERO_DIGEST,
                            state_digest=STATE, created_at=NOW, counter=counter or _auto_counter())


def _genesis(leaves) -> tuple[bytes, list[bytes]]:
    """The header and encoded tokens of a shard's first batch."""
    cp, tokens = build(leaves, counter=1)  # a shard's first checkpoint takes counter 1 (Lean ``follows none``)
    return gate.encode_checkpoint_header(cp), [gate.encode_token(t) for t in tokens]


def signed_genesis(handle: str, n: int = 0, seal: tuple[bytes, bytes] | None = None) -> tuple[bytes, list[bytes]]:
    """Payments 0-1 as a shard's first checkpoint (genesis n), signed by the epoch key or, with ``seal`` = (link, cert), by custody;
    and its tokens.  Either way it carries the test verifier's cosign record."""
    header, tokens = _genesis(batch_leaves(0, 2, n))
    if seal:
        signature, record = signer.seal(handle, *seal, None, header, tokens, 0, cosigner())
        return gate.attach_signature(header, signature) + record, tokens
    return gate.attach_signature(header, signer.sign(handle, header)) + cosign_record(header), tokens


def _u16(n: int) -> bytes:
    return n.to_bytes(2, "big")


def _blob(x: bytes) -> bytes:
    return _u16(len(x)) + x


def _list(items) -> bytes:
    return _u16(len(items)) + b"".join(items)


def _authority(certs, conflict: bytes = b"", fence: bytes = b"") -> bytes:
    """A STORE or RELEASE frame's authority part: the tenant's held link as head, a carried link conflict, the link the
    certificates name, the certificate witnesses and the fence certificate (empty: none)."""
    held = signer.framed(link(TENANT))
    return held + signer.framed(conflict) + _list([held]) + _list([signer.framed(c) for c in certs]) + signer.framed(fence)


def _genesis_after(leaves, prev: bytes, counter: int) -> tuple[bytes, list[bytes]]:
    """The header and encoded tokens of a batch linked to ``prev``, taking ``counter``."""
    cp, tokens = build(leaves, prev, prev, counter)
    digest = gate.checkpoint_digest(cp)
    return gate.encode_checkpoint_header(cp), [gate.encode_token(replace(t, checkpoint_digest=digest)) for t in tokens]


def _publish(held: bytes, cert: bytes, signed: bytes, tokens: list[bytes]) -> str:
    """``gate_verify`` PUBLISH of a shard's first checkpoint: the frame ``seal`` builds."""
    return signer.gate_verify(1, signer.framed(held) + signer.framed(cert) + signer.framed(b"") + signer.framed(signed)
                              + _u16(len(tokens)) + b"".join(map(signer.framed, tokens)) + (0).to_bytes(8, "big"))


class GateVerifyModeTests(unittest.TestCase):
    """``gate_verify``'s five modes, each with an accepting and a refusing frame; ``seal`` is mode PUBLISH."""

    def test_signature_leaves_only_when_gate_verify_accepts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            handle, held, cert = custody(tmp)
            header, tokens = _genesis([_leaf(n, n) for n in range(5)])
            self.assertEqual(len(_tpm_seal(handle, held, cert, None, header, tokens)), gate.ML_DSA_87_SIGNATURE)
            epoch_at = len(gate.KEY_CERT) + 2 + len(TENANT)
            body = gate.read_key_cert(cert).body
            by_epoch_key = gate.attach_signatures(body, signer.sign(handle, body), signer.sign(handle, body))
            root_only = gate.attach_signatures(body, det_sign(f"root-{TENANT}", body), signer.sign(handle, body))
            epoch_edited = cert[:epoch_at] + (EPOCH + 1).to_bytes(8, "big") + cert[epoch_at + 8 :]
            old = custody(tmp, "e6")
            # Each case breaks one link; the verifier refuses and no signature leaves
            for name, key, chain, change in (
                ("another tenant's link", handle, (link(OTHER), cert), {}),
                ("a certificate whose cosignature bit was flipped", handle, (held, _flip(cert, len(cert) - 1, 0x01)), {}),
                ("a certificate whose root signature bit was flipped", handle,
                 (held, _flip(cert, len(cert) - 2 - gate.ML_DSA_87_SIGNATURE - 1, 0x01)), {}),
                ("a certificate signed by the epoch key, not the root and witness", handle, (held, by_epoch_key), {}),
                ("a certificate the witness did not cosign", handle, (held, root_only), {}),
                ("a certificate whose epoch was edited after signing", handle, (held, epoch_edited), {"epoch": EPOCH + 1}),
                ("an epoch 6 header signed with the epoch 7 key", handle, (held, cert), {"epoch": EPOCH - 1}),
                ("an epoch 8 header signed with the epoch 7 key", handle, (held, cert), {"epoch": EPOCH + 1}),
                ("a header for another tenant", handle, (held, cert), {"tenant_id": OTHER}),
                ("an epoch 6 key and certificate on an epoch 7 header", old[0], old[1:], {}),
            ):
                with self.subTest(name), self.assertRaisesRegex(signer.GateSignerError, "gate_verify_refused"):
                    _tpm_seal(key, *chain, None, *_genesis([replace(_leaf(0, 0), **change)]))
            # The verifier's cosignature is required, and it must be this tenant's verifier's over this header
            for name, cosign in (
                ("a cosignature by another tenant's verifier", lambda s: cosign_record(_header_of(s), OTHER)),
                ("a cosignature of another header", lambda s: cosign_record(_flip(_header_of(s), 40, 0x01))),
                ("a cosignature by the epoch key", lambda s: gate.encode_cosign(VREL, signer.sign(handle, gate.cosign_message(_header_of(s), VREL)))),
                ("no cosignature", lambda s: b""),
                ("a cosignature cut short", lambda s: cosign_record(_header_of(s))[:-1]),
            ):
                with self.subTest(name), self.assertRaisesRegex(signer.GateSignerError, "gate_verify_refused"):
                    signer.seal(handle, held, cert, None, header, tokens, 0, cosign)
            real = signer.sign  # a faulty signature never leaves
            with mock.patch.object(signer, "sign", lambda h, m: _flip(real(h, m), 100)), \
                    self.assertRaisesRegex(signer.GateSignerError, "gate_verify_refused"):
                _tpm_seal(handle, held, cert, None, header, tokens)

    def test_publish_refuses_a_counter_that_is_not_the_one_read_plus_one(self) -> None:
        """Review L: ``tpm`` is its own input, so a header whose counter is not ``tpm`` + 1 is refused through ``_tpm_seal``."""
        with tempfile.TemporaryDirectory() as tmp:
            handle, held, cert = custody(tmp)
            header, tokens = _genesis([_leaf(n, n) for n in range(2)])
            counter = int.from_bytes(header[-8:], "big")
            for tpm in (counter, counter + 1, counter + 4):
                with self.subTest(tpm=tpm), self.assertRaisesRegex(signer.GateSignerError, "gate_verify_refused"):
                    _tpm_seal(handle, held, cert, None, header, tokens, tpm=tpm)
            self.assertEqual(len(_tpm_seal(handle, held, cert, None, header, tokens, tpm=counter - 1)), gate.ML_DSA_87_SIGNATURE)

    def test_publish_refuses_a_first_checkpoint_that_is_not_counter_1(self) -> None:
        """Review H, golden vector: a store deleted or recreated while its counter is at t > 0 would sign seq 0 at counter
        t + 1, which is ``tpm`` + 1; with no predecessor the verifier requires counter 1, so it is refused for every t > 0."""
        with tempfile.TemporaryDirectory() as tmp:
            handle, held, cert = custody(tmp)
            for counter in (2, 3, 8, 2**40):
                checkpoint, tokens = build(batch_leaves(0, 2), counter=counter)
                header, encoded = gate.encode_checkpoint_header(checkpoint), [gate.encode_token(t) for t in tokens]
                with self.subTest(counter=counter), self.assertRaisesRegex(signer.GateSignerError, "gate_verify_refused"):
                    signer.seal(handle, held, cert, None, header, encoded, counter - 1, cosigner())

    def test_publish_takes_the_next_counter_on_the_linked_chain(self) -> None:
        """A successor is the next seq on the previous digest and takes the counter after the one read (``tpm`` + 1)."""
        with tempfile.TemporaryDirectory() as tmp:
            handle, held, cert = custody(tmp)
            first, first_tokens = _genesis([_leaf(n, n) for n in range(2)])
            signature, record = signer.seal(handle, held, cert, None, first, first_tokens, 0, cosigner())
            last = gate.attach_signature(first, signature) + record
            previous = gate.sha3_512(first)
            for name, prev, counter, tpm, outcome in (
                ("next counter", previous, 2, 1, None),
                ("unlinked", D[0], 2, 1, "gate_verify_refused"),
                ("counter skipped", previous, 3, 1, "gate_verify_refused"),
                ("counter repeated", previous, 1, 0, "gate_verify_refused"),
                ("counter not tpm + 1", previous, 2, 2, "gate_verify_refused"),
            ):
                header, raw = _genesis_after([_leaf(2, 2)], prev, counter)
                with self.subTest(name):
                    if outcome is None:
                        self.assertEqual(len(signer.seal(handle, held, cert, last, header, raw, tpm, cosigner())[0]), gate.ML_DSA_87_SIGNATURE)
                    else:
                        with self.assertRaisesRegex(signer.GateSignerError, outcome):
                            signer.seal(handle, held, cert, last, header, raw, tpm, cosigner())

    def test_custody_step_answers_from_the_two_counters(self) -> None:
        """The store's counter is read by Lean from the signed checkpoint (Round 3): a checkpoint at ``newest``, or none."""
        with tempfile.TemporaryDirectory() as tmp:
            handle, held, cert = custody(tmp)
            at = lambda n: gate.attach_signature(gate.encode_checkpoint_header(build([_leaf(0, 0)], counter=n)[0]), bytes(gate.ML_DSA_87_SIGNATURE))
            for tpm, newest, answer in ((None, None, "create"), (5, 5, "ready"), (5, 6, "catch_up"), (None, 4, "counter_reset"),
                                        (None, 1, "counter_reset"), (5, None, "no_store"), (6, 5, "store_rewound"), (5, 7, "store_ahead")):
                with self.subTest(tpm=tpm, newest=newest):
                    self.assertEqual(signer.custody(tpm, held, b"", at(newest) if newest else b""), answer)
            for tpm in (None, 5):  # a newest checkpoint that does not decode is never served or created on
                with self.subTest(unreadable=tpm):
                    self.assertEqual(signer.custody(tpm, held, cert, b"not a checkpoint"), "store_rewound")

    def test_an_unwritten_counter_catches_up_only_under_the_signed_first_checkpoint(self) -> None:
        """Final review U5: a crash between the first seal's signature commit and the counter's first increment leaves the
        counter unwritten under the signed first checkpoint; the start catches up (Lean ``first_seal_crash_heals``).  The
        same counter values under a later checkpoint, a forged signature, another root key or certificate, or a counter
        other than the header's are still ``counter_reset``, and a written counter answers as before."""
        with tempfile.TemporaryDirectory() as tmp:
            handle, held, cert = custody(tmp)
            first, tokens = _genesis([_leaf(n, n) for n in range(2)])
            signature, record = signer.seal(handle, held, cert, None, first, tokens, 0, cosigner())
            signed = gate.attach_signature(first, signature) + record
            later, later_tokens = _genesis_after([_leaf(2, 2)], gate.sha3_512(first), 2)
            signature, record = signer.seal(handle, held, cert, signed, later, later_tokens, 1, cosigner())
            signed_later = gate.attach_signature(later, signature) + record
            at = len(first) + 1 + 2  # a byte inside the checkpoint signature
            forged = _flip(signed, at)
            uncosigned = signed[: -gate.COSIGN_RECORD]
            other_link, other_cert = link(OTHER), custody(tmp, "e6")[2]
            self.assertEqual(signer.custody(None, held, cert, signed), "catch_up")
            for name, pk, c, s, answer in (
                    ("later checkpoint", held, cert, signed_later, "counter_reset"),
                    ("forged signature", held, cert, forged, "counter_reset"),
                    ("no cosignature", held, cert, uncosigned, "counter_reset"),
                    ("other link", other_link, cert, signed, "counter_reset"),
                    ("other certificate", held, other_cert, signed, "counter_reset"),
                    ("written counter", held, cert, signed, "ready")):
                with self.subTest(name):
                    self.assertEqual(signer.custody(1 if name == "written counter" else None, pk, c, s), answer)

    def test_a_self_certified_root_never_verifies_a_checkpoint(self) -> None:
        """A certificate for the root key itself, with a checkpoint the root key signed: refused to publish and to store.  The
        certificate carries the link's signatures, but a certificate may not name a key of its own link (key reuse), so the
        payer refuses to install it and a STORE frame that carries it decides as if it were absent."""
        name, root_pk = f"root-{TENANT}", keypair(f"root-{TENANT}")[0]
        cert = certify(cert_body("e7", root_pk), TENANT)
        header, tokens = _genesis([_leaf(n, n) for n in range(2)])
        signed = gate.attach_signature(header, det_sign(name, header)) + cosign_record(header)
        self.assertEqual(_publish(link(TENANT), cert, signed, tokens), "GATE_VERIFY=REJECT")
        with tempfile.TemporaryDirectory() as tmp, contextlib.closing(
                payer.PayerStore(Path(tmp) / "payer.sqlite3", links={TENANT: link(TENANT)}, grants=())) as store:
            with self.assertRaisesRegex(payer.GatePayerError, "cert_refused"):
                store.install_cert(cert)
            with self.assertRaisesRegex(payer.GatePayerError, "checkpoint_rejected"):
                store.store_checkpoint(signed)
            self.assertEqual(store._db.execute("SELECT count(*) FROM checkpoints").fetchone()[0], 0)
        self.assertEqual(signer.gate_verify(3, _authority([cert]) + _u16(0) + _u16(0) + signer.framed(signed)), "GATE_VERIFY=REJECT")

    def test_a_signature_for_one_purpose_is_refused_for_every_other(self) -> None:
        """One key signs a KEY-CERT body, a checkpoint header, an AUTHORITY-LINK body and both financial custody records; no signature
        verifies as another purpose, and no tag is a prefix of another."""
        name = f"root-{TENANT}"
        d = bytes(range(64))
        tags = (gate.KEY_CERT, gate.CHECKPOINT, gate.VCOSIGN, b"RR/FINANCIAL/CUSTODY-SIGNED/v1\x00", b"RR/FINANCIAL/PACK-SIGNED/v1\x00")
        self.assertFalse(any(b.startswith(a) for a, b in permutations(tags, 2)))
        header, tokens = _genesis([_leaf(n, n) for n in range(2)])
        good = key_cert("e7"), gate.attach_signature(header, det_sign("e7", header)) + cosign_record(header)
        self.assertEqual(_publish(link(TENANT), *good, tokens), "GATE_VERIFY=ACCEPT")  # control: the proper pair verifies
        messages = (cert_body("e7"), header, gate.cosign_message(header, VREL), tags[3] + d, tags[4] + d, gate.read_link(link(TENANT)).body)
        signed = [gate.attach_signature(m, det_sign(name, m)) for m in messages]
        for i, one in enumerate(signed):
            with self.subTest(i):
                if i != 0:  # in the certificate's place
                    self.assertEqual(_publish(link(TENANT), one, good[1], tokens), "GATE_VERIFY=REJECT")
                if i != 1:  # in the checkpoint's place
                    self.assertEqual(_publish(link(TENANT), good[0], one + cosign_record(header), tokens), "GATE_VERIFY=REJECT")

    def test_a_malformed_frame_is_not_an_answer(self) -> None:
        for mode, frame in ((1, b""), (2, b"\x00\x00\x00\x05abc"), (3, bytes(2592)), (4, b"\x00"), (5, b"\x00"), (9, b"")):
            with self.subTest(mode), self.assertRaisesRegex(signer.GateSignerError, "gate_verify_failed"):
                signer.gate_verify(mode, frame)

    def test_index_prints_the_decoded_checkpoint(self) -> None:
        header = _genesis([_leaf(n, n) for n in range(3)])[0]
        signed = sign_header(header)
        self.assertEqual(signer.gate_verify(2, signer.framed(signed)),
                         f"GATE_VERIFY=INDEX {TENANT.encode().hex()} {SHARD} {EPOCH} 0 2 {gate.sha3_512(header).hex()} {'00' * 64} 1")
        self.assertEqual(signer.gate_verify(2, signer.framed(signed[:-1])), "GATE_VERIFY=REJECT")

    def test_store_stores_a_batch_and_names_the_checkpoint_a_second_one_forks(self) -> None:
        cert = key_cert("e7")
        first, second = (_genesis([_leaf(n + k, n) for n in range(2)])[0] for k in (0, 5))
        sign = sign_header

        def store(candidates: list[bytes], new: bytes, certs: tuple[bytes, ...] = (cert,)) -> str:
            frame = _authority(certs) + _list([signer.framed(c) for c in candidates])
            return signer.gate_verify(3, frame + _u16(0) + signer.framed(new))

        self.assertEqual(store([], sign(first)), "GATE_VERIFY=STORED")
        self.assertEqual(store([sign(first)], sign(second)), f"GATE_VERIFY=FORK {gate.sha3_512(first).hex()}")
        self.assertEqual(store([], _flip(sign(first), len(first) + 100)), "GATE_VERIFY=REJECT")
        self.assertEqual(store([], sign(first)[: -gate.COSIGN_RECORD]), "GATE_VERIFY=REJECT")  # no cosignature
        self.assertEqual(store([], _flip(sign(first), len(sign(first)) - 100)), "GATE_VERIFY=REJECT")  # a cosignature bit flipped
        self.assertEqual(store([], sign(first), ()), "GATE_VERIFY=REJECT")  # no installed certificate

    def test_store_and_release_take_a_recorded_fork_as_a_pair_and_stop_its_shard(self) -> None:
        """Evidence is ``u16 f`` then two ``u32``-framed checkpoints per fork.  A fork pins its shard in every epoch and keeps
        blocking both sides' epochs on every shard of the tenant; another shard in other epochs is not blocked."""
        sign = lambda leaves, epoch, key: sign_header(
            gate.encode_checkpoint_header(build([replace(leaf, epoch=epoch) for leaf in leaves], counter=1)[0]), key)
        a, b = sign(batch_leaves(0, 2), EPOCH - 1, "e6"), sign(batch_leaves(0, 2, 5), EPOCH + 1, "e8")  # a recorded fork, epochs 6 and 8
        other = sign([replace(leaf, shard_id=SHARD + 1) for leaf in batch_leaves(0, 2)], EPOCH - 1, "e6")
        pairs = lambda *forks: _list([signer.framed(x) + signer.framed(y) for x, y in forks])
        new = sign(batch_leaves(0, 2, 10), EPOCH, "e7")
        store = lambda forks: signer.gate_verify(3, _authority([key_cert("e7")]) + _u16(0) + pairs(*forks) + signer.framed(new))
        self.assertEqual(store([]), "GATE_VERIFY=STORED")
        self.assertEqual(store([(a, b)]), "GATE_VERIFY=REJECT")  # its shard, an epoch other than the fork's two
        self.assertEqual(store([(other, other)]), "GATE_VERIFY=STORED")  # another shard, other epochs
        header, tokens = _genesis([_leaf(n, n) for n in range(2)])
        signed, request = sign_header(header), gate.encode_decide_request(payment_request(0))
        grants = _list([_blob(TENANT.encode()) + _blob(D[3]) + _list([_blob(D[4])]) + _list([_blob(D[6])])])

        def release(forks) -> str:
            frame = _authority([key_cert("e7")]) + pairs(*forks) + signer.framed(signed) + NOW.to_bytes(8, "big")
            return signer.gate_verify(5, frame + grants + bytes([0, 1]) + member(0) + signer.framed(request) + signer.framed(tokens[0]))
        self.assertEqual(release([]), "GATE_VERIFY=ACCEPT")
        self.assertEqual(release([(a, b)]), "GATE_VERIFY=HOLD forked")
        self.assertEqual(release([(other, other)]), "GATE_VERIFY=ACCEPT")

    def test_store_forks_across_epochs_when_the_next_counter_does_not_name_the_other(self) -> None:
        """``unlinked a b`` in two epochs: counter 2 in epoch 8 whose chain head is not the epoch 7 checkpoint of counter 1."""
        first = _genesis([_leaf(n, n) for n in range(2)])[0]
        cp, _ = build(batch_leaves(2, 2, 10), gate.sha3_512(first), D[5], 2)  # linked by prev, not by chain head
        header = gate.encode_checkpoint_header(replace(cp, epoch=EPOCH + 1))
        frame = _authority([key_cert("e7"), key_cert("e8")]) + _list([signer.framed(sign_header(first))]) + _u16(0)
        self.assertEqual(signer.gate_verify(3, frame + signer.framed(sign_header(header, "e8"))),
                         f"GATE_VERIFY=FORK {gate.sha3_512(first).hex()}")

    def test_release_accepts_a_payer_state_and_holds_with_the_first_failure(self) -> None:
        cert = key_cert("e7")
        header, tokens = _genesis([_leaf(n, n) for n in range(2)])
        signed, request = sign_header(header), gate.encode_decide_request(payment_request(0))
        untenanted = _blob(D[3]) + _list([_blob(D[4])]) + _list([_blob(D[6])])

        def release(pinned: bool = True, released: bool = False, token: bytes = tokens[0], tenant: str = TENANT,
                    mode: int = 5, grant: bytes | None = None) -> str:
            frame = _authority([cert]) + _u16(0) + signer.framed(signed) + NOW.to_bytes(8, "big")
            frame += _list([_blob(tenant.encode()) + untenanted if grant is None else grant]) + bytes([released, pinned]) + (member(0) if pinned else b"")
            return signer.gate_verify(mode, frame + signer.framed(request) + signer.framed(token))

        self.assertEqual(release(), "GATE_VERIFY=ACCEPT")
        self.assertEqual(release(tenant=OTHER), "GATE_VERIFY=HOLD grant")  # another tenant's grant, same id
        for mode, grant in ((4, untenanted), (5, untenanted), (5, _blob(b"-x") + untenanted)):
            with self.subTest(mode=mode, grant=grant[:4]), self.assertRaisesRegex(signer.GateSignerError, "gate_verify_failed"):
                release(mode=mode, grant=grant)  # the retired 0x04 frame, its grant under 0x05, a non-ident tenant
        self.assertEqual(release(pinned=False), "GATE_VERIFY=HOLD pin")
        self.assertEqual(release(released=True), "GATE_VERIFY=HOLD released")
        self.assertEqual(release(token=tokens[0][:-1]), "GATE_VERIFY=HOLD parse")
        with self.assertRaisesRegex(signer.GateSignerError, "gate_verify_failed"):
            signer.gate_verify(5, b"\x00\x00\x00\x00" + _u16(0) + _u16(0) + signer.framed(signed))  # a link that does not decode

    def test_stateless_signing_path_is_gone(self) -> None:
        for name in ("sign_batch", "CheckedSigner"):
            self.assertFalse(hasattr(gate, name), name)
        self.assertFalse(hasattr(signer, "checked"))
        for source in (signer.ROOT / "app").rglob("*.py"):
            self.assertNotIn("sign_batch(", source.read_text("utf-8"), source.name)

    def test_seal_releases_a_signature_only_for_a_publishable_batch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            handle, held, cert = custody(tmp)
            checkpoint, tokens = build(batch_leaves(0, 5), counter=1)
            header, encoded = gate.encode_checkpoint_header(checkpoint), [gate.encode_token(t) for t in tokens]
            signature = _tpm_seal(handle, held, cert, None, header, encoded)
            first = gate.attach_signature(header, signature) + cosign_record(header)
            self.assertEqual(len(signature), gate.ML_DSA_87_SIGNATURE)
            nxt, nxt_tokens = build(batch_leaves(5, 3, 5), prev=gate.checkpoint_digest(checkpoint),
                                     head=gate.checkpoint_digest(checkpoint), counter=2)
            nxt_header, nxt_encoded = gate.encode_checkpoint_header(nxt), [gate.encode_token(t) for t in nxt_tokens]
            _tpm_seal(handle, held, cert, first, nxt_header, nxt_encoded)  # the chain extends
            refused = {
                "a token missing": (first, nxt_header, nxt_encoded[:-1]),
                "tokens out of seq order": (first, nxt_header, nxt_encoded[::-1]),
                "a token of another batch": (first, nxt_header, nxt_encoded[:-1] + encoded[:1]),
                "a fresh genesis after a published checkpoint": (first, header, encoded),
                "a successor with no predecessor": (None, nxt_header, nxt_encoded),
                "a last checkpoint that does not decode": (first[:-1], nxt_header, nxt_encoded),
            }
            back, back_tokens = build(batch_leaves(3, 2, 7), prev=gate.checkpoint_digest(checkpoint),
                                       head=gate.checkpoint_digest(checkpoint), counter=2)  # overlaps seq 3-4: a fork
            refused["a fork of the last checkpoint"] = (first, gate.encode_checkpoint_header(back),
                                                       [gate.encode_token(t) for t in back_tokens])
            for name, (last, head, toks) in refused.items():
                with self.subTest(name), self.assertRaisesRegex(signer.GateSignerError, "gate_verify"):
                    _tpm_seal(handle, held, cert, last, head, toks)

    def test_payment_ids_ascend_within_a_batch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            handle, held, cert = custody(tmp)
            leaves = batch_leaves(0, 3)
            checkpoint, tokens = build([leaves[0], leaves[2], leaves[1]], counter=1)
            with self.assertRaisesRegex(signer.GateSignerError, "gate_verify"):
                _tpm_seal(handle, held, cert, None, gate.encode_checkpoint_header(checkpoint),
                            [gate.encode_token(t) for t in tokens])

    def test_a_verifier_killed_mid_seal_releases_nothing_and_the_next_call_relaunches(self) -> None:
        """The REAL resident verifier is killed (its Job terminated) as the seal's check is sent: no signature leaves, the dead
        worker is dropped, the next call launches one verifier and gives the right verdicts (accept, then refuse)."""
        worker, real = signer.process.ContainedWorker, signer.process.ContainedWorker.exchange
        with tempfile.TemporaryDirectory() as tmp:
            handle, held, cert = custody(tmp)
            header, tokens = _genesis([_leaf(n, n) for n in range(3)])
            self.assertEqual(len(_tpm_seal(handle, held, cert, None, header, tokens)), gate.ML_DSA_87_SIGNATURE)
            victim = signer._VSERVER[0]

            def dies(self, *a, **kw):
                if self is victim:
                    self._terminate()
                return real(self, *a, **kw)
            with mock.patch.object(worker, "exchange", dies), self.assertRaisesRegex(signer.GateSignerError, "gate_verify_failed"):
                _tpm_seal(handle, held, cert, None, header, tokens)
            self.assertIsNone(signer._VSERVER[0])
            with mock.patch.object(signer.process, "launch_contained_worker", wraps=signer.process.launch_contained_worker) as launch:
                self.assertEqual(len(_tpm_seal(handle, held, cert, None, header, tokens)), gate.ML_DSA_87_SIGNATURE)
                with self.assertRaisesRegex(signer.GateSignerError, "gate_verify_refused"):
                    _tpm_seal(handle, held, _flip(cert, len(cert) - 1, 0x01), None, header, tokens)
                self.assertEqual(launch.call_count, 1)
            live = signer._VSERVER[0]
            real_read = live._read_exact

            def eof_mid_read(count):  # the request is sent; the verifier dies before its answer is read
                live._terminate()
                return real_read(count)
            with mock.patch.object(live, "_read_exact", eof_mid_read), self.assertRaisesRegex(signer.GateSignerError, "gate_verify_failed"):
                _tpm_seal(handle, held, cert, None, header, tokens)
            self.assertIsNone(signer._VSERVER[0])
            self.assertEqual(len(_tpm_seal(handle, held, cert, None, header, tokens)), gate.ML_DSA_87_SIGNATURE)

    @staticmethod
    def _forks_frame(forks: int = 500) -> bytes:
        """A RELEASE (mode 5) frame of 64 certs and ``forks`` stored forks, answered HOLD forked."""
        cert = key_cert("e7")
        header, tokens = _genesis([_leaf(n, n) for n in range(2)])
        signed, request = sign_header(header), gate.encode_decide_request(payment_request(0))
        untenanted = _blob(D[3]) + _list([_blob(D[4])]) + _list([_blob(D[6])])
        return (_authority([cert] * 64) +_list([signer.framed(signed) * 2] * forks) + signer.framed(signed)
                + NOW.to_bytes(8, "big") + _list([_blob(TENANT.encode()) + untenanted]) + bytes([0, 1]) + member(0)
                + signer.framed(request) + signer.framed(tokens[0]))

    def test_the_resident_verifier_answers_a_frame_of_64_certs_and_500_stored_forks_inside_its_cap_and_time(self) -> None:
        """Measured (one-shot, peak private bytes, uncapped): 64 certs + 500 forks = 10.7 MB, 94 MB, 1.4 s; 1000 forks 120 MB,
        2.6 s.  Recorded forks are read without their signed bytes, so under the 512 MB cap the verifier answers up to about
        1,100 forks (a hold, not an acceptance, so liveness only); 500 forks (a fork is two rows) must be answered, as a fork."""
        frame = self._forks_frame()
        self.assertGreater(len(frame), 2_900_000)
        self.assertEqual(signer.gate_verify(5, frame), "GATE_VERIFY=HOLD forked")

    def test_the_resident_verifier_answers_any_number_of_large_frames_in_bounded_memory(self) -> None:
        """The Windows Lean runtime's allocator never reuses or returns memory that a large request freed (the live heap stays
        flat, the commit does not), so one resident verifier grew with each such request until its 512 MiB cap killed it: the
        15th 1,000-claim checkpoint of a 100,000-line replay.  The 1,000-fork frame (20 MB) grows a kept worker by about
        85 MB a request, so the old worker died on the 6th.  Twelve all answer and no worker passes its cap: one holding over
        half of it after an answer is closed."""
        frame, real, commits = self._forks_frame(1000), signer.process.ContainedWorker.exchange, []

        def measured(worker, *a, **kw):
            out = real(worker, *a, **kw)
            commits.append(worker.commit_bytes())
            return out
        signer._close_server(signer._VSERVER)
        self.addCleanup(signer._close_server, signer._VSERVER)
        with mock.patch.object(signer.process.ContainedWorker, "exchange", measured):
            answers = [signer.gate_verify(5, frame) for _ in range(12)]
        self.assertEqual(answers, ["GATE_VERIFY=HOLD forked"] * 12)
        self.assertEqual(len(commits), 12)
        self.assertLess(max(commits), 512 << 20)
        live = signer._VSERVER[0]
        self.assertTrue(live is None or live.commit_bytes() <= 256 << 20)

    def test_a_verifier_that_will_not_close_after_an_answer_fails_the_call_without_a_retry(self) -> None:
        """A worker over half its cap after an answer is closed; if that close fails, the call fails, its answer is neither
        returned nor asked for again, the slot is empty, and the next call's fresh worker answers."""
        frame, worker = self._forks_frame(0), signer.process.ContainedWorker
        real_close = worker.close

        def refuses(self):
            real_close(self)
            raise signer.process.VerifierProcessError("worker_terminate")
        signer._close_server(signer._VSERVER)
        self.addCleanup(signer._close_server, signer._VSERVER)
        with mock.patch.object(worker, "commit_bytes", return_value=1 << 63), mock.patch.object(worker, "close", refuses), \
                mock.patch.object(worker, "exchange", autospec=True, side_effect=worker.exchange) as exchange, \
                self.assertRaisesRegex(signer.GateSignerError, "gate_verify_failed"):
            signer.gate_verify(5, frame)
        self.assertEqual(exchange.call_count, 1)
        self.assertIsNone(signer._VSERVER[0])
        self.assertEqual(signer.gate_verify(5, frame), "GATE_VERIFY=ACCEPT")

    def test_a_replaced_verifier_gives_every_answer_a_kept_one_gives(self) -> None:
        """Replacing the resident verifier between requests never changes an answer: the same requests (accepted, held for
        four causes, a certificate index, a rejection, two custody steps, and a malformed frame) answered by one kept worker
        (relaunched only after the malformed frame) and by a fresh worker per request give the same lines."""
        f0, cert, held = self._forks_frame(0), key_cert("e7"), signer.framed(link(TENANT))

        def custody(tpm: int | None) -> bytes:
            return bytes([tpm is not None]) + (tpm or 0).to_bytes(8, "big") + held + signer.framed(b"") + signer.framed(b"")
        requests = [(5, f0), (5, self._forks_frame(1)), (5, _flip(f0, len(f0) - 1, 0x01)), (5, _flip(f0, 40, 0x01)),
                    (9, signer.framed(cert)), (9, signer.framed(_flip(cert, 7))), (7, custody(None)), (7, custody(3)),
                    (5, f0), (5, f0[:-1]), (5, f0)]
        expected = ["GATE_VERIFY=ACCEPT", "GATE_VERIFY=HOLD forked", "GATE_VERIFY=HOLD batch", "GATE_VERIFY=HOLD fence",
                    "GATE_VERIFY=CERT-INDEX ", "GATE_VERIFY=REJECT", "GATE_VERIFY=CUSTODY create", "GATE_VERIFY=CUSTODY no_store",
                    "GATE_VERIFY=ACCEPT", "gate_verify_failed", "GATE_VERIFY=ACCEPT"]

        def answers(commit: int) -> tuple[list, int]:
            signer._close_server(signer._VSERVER)
            out = []
            with mock.patch.object(signer.process.ContainedWorker, "commit_bytes", return_value=commit), \
                    mock.patch.object(signer.process, "launch_contained_worker", wraps=signer.process.launch_contained_worker) as launch:
                for mode, f in requests:
                    try:
                        out.append(signer.gate_verify(mode, f))
                    except signer.GateSignerError as error:
                        out.append(str(error))
            return out, launch.call_count
        self.addCleanup(signer._close_server, signer._VSERVER)
        kept, replaced = answers(0), answers(1 << 63)
        self.assertEqual(replaced[0], kept[0])
        self.assertEqual([a[:len(e)] for a, e in zip(kept[0], expected)], expected)
        self.assertEqual(len(kept[0]), len(expected))
        self.assertEqual(kept[1], 2)  # one worker answers the first nine; the malformed frame kills it
        self.assertEqual(replaced[1], len(requests))  # a fresh worker for every request

    def test_the_resident_verifier_equals_the_one_shot_exe_on_valid_and_mutated_frames(self) -> None:
        """Every frame the mode tests send, and each with a flipped first, middle and last byte, a dropped last byte, an extra
        byte and every other mode byte: the resident worker and a fresh one-shot exe give the same line, or both refuse."""
        seen: dict[tuple[int, bytes], None] = {}
        real = signer.gate_verify

        def record(mode: int, frame: bytes) -> str:
            seen[(mode, frame)] = None
            return real(mode, frame)
        cases = self.__class__
        with mock.patch.object(signer, "gate_verify", record):
            for name in ("test_signature_leaves_only_when_gate_verify_accepts", "test_a_self_certified_root_never_verifies_a_checkpoint",
                         "test_index_prints_the_decoded_checkpoint", "test_store_and_release_take_a_recorded_fork_as_a_pair_and_stop_its_shard", "test_store_stores_a_batch_and_names_the_checkpoint_a_second_one_forks",
                         "test_release_accepts_a_payer_state_and_holds_with_the_first_failure", "test_a_signature_for_one_purpose_is_refused_for_every_other"):
                getattr(cases(name), name)()
        frames = [(m, f) for m, f in seen if 0 < len(f) < 40_000]
        self.assertGreaterEqual(len(frames), 20)
        root, cert = signer.framed(link(TENANT)), key_cert("e7")
        forged = _flip(cert, len(cert) - 1)  # INSTALL (8) answers REFUSED, CERT-INDEX (9) still indexes it
        frames += [(8, root + _list([]) + signer.framed(cert)), (8, root + _list([signer.framed(cert)]) + signer.framed(cert)),
                   (8, root + _list([]) + signer.framed(forged)), (9, signer.framed(cert)), (9, signer.framed(forged))]
        for mode, frame in frames:
            variants = [(mode, frame)] + [(mode, _flip(frame, at, 0x01)) for at in (0, len(frame) // 2, len(frame) - 1)]
            variants += [(mode, frame[:-1]), (mode, frame + b"\x00")] + [(m, frame) for m in (1, 2, 3, 4, 5, 8, 9) if m != mode]
            for m, f in variants:
                done = signer._exec(signer.VERIFY, signer.VERIFY_PIN, (), bytes([m]) + f)
                shot = done.stdout.decode("ascii").strip() if done.returncode in (0, 1) else None
                with signer._SERVE:
                    try:  # a refusal is a dead worker (no exit byte) or an exit byte outside 0/1; an answer carries the one-shot's exit
                        out = signer._resident(signer._VSERVER, signer.VERIFY, signer.VERIFY_PIN, ("serve",), bytes([m]) + f, 65536, 512 << 20)
                    except signer.GateSignerError:
                        out = None
                    else:
                        if out[0] not in (0, 1):
                            signer._close_server(signer._VSERVER)
                resident = out[1:].decode("ascii").strip() if out and out[0] in (0, 1) else None
                self.assertEqual((out[0] if resident is not None else None, resident),
                                 (done.returncode if shot is not None else None, shot), (m, len(f)))
                if shot is None:
                    self.assertEqual(done.returncode, 2)


class AxiomRecordTests(unittest.TestCase):
    def test_axioms_txt_is_exactly_the_pinned_axioms(self) -> None:
        """AXIOMS.txt is the output of ``lake env lean tools/gate_print_axioms.lean``; the build's
        ``#guard_msgs`` pins in AxiomCheck.lean must be that text, theorem for theorem."""
        root = VECTORS.parents[2]
        check = (root / "lean" / "BlindLedger" / "Gate" / "AxiomCheck.lean").read_text("utf-8")
        printed = re.findall(r"^#print axioms (\S+)$", (root / "tools" / "gate_print_axioms.lean").read_text("utf-8"), re.M)
        self.assertEqual(re.findall(r"^#guard_msgs in #print axioms (\S+)$", check, re.M), printed)
        self.assertEqual(re.findall(r"^/-- info: (.*) -/$", check, re.M),
                         (root / "lean" / "BlindLedger" / "Gate" / "AXIOMS.txt").read_text("utf-8").splitlines())

    def test_no_pin_names_an_axiom_outside_the_standard_three(self) -> None:
        """Every axiom set pinned anywhere under lean/ or tools/ is within `propext`, `Classical.choice` and `Quot.sound`.
        The one exception is the vector theorems of Financial/AxiomCheck.lean, whose `native_decide` pins name their own
        per-theorem axiom `<theorem>._native.native_decide.ax_1_1` (never `sorryAx`, `Lean.ofReduceBool` or a project axiom)."""
        root = VECTORS.parents[2]
        standard = {"propext", "Classical.choice", "Quot.sound"}
        native_file = Path("lean/BlindLedger/Financial/AxiomCheck.lean")
        seen = 0
        for path in sorted([*(root / "lean").rglob("*.lean"), *(root / "lean").rglob("*.txt"), *(root / "tools").rglob("*.lean")]):
            if ".lake" in path.parts:
                continue
            for found in re.finditer(r"depends on axioms: \[(.*?)\]", path.read_text("utf-8"), re.S):
                for axiom in re.split(r",\s*", " ".join(found.group(1).split())):
                    seen += 1
                    if axiom in standard:
                        continue
                    self.assertEqual(path.relative_to(root), native_file, f"{axiom} in {path}")
                    self.assertRegex(axiom, r"^[A-Za-z_.0-9']+\._native\.native_decide\.ax_1_1$")
        self.assertGreater(seen, 1500)

    def test_the_producer_payer_and_anchor_goals_are_proved(self) -> None:
        gate_dir = VECTORS.parents[2] / "lean" / "BlindLedger" / "Gate"
        record = {m.group(1): line for line in (gate_dir / "AXIOMS.txt").read_text("utf-8").splitlines()
                  if (m := re.match(r"'BlindLedger\.Gate\.(\S+)' depends", line))}
        for name in ("storedOf_wf", "forks_comm", "chain_no_fork", "follows_twice_forks", "publishOk_sound",
                     "publish_payer_local", "verifyToken_slice", "storeCheckpoint_slice", "firstFailure_none",
                     "anchored_binding_witness", "Cosign.keysApart_iff", "accepts_cert_not_root", "Cosign.body_ne_checkpoint_header", "pinInput_lines", "decideAnchored_some", "load_ok", "step_ok", "natBE_beNat",
                     "verifyToken_transfer", "blocked_shard", "forks_candidate", "storeCheckpoint_candidates",
                     "storeCheckpoint_pinned", "release_after_fork"):
            with self.subTest(name):
                self.assertIn(name, record)
                self.assertNotIn("sorryAx", record[name])
        # The grant-tenant theorems keep their statement pins, so weakening a theorem must change the pin in the same commit
        check = (gate_dir / "AxiomCheck.lean").read_text("utf-8")
        for name in ("verifyToken_grant_tenant", "verifyToken_foreign_grant", "releaseBatch_grant_tenant",
                     "publishOkTree_sound", "publishOkTree_complete", "publishOkTree_eq"):
            with self.subTest(name):
                self.assertRegex(check, re.compile(rf"^example : [^\n]*\n(?: [^\n]*\n)*? [^\n]*:=\n  @BlindLedger\.Gate\.{name}$", re.M))
        # The recovery theorems' statements reach IO primitives the statement digest refuses, so their statement and
        # axiom pins sit beside them, in a file the axiom build imports
        self.assertIn("import BlindLedger.Gate.Engine3.VerifyTheorems", check)
        recovery = (gate_dir / "Engine3" / "VerifyTheorems.lean").read_text("utf-8")
        self.assertRegex(recovery, re.compile(r"^example \(v : VC\) :\n    v\.Good ↔ \(v\.sb = storeBytes v\.fs\.st ∧ "
                                              r"∀ t, v\.tg = some t → t = factsTag v\.sb v\.rf v\.ft\) := Iff\.rfl$", re.M))
        for name in ("checkF_good", "checkFrame_dec_facts", "checkFrame_good", "saveLast_ret", "saveLast_good", "resume_good"):
            with self.subTest(name):
                self.assertRegex(recovery, re.compile(
                    rf"^example : [^\n]*\n(?: [^\n]*\n)*? [^\n]*:=\n  @BlindLedger\.Gate\.Engine3\.Verify\.{name}$", re.M))
                self.assertRegex(recovery, re.compile(
                    rf"^/-- info: 'BlindLedger\.Gate\.Engine3\.Verify\.{name}' depends on axioms: "
                    rf"\[propext, Classical\.choice, Quot\.sound\] -/\n#guard_msgs in #print axioms {name}$", re.M))
        # The pinned verifier decides no rule: only the anchor, which runs in the decide runtime, imports them
        self.assertNotIn("Rules", (gate_dir / "Producer.lean").read_text("utf-8"))
        self.assertIn("import BlindLedger.Gate.Rules.Spec", (gate_dir / "Anchor.lean").read_text("utf-8"))


def _fold(index: int, count: int, node: bytes, path: list[bytes]) -> bytes:
    """Test-only reference fold of a token-tree path (the verifier is Lean's)."""
    path = list(path)
    while count > 1:
        if not (index % 2 == 0 and index + 1 == count):
            s = path.pop(0)
            node = gate.sha3_512(gate.MERKLE_NODE + b"\x01" + (node + s if index % 2 == 0 else s + node))
        index, count = index // 2, (count + 1) // 2
    assert not path
    return node


class EncoderLawTests(unittest.TestCase):
    def test_encoder_refuses_noncanonical_values(self) -> None:
        leaf = _leaf(1, 41)
        bad = [
            replace(leaf, reason_codes=("RATE_OK", "ELIGIBLE")),
            replace(leaf, reason_codes=("rate_ok",)),
            replace(leaf, lines_root=gate.ZERO_DIGEST),
            replace(leaf, decided_at=leaf.issued_at + 1),
            replace(leaf, amount_cents=gate.MAX_NAT + 1),
            replace(leaf, amount_cents=True),
            replace(leaf, tenant_id="-leading-dash"),
            replace(leaf, outcome="MAYBE"),
            replace(leaf, expires_at=leaf.issued_at - 1),
            replace(leaf, expires_at=leaf.issued_at + gate.MAX_TOKEN_LIFETIME + 1),
            replace(leaf, member_key=leaf.member_key[:-1]),
            _leaf(7, 0, flow="SDP"),
        ]
        for value in bad:
            with self.subTest(value), self.assertRaises(gate.GateCodecError):
                gate.encode_token_leaf(value)
        for flow in gate.RULED:
            with self.subTest(flow), self.assertRaises(gate.GateCodecError):
                gate.encode_decide_request(_request(flow, 1))

    def test_batch_is_one_signature_and_one_leaf_per_payment(self) -> None:
        calls: list[bytes] = []
        cp, _, tokens = _batch([_leaf(n, 40 + n) for n in range(5)],
                               lambda m: calls.append(m) or bytes(gate.ML_DSA_87_SIGNATURE))
        self.assertEqual(calls, [gate.encode_checkpoint_header(cp)])
        self.assertEqual({t.checkpoint_digest for t in tokens}, {gate.sha3_512(calls[0])})
        for header in (replace(cp, seq_from=0, seq_to=4), replace(cp, prev_checkpoint_digest=gate.ZERO_DIGEST),
                       replace(cp, state_digest=gate.ZERO_DIGEST)):
            with self.subTest(header), self.assertRaises(gate.GateCodecError):
                gate.encode_checkpoint_header(header)

    def test_merkle_paths_fold_to_root_with_bounded_depth(self) -> None:
        for count in [*range(1, 34), 999, 1000]:
            leaves = [bytes([k % 256, k // 256]) for k in range(count)]
            root, paths = gate.merkle_tree(gate.MERKLE_NODE, leaves)
            self.assertLessEqual(max(map(len, paths)), gate.MAX_TOKEN_PATH)
            for index in {0, count // 2, count - 1}:
                leaf = gate.sha3_512(gate.MERKLE_NODE + b"\x00" + leaves[index])
                self.assertEqual(_fold(index, count, leaf, paths[index]), root)
                if count > 1:
                    self.assertNotEqual(_fold(index, count, gate.sha3_512(b"other"), paths[index]), root)
        self.assertNotEqual(gate.merkle_tree(gate.LINES_NODE, [b"x"])[0], gate.merkle_tree(gate.MERKLE_NODE, [b"x"])[0])


if __name__ == "__main__":
    VECTORS.parent.mkdir(exist_ok=True)
    VECTORS.write_text(build_vectors(), "ascii", newline="\n")
    sys.exit(0)
