"""Gate formats #1-#4 and #12: encoder laws, batch builder, golden vectors.

``tests/gate_vectors/gate_v1.vectors`` is produced by ``build_vectors`` with the
real AWS-LC ML-DSA-87 signer (``python -m tests.test_right_rail_gate_formats``)
and judged by the Lean ``gate_vectors`` executable, the only decoder.  Here
Python must reproduce every byte of it (signatures are looked up, since
ML-DSA-87 signing is randomized) and AWS-LC must accept every recorded
signature and reject flipped ones.  Synthetic, non-PHI.
"""

from __future__ import annotations

from dataclasses import replace
from itertools import count
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from app import right_rail_gate_codec as gate
from app import right_rail_gate_signer as signer

VECTORS = Path(__file__).resolve().parent / "gate_vectors" / "gate_v1.vectors"
TENANT, OTHER, PROGRAM, PERIOD = "nc-dhhs", "nc-other", "medicaid-ffs", "2026-09"
EPOCH, NOW, EXPIRES = 7, 1_790_000_000, 1_790_086_400
D = [gate.sha3_512(bytes([i])) for i in range(14)]
SHARDS, SHARD, OTHER_SHARDS = 8, 3, 4  # shard counts, and the shard of the main batch
# Epoch certificates: id, epoch, tenant, shard count.  Each has its own test-only key.
CERTS = {"e7": (D[5], EPOCH, TENANT, SHARDS), "e6": (D[8], EPOCH - 1, TENANT, SHARDS), "other": (D[9], EPOCH, OTHER, OTHER_SHARDS),
         "bad": (D[10], EPOCH, TENANT, SHARDS), "reshard": (D[12], EPOCH, TENANT, 2 * SHARDS),
         "no-shards": (D[13], EPOCH, "nc-third", 0), "other8": (D[11], EPOCH + 1, OTHER, OTHER_SHARDS),
         "e8": (D[1], EPOCH + 1, TENANT, SHARDS)}
CHECKED = ("cert", "checkpoint", "token", "release", "request", "response", "reissue", "decision-id", "input",
           "lines-root")


def seed(cert: str) -> bytes:
    return gate.sha3_512(b"RR/GATE/TEST-ONLY-SEED/" + cert.encode())[:32]


def member(n: int, shard: int = SHARD) -> bytes:
    """A synthetic member key for payment ``n`` that routes to ``shard``, and to ``shard`` mod 4 for the
    other tenant, so a swapped tenant is caught by the tenant compare and not by routing."""
    return next(key for i in count() if (
        key := gate.sha3_512(f"RR/GATE/TEST-ONLY-MEMBER/{n}/{i}".encode())[:gate.MEMBER_KEY]) and
        gate.shard_of(TENANT, key, SHARDS) == shard and gate.shard_of(OTHER, key, OTHER_SHARDS) == shard % OTHER_SHARDS)


def _request(flow: str = "FFS_CYCLE", n: int = 0, lines: tuple[bytes, ...] = (), key: int | None = None,
             member_key: bytes | None = None) -> gate.DecideRequest:
    return gate.DecideRequest(TENANT, PROGRAM, flow, f"cmd-{n if key is None else key:04d}", f"pay-{n:04d}",
                              member_key or member(n), f"payee-{n % 3}", 125_000 + n, PERIOD, lines,
                              tuple(sorted((D[2], D[5]))))


def _lines(n: int) -> tuple[bytes, ...]:
    return tuple(f"line:{n}:{k}:units=1".encode() for k in range(n % 4))


def _leaf(n: int, seq: int, outcome: str = "ALLOW", flow: str = "", shard: int = SHARD,
          member_key: bytes | None = None) -> gate.TokenLeaf:
    """Payment ``n`` decided by engine release D[6] on ``shard``."""
    lines = _lines(n)
    flow = flow or ("FFS_CYCLE" if lines else "FFS_CLAIM")
    request = _request(flow, n, lines, member_key=member_key)
    return gate.TokenLeaf(
        TENANT, PROGRAM, shard, flow, n % 2, request.payment_id, request.member_key, request.payee_ref,
        request.amount_cents, PERIOD, gate.lines_root(lines), outcome,
        ("ELIGIBLE", "RATE_OK") if outcome == "ALLOW" else ("PA_MISSING",), "TRANSFER", D[3], D[4], D[6],
        gate.input_commitment(request, D[1]), EPOCH, seq, NOW - 5, EXPIRES,
    )


def _batch(leaves, sign, prev: bytes = D[0]) -> tuple[gate.Checkpoint, bytes, list[gate.Token]]:
    return gate.sign_batch(leaves, prev_checkpoint_digest=prev, event_head=D[1], evidence_root=D[2],
                           created_at=NOW, sign=sign)


def _flip(data: bytes, at: int, bit: int = 0x80) -> bytes:
    return data[:at] + bytes([data[at] ^ bit]) + data[at + 1 :]


def build_vectors(sign) -> str:
    """Every vector, deterministic except the signatures ``sign(cert, message)`` returns."""
    out = ["# RR/GATE formats #1-#4, #12 golden vectors (D1). Synthetic, non-PHI, activation=false."]
    add = out.append
    h = bytes.hex

    def hexes(values) -> str:
        return ",".join(map(h, values)) or "-"

    # #12 digests: the decision id has no flow and no command key
    for n in (0, 1):
        add(f"decision-id d{n} {TENANT} {PROGRAM} pay-{n:04d} {n} {h(gate.decision_id(TENANT, PROGRAM, f'pay-{n:04d}', n))}")
    request = _request("FFS_CYCLE", 3, _lines(3))
    add(f"input i0 {h(gate.encode_decide_request(request))} {h(D[1])} {h(gate.input_commitment(request, D[1]))}")
    for n in (0, 1, 3, 5):
        lines = tuple(f"l{k}".encode() for k in range(n))
        add(f"lines-root r{n} {hexes(lines)} {h(gate.lines_root(lines))}")

    # #1 DECIDE-REQUEST/v1; accepted requests are named for the responses below
    def request_line(name: str, r: gate.DecideRequest) -> None:
        fields = [r.tenant_id, r.program_id, r.flow, r.command_key, r.payment_id, h(r.member_key), r.payee_ref,
                  str(r.amount_cents), r.period, hexes(r.lines), hexes(r.evidence_refs)]
        add(f"request accept {name} {h(gate.encode_decide_request(r))} {' '.join(fields)}")

    req = gate.encode_decide_request(request)
    flow_at = len(gate.DECIDE_REQUEST) + 2 + len(TENANT) + 2 + len(PROGRAM)
    request_line("cycle", request)
    for name, data in (
        ("truncated", req[:-1]),
        ("trailing", req + b"\x00"),
        ("wrong-domain", gate.DECIDE_RESPONSE + req[len(gate.DECIDE_REQUEST) :]),
        ("flipped-flow-bit", _flip(req, flow_at)),
        ("claim-with-lines", req[:flow_at] + b"\x02" + req[flow_at + 1 :]),
        ("refs-unsorted", req[:-128] + req[-64:] + req[-128:-64]),
    ):
        add(f"request reject {name} {h(data)}")

    # Payer setup: certificates (checked installs) and one active grant
    pks = {name: signer.public_key(seed(name)) for name in CERTS}

    def cert(name: str, verdict: str = "accept", chain: str = "ok") -> None:
        cert_id, epoch, tenant, shards = CERTS[name]
        add(f"cert {verdict} {h(cert_id)} {epoch} {tenant} {shards} {h(pks[name])} chain-{chain}")

    for name in ("e7", "e6", "other"):
        cert(name)
    cert("bad", "reject", "bad")
    cert("reshard", "reject")  # a second shard count for the tenant: v1 has no resharding
    cert("no-shards", "reject")
    add(f"grants {h(D[3])} {h(D[4])} {h(D[6])}")
    add(f"now {NOW}")

    # #4 CHECKPOINT/v1: one signed batch plus single-field variants, each signed
    # by the key of the certificate for its tenant and epoch
    cp, signature, tokens = _batch([_leaf(n, 40 + n, "HOLD" if n == 4 else "ALLOW") for n in range(5)],
                                   lambda m: sign("e7", m))

    def signed(c: gate.Checkpoint, key: str = "e7", sig: bytes | None = None) -> bytes:
        header = gate.encode_checkpoint_header(c)
        sig = sig if sig is not None else sign(key, header)
        add(f"sig {h(pks[key])} {h(header)} {h(sig)}")
        return gate.encode_checkpoint(c, sig)

    def resigned(header: bytes) -> bytes:
        """A changed header signed again, so it is refused for the change itself."""
        sig = sign("e7", header)
        add(f"sig {h(pks['e7'])} {h(header)} {h(sig)}")
        return header + len(sig).to_bytes(2, "big") + sig

    def checkpoint_line(name: str, c: gate.Checkpoint, data: bytes) -> None:
        fields = [c.tenant_id, c.program_id, *map(str, (c.shard_id, c.seq_from, c.seq_to, c.epoch)),
                  *(h(getattr(c, n)) for n in gate._CHECKPOINT_DIGESTS), str(c.count), str(c.created_at),
                  h(gate.checkpoint_digest(c))]
        add(f"checkpoint accept {name} {h(data)} {' '.join(fields)}")

    signed_cp = signed(cp, sig=signature)
    checkpoint_line("batch", cp, signed_cp)
    checkpoint_line("batch-fetched-again", cp, signed_cp)
    # Stored checkpoints that differ from a token's batch in one field.  The
    # program and seq variants commit to a lone leaf at a fresh seq, since a
    # variant of the batch at its own seqs would fork it.
    lone = {name: _batch([_leaf(n, seq)], lambda m: b"") for name, n, seq in (("program", 2, 60), ("seq", 3, 70))}
    variants = {
        "other-tenant": (replace(cp, tenant_id=OTHER), "other", tokens[0]),
        "epoch-6": (replace(cp, epoch=EPOCH - 1), "e6", tokens[0]),
        "second-shard-same-seq": (replace(cp, shard_id=1), "e7", tokens[0]),
        "other-program": (replace(lone["program"][0], program_id="medicaid-cap"), "e7", lone["program"][2][0]),
        "seq-from-past-leaf": (replace(lone["seq"][0], seq_from=71, seq_to=71), "e7", lone["seq"][2][0]),
    }
    for name, (c, key, _) in variants.items():
        checkpoint_line(name, c, signed(c, key))
    header, nonzero = gate.encode_checkpoint_header(cp), gate.encode_checkpoint_header(lone["seq"][0])
    for name, data in (
        ("truncated", signed_cp[:-1]),
        ("trailing", signed_cp + b"\x00"),
        ("wrong-domain", gate.TOKEN + signed_cp[len(gate.CHECKPOINT) :]),
        ("variant-2", resigned(_flip(header, len(gate.CHECKPOINT), 0x03))),
        ("flipped-count-bit", resigned(_flip(header, len(header) - 9, 0x01))),
        ("flipped-signature-bit", _flip(signed_cp, len(signed_cp) - 100)),
        ("retired-epoch-key", signed(cp, "e6")),
        ("other-tenant-key", signed(cp, "other")),
        ("state-digest-nonzero", resigned(nonzero[:-74] + D[7] + nonzero[-10:])),
    ):
        add(f"checkpoint reject {name} {h(data)}")
    # A second decision for pay-0004 and pay-0000 under CAP_820, as a gate that
    # keyed decisions by flow would sign it (review scenarios A and B)
    rogue_cp, _, rogue = _batch([_leaf(4, 45, flow="CAP_820"), _leaf(0, 46, flow="CAP_820")],
                                lambda m: sign("e7", m), gate.checkpoint_digest(cp))
    checkpoint_line("cross-flow", rogue_cp, signed(rogue_cp))
    # Shard 7 decides pay-0004 again under a mistyped member key that routes
    # there, and signs pay-0001 although its member routes to shard 3
    typo_cp, _, typo = _batch([_leaf(4, 1, shard=7, member_key=member(4, 7)), _leaf(1, 2, shard=7)],
                              lambda m: sign("e7", m))
    checkpoint_line("shard-7", typo_cp, signed(typo_cp))

    # #3 TOKEN/v1: the batch, then one reject per check, each one field away
    def payment_line(name: str, leaf: gate.TokenLeaf) -> None:
        add(f"payment {name} {TENANT} {PROGRAM} {leaf.flow} {leaf.payment_id} {h(leaf.member_key)} {leaf.payee_ref} "
            f"{leaf.amount_cents} {PERIOD} {hexes(_lines(int(leaf.payment_id[4:])))}")

    raw = [gate.encode_token(t) for t in tokens]
    for n, t in enumerate(tokens):
        payment_line(f"p{n}", t.leaf)
        verdict = "reject" if t.leaf.outcome != "ALLOW" else "accept"
        add(f"token {verdict} decode-ok t{n}-{t.leaf.outcome.lower()} p{n} {h(raw[n])}")
    p0 = [TENANT, PROGRAM, "FFS_CLAIM", "pay-0000", h(member(0)), "payee-0", "125000", PERIOD, "-"]
    for name, index, value in (("tenant", 0, OTHER), ("program", 1, "medicaid-cap"), ("flow", 2, "FFS_CYCLE"),
                               ("payment-id", 3, "pay-0009"), ("member-key", 4, h(member(90))),
                               ("payee", 5, "payee-9"), ("amount", 6, "124999"), ("period", 7, "2026-10"),
                               ("cap", 2, "CAP_820")):
        add(f"payment p0-{name} {' '.join(p0[:index] + [value] + p0[index + 1 :])}")
    add(f"payment p1-lines {TENANT} {PROGRAM} FFS_CYCLE pay-0001 {h(member(1))} payee-1 125001 {PERIOD} {h(b'line:1:9:units=1')}")
    t0, leaf0 = tokens[0], gate.encode_token_leaf(tokens[0].leaf)

    def lifetime(expires: int) -> bytes:
        return leaf0[:-8] + expires.to_bytes(8, "big") + raw[0][len(leaf0) :]

    token_flow_at = flow_at - len(gate.DECIDE_REQUEST) + len(gate.TOKEN) + 4  # after the u32 shard_id
    for name, data in (
        ("truncated", raw[0][:-1]),
        ("trailing", raw[0] + b"\x00"),
        ("wrong-domain", gate.CHECKPOINT + raw[0][len(gate.TOKEN) :]),
        ("flipped-flow-bit", _flip(raw[0], token_flow_at)),
        ("claim-with-lines-root", raw[1][:token_flow_at] + b"\x02" + raw[1][token_flow_at + 1 :]),
        ("reasons-unsorted", raw[0].replace(b"\x00\x08ELIGIBLE\x00\x07RATE_OK", b"\x00\x07RATE_OK\x00\x08ELIGIBLE", 1)),
        ("expires-before-issue", lifetime(NOW - 6)),
        ("lifetime-over-7-days", lifetime(NOW - 5 + gate.MAX_TOKEN_LIFETIME + 1)),
    ):
        add(f"token reject decode-bad {name} p0 {h(data)}")
    isolated = [
        ("checkpoint-not-stored", "p0", gate.encode_token(replace(t0, checkpoint_digest=D[11]))),
        *((f"checkpoint-{name}", f"p{int(t.leaf.payment_id[-1])}",
           gate.encode_token(replace(t, checkpoint_digest=gate.checkpoint_digest(c))))
          for name, (c, _, t) in variants.items()),
        ("wrong-path", "p0", gate.encode_token(replace(t0, siblings=tokens[1].siblings))),
        *((f"payment-{name}", f"p0-{name}", raw[0])
          for name in ("tenant", "program", "flow", "payment-id", "member-key", "payee", "amount", "period")),
        ("payment-lines-same-count", "p1-lines", raw[1]),
        ("hold-escape-other-flow", "p4", gate.encode_token(rogue[0])),
        ("hold-escape-mistyped-member", "p4", gate.encode_token(typo[0])),
        ("wrong-shard", "p1", gate.encode_token(typo[1])),
    ]
    for name, payment, data in isolated:
        add(f"token reject decode-ok {name} {payment} {h(data)}")
    for name, grant in (("grant-id", (D[0], D[4], D[6])), ("grant-rule", (D[3], D[0], D[6])),
                        ("grant-release", (D[3], D[4], D[0]))):
        add(f"grants {' '.join(map(h, grant))}")
        add(f"token reject decode-ok {name} p1 {h(raw[1])}")
    add(f"grants {h(D[3])} {h(D[4])} {h(D[6])}")
    for now, verdict, name in ((NOW - 5 - 300, "accept", "issue-skew-edge"), (NOW - 5 - 301, "reject", "not-yet-issued"),
                               (EXPIRES + 299, "accept", "expiry-skew-edge"), (EXPIRES + 300, "reject", "expired")):
        add(f"now {now}")
        add(f"token {verdict} decode-ok {name} p1 {h(raw[1])}")
    add(f"now {NOW}")
    # A fork on shard 5 blocks every release under (tenant, shard 5, epoch 7),
    # the batch it forks and any later one; shard 3 is unaffected
    fork_cp, _, fork = _batch([_leaf(20, 1, shard=5, member_key=member(20, 5)),
                               _leaf(21, 2, shard=5, member_key=member(21, 5))], lambda m: sign("e7", m))
    later_cp, _, (later,) = _batch([_leaf(22, 3, shard=5, member_key=member(22, 5))], lambda m: sign("e7", m),
                                   gate.checkpoint_digest(fork_cp))
    checkpoint_line("fork-base", fork_cp, signed(fork_cp))
    payment_line("p20", fork[0].leaf)
    add(f"token accept decode-ok before-fork p20 {h(gate.encode_token(fork[0]))}")
    for name, c in (("fork-same-seq", replace(fork_cp, token_root=_flip(fork_cp.token_root, 0, 0x01))),
                    ("fork-overlapping-seq", replace(fork_cp, seq_from=2, seq_to=3))):
        add(f"checkpoint fork {name} {h(signed(c))}")
    add(f"token reject decode-ok forked-batch p20 {h(gate.encode_token(fork[0]))}")
    checkpoint_line("after-fork", later_cp, signed(later_cp))
    payment_line("p22", later.leaf)
    add(f"token reject decode-ok forked-later-batch p22 {h(gate.encode_token(later))}")
    cross = h(gate.encode_token(rogue[1]))
    add(f"token accept decode-ok cross-flow-before-release p0-cap {cross}")
    add(f"release accept t0 p0 {h(raw[0])}")
    add(f"token reject decode-ok released p0 {h(raw[0])}")
    add(f"release reject t0-again p0 {h(raw[0])}")
    add(f"token reject decode-ok cross-flow-after-release p0-cap {cross}")
    cert("other8")
    add(f"token accept decode-ok other-tenant-fence p1 {h(raw[1])}")
    cert("e8")
    add(f"token reject decode-ok stale-epoch p1 {h(raw[1])}")
    # Re-issue: the fenced, unreleased t1 comes back as the same decision at epoch 8
    new = replace(tokens[1].leaf, epoch=EPOCH + 1, seq=47, issued_at=NOW, expires_at=NOW + 2 * 86_400)
    e8_cp, _, (t1_e8,) = _batch([new], lambda m: sign("e8", m), gate.checkpoint_digest(rogue_cp))
    checkpoint_line("reissue-e8", e8_cp, signed(e8_cp, "e8"))
    add(f"token accept decode-ok reissued-e8 p1 {h(gate.encode_token(t1_e8))}")
    # The grant moves to engine D[7]: the re-issued leaf still carries D[6], its deciding release
    add(f"grants {h(D[3])} {h(D[4])} {h(D[7])}")
    add(f"token reject decode-ok reissued-revoked-engine p1 {h(gate.encode_token(t1_e8))}")
    for verdict, name, latest, leaf in (
        ("accept", "same-decision-e8", 1, new), ("reject", "re-decided", 1, replace(new, outcome="HOLD")),
        ("reject", "other-engine", 1, replace(new, engine_release=D[7])),
        ("reject", "older-epoch", 1, replace(new, epoch=EPOCH - 1)), ("reject", "older-seq", 1, replace(new, seq=40)),
        ("reject", "not-latest-revision", 2, new),
    ):
        add(f"reissue {verdict} {name} {latest} {h(raw[1])} {h(gate.encode_token(replace(t1_e8, leaf=leaf)))}")

    # #2 DECIDE-RESPONSE/v1, each judged against the request it answers
    requests = {"r0": _request("FFS_CLAIM", 0), "r1": _request("FFS_CYCLE", 1, _lines(1)),
                "r0-new-key": _request("FFS_CLAIM", 0, key=100), "r4-cap": _request("CAP_820", 4, key=104),
                "r9": _request("FFS_CYCLE", 9), "r0-cycle": _request("FFS_CYCLE", 0)}
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
        ("already-decided-other-flow", "r4-cap", R(TENANT, PROGRAM, "cmd-0104", "PAYMENT_ALREADY_DECIDED", token=tokens[4])),
        ("rejected", "r9", refused),
        ("unavailable", "r9", R(TENANT, PROGRAM, "cmd-0009", "UNAVAILABLE", retry_after_ms=2_000)),
    )
    for name, request_name, r in accepted:
        payload = h(gate.encode_token(r.token)) if r.token else r.reject_code or str(r.retry_after_ms)
        add(f"response accept {name} {request_name} {h(gate.encode_decide_response(r))} {r.tenant_id} {r.program_id} {r.command_key} {r.status} {payload}")
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
        ("decided-other-flow", "r0-cycle", ok),
        ("retry-zero", "r9", enc(accepted[6][2])[:-4] + bytes(4)),
        ("flipped-status-bit", "r9", _flip(no, len(no) - 2)),
    ):
        add(f"response reject {name} {request_name} {h(data)}")
    add(f"end {sum(line.split(' ', 1)[0] in CHECKED for line in out)}")
    return "\n".join(out) + "\n"


def _records() -> list[list[str]]:
    return [line.split(" ") for line in VECTORS.read_text("ascii").splitlines() if not line.startswith("#")]


def _verify(pk: bytes, message: bytes, signature: bytes) -> bool:
    """AWS-LC's verdict byte; anything but 0 or 1 is a failure."""
    verdict = signer._run("verify", pk + signature + message, 1)
    if verdict not in (b"\x00", b"\x01"):
        raise signer.GateSignerError("mldsa87_verify_output")
    return verdict == b"\x01"


class GoldenVectorTests(unittest.TestCase):
    def test_python_reproduces_every_vector_byte(self) -> None:
        recorded = {(r[1], r[2]): bytes.fromhex(r[3]) for r in _records() if r[0] == "sig"}
        self.assertEqual(len(recorded), 18)
        pks = {name: signer.public_key(seed(name)).hex() for name in CERTS}
        self.assertEqual(build_vectors(lambda key, m: recorded[(pks[key], m.hex())]), VECTORS.read_text("ascii"))

    def test_aws_lc_accepts_recorded_signatures_and_rejects_flips(self) -> None:
        triples = [[bytes.fromhex(x) for x in r[1:]] for r in _records() if r[0] == "sig"]
        pks = {signer.public_key(seed(name)) for name in CERTS}
        self.assertEqual(len(pks), len(CERTS))
        for pk, message, signature in triples:
            self.assertIn(pk, pks)
            self.assertTrue(_verify(pk, message, signature))
        pk, message, signature = triples[0]
        self.assertFalse(_verify(pk, message, _flip(signature, 100)))
        self.assertFalse(_verify(pk, _flip(message, 40, 1), signature))
        self.assertTrue(_verify(pk, message, signer.sign(seed("e7"), message)))
        with self.assertRaises(signer.GateSignerError):
            signer._run("verify", pk + signature[:-1], 1)

    def test_signer_refuses_an_unpinned_or_missing_binary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            wrong = Path(tmp) / "pin"
            wrong.write_text("0" * 64 + "\n", "ascii")
            for name, value in (("PIN", wrong), ("BINARY", Path(tmp) / "absent.exe")):
                with self.subTest(name), mock.patch.object(signer, name, value), self.assertRaises(signer.GateSignerError):
                    signer.public_key(seed("e7"))


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
            replace(leaf, flow="FFS_CLAIM"),
            replace(leaf, amount_cents=gate.MAX_NAT + 1),
            replace(leaf, amount_cents=True),
            replace(leaf, tenant_id="-leading-dash"),
            replace(leaf, outcome="MAYBE"),
            replace(leaf, expires_at=leaf.issued_at - 1),
            replace(leaf, expires_at=leaf.issued_at + gate.MAX_TOKEN_LIFETIME + 1),
            replace(leaf, member_key=leaf.member_key[:-1]),
        ]
        for value in bad:
            with self.subTest(value), self.assertRaises(gate.GateCodecError):
                gate.encode_token_leaf(value)
        with self.assertRaises(gate.GateCodecError):
            gate.encode_decide_request(_request("FFS_CLAIM", 1, (b"x",)))

    def test_batch_is_one_signature_and_one_leaf_per_payment(self) -> None:
        calls: list[bytes] = []
        cp, _, tokens = _batch([_leaf(n, 40 + n) for n in range(5)],
                               lambda m: calls.append(m) or bytes(gate.ML_DSA_87_SIGNATURE))
        self.assertEqual(calls, [gate.encode_checkpoint_header(cp)])
        self.assertEqual({t.checkpoint_digest for t in tokens}, {gate.sha3_512(calls[0])})
        for broken in ([_leaf(0, 40), _leaf(1, 42)], [_leaf(0, 40), replace(_leaf(1, 41), epoch=8)],
                       [_leaf(0, 40), _leaf(0, 41, flow="CAP_820")], []):
            with self.assertRaises(gate.GateCodecError):
                _batch(broken, calls.append)

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
    VECTORS.write_text(build_vectors(lambda key, message: signer.sign(seed(key), message)), "ascii", newline="\n")
    sys.exit(0)
