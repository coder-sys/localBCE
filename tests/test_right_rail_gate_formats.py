"""Gate formats #1-#4 and #12: codec laws, batch builder, golden vectors.

``tests/gate_vectors/gate_v1.vectors`` is produced by ``build_vectors`` with the
real AWS-LC ML-DSA-87 signer (``python -m tests.test_right_rail_gate_formats``)
and judged independently by the Lean ``gate_vectors`` executable.  Here Python
must reproduce every byte of it (signatures are looked up, since ML-DSA-87
signing is randomized), agree on every decode verdict, and AWS-LC must accept
every recorded signature and reject a flipped one.  Synthetic, non-PHI.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import sys
import unittest

from app import right_rail_gate_codec as gate
from app import right_rail_gate_signer as signer

VECTORS = Path(__file__).resolve().parent / "gate_vectors" / "gate_v1.vectors"
SEED = gate.sha3_512(b"RR/GATE/TEST-ONLY-SEED/synthetic")[:32]
TENANT, PROGRAM, PERIOD = "nc-dhhs", "medicaid-ffs", "2026-09"
EPOCH, NOW, EXPIRES = 7, 1_790_000_000, 1_790_086_400
D = [gate.sha3_512(bytes([i])) for i in range(8)]


def _request(flow: str = "FFS_CYCLE", n: int = 0, lines: tuple[bytes, ...] = ()) -> gate.DecideRequest:
    return gate.DecideRequest(TENANT, PROGRAM, flow, f"cmd-{n:04d}", f"pay-{n:04d}", f"payee-{n % 3}",
                              125_000 + n, PERIOD, lines, tuple(sorted((D[2], D[5]))))


def _lines(n: int) -> tuple[bytes, ...]:
    return tuple(f"line:{n}:{k}:units=1".encode() for k in range(n % 4))


def _leaf(n: int, seq: int, outcome: str = "ALLOW") -> gate.TokenLeaf:
    lines = _lines(n)
    flow = "FFS_CYCLE" if lines else "FFS_CLAIM"
    request = _request(flow, n, lines)
    revision = n % 2
    return gate.TokenLeaf(
        TENANT, PROGRAM, flow, gate.decision_id(TENANT, PROGRAM, request.command_key, revision), revision,
        D[7] if revision else None, request.payment_id, request.payee_ref, request.amount_cents, PERIOD,
        gate.lines_root(lines), len(lines), outcome, ("ELIGIBLE", "RATE_OK") if outcome == "ALLOW" else ("PA_MISSING",),
        "TRANSFER", D[3], D[4], D[6], gate.input_commitment(request, D[1]), EPOCH, seq, NOW - 5, EXPIRES,
    )


def _batch(sign) -> list[gate.Token]:
    leaves = [_leaf(n, 40 + n, "HOLD" if n == 4 else "ALLOW") for n in range(5)]
    return gate.sign_batch(leaves, prev_checkpoint_digest=D[0], event_head=D[1], evidence_root=D[2],
                           projections_digest=D[3], created_at=NOW, epoch_cert_id=D[5], sign=sign)


def _flip(data: bytes, at: int, bit: int = 0x80) -> bytes:
    return data[:at] + bytes([data[at] ^ bit]) + data[at + 1 :]


def build_vectors(sign) -> str:
    """Every vector, deterministic except the signature ``sign`` returns."""
    out = ["# RR/GATE formats #1-#4, #12 golden vectors (D1). Synthetic, non-PHI, activation=false."]
    add = out.append
    h = bytes.hex

    def fmt(kind: str, verdict: str, name: str, data: bytes) -> None:
        add(f"{kind} {verdict} {name} {h(data)}")

    # #12 digests
    add(f"decision-id d0 {TENANT} {PROGRAM} cmd-0000 0 {h(gate.decision_id(TENANT, PROGRAM, 'cmd-0000', 0))}")
    add(f"decision-id d1 {TENANT} {PROGRAM} cmd-0001 1 {h(gate.decision_id(TENANT, PROGRAM, 'cmd-0001', 1))}")
    request = _request("FFS_CYCLE", 3, _lines(3))
    add(f"input i0 {h(gate.encode_decide_request(request))} {h(D[1])} {h(gate.input_commitment(request, D[1]))}")
    for n in (0, 1, 3, 5):
        lines = tuple(f"l{k}".encode() for k in range(n))
        add(f"lines-root r{n} {','.join(map(h, lines)) or '-'} {h(gate.lines_root(lines))}")

    # #1 DECIDE-REQUEST/v1
    req = gate.encode_decide_request(request)
    flow_at = len(gate.DECIDE_REQUEST) + 2 + len(TENANT) + 2 + len(PROGRAM)
    fmt("request", "accept", "cycle", req)
    fmt("request", "accept", "claim", gate.encode_decide_request(_request("FFS_CLAIM", 0)))
    fmt("request", "reject", "truncated", req[:-1])
    fmt("request", "reject", "trailing", req + b"\x00")
    fmt("request", "reject", "wrong-domain", gate.DECIDE_RESPONSE + req[len(gate.DECIDE_REQUEST) :])
    fmt("request", "reject", "flipped-flow-bit", _flip(req, flow_at))
    fmt("request", "reject", "claim-with-lines", req[:flow_at] + b"\x02" + req[flow_at + 1 :])
    fmt("request", "reject", "refs-unsorted", req[: -128] + req[-64:] + req[-128:-64])

    # #4 CHECKPOINT/v1 and #3 TOKEN/v1 from one signed batch
    tokens = _batch(sign)
    cp = gate.encode_checkpoint(tokens[0].checkpoint)
    add(f"sig {h(signer.public_key(SEED))} {h(cp)} {h(tokens[0].signature)}")
    fmt("checkpoint", "accept", "batch", cp)
    fmt("checkpoint", "reject", "truncated", cp[:-1])
    fmt("checkpoint", "reject", "trailing", cp + b"\x00")
    fmt("checkpoint", "reject", "wrong-domain", gate.TOKEN + cp[len(gate.CHECKPOINT) :])
    fmt("checkpoint", "reject", "variant-2", _flip(cp, len(gate.CHECKPOINT), 0x03))
    fmt("checkpoint", "reject", "flipped-count-bit", _flip(cp, len(cp) - 9, 0x01))

    add(f"cert {h(D[5])} {EPOCH} {TENANT} {h(signer.public_key(SEED))} chain-ok")
    add(f"grant {h(D[3])} {h(D[4])} {h(D[6])}")
    add(f"state {EPOCH} {NOW} -")
    raw = [gate.encode_token(t) for t in tokens]
    for n, t in enumerate(tokens):
        leaf = t.leaf
        lines = ",".join(map(h, _lines(n))) or "-"
        add(f"payment p{n} {TENANT} {PROGRAM} {leaf.flow} {leaf.payment_id} {leaf.payee_ref} {leaf.amount_cents} {PERIOD} {lines}")
        verdict = "reject" if leaf.outcome != "ALLOW" else "accept"
        add(f"token {verdict} decode-ok t{n}-{leaf.outcome.lower()} p{n} {h(raw[n])}")
    add(f"payment p0-short {TENANT} {PROGRAM} FFS_CLAIM pay-0000 payee-0 124999 {PERIOD} -")
    add(f"payment p0-other-flow {TENANT} {PROGRAM} FFS_CYCLE pay-0000 payee-0 125000 {PERIOD} -")
    add(f"payment p1-no-lines {TENANT} {PROGRAM} FFS_CYCLE pay-0001 payee-1 125001 {PERIOD} -")
    leaf0 = len(gate.encode_token_leaf(tokens[0].leaf))
    wrong_path = gate.encode_token(replace(tokens[0], siblings=tokens[1].siblings))
    token_rows = [
        ("truncated", "decode-bad", "p0", raw[0][:-1]),
        ("trailing", "decode-bad", "p0", raw[0] + b"\x00"),
        ("wrong-domain", "decode-bad", "p0", gate.CHECKPOINT + raw[0][len(gate.TOKEN) :]),
        ("flipped-flow-bit", "decode-bad", "p0", _flip(raw[0], flow_at - len(gate.DECIDE_REQUEST) + len(gate.TOKEN))),
        ("flipped-signature-bit", "decode-ok", "p0", _flip(raw[0], len(raw[0]) - 100)),
        ("flipped-root-bit", "decode-ok", "p0", _flip(raw[0], leaf0 + len(cp) - 10 - 2 * 64 - 1, 0x01)),
        ("wrong-path", "decode-ok", "p0", wrong_path),
        ("other-leaf-payment", "decode-ok", "p1", raw[0]),
        ("amount-mismatch", "decode-ok", "p0-short", raw[0]),
        ("flow-mismatch", "decode-ok", "p0-other-flow", raw[0]),
        ("lines-mismatch", "decode-ok", "p1-no-lines", raw[1]),
    ]
    for name, decodes, payment, data in token_rows:
        add(f"token reject {decodes} {name} {payment} {h(data)}")
    add(f"state {EPOCH + 1} {NOW} -")
    add(f"token reject decode-ok stale-epoch p0 {h(raw[0])}")
    add(f"state {EPOCH} {EXPIRES + 59} -")
    add(f"token accept decode-ok skew-edge p0 {h(raw[0])}")
    add(f"state {EPOCH} {EXPIRES + 60} -")
    add(f"token reject decode-ok expired p0 {h(raw[0])}")
    add(f"state {EPOCH} {NOW} pay-0000")
    add(f"token reject decode-ok released p0 {h(raw[0])}")

    # #2 DECIDE-RESPONSE/v1
    responses = [
        ("decided", gate.DecideResponse(TENANT, PROGRAM, "cmd-0000", "DECIDED", token=raw[0])),
        ("duplicate", gate.DecideResponse(TENANT, PROGRAM, "cmd-0001", "DUPLICATE", token=raw[1])),
        ("rejected", gate.DecideResponse(TENANT, PROGRAM, "cmd-0009", "REJECTED", reject_code="COMMAND_KEY_CONFLICT")),
        ("unavailable", gate.DecideResponse(TENANT, PROGRAM, "cmd-0009", "UNAVAILABLE", retry_after_ms=2_000)),
    ]
    encoded = {name: gate.encode_decide_response(r) for name, r in responses}
    for name, data in encoded.items():
        fmt("response", "accept", name, data)
    decided = encoded["decided"]
    fmt("response", "reject", "truncated", decided[:-1])
    fmt("response", "reject", "trailing", decided + b"\x00")
    fmt("response", "reject", "wrong-domain", gate.DECIDE_REQUEST + decided[len(gate.DECIDE_RESPONSE) :])
    fmt("response", "reject", "other-command-key", decided.replace(b"cmd-0000", b"cmd-0002", 1))
    fmt("response", "reject", "retry-zero", encoded["unavailable"][:-4] + bytes(4))
    fmt("response", "reject", "flipped-status-bit", _flip(encoded["rejected"], len(encoded["rejected"]) - 2))
    return "\n".join(out) + "\n"


def _records() -> list[list[str]]:
    return [line.split(" ") for line in VECTORS.read_text("ascii").splitlines() if not line.startswith("#")]


class GoldenVectorTests(unittest.TestCase):
    def test_python_reproduces_every_vector_byte(self) -> None:
        recorded = {bytes.fromhex(r[2]): bytes.fromhex(r[3]) for r in _records() if r[0] == "sig"}
        self.assertEqual(len(recorded), 1)
        self.assertEqual(build_vectors(recorded.__getitem__), VECTORS.read_text("ascii"))

    def test_python_decode_verdicts_match(self) -> None:
        decoders = {"request": gate.decode_decide_request, "checkpoint": gate.decode_checkpoint,
                    "response": gate.decode_decide_response, "token": gate.decode_token}
        checked = 0
        for record in _records():
            if record[0] not in decoders:
                continue
            expect = record[2] == "decode-ok" if record[0] == "token" else record[1] == "accept"
            data = bytes.fromhex(record[-1])
            with self.subTest(record[:4]):
                try:
                    decoders[record[0]](data)
                    accepted = True
                except gate.GateCodecError:
                    accepted = False
                self.assertEqual(accepted, expect)
            checked += 1
        self.assertEqual(checked, 44)

    def test_aws_lc_accepts_recorded_signature_and_rejects_a_flip(self) -> None:
        (pk, message, signature), = [[bytes.fromhex(x) for x in r[1:]] for r in _records() if r[0] == "sig"]
        self.assertEqual(pk, signer.public_key(SEED))
        self.assertTrue(signer.verify(pk, message, signature))
        self.assertFalse(signer.verify(pk, message, _flip(signature, 100)))
        self.assertFalse(signer.verify(pk, _flip(message, 40, 1), signature))
        fresh = signer.sign(SEED, message)
        self.assertTrue(signer.verify(pk, message, fresh))
        with self.assertRaises(signer.GateSignerError):
            signer.verify(pk[:-1], message, signature)


def _fold(index: int, count: int, node: bytes, path: list[bytes]) -> bytes:
    """Test-only reference fold of an inclusion path (the verifier is Lean's)."""
    path = list(path)
    while count > 1:
        if not (index % 2 == 0 and index + 1 == count):
            s = path.pop(0)
            node = gate.merkle_node(node, s) if index % 2 == 0 else gate.merkle_node(s, node)
        index, count = index // 2, (count + 1) // 2
    assert not path
    return node


class CodecLawTests(unittest.TestCase):
    def test_round_trips(self) -> None:
        tokens = _batch(lambda m: bytes(gate.ML_DSA_87_SIGNATURE))
        request = _request("FFS_CYCLE", 3, _lines(3))
        self.assertEqual(gate.decode_decide_request(gate.encode_decide_request(request)), request)
        for t in tokens:
            self.assertEqual(gate.decode_token(gate.encode_token(t)), t)
        self.assertEqual(gate.decode_checkpoint(gate.encode_checkpoint(tokens[0].checkpoint)), tokens[0].checkpoint)

    def test_every_strict_prefix_is_rejected(self) -> None:
        data = gate.encode_decide_request(_request("FFS_CYCLE", 3, _lines(3)))
        for end in range(len(data)):
            with self.assertRaises(gate.GateCodecError):
                gate.decode_decide_request(data[:end])

    def test_encoder_refuses_noncanonical_values(self) -> None:
        leaf = _leaf(1, 41)
        bad = [
            replace(leaf, supersedes=None),
            replace(leaf, reason_codes=("RATE_OK", "ELIGIBLE")),
            replace(leaf, reason_codes=("rate_ok",)),
            replace(leaf, lines_root=gate.ZERO_DIGEST),
            replace(leaf, flow="FFS_CLAIM"),
            replace(leaf, amount_cents=gate.MAX_NAT + 1),
            replace(leaf, amount_cents=True),
            replace(leaf, tenant_id="-leading-dash"),
            replace(leaf, outcome="MAYBE"),
        ]
        for value in bad:
            with self.subTest(value), self.assertRaises(gate.GateCodecError):
                gate.encode_token_leaf(value)
        with self.assertRaises(gate.GateCodecError):
            gate.encode_decide_request(_request("FFS_CLAIM", 1, (b"x",)))

    def test_batch_is_one_signature_and_bounded(self) -> None:
        calls: list[bytes] = []
        tokens = _batch(lambda m: calls.append(m) or bytes(gate.ML_DSA_87_SIGNATURE))
        self.assertEqual(calls, [gate.encode_checkpoint(tokens[0].checkpoint)])
        for broken in ([_leaf(0, 40), _leaf(1, 42)], [_leaf(0, 40), replace(_leaf(1, 41), epoch=8)], []):
            with self.assertRaises(gate.GateCodecError):
                gate.sign_batch(broken, prev_checkpoint_digest=D[0], event_head=D[1], evidence_root=D[2],
                                projections_digest=D[3], created_at=NOW, epoch_cert_id=D[5], sign=calls.append)

    def test_merkle_paths_fold_to_root_with_bounded_depth(self) -> None:
        for count in [*range(1, 34), 999, 1000]:
            leaves = [bytes([k % 256, k // 256]) for k in range(count)]
            root, paths = gate.merkle_tree(leaves)
            self.assertLessEqual(max(map(len, paths)), gate.MAX_TOKEN_PATH)
            for index in {0, count // 2, count - 1}:
                self.assertEqual(_fold(index, count, gate.merkle_leaf(leaves[index]), paths[index]), root)
                if count > 1:
                    self.assertNotEqual(_fold(index, count, gate.merkle_leaf(b"other"), paths[index]), root)


if __name__ == "__main__":
    VECTORS.parent.mkdir(exist_ok=True)
    VECTORS.write_text(build_vectors(lambda message: signer.sign(SEED, message)), "ascii", newline="\n")
    sys.exit(0)
