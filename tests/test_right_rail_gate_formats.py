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
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from app import right_rail_gate_codec as gate
from app import right_rail_gate_signer as signer

VECTORS = Path(__file__).resolve().parent / "gate_vectors" / "gate_v1.vectors"
SEED = gate.sha3_512(b"RR/GATE/TEST-ONLY-SEED/synthetic")[:32]
TENANT, OTHER, PROGRAM, PERIOD = "nc-dhhs", "nc-other", "medicaid-ffs", "2026-09"
EPOCH, NOW, EXPIRES = 7, 1_790_000_000, 1_790_086_400
D = [gate.sha3_512(bytes([i])) for i in range(12)]
CHECKED = ("cert", "admit", "token", "release", "request", "response", "decision-id", "input", "lines-root")


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
        TENANT, PROGRAM, flow, revision, D[7] if revision else None, request.payment_id, request.payee_ref,
        request.amount_cents, PERIOD, gate.lines_root(lines), len(lines), outcome,
        ("ELIGIBLE", "RATE_OK") if outcome == "ALLOW" else ("PA_MISSING",),
        "TRANSFER", D[3], D[4], D[6], gate.input_commitment(request, D[1]), EPOCH, seq, NOW - 5, EXPIRES,
    )


def _batch(sign) -> tuple[gate.Checkpoint, bytes, list[gate.Token]]:
    leaves = [_leaf(n, 40 + n, "HOLD" if n == 4 else "ALLOW") for n in range(5)]
    return gate.sign_batch(leaves, prev_checkpoint_digest=D[0], event_head=D[1], evidence_root=D[2],
                           projections_digest=D[3], created_at=NOW, epoch_cert_id=D[5], sign=sign)


def _flip(data: bytes, at: int, bit: int = 0x80) -> bytes:
    return data[:at] + bytes([data[at] ^ bit]) + data[at + 1 :]


def build_vectors(sign) -> str:
    """Every vector, deterministic except the signatures ``sign`` returns."""
    out = ["# RR/GATE formats #1-#4, #12 golden vectors (D1). Synthetic, non-PHI, activation=false."]
    add = out.append
    h = bytes.hex

    def hexes(values) -> str:
        return ",".join(map(h, values)) or "-"

    # #12 digests
    for name, flow, n in (("d0", "FFS_CLAIM", 0), ("d1", "FFS_CYCLE", 1)):
        add(f"decision-id {name} {TENANT} {PROGRAM} {flow} pay-{n:04d} {n} {h(gate.decision_id(TENANT, PROGRAM, flow, f'pay-{n:04d}', n))}")
    request = _request("FFS_CYCLE", 3, _lines(3))
    add(f"input i0 {h(gate.encode_decide_request(request))} {h(D[1])} {h(gate.input_commitment(request, D[1]))}")
    for n in (0, 1, 3, 5):
        lines = tuple(f"l{k}".encode() for k in range(n))
        add(f"lines-root r{n} {hexes(lines)} {h(gate.lines_root(lines))}")

    # #1 DECIDE-REQUEST/v1
    def request_line(name: str, r: gate.DecideRequest) -> None:
        fields = [r.tenant_id, r.program_id, r.flow, r.command_key, r.payment_id, r.payee_ref,
                  str(r.amount_cents), r.period, hexes(r.lines), hexes(r.evidence_refs)]
        add(f"request accept {name} {h(gate.encode_decide_request(r))} {' '.join(fields)}")

    req = gate.encode_decide_request(request)
    flow_at = len(gate.DECIDE_REQUEST) + 2 + len(TENANT) + 2 + len(PROGRAM)
    request_line("cycle", request)
    request_line("claim", _request("FFS_CLAIM", 0))
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
    pk = signer.public_key(SEED)
    certs = {"e7": (D[5], EPOCH, TENANT), "e6": (D[8], EPOCH - 1, TENANT), "other": (D[9], EPOCH, OTHER)}
    for name, (cert_id, epoch, tenant) in certs.items():
        add(f"cert accept {cert_id.hex()} {epoch} {tenant} {h(pk)} chain-ok")
    add(f"cert reject {h(D[10])} {EPOCH} {TENANT} {h(pk)} chain-bad")
    add(f"grants {h(D[3])} {h(D[4])} {h(D[6])}")
    add(f"now {NOW}")

    # #4 CHECKPOINT/v1: one signed batch plus single-field variants, each signed
    cp, signature, tokens = _batch(sign)

    def signed(c: gate.Checkpoint, sig: bytes | None = None) -> bytes:
        header = gate.encode_checkpoint_header(c)
        sig = sig if sig is not None else sign(header)
        add(f"sig {h(pk)} {h(header)} {h(sig)}")
        return gate.encode_checkpoint(c, sig)

    def admit_line(name: str, c: gate.Checkpoint, data: bytes) -> None:
        fields = [c.tenant_id, c.program_id, *map(str, (c.seq_from, c.seq_to, c.epoch)),
                  *(h(getattr(c, n)) for n in gate._CHECKPOINT_DIGESTS), str(c.count), str(c.created_at),
                  h(gate.checkpoint_digest(c))]
        add(f"admit accept {name} {h(data)} {' '.join(fields)}")

    signed_cp = signed(cp, signature)
    admit_line("batch", cp, signed_cp)
    variants = {
        "other-tenant": replace(cp, tenant_id=OTHER),
        "other-program": replace(cp, program_id="medicaid-cap"),
        "epoch-6": replace(cp, epoch=EPOCH - 1),
        "seq-from-41": replace(cp, seq_from=41, seq_to=45),
        "flipped-root": replace(cp, token_root=_flip(cp.token_root, 0, 0x01)),
    }
    for name, c in variants.items():
        admit_line(name, c, signed(c))
    for name, data in (
        ("truncated", signed_cp[:-1]),
        ("trailing", signed_cp + b"\x00"),
        ("wrong-domain", gate.TOKEN + signed_cp[len(gate.CHECKPOINT) :]),
        ("variant-2", _flip(signed_cp, len(gate.CHECKPOINT), 0x03)),
        ("flipped-count-bit", _flip(signed_cp, len(signed_cp) - 4629 - 9, 0x01)),
        ("flipped-signature-bit", _flip(signed_cp, len(signed_cp) - 100)),
        ("no-cert-for-epoch", signed(replace(cp, epoch=9))),
        ("no-cert-for-tenant", signed(replace(cp, tenant_id="nc-none"))),
    ):
        add(f"admit reject {name} {h(data)}")

    # #3 TOKEN/v1: the batch, then one reject per check, each one field away
    raw = [gate.encode_token(t) for t in tokens]
    for n, t in enumerate(tokens):
        leaf = t.leaf
        add(f"payment p{n} {TENANT} {PROGRAM} {leaf.flow} {leaf.payment_id} {leaf.payee_ref} {leaf.amount_cents} {PERIOD} {hexes(_lines(n))}")
        verdict = "reject" if leaf.outcome != "ALLOW" else "accept"
        add(f"token {verdict} decode-ok t{n}-{leaf.outcome.lower()} p{n} {h(raw[n])}")
    p0 = [TENANT, PROGRAM, "FFS_CLAIM", "pay-0000", "payee-0", "125000", PERIOD, "-"]
    for name, index, value in (("tenant", 0, OTHER), ("program", 1, "medicaid-cap"), ("flow", 2, "FFS_CYCLE"),
                               ("payment-id", 3, "pay-0009"), ("payee", 4, "payee-9"), ("amount", 5, "124999"),
                               ("period", 6, "2026-10")):
        add(f"payment p0-{name} {' '.join(p0[:index] + [value] + p0[index + 1 :])}")
    add(f"payment p1-lines {TENANT} {PROGRAM} FFS_CYCLE pay-0001 payee-1 125001 {PERIOD} {h(b'line:1:9:units=1')}")
    t0, leaf0 = tokens[0], gate.encode_token_leaf(tokens[0].leaf)

    def token(**changes) -> bytes:
        return gate.encode_token(replace(t0, **changes))

    def lifetime(expires: int) -> bytes:
        return leaf0[:-8] + expires.to_bytes(8, "big") + raw[0][len(leaf0) :]

    for name, data in (
        ("truncated", raw[0][:-1]),
        ("trailing", raw[0] + b"\x00"),
        ("wrong-domain", gate.CHECKPOINT + raw[0][len(gate.TOKEN) :]),
        ("flipped-flow-bit", _flip(raw[0], flow_at - len(gate.DECIDE_REQUEST) + len(gate.TOKEN))),
        ("expires-before-issue", lifetime(NOW - 6)),
        ("lifetime-over-7-days", lifetime(NOW - 5 + gate.MAX_TOKEN_LIFETIME + 1)),
    ):
        add(f"token reject decode-bad {name} p0 {h(data)}")
    isolated = [
        ("cert-not-installed", "p0", token(epoch_cert_id=D[10])),
        ("cert-epoch", "p0", token(epoch_cert_id=certs["e6"][0])),
        ("cert-tenant", "p0", token(epoch_cert_id=certs["other"][0])),
        ("checkpoint-not-admitted", "p0", token(checkpoint_digest=D[11])),
        *((f"checkpoint-{name}", "p0", token(checkpoint_digest=gate.checkpoint_digest(c))) for name, c in variants.items()),
        ("wrong-path", "p0", token(siblings=tokens[1].siblings)),
        *((f"payment-{name}", f"p0-{name}", raw[0]) for name in ("tenant", "program", "flow", "payment-id", "payee", "amount", "period")),
        ("payment-lines-same-count", "p1-lines", raw[1]),
    ]
    for name, payment, data in isolated:
        add(f"token reject decode-ok {name} {payment} {h(data)}")
    for name, grant in (("grant-id", (D[0], D[4], D[6])), ("grant-rule", (D[3], D[0], D[6])),
                        ("grant-release", (D[3], D[4], D[0]))):
        add(f"grants {' '.join(map(h, grant))}")
        add(f"token reject decode-ok {name} p1 {h(raw[1])}")
    add(f"grants {h(D[3])} {h(D[4])} {h(D[6])}")
    add(f"now {EXPIRES + 59}")
    add(f"token accept decode-ok skew-edge p1 {h(raw[1])}")
    add(f"now {EXPIRES + 60}")
    add(f"token reject decode-ok expired p1 {h(raw[1])}")
    add(f"now {NOW}")
    add(f"release accept t0 p0 {h(raw[0])}")
    add(f"token reject decode-ok released p0 {h(raw[0])}")
    add(f"release reject t0-again p0 {h(raw[0])}")
    add(f"cert accept {h(D[11])} {EPOCH + 1} {OTHER} {h(pk)} chain-ok")
    add(f"token accept decode-ok other-tenant-fence p1 {h(raw[1])}")
    add(f"cert accept {h(D[1])} {EPOCH + 1} {TENANT} {h(pk)} chain-ok")
    add(f"token reject decode-ok stale-epoch p1 {h(raw[1])}")

    # #2 DECIDE-RESPONSE/v1
    responses = {
        "decided": gate.DecideResponse(TENANT, PROGRAM, "cmd-0000", "DECIDED", token=t0),
        "duplicate": gate.DecideResponse(TENANT, PROGRAM, "cmd-0001", "DUPLICATE", token=tokens[1]),
        "already-decided": gate.DecideResponse(TENANT, PROGRAM, "cmd-0100", "PAYMENT_ALREADY_DECIDED", token=t0),
        "rejected": gate.DecideResponse(TENANT, PROGRAM, "cmd-0009", "REJECTED", reject_code="COMMAND_KEY_CONFLICT"),
        "unavailable": gate.DecideResponse(TENANT, PROGRAM, "cmd-0009", "UNAVAILABLE", retry_after_ms=2_000),
    }
    encoded = {name: gate.encode_decide_response(r) for name, r in responses.items()}
    for name, r in responses.items():
        payload = h(gate.encode_token(r.token)) if r.token else r.reject_code or str(r.retry_after_ms)
        add(f"response accept {name} {h(encoded[name])} {r.tenant_id} {r.program_id} {r.command_key} {r.status} {payload}")
    decided = encoded["decided"]
    decision_at = len(decided) - len(raw[0]) + len(gate.TOKEN) + 2 + len(TENANT) + 2 + len(PROGRAM) + 1
    for name, data in (
        ("truncated", decided[:-1]),
        ("trailing", decided + b"\x00"),
        ("wrong-domain", gate.DECIDE_REQUEST + decided[len(gate.DECIDE_RESPONSE) :]),
        ("other-tenant", decided.replace(b"\x00\x07" + TENANT.encode(), b"\x00\x08" + OTHER.encode(), 1)),
        ("flipped-decision-id-bit", _flip(decided, decision_at)),
        ("retry-zero", encoded["unavailable"][:-4] + bytes(4)),
        ("flipped-status-bit", _flip(encoded["rejected"], len(encoded["rejected"]) - 2)),
    ):
        add(f"response reject {name} {h(data)}")
    add(f"end {sum(line.split(' ', 1)[0] in CHECKED for line in out)}")
    return "\n".join(out) + "\n"


def _records() -> list[list[str]]:
    return [line.split(" ") for line in VECTORS.read_text("ascii").splitlines() if not line.startswith("#")]


def _verify(pk: bytes, message: bytes, signature: bytes) -> bool:
    """AWS-LC's verdict byte; anything but 0 or 1 is a failure."""
    verdict = signer.run("verify", pk + signature + message, 1)
    if verdict not in (b"\x00", b"\x01"):
        raise signer.GateSignerError("mldsa87_verify_output")
    return verdict == b"\x01"


class GoldenVectorTests(unittest.TestCase):
    def test_python_reproduces_every_vector_byte(self) -> None:
        recorded = {bytes.fromhex(r[2]): bytes.fromhex(r[3]) for r in _records() if r[0] == "sig"}
        self.assertEqual(len(recorded), 8)
        self.assertEqual(build_vectors(recorded.__getitem__), VECTORS.read_text("ascii"))

    def test_aws_lc_accepts_recorded_signatures_and_rejects_flips(self) -> None:
        triples = [[bytes.fromhex(x) for x in r[1:]] for r in _records() if r[0] == "sig"]
        for pk, message, signature in triples:
            self.assertEqual(pk, signer.public_key(SEED))
            self.assertTrue(_verify(pk, message, signature))
        pk, message, signature = triples[0]
        self.assertFalse(_verify(pk, message, _flip(signature, 100)))
        self.assertFalse(_verify(pk, _flip(message, 40, 1), signature))
        self.assertTrue(_verify(pk, message, signer.sign(SEED, message)))
        with self.assertRaises(signer.GateSignerError):
            signer.run("verify", pk + signature[:-1], 1)

    def test_signer_refuses_an_unpinned_or_missing_binary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            wrong = Path(tmp) / "pin"
            wrong.write_text("0" * 64 + "\n", "ascii")
            for name, value in (("PIN", wrong), ("BINARY", Path(tmp) / "absent.exe")):
                with self.subTest(name), mock.patch.object(signer, name, value), self.assertRaises(signer.GateSignerError):
                    signer.public_key(SEED)


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
            replace(leaf, supersedes=None),
            replace(leaf, reason_codes=("RATE_OK", "ELIGIBLE")),
            replace(leaf, reason_codes=("rate_ok",)),
            replace(leaf, lines_root=gate.ZERO_DIGEST),
            replace(leaf, flow="FFS_CLAIM"),
            replace(leaf, amount_cents=gate.MAX_NAT + 1),
            replace(leaf, amount_cents=True),
            replace(leaf, tenant_id="-leading-dash"),
            replace(leaf, outcome="MAYBE"),
            replace(leaf, expires_at=leaf.issued_at - 1),
            replace(leaf, expires_at=leaf.issued_at + gate.MAX_TOKEN_LIFETIME + 1),
        ]
        for value in bad:
            with self.subTest(value), self.assertRaises(gate.GateCodecError):
                gate.encode_token_leaf(value)
        with self.assertRaises(gate.GateCodecError):
            gate.encode_decide_request(_request("FFS_CLAIM", 1, (b"x",)))

    def test_batch_is_one_signature_and_one_leaf_per_payment(self) -> None:
        calls: list[bytes] = []
        cp, _, tokens = _batch(lambda m: calls.append(m) or bytes(gate.ML_DSA_87_SIGNATURE))
        self.assertEqual(calls, [gate.encode_checkpoint_header(cp)])
        self.assertEqual({t.checkpoint_digest for t in tokens}, {gate.sha3_512(calls[0])})
        for broken in ([_leaf(0, 40), _leaf(1, 42)], [_leaf(0, 40), replace(_leaf(1, 41), epoch=8)], [_leaf(0, 40), _leaf(0, 41)], []):
            with self.assertRaises(gate.GateCodecError):
                gate.sign_batch(broken, prev_checkpoint_digest=D[0], event_head=D[1], evidence_root=D[2],
                                projections_digest=D[3], created_at=NOW, epoch_cert_id=D[5], sign=calls.append)

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
    VECTORS.write_text(build_vectors(lambda message: signer.sign(SEED, message)), "ascii", newline="\n")
    sys.exit(0)
