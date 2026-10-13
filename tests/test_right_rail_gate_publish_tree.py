"""The pinned ``gate_verify`` PUBLISH runs ``publishOkTree`` (Gate/Batch.lean), the one-tree check proved equal to ``publishOkAny``.

Real exe, real ML-DSA-87 signatures, no mocks.  Every refusing frame differs from an accepting control in exactly one respect,
and the answer asserted is the exe's named refusal line ``GATE_VERIFY=REJECT`` (exit 1), never a malformed-frame error."""

from __future__ import annotations

from dataclasses import replace
import tempfile
import unittest

from app import right_rail_gate_codec as gate
from app import right_rail_gate_signer as signer
from tests import test_right_rail_gate_formats as fx

ACCEPT = "GATE_VERIFY=ACCEPT"
REJECT = "GATE_VERIFY=REJECT"
REGISTRY = fx.D[12]


class PublishTreeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls._tmp.cleanup)
        cls.handle, cls.root_pk, cls.cert = fx.custody(cls._tmp.name)

    def batch(self, first_seq: int, n: int, prev: bytes = gate.ZERO_DIGEST, v2: bool = False):
        """A signed batch of ``n`` tokens from ``first_seq``: (signed checkpoint, header, token objects)."""
        cp, tokens = fx.build(fx.batch_leaves(first_seq, n, first_seq), prev, prev, REGISTRY if v2 else None)
        header = gate.encode_checkpoint_header(cp)
        return gate.attach_signature(header, signer.sign(self.handle, header)), header, tokens

    def publish(self, last: bytes | None, signed: bytes, tokens) -> str:
        raw = [gate.encode_token(t) if isinstance(t, gate.Token) else t for t in tokens]
        return signer.gate_verify(1, self.root_pk + signer.framed(self.cert) + signer.framed(last or b"")
                                  + signer.framed(signed) + len(raw).to_bytes(2, "big") + b"".join(map(signer.framed, raw)))

    def test_accepts_a_multi_token_v2_batch_with_a_carried_odd_node(self) -> None:
        # Five leaves: the fifth is the odd node carried through two levels before it meets a sibling
        signed, _, tokens = self.batch(0, 5, v2=True)
        self.assertEqual([len(t.siblings) for t in tokens], [3, 3, 3, 3, 1])
        self.assertEqual(self.publish(None, signed, tokens), ACCEPT)

    def test_accepts_a_v1_batch(self) -> None:
        for n in (1, 2, 3, 5):
            with self.subTest(tokens=n):
                signed, _, tokens = self.batch(0, n)
                self.assertEqual(self.publish(None, signed, tokens), ACCEPT)

    def test_accepts_a_v2_published_after_a_v1_and_after_a_v2(self) -> None:
        v1, v1_header, _ = self.batch(0, 2)
        v2, v2_header, tokens = self.batch(2, 3, gate.sha3_512(v1_header), v2=True)
        self.assertEqual(self.publish(v1, v2, tokens), ACCEPT)
        again, _, again_tokens = self.batch(5, 5, gate.sha3_512(v2_header), v2=True)
        self.assertEqual(self.publish(v2, again, again_tokens), ACCEPT)

    def test_refuses_a_flipped_sibling_in_any_token(self) -> None:
        signed, _, tokens = self.batch(0, 5, v2=True)
        self.assertEqual(self.publish(None, signed, tokens), ACCEPT)
        for i, t in enumerate(tokens):
            for at in range(len(t.siblings)):
                flipped = replace(t, siblings=t.siblings[:at] + (fx._flip(t.siblings[at], 0, 0x01),) + t.siblings[at + 1:])
                with self.subTest(token=i, sibling=at):
                    self.assertEqual(self.publish(None, signed, tokens[:i] + [flipped] + tokens[i + 1:]), REJECT)

    def test_refuses_a_token_count_that_is_not_the_checkpoints(self) -> None:
        signed, _, tokens = self.batch(0, 5, v2=True)
        self.assertEqual(self.publish(None, signed, tokens), ACCEPT)
        for name, sent in (("one fewer", tokens[:-1]), ("one more", tokens + tokens[-1:]), ("none", [])):
            with self.subTest(name):
                self.assertEqual(self.publish(None, signed, sent), REJECT)

    def test_refuses_a_checkpoint_not_linked_to_the_last(self) -> None:
        v1, v1_header, _ = self.batch(0, 2)
        linked, _, linked_tokens = self.batch(2, 3, gate.sha3_512(v1_header), v2=True)
        self.assertEqual(self.publish(v1, linked, linked_tokens), ACCEPT)
        unlinked, _, unlinked_tokens = self.batch(2, 3, fx.D[0], v2=True)
        self.assertEqual(self.publish(v1, unlinked, unlinked_tokens), REJECT)

    def test_refuses_a_v1_after_a_v2(self) -> None:
        v2, v2_header, _ = self.batch(0, 2, v2=True)
        prev = gate.sha3_512(v2_header)
        chained, _, chained_tokens = self.batch(2, 3, prev, v2=True)
        self.assertEqual(self.publish(v2, chained, chained_tokens), ACCEPT)
        downgrade, _, downgrade_tokens = self.batch(2, 3, prev)
        self.assertEqual(self.publish(v2, downgrade, downgrade_tokens), REJECT)

    def test_refuses_an_undecodable_last(self) -> None:
        v1, v1_header, _ = self.batch(0, 2)
        signed, _, tokens = self.batch(2, 3, gate.sha3_512(v1_header), v2=True)
        self.assertEqual(self.publish(v1, signed, tokens), ACCEPT)
        for name, last in (("garbage", b"\x01\x02not a checkpoint"), ("truncated", v1[:-1]), ("header only", v1_header[:-1])):
            with self.subTest(name):
                self.assertEqual(self.publish(last, signed, tokens), REJECT)


if __name__ == "__main__":
    unittest.main()
