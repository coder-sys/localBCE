"""Hostile data at the reference payer: mutated checkpoints, tokens, KEY-CERTs, DecideRequest fields and clocks.

Fixed seeds.  Every case is a typed refusal that changes no table, or a recorded hold that adds one ``holds`` row
and nothing else, or behaves exactly like its clean version; a mutant is never released.  Values are of the right
type (a wrong-type argument is a caller bug, not hostile data).  Synthetic, non-PHI."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import random
import unittest

from app import right_rail_gate_codec as gate
from app import right_rail_gate_payer as payer
from app import right_rail_gate_signer as signer
from tests import test_right_rail_gate_formats as fx
from tests.test_hostile_worker_frames import _mutate

TYPED = (payer.GatePayerError, signer.GateSignerError, gate.GateCodecError)
_TEXT = ("", "\x00", "a\x00b", "é€", "\ud800", "x" * 70000, "a\nb", "\U0001f600")
_INTS = (-1, 2**63, 2**64, 10**30, -(2**63) - 1)
_VALUES = {
    **{name: _TEXT for name in ("tenant_id", "program_id", "flow", "command_key", "payment_id", "payee_ref", "period")},
    "amount_cents": _INTS,
    "member_key": (b"", b"\x00" * 31, b"\x00" * 33, b"\xff" * 64),
    "lines": ((), (b"",), (b"\x00" * 70000,), (b"x",) * 65536),
    "evidence_refs": ((b"",), (b"\x00" * 63,), (fx.D[1], fx.D[1]), tuple(sorted(fx.D[1:3], reverse=True))),
}


def _image(store: payer.PayerStore) -> dict[str, list[tuple]]:
    return {table: sorted(store._db.execute(f"SELECT rowid, * FROM {table}").fetchall()) for table in payer._TABLES}


class HostileGatePayerTests(fx.Scratch):
    def _keys(self, tmp: str) -> None:
        handle, self.root_pk, self.cert = fx.custody(tmp)
        checkpoint, tokens = fx.build(fx.batch_leaves(0, 2))
        header = gate.encode_checkpoint_header(checkpoint)
        self.signed = gate.attach_signature(header, signer.seal(handle, self.root_pk, self.cert, None, header,
                                                                [gate.encode_token(t) for t in tokens]))
        self.request, self.token = fx.payment_request(0), gate.encode_token(tokens[0])

    def _store(self, tmp: str, name: str = "payer", *, ready: bool = True) -> payer.PayerStore:
        """A store with the clean certificate; ``ready``: also the clean checkpoint stored and the request sent."""
        store = self.track(payer.PayerStore(Path(tmp) / f"{name}.sqlite3", root_keys={fx.TENANT: self.root_pk},
                                            grants=((fx.TENANT, fx.D[3], (fx.D[4],), (fx.D[6],)),)))
        store.install_cert(self.cert)
        if ready:
            self.assertEqual(store.store_checkpoint(self.signed), "stored")
            store.send(self.request, transmit=lambda data: None)
        return store

    def _try(self, store: payer.PayerStore, call):
        """(result or the typed refusal, image before, image after); a typed refusal changes nothing."""
        before = _image(store)
        try:
            result = call()
        except TYPED as error:
            result = error
        after = _image(store)
        if isinstance(result, TYPED):
            self.assertEqual(after, before, result)
        return result, before, after

    def _held(self, store: payer.PayerStore, call) -> None:
        """A hostile release is a typed refusal or one recorded hold, never a release."""
        result, before, after = self._try(store, call)
        self.assertIsNotNone(result)
        if isinstance(result, str):
            self.assertEqual(len(after.pop("holds")), len(before.pop("holds")) + 1)
            self.assertEqual(after, before)

    def test_mutated_checkpoints_are_refused_or_recorded_as_forks(self) -> None:
        with self.scratch() as tmp:
            self._keys(tmp)
            store = self._store(tmp, ready=False)
            self.assertEqual(store.store_checkpoint(self.signed), "stored")
            rng = random.Random("gate-checkpoints")
            for i in range(150):
                mutant = _mutate(rng, self.signed)
                with self.subTest(i):
                    result, before, after = self._try(store, lambda: store.store_checkpoint(mutant))
                    if result == "fork":
                        self.assertEqual(len(after.pop("forks")), len(before.pop("forks")) + 1)
                    elif result == "stored":  # only the clean one again, which changes nothing
                        self.assertEqual(mutant, self.signed)
                    else:
                        self.assertIsInstance(result, TYPED)
                    self.assertEqual(after, before)

    def test_mutated_tokens_are_never_released(self) -> None:
        with self.scratch() as tmp:
            self._keys(tmp)
            store = self._store(tmp)
            rng = random.Random("gate-tokens")
            for i in range(150):
                mutant = _mutate(rng, self.token)
                if mutant != self.token:
                    with self.subTest(i):
                        self._held(store, lambda: store.release(self.request, mutant, now=fx.NOW))
            self.assertIsNone(store.release(self.request, self.token, now=fx.NOW))

    def test_hostile_request_fields_are_refused_typed_and_send_nothing(self) -> None:
        with self.scratch() as tmp:
            self._keys(tmp)
            store = self._store(tmp)
            rng = random.Random("gate-requests")
            for i in range(250):
                fields = rng.sample(sorted(_VALUES), rng.randint(1, 2))
                hostile = replace(self.request, **{name: rng.choice(_VALUES[name]) for name in fields})
                with self.subTest(i, fields=fields):
                    if i % 2:
                        sent: list[bytes] = []
                        result, _, _ = self._try(store, lambda: store.send(hostile, sent.append))
                        self.assertEqual(sent, [] if isinstance(result, TYPED) else [gate.encode_decide_request(hostile)])
                    else:
                        self._held(store, lambda: store.release(hostile, self.token, now=fx.NOW))
            self.assertIsNone(store.release(self.request, self.token, now=fx.NOW))

    def test_an_out_of_range_clock_escapes_untyped_instead_of_a_typed_refusal(self) -> None:
        with self.scratch() as tmp:
            self._keys(tmp)
            store = self._store(tmp)
            for now in (-1, -(2**63) - 1, 2**63, 2**64 - 1, 2**64, 10**30):  # 2**63..: the u64 fits, SQLite INTEGER not
                with self.subTest(now=now):
                    result, _, _ = self._try(store, lambda: store.release(self.request, self.token, now=now))
                    self.assertIsInstance(result, payer.GatePayerError)
            self.assertEqual(store.release(self.request, self.token, now=2**63 - 1), "expiry")  # the top reaches Lean
            self.assertIsNone(store.release(self.request, self.token, now=fx.NOW))

    def test_an_oversize_or_excess_certificate_is_refused_before_lean(self) -> None:
        """A cert over Lean's cap, or one past MAX_CERTS, is a typed refusal that stores nothing."""
        with self.scratch() as tmp:
            self._keys(tmp)
            store = self._store(tmp, "big", ready=False)
            result, _, _ = self._try(store, lambda: store.install_cert(b"\x00" * (payer.MAX_CERT_BYTES + 1)))
            self.assertEqual(str(result), "cert_too_large")
            store._db.executemany("INSERT INTO certs VALUES(?)", ((bytes([i]),) for i in range(payer.MAX_CERTS - 1)))
            result, _, _ = self._try(store, lambda: store.install_cert(b"\xff\xff"))
            self.assertEqual(str(result), "cert_store_full")
            store.install_cert(self.cert)

    def test_one_malformed_certificate_blocks_every_later_checkpoint_and_release(self) -> None:
        """A mutated KEY-CERT is refused at install, or Lean ignores it: the clean checkpoint and token still work."""
        with self.scratch() as tmp:
            self._keys(tmp)
            rng = random.Random("gate-certs")
            for i in range(40):
                mutant = _mutate(rng, self.cert)
                with self.subTest(i):
                    store = self._store(tmp, f"cert-{i}", ready=False)
                    self._try(store, lambda: store.install_cert(mutant))
                    self.assertEqual(store.store_checkpoint(self.signed), "stored")
                    store.send(self.request, transmit=lambda data: None)
                    self.assertIsNone(store.release(self.request, self.token, now=fx.NOW))


if __name__ == "__main__":
    unittest.main()
