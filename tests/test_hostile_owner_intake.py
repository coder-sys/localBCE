"""Hostile input at the owner's intake: cash files (bytes, fields, commands, bindings) and the payment, offset and correction methods.

Fixed seeds, a few hundred cases per entry point.  Every case is a typed refusal that leaves the whole store image as it was
(rowids, value types, schema), never a crash, an untyped error or a slow call."""

import copy
import random
import timeit
import unittest

from app import right_rail_financial_cash_file as cash_file
from app import right_rail_financial_cash_file_independent as check
from app import right_rail_financial_owner as owner
from tests import rightrail_financial_expected_cases as expected
from tests import test_hostile_worker_frames as frames
from tests import test_right_rail_financial_cash_file as cash_tests

_BOUND_SECONDS = 5.0
_STR = ["", " ", "\x00", "a\x00", "é", "\ud800", "a\n", "../x", "x" * 129, "a b", "-a", b"x", 1, True, [], ["x"], {}, 1.5]
_INT = [-1, 2**63, 2**64, 10**30, True, 1.5, "1", float("nan"), b"1", [1], -(2**63) - 1]
_POOLS = {
    "id": _STR, "text": ["", "\x00", "x" * 513, 1, b"x", [], True], "role": ["lower", "", "A B", "A" * 65, 1, b"A", ["A"]],
    "int": _INT, "revision": _INT[1:], "digest": ["zz", "00" * 31, "g" * 64, b"\x00" * 31, 1, [], ""],
}
_METHODS = {
    "record_payment_evidence": (dict(item_id=expected.H_ITEM_ID, payment_id="hp-1", common_origin_id="ho-1", amount_cents=100, evidence_id="he-1", event_at_ms=expected.CASH_EVENT_MS),
                                dict(item_id="id", payment_id="id", common_origin_id="id", amount_cents="int", evidence_id="id", event_at_ms="int", source_id="id",
                                     source_version="text", local_ref="text", expected_revision="revision", pays_action_id="id")),
    "reverse_payment": (dict(item_id=expected.H_ITEM_ID, payment_id="hp-1", evidence_id="he-2"),
                        dict(item_id="id", payment_id="id", evidence_id="id", common_origin_id="id", event_at_ms="int", expected_revision="revision")),
    "record_offset_claim": (dict(item_id=expected.H_ITEM_ID, claim_id="hc-1", amount_cents=100, evidence_id="he-3", deadline_ms=expected.CASH_EVENT_MS + 10),
                            dict(item_id="id", claim_id="id", amount_cents="int", evidence_id="id", owner_role="role", deadline_ms="int", expected_revision="revision")),
    "authorize_offset": (dict(item_id=expected.H_ITEM_ID, claim_id="hc-1"),
                         dict(item_id="id", claim_id="id", actor_id="id", actor_role="role", expected_revision="revision", action_id="id", decision_at_ms="int",
                              evaluation_id="id", evaluation_result_digest="digest")),
    "reject_offset_and_authorize_correction": (dict(item_id=expected.H_ITEM_ID, claim_id="hc-1"),
                                               dict(item_id="id", claim_id="id", actor_id="id", actor_role="role", expected_revision="revision", action_id="id",
                                                    decision_at_ms="int", evaluation_id="id", evaluation_result_digest="digest")),
}
_CASH_BAD = [None, True, 0, -1, 2**63, 2**64, 10**30, 1.5, "", "x" * 10_000, "\x00", "é", "\ud800", [], {}, [1], "1", "USD ", "usd"]


def _walk(value):
    yield value
    for child in (value.values() if isinstance(value, dict) else value if isinstance(value, list) else ()):
        yield from _walk(child)


class HostileOwnerIntakeTests(unittest.TestCase):
    def setUp(self) -> None:
        cash = cash_tests.ReceiverCashFileTests("test_preview_apply_retry_restart_and_reversal")
        cash.setUp()
        self.addCleanup(cash.doCleanups)
        self.cash = cash

    def _timed(self, bad: list, label, call) -> object:
        """The call's typed refusal (its text), or None for an accepted call; anything else is recorded as a defect."""
        started = timeit.default_timer()
        try:
            call()
            return None
        except (check.CashFileError, owner.FinancialError) as error:
            return str(error)
        except Exception as error:  # noqa: BLE001 - an untyped escape is the defect under test
            bad.append((label, "untyped", type(error).__name__))
        finally:
            if timeit.default_timer() - started > _BOUND_SECONDS:
                bad.append((label, "slow"))

    def _refusal_leaves_the_store(self, bad: list, label, call) -> None:
        before = cash_tests._tables(self.cash.store.path)
        refused = self._timed(bad, label, call)
        if refused is None:
            bad.append((label, "accepted"))
        elif cash_tests._tables(self.cash.store.path) != before:
            bad.append((label, "store_changed", refused))

    def test_mutated_cash_file_bytes_get_a_typed_refusal(self) -> None:
        cash, bad, rng = self.cash, [], random.Random("hostile-cash-bytes")
        clean = cash_tests.canonical(cash.value)
        deep = [b"[" * 100_000 + b"]" * 100_000, b'{"a":' * 50_000, b"1" + b"0" * 5_000, clean + b"\x00", b"\xef\xbb\xbf" + clean, clean.replace(b'"rows"', b'"rows","rows"', 1), clean.decode().replace("e", "é", 1).encode()]
        for case, raw in enumerate(deep + [frames._mutate(rng, clean) for _ in range(300)]):
            refused = self._timed(bad, ("bytes", case), lambda: self._prepare_raw(raw))
            if refused is not None and refused not in check.REFUSALS:
                bad.append((("bytes", case), "untyped_code", refused))
        self.assertEqual(bad, [])

    def _prepare_raw(self, raw: bytes):
        cash = self.cash
        baseline = cash.baseline
        return cash_file.prepare_cash_file(
            raw, baseline, expected_source_sha256=cash_tests.sha(raw), expected_baseline_sha256=cash_tests.sha(baseline), expected_scope=cash.scope,
            expected_source=cash.source, expected_owner_id=cash.store.owner_id, expected_mode=cash.store.mode, trusted_authority=cash.fixture.authority)

    def test_hostile_cash_file_fields_get_a_typed_refusal(self) -> None:
        cash, bad, rng = self.cash, [], random.Random("hostile-cash-fields")
        for case in range(300):
            value = copy.deepcopy(cash.value)
            for _ in range(rng.randint(1, 2)):
                containers = [node for node in _walk(value) if isinstance(node, dict) and node]
                target = rng.choice(containers)
                key = rng.choice(sorted(target))
                op = rng.randrange(4)
                if op == 0:
                    target[key] = rng.choice(_CASH_BAD)
                elif op == 1:
                    del target[key]
                elif op == 2:
                    target[rng.choice(("unknown", "", "\x00", "rows"))] = rng.choice(_CASH_BAD)
                else:
                    rows = cash.value["rows"]
                    value["rows"] = rng.choice((rows * 2, rows[::-1], rows[:1], [], rows + rows[:1], None))
            try:
                raw = cash_tests.canonical(value)
            except (ValueError, TypeError, UnicodeError):
                continue
            outcome = []
            refused = self._timed(bad, ("field", case), lambda: outcome.append(self._prepare_raw(raw)))
            if refused is not None and refused not in check.REFUSALS:
                bad.append((("field", case), "untyped_code", refused))
            if outcome and len(outcome[0][0]) != len(value["rows"]):
                bad.append((("field", case), "commands_do_not_match_rows"))
        self.assertEqual(bad, [])

    def test_a_tampered_checked_batch_is_refused_and_leaves_the_store(self) -> None:
        cash, bad, rng = self.cash, [], random.Random("hostile-cash-apply")
        commands, context = cash._prepare()
        for case in range(150):
            cmds, ctx, op = [(name, dict(row)) for name, row in commands], dict(context), rng.randrange(7)
            if op == 0:
                key = rng.choice(sorted(ctx))
                ctx[key] = rng.choice([None, "", b"", 0, "00" * 32, ctx[key] if not isinstance(ctx[key], (bytes, bytearray)) else ctx[key][:-1], {}, []])
            elif op == 1:
                ctx["source_bytes"] = frames._mutate(rng, ctx["source_bytes"])
            elif op == 2:
                cmds[rng.randrange(len(cmds))][1][rng.choice(sorted(cmds[0][1]))] = rng.choice(_CASH_BAD + [100, 101, 7])
            elif op == 3:
                cmds = cmds[::-1] if len(cmds) > 1 else cmds[:0] or [("record_payment_evidence", {})]
            elif op == 4:
                cmds = cmds + cmds[:1]
            elif op == 5:
                cmds = cmds[:1]
            else:
                cmds.append((rng.choice(("record_payment_evidence", "reverse_payment", "nonsense", "")), {"item_id": expected.H_ITEM_ID}))
            if (cmds, ctx) == (commands, context):
                continue
            self._refusal_leaves_the_store(bad, ("apply", case, op), lambda: cash.store.run_batch(cmds, cash_file_context=ctx))
        self.assertEqual(bad, [])

    def test_hostile_owner_method_arguments_get_a_typed_refusal_and_leave_the_store(self) -> None:
        store, bad = self.cash.store, []
        for method, (base, spec) in _METHODS.items():
            rng = random.Random(f"hostile-owner:{method}")
            for case in range(150):
                arguments = dict(base)
                for name in rng.sample(sorted(spec), rng.randint(1, 2)):
                    arguments[name] = rng.choice(_POOLS[spec[name]])
                self._refusal_leaves_the_store(bad, (method, case, repr(arguments)[:200]), lambda: getattr(store, method)(**arguments))
        self.assertEqual(bad, [])
        _base, _spec = _METHODS["record_payment_evidence"]
        store.record_payment_evidence(**_base)  # the control: the same store takes the clean call, so the refusals above were about the input


if __name__ == "__main__":
    unittest.main()
