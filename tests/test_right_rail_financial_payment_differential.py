"""M3 gate: Lean's payment decision equals the Python owner's on every existing vector and a generated corpus.
Python decides and commits; Lean answers the same pre-state in the same transaction. Deleted with the Python (step 5)."""

import collections
import dataclasses
import inspect
import io
import random
import statistics
import threading
import time
import unittest
from unittest.mock import patch

from app import right_rail_financial_engine as engine
from app import right_rail_financial_owner as owner_module
from app import right_rail_financial_semantic_adapter as adapter
from tests import rightrail_financial_expected_cases as expected
from tests import test_right_rail_financial_acceptance as fixtures

PAYMENT_MODULES = (
    "tests.test_right_rail_financial_acceptance", "tests.test_right_rail_financial_cash_file",
    "tests.test_right_rail_financial_constitution_invariants", "tests.test_right_rail_financial_followthrough",
    "tests.test_right_rail_financial_history_segments", "tests.test_right_rail_financial_independent",
    "tests.test_right_rail_financial_line_pack", "tests.test_right_rail_financial_mirror",
    "tests.test_right_rail_financial_retry_order", "tests.test_right_rail_financial_semantic_adapter",
    "tests.test_right_rail_financial_staff_server", "tests.test_right_rail_financial_core_r1",
    "tests.test_right_rail_financial_core_r05", "tests.test_right_rail_financial_custody", "tests.test_history_growth",
)
# Timing and work-count pins that a second decider running in the same process must perturb; each is green alone (run m3s3 cash_file and history_growth without the harness).
RED_UNDER_HARNESS = ("test_quarter_end_file_within_writer_timeout", "test_two_thousand_rows_in_files_within_writer_timeout_and_size", "test_work_stays_at_its_pinned_values")
REFUSAL_CODES = (None, "payment_amount_zero", "payment_request_conflict", "payment_origin_reversed",
                 "obligation_revision_conflict", "evidence_identity_conflict", "evidence_chronology",
                 "payment_request_unknown", "payment_exceeds_unpaid_balance", "payment_missing",
                 "payment_already_reversed", "common_origin_id", "local_ref", "INTEGRITY", "INTEGRITY", "INTEGRITY",
                 "shadow_owner_read_only")
ROW_COLUMNS = {
    "payments": "payment_id,obligation_id,item_id,evidence_id,common_origin_id,amount_cents,event_at_ms,active,reversed_by_evidence_id",
    "evidence": "evidence_id,item_id,kind,common_origin_id,source_id,source_version,local_ref,applicable_at_ms,event_at_ms,received_at_ms,amount_cents,reversal_of,supersedes",
    "financial_conflicts": "conflict_id,obligation_id,common_origin_id,existing_payment_id,candidate_evidence_id,existing_amount_cents,candidate_amount_cents,reason,visible_at_ms",
}
LEAN_ROWS = {"payments": "payment_row", "evidence": "evidence", "financial_conflicts": "conflict_row"}
_DECIDED_STATUS = {"PAYMENT_RECEIVED": "RECORDED", "PAYMENT_REVERSED": "REVERSED", "PAYMENT_CONFLICT_VISIBLE": "CONFLICT"}
EXISTING_FLOOR, CORPUS_FLOOR = 12049, 716


@dataclasses.dataclass
class _Call:
    command: dict
    expected_revision: object
    out: object = None
    lean: tuple | None = None
    foreign: tuple = (False, False)
    python: tuple | None = None
    rows: dict = dataclasses.field(default_factory=dict)
    event: tuple | None = None
    py_open: dict | None = None
    error: str = ""
    lean_error: str = ""
    clock_behind: bool = False


def _rows(connection, table, key, value):
    row = connection.execute(f"SELECT {ROW_COLUMNS[table]} FROM {table} WHERE {key}=?", (value,)).fetchone()
    return None if row is None else dict(zip(ROW_COLUMNS[table].split(","), tuple(row)))


def _lean_view(out) -> tuple:
    """Lean's outcome as the same classes and rows the Python path leaves in the database."""
    if out.reason:
        return ("REFUSED", REFUSAL_CODES[out.reason])
    if out.status == "DUPLICATE":
        return (out.status, out.payment_id)
    if out.status == "CONFLICT_UNCHANGED":
        return (out.status, out.conflict_id)
    rows = {table: {c: getattr(out, attr).get(c) for c in ROW_COLUMNS[table].split(",")}
            for table, attr in LEAN_ROWS.items() if getattr(out, attr) is not None}
    return (out.status, rows)


def _lean_open(out) -> dict:
    """R2 from the requests Lean returns: oldest first, each bounded by what it has left unpaid and the balance."""
    left, opened = out.decided.shortfall_cents, {}
    for action_id, amount, paid, _revision, counted in sorted(out.requests, key=lambda r: (r[3], r[0])):
        if counted:
            opened[action_id] = min(max(amount - paid, 0), left)
            left -= opened[action_id]
    return opened


class _Harness:
    """Wraps the two payment commands; Lean answers each from the owner's own connection and clock."""

    def __init__(self):
        self.calls: list[_Call] = []
        self.local = threading.local()
        self.hits = collections.Counter()

    def __enter__(self):
        cls = owner_module.FinancialOwner
        real = {name: getattr(cls, name) for name in ("record_payment_evidence", "reverse_payment", "_get_obligation_row", "_recompute_and_record", "_append_event")}
        harness, correction_paid = self, owner_module._correction_paid

        def command(kind, name):
            signature = inspect.signature(real[name])

            def wrapped(owner, **kwargs):
                args = signature.bind(owner, **kwargs)
                args.apply_defaults()
                a = args.arguments
                if kind == "record":
                    shape = {k: a[k] for k in ("payment_id", "evidence_id", "common_origin_id", "source_id", "source_version", "amount_cents", "event_at_ms", "pays_action_id")}
                    shape["local_ref"] = a["local_ref"] or None
                else:
                    shape = {k: a[k] for k in ("payment_id", "evidence_id", "event_at_ms")} | {"common_origin_id": a["common_origin_id"] or None}
                call = _Call({"kind": kind, **shape}, a["expected_revision"])
                harness.local.call = call
                try:
                    result = real[name](owner, **kwargs)
                    call.python = harness._python_view(call, result)
                    return result
                except owner_module.FinancialError as error:
                    code = str(error)
                    if code == "payment_exceeds_unpaid_request":
                        code = "payment_exceeds_unpaid_balance"  # S2: one code for Lean's link refusal (lead E2)
                        harness.hits["S2"] += 1
                    lean_made = type(error) is owner_module.FinancialIntegrityError and code.startswith(("lean_", "semantic", "evaluation"))
                    call.python, call.error = ("REFUSED", "INTEGRITY" if lean_made else code), f"{type(error).__name__}:{code}"
                    if type(error) is owner_module.FinancialIntegrityError and "kind" in call.rows and call.lean != call.python:  # a later layer refused after the decision was written: compare the decision
                        call.python = harness._python_view(call, {"status": _DECIDED_STATUS.get(call.rows["kind"], "ALIAS")})
                    raise
                finally:
                    harness.local.call = None
                    harness.calls.append(call)
            return wrapped

        def obligation_row(owner, connection, item_id):
            row = real["_get_obligation_row"](owner, connection, item_id)
            call = getattr(harness.local, "call", None)
            if call is None or call.lean is not None:
                return row
            if owner_module._correction_paid is not correction_paid:  # the test swapped in a wrong Python decider (cash_file S4); Lean never reads it
                harness.hits["decider-patched"] += 1
                print("FINANCIAL_M3_SKIPPED decider-patched", call.command)
                return row
            command, revision, obligation_id = call.command, call.expected_revision, str(row["obligation_id"])
            try:  # the flag-True path up to Lean: the S16 pre-checks (owner 4141-4145, 4283), then _decide_payment's S14 guard and clock read (4027-4029)
                for key in ("evidence_id", "source_version", "local_ref") if command["kind"] == "record" else ("evidence_id",):
                    if key != "local_ref" or command[key]:
                        owner_module._id(command[key], key)
                if revision is not None and (type(revision) is not int or not 0 <= revision < 1 << 63):
                    owner_module._fail(owner_module.FinancialRevisionError, "obligation_revision_conflict")
                now = owner._now()
                call.clock_behind = now < int(row["updated_at_ms"])
            except owner_module.FinancialError as error:
                call.lean = ("REFUSED", str(error))
                return row
            try:
                wire, data = adapter.live_payment_input(
                    connection, obligation_id=obligation_id, authority_context=adapter.TrustedAuthorityContext.from_authority(owner.trusted_authority),
                    now_ms=now, verification={"scope": owner._scope_value(), "owner_id": owner.owner_id, "mode": owner.mode},
                    expected_revision=revision, command=command, receipts=owner_module._payment_receipts(connection, obligation_id))
                call.foreign = data["foreign"]
                call.out = adapter.decode_payment_outcome(engine._evaluate_wire(wire), data, command)
                call.lean = _lean_view(call.out)
            except (owner_module.FinancialError, engine.FinancialEngineError) as error:  # the owner reports these as lean_payment:* integrity (4035-4036)
                call.lean, call.lean_error = ("REFUSED", "INTEGRITY"), f"{type(error).__name__}:{error}"
            except Exception as error:  # the live path would raise it unwrapped: fails the comparison
                call.lean = ("LEAN_ERROR", f"{type(error).__name__}:{error}")
            return row

        def recompute(owner, connection, obligation_id, *, kind, payload, now_ms, **rest):
            call = getattr(harness.local, "call", None)
            if call is not None:
                call.event = (kind, dict(payload))
                call.rows = {"kind": kind}
                if kind != "PAYMENT_CONFLICT_VISIBLE":
                    call.rows["payments"] = _rows(connection, "payments", "payment_id", payload.get("payment_id"))
                call.rows["evidence"] = _rows(connection, "evidence", "evidence_id", payload.get("evidence_id") or payload.get("candidate_evidence_id"))
                if "conflict_id" in payload:
                    call.rows["financial_conflicts"] = _rows(connection, "financial_conflicts", "conflict_id", payload["conflict_id"])
            evaluation = real["_recompute_and_record"](owner, connection, obligation_id, kind=kind, payload=payload, now_ms=now_ms, **rest)
            if call is not None:
                call.rows["evaluation"] = {f: evaluation[f] for f in owner_module._DECIDED_VALUES}
                call.py_open = owner_module._open_requests(connection, obligation_id, int(evaluation["shortfall_cents"]))
            return evaluation

        def append_event(owner, connection, **kwargs):
            call = getattr(harness.local, "call", None)
            if call is not None and kwargs["kind"] == "PAYMENT_DUPLICATE_EVIDENCE":
                call.event = (kwargs["kind"], dict(kwargs["payload"]))
                call.rows = {"kind": "ALIAS", "evidence": _rows(connection, "evidence", "evidence_id", kwargs["payload"]["candidate_evidence_id"])}
            return real["_append_event"](owner, connection, **kwargs)

        self.patches = [patch.object(cls, "record_payment_evidence", command("record", "record_payment_evidence")),
                        patch.object(cls, "reverse_payment", command("reverse", "reverse_payment")),
                        patch.object(cls, "_get_obligation_row", obligation_row),
                        patch.object(cls, "_recompute_and_record", recompute),
                        patch.object(cls, "_append_event", append_event)]
        for p in self.patches:
            p.start()
        return self

    def __exit__(self, *exc):
        for p in reversed(self.patches):
            p.stop()

    @staticmethod
    def _python_view(call, result) -> tuple:
        kind, status = call.rows.get("kind"), result["status"]
        rows = {k: v for k, v in call.rows.items() if k in ROW_COLUMNS and v is not None}
        if status in ("RECORDED", "REVERSED"):
            return (status, rows)
        if status == "CONFLICT":
            return ("CONFLICT_RECORDED", rows) if kind == "PAYMENT_CONFLICT_VISIBLE" else ("CONFLICT_UNCHANGED", result["conflict_id"])
        if kind == "ALIAS":
            return ("ALIAS", rows)
        return ("DUPLICATE", result.get("payment_id"))

    def disagreements(self) -> list:
        bad = []
        for call in self.calls:
            if call.lean is None:  # refused by an adapter shape check before any snapshot: stays Python
                continue
            if call.error and call.python[0] != "REFUSED":
                self.hits["after-decision"] += 1
                print("FINANCIAL_M3_AFTER_DECISION", call.command["kind"], call.command["payment_id"], call.error)
            if call.python != call.lean:
                label = self._allowed(call)
                if label:
                    self.hits[label] += 1
                    print("FINANCIAL_M3_ALLOWED", label, call.command["kind"], call.python, call.lean)
                else:
                    bad.append((call.command, call.expected_revision, call.python, call.lean))
            elif call.out is not None and call.out.status != "REFUSED":
                if (call.out.event_kind and (call.out.event_kind, call.out.event_payload)) != (call.event or None):
                    bad.append((call.command, "event", call.event, (call.out.event_kind, call.out.event_payload)))
                if call.out.decided is not None and call.rows.get("evaluation") is not None:
                    lean_values = {f: getattr(call.out.decided, f) for f in owner_module._DECIDED_VALUES}
                    if lean_values != call.rows["evaluation"]:
                        bad.append((call.command, "evaluation", lean_values, call.rows["evaluation"]))
                    if _lean_open(call.out) != call.py_open:  # S11: Python's open_cents projection is Lean's openState
                        bad.append((call.command, "open_cents", _lean_open(call.out), call.py_open))
        return bad

    @staticmethod
    def _allowed(call) -> str | None:
        py, lean = call.python, call.lean
        if py == ("REFUSED", "obligation_revision_conflict") and lean[0] == "CONFLICT_UNCHANGED":
            return "D1"  # an exact retry of a visible conflict is CONFLICT at any revision (III.3)
        if py and py[0] == "REFUSED" and lean[0] == "REFUSED" and (any(call.foreign) or "INTEGRITY" in (py[1], lean[1])):
            return "D3" if call.out is not None and call.out.reason == 14 else "D2"  # both refuse and write nothing; only the reported code differs (D3: capacity)
        if py[0] == "DUPLICATE" and lean == ("REFUSED", "INTEGRITY") and call.clock_behind:
            return "D4"  # an exact retry while the owner clock is behind the obligation's last update: Python returns DUPLICATE unread, the live path fails closed; both write nothing
        return None


class PaymentDifferentialTests(unittest.TestCase):
    def test_existing_payment_vectors_agree(self) -> None:
        suite = unittest.defaultTestLoader.loadTestsFromNames(PAYMENT_MODULES)
        with patch.object(owner_module, "_LEAN_DECIDES_PAYMENTS", False), _Harness() as harness:
            result = unittest.TextTestRunner(stream=io.StringIO(), verbosity=0).run(suite)
        red = [str(test) for test, _ in result.failures + result.errors]
        print("FINANCIAL_M3_DIFFERENTIAL existing tests", result.testsRun, "red", red)
        compared = [call for call in harness.calls if call.lean is not None]
        bad = harness.disagreements()
        for entry in bad:
            print("FINANCIAL_M3_DISAGREE", entry[0]["kind"], entry[0]["payment_id"], str(entry[2])[:200], str(entry[3])[:200], [(c.error, c.lean_error) for c in harness.calls if c.command is entry[0]])
        self.assertEqual(bad, [])
        self.assertEqual([name for name in red if not name.startswith(RED_UNDER_HARNESS)], [])
        self.assertGreaterEqual(len(compared), EXISTING_FLOOR)
        print("FINANCIAL_M3_DIFFERENTIAL existing", len(compared), len(harness.calls), sorted({c.lean[0] for c in compared}), dict(harness.hits))

    def test_generated_corpus_agrees(self) -> None:
        seen: set = set()
        total, hits = 0, collections.Counter()
        for seed in range(24):
            fixture = fixtures.RightRailFinancialAcceptanceTests()
            fixture.setUp()
            try:
                store, reject_b = fixture._two_claim_corrections(300_000, 300_000, 600_000)
                reject_b()
                with patch.object(owner_module, "_LEAN_DECIDES_PAYMENTS", False), _Harness() as harness:
                    self._drive(store, random.Random(seed), calls=30)
                self.assertEqual(harness.disagreements(), [], f"seed={seed}")
                total += sum(call.lean is not None for call in harness.calls)
                hits += harness.hits
                seen |= {call.lean[0] if call.lean[0] != "REFUSED" else call.lean[1] for call in harness.calls if call.out}  # Lean's own answers only
            finally:
                fixture.doCleanups()
        print("FINANCIAL_M3_DIFFERENTIAL corpus", total, sorted(seen), dict(hits))
        self.assertGreaterEqual(total, CORPUS_FLOOR)
        must = {"RECORDED", "REVERSED", "CONFLICT_RECORDED", "CONFLICT_UNCHANGED", "ALIAS", "DUPLICATE",
                "payment_request_conflict", "payment_origin_reversed", "obligation_revision_conflict",
                "evidence_identity_conflict", "evidence_chronology", "payment_request_unknown", "payment_exceeds_unpaid_balance",
                "payment_missing", "payment_already_reversed", "local_ref"}
        self.assertEqual(must - seen, set())

    def _drive(self, store, rng, *, calls):
        h = expected.H_ITEM_ID
        requests = (expected.ACTION_CORRECTION_ID, fixtures._ACTION_B)
        history: list[tuple[str, dict]] = []
        record = dict(item_id=h, common_origin_id="so", amount_cents=100, event_at_ms=expected.CASH_EVENT_MS)
        for method, kwargs in ((store.record_payment_evidence, dict(record, payment_id="s0", evidence_id="se0")),  # a repeat of a reversed origin
                               (store.reverse_payment, dict(item_id=h, payment_id="s0", evidence_id="sr0", event_at_ms=store.clock.value)),
                               (store.record_payment_evidence, dict(record, payment_id="s1", evidence_id="se1", event_at_ms=store.clock.value + 10_000))):
            try:
                method(**kwargs)
            except owner_module.FinancialError:
                pass
        for _ in range(calls):
            revision = store.obligation_detail(h)["revision"]
            if history and rng.random() < 0.25:
                kind, kwargs = rng.choice(history)  # exact retry, at the original or the current revision
                kwargs = dict(kwargs, expected_revision=rng.choice([kwargs.get("expected_revision"), revision, None]))
            elif rng.random() < 0.3:
                kind, kwargs = "reverse", {
                    "item_id": h, "payment_id": f"p{rng.randrange(8)}", "evidence_id": f"r{rng.randrange(6)}",
                    "common_origin_id": rng.choice([None, "", "rev-origin"]),
                    "event_at_ms": rng.choice([None, store.clock.value - 5, store.clock.value + 10_000]),
                    "expected_revision": rng.choice([revision, revision - 1, None])}
            else:
                kind, kwargs = "record", {
                    "item_id": h, "payment_id": rng.choice([f"p{rng.randrange(8)}", "p" + "9" * 121]),
                    "evidence_id": f"e{rng.randrange(10)}", "common_origin_id": f"o{rng.randrange(4)}",
                    "amount_cents": rng.choice([0, 1, 40, 100, 100_000, 300_000]),
                    "event_at_ms": rng.choice([expected.CASH_EVENT_MS, store.clock.value - 1, store.clock.value + 10_000]),
                    "source_id": "corpus", "source_version": rng.choice(["v1", "v2"]),
                    "local_ref": rng.choice([None, "", "direct"]),
                    "pays_action_id": rng.choice([None, None, *requests, "no-such-request"]),
                    "expected_revision": rng.choice([revision, revision, revision - 1, None])}
            try:
                (store.record_payment_evidence if kind == "record" else store.reverse_payment)(**kwargs)
                history.append((kind, kwargs))
            except owner_module.FinancialError:
                pass
            store.clock.value += rng.choice([0, 1, 60_000])

    def test_lean_decided_payments_cost_the_same_as_python_decided(self) -> None:
        """T2 (steps 3-4 only): per-command wall time through the owner, both paths, same fixture."""
        medians = {}
        for lean in (False, True):
            fixture = fixtures.RightRailFinancialAcceptanceTests()
            fixture.setUp()
            try:
                store = fixture._build_base()
                samples = []
                with patch.object(owner_module, "_LEAN_DECIDES_PAYMENTS", lean):
                    for n in range(40):
                        revision = store.obligation_detail(expected.H_ITEM_ID)["revision"]
                        started = time.perf_counter()
                        store.record_payment_evidence(item_id=expected.H_ITEM_ID, payment_id=f"t2-{n}", common_origin_id=f"t2-o{n}",
                                                      evidence_id=f"t2-e{n}", amount_cents=10, event_at_ms=expected.CASH_EVENT_MS,
                                                      source_id="t2", source_version="v1", expected_revision=revision)
                        samples.append((time.perf_counter() - started) * 1000)
                medians[lean] = statistics.median(samples[5:])
            finally:
                fixture.doCleanups()
        print("FINANCIAL_M3_OWNER_PROFILE", medians)
        self.assertLessEqual(medians[True], medians[False] * 1.10 + 1.0)


if __name__ == "__main__":
    unittest.main()
