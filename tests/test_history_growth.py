"""History never costs more (CONSTITUTION IX.3; design C:/Users/neers/rrb/designs/history-guard-v1.md).

Each hot-path operation runs at a small and a large history of one fixed synthetic corpus, and
deterministic work counters, never wall time, are compared:
  sql_ops   SQLite virtual-machine steps on every connection (a progress handler called at each step);
  hashed    bytes fed to SHA3-512 and SHA-256;
  frame     Lean evaluator frame bytes, request plus answer;
  peak_kib  the operation's peak Python allocation (tracemalloc);
  refused   1 when the owner refuses the operation.
A counter may grow at most like log n: large <= small * log2(L) / log2(S) * SLACK.  That is
1 + c * log2(L / S) with c = 1 / log2(S), the tightest c that admits every a + b * log n cost (a
Merkle path), and SLACK covers digit-width wobble.  A counter that grows faster must be on GROWS,
a dated exception list that only shrinks: the test fails when an unlisted counter grows and when a
listed one has stopped growing.  PINNED holds today's measured work at both sizes (5% margin,
2 KiB for peak_kib), so no operation, listed or not, can get costlier unnoticed.  Synthetic, non-PHI, nonpayment; proofSuiteId=null,
production_usable=false, activation=false.
"""

import functools
import gc
import hashlib
import math
from pathlib import Path
import sqlite3
import tempfile
import tracemalloc
import unittest
from unittest.mock import patch

from app import right_rail_financial_cash_file as cash
from app import right_rail_financial_cash_file_independent as cash_check
from app import right_rail_financial_engine as engine
from app import right_rail_financial_owner as owner
from app import right_rail_financial_owner_independent as independent
from tests import rightrail_financial_expected_cases as expected
from tests import test_right_rail_financial_cash_file as cash_tests
from tools import gate_rules_data

COUNTERS = ("sql_ops", "hashed", "frame", "peak_kib", "refused")
SIZES = {"store": (256, 2_560), "item": (16, 160), "gate": (256, 2_560)}  # earlier payments; one item's payments; released rows
SLACK = 1.05
MARGIN = 1.05  # PINNED: deterministic counters, plus room for tracemalloc's small run-to-run spread
CHAIN = "EXACT if each indexed read is verified against the M3 chain / auth-state head; else WEAKENS: an index-only tamper waits for the sweep"
GROWS = {  # operation: (counters that grow, owner branch, listed, strength of the planned fix); design (c)
    "decision": ("sql_ops", "hist-flat S1-S6", "2026-10-01", CHAIN),
    "reverse": ("sql_ops", "hist-flat S1-S6", "2026-10-01", CHAIN),
    "evaluate": ("sql_ops", "hist-flat S1-S6", "2026-10-01", CHAIN),
    "audit": ("sql_ops", "hist-flat S1-S6", "2026-10-01", CHAIN),
    "cash_file": ("sql_ops peak_kib", "hist-flat", "2026-10-01", "EXACT: the whole-store before/after diff becomes a diff of the auth-state map, which commits to every row"),
    "export": ("sql_ops peak_kib", "none", "2026-10-01", "WEAKENS: earlier exported segments stop being re-compared; a tampered copy is caught by its reader's chain check, not by the next export"),
    "continuity": ("sql_ops hashed peak_kib refused", "auth-state K1", "2026-10-01", "EXACT: a manifest of sealed segments plus current state, each verified against its digest on restore"),
    "open": ("sql_ops hashed peak_kib", "auth-state R1/R2", "2026-10-01", "EXACT only if the off-lock history sweep gates release; else WEAKENS: tamper in unread history found after open"),
    "item_decision": ("sql_ops hashed frame peak_kib", "hist-flat S3 + S6", "2026-10-01", "EXACT: M3 view decide with a Lean _eq theorem against the full decide"),  # sql_ops: the per-item payment read is old, its growth unchanged (~36k steps for 16 to 160 payments, 37k before); core-r1c halved the base, so the ratio now shows it. S3 + S6 remove it.
    "gate_state_pin": ("hashed peak_kib", "auth-state STATE/v2", "2026-10-01", "EXACT: decideBatch_slice"),
}
SQLITE = "3.53.1"  # sql_ops counts this library's VM steps; another version changes them, so re-measure
PINNED = {  # operation: (small-history work, large-history work) on trunk 70f9606 (run hy-growth4); lower it when an operation gets cheaper
    "decision": ((11777, 32313, 1939, 119, 0), (31560, 32313, 1939, 116, 0)),
    "reverse": ((11985, 34012, 2208, 128, 0), (31768, 34012, 2208, 131, 0)),
    "evaluate": ((11738, 37428, 2208, 141, 0), (31521, 37428, 2208, 134, 0)),
    "cash_file": ((117792, 138208, 19248, 3091, 0), (266108, 137849, 18852, 29369, 0)),
    "export": ((7042, 48693, 0, 11827, 0), (46935, 48542, 0, 58527, 0)),
    "continuity": ((32004, 2226225, 0, 10760, 0), (229802, 44523292, 0, 141728, 1)),
    "package": ((3152, 18608, 0, 112, 0), (3152, 18608, 0, 112, 0)),
    "audit": ((18364, 55862, 0, 182, 0), (38147, 55862, 0, 181, 0)),
    "summary": ((2796, 0, 0, 11, 0), (2796, 0, 0, 11, 0)),
    "history": ((2306, 0, 0, 328, 0), (2306, 0, 0, 328, 0)),
    "open": ((257358, 3924859, 0, 6039, 0), (2442549, 83604988, 0, 96729, 0)),
    "item_decision": ((34055, 63415, 8364, 289, 0), (69911, 361982, 70428, 7852, 0)),
    "gate_state_pin": ((0, 236354, 0, 706, 0), (0, 2362946, 0, 7046, 0)),
}
# Every public FinancialOwner method is measured or named here with the reason it is not (history-guard-v1.md, inventory).
MEASURED = {"record_payment_evidence", "reverse_payment", "evaluate_obligation", "run_batch", "export_history", "export_continuity", "decision_package", "summary", "history"}
UNMEASURED = {
    "setup, scales with its own input": "publish_control_pack register_population_manifest stage_population validate_population publish_population population_status",
    "decision-path writes, not yet measured (gap)": "record_support_evidence record_offset_claim retry_action authorize_offset reject_offset_and_authorize_correction acknowledge_action record_followthrough_decision record_reporting_evidence record_reporting_correction drain_correction_followups record_program_funding_receipt",
    "bounded staff reads, not yet measured (gap)": "list_obligations obligation_detail read_verified_staff_snapshot action_payload current_evaluation_receipt correction_followup_outputs program_funding_summary",
    "whole state by design (restore, full audit)": "validate_continuity_package restore_continuity verify_integrity",
    "operator-only, once per recovery, never per claim or commit (reads one head row)": "resolve_custody",
    "no work": "dispatch_outbox close",
}
_work = dict.fromkeys(COUNTERS[:3], 0)


def _step():
    _work["sql_ops"] += 1


class _Hashed:
    def __init__(self, make, data=b"", **kwargs):
        self._hash = make(**kwargs)
        self.update(data)

    def update(self, data):
        _work["hashed"] += memoryview(data).nbytes
        self._hash.update(data)

    def __getattr__(self, name):
        return getattr(self._hash, name)


def _hooks():
    connect, wire = sqlite3.connect, engine._evaluate_wire

    def counted_connect(*args, **kwargs):
        connection = connect(*args, **kwargs)
        connection.set_progress_handler(_step, 1)
        return connection

    def counted_wire(frame, *rest):
        answer = wire(frame, *rest)
        _work["frame"] += len(frame) + len(answer)
        return answer
    hashes = [(f"hashlib.{name}", functools.partial(_Hashed, getattr(hashlib, name))) for name in ("sha3_512", "sha256")]
    return [("sqlite3.connect", counted_connect), ("app.right_rail_financial_engine._evaluate_wire", counted_wire), *hashes]


def _measure(operation):
    with engine._evaluator_lock:
        engine._running_evaluator()  # warm, so no operation pays (and hashes) a worker launch
        engine._evaluator_requests = 0  # and none recycles one mid-operation
    before, refused = dict(_work), 0
    gc.collect()
    gc.disable()  # a collection that fires mid-call frees cycles at a point that depends on earlier tests; the peak swung 20% between runs
    tracemalloc.start()
    try:
        operation()
    except owner.FinancialError as error:  # a refusal only history causes is a block-service lever (design, d.1)
        refused = 1
        print(f"HISTORY_GROWTH refused {error}", flush=True)
    finally:
        peak = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()
        gc.enable()
    return tuple(_work[name] - before[name] for name in COUNTERS[:3]) + (peak // 1024, refused)


def _payment(item, tag, number=1):
    return {"item_id": item, "payment_id": f"{tag}-payment-{number}", "common_origin_id": f"{tag}-origin-{number}",
            "evidence_id": f"{tag}-evidence-{number}", "amount_cents": 1, "event_at_ms": expected.CASH_EVENT_MS}


def _gate_pin(rows):
    lines = ["snap released 20270405 0 ?", *(f"released {n} FFS_CLAIM {100001 + n % 1000} 70001 70001 20270101 99213 1 9200" for n in range(1, rows + 1)),
             "snap unresolved 20270405 0 ?"]
    return lambda: gate_rules_data.pin(lines)


class HistoryGrowthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for target, new in _hooks():
            patcher = patch(target, new)
            patcher.start()
            cls.addClassCleanup(patcher.stop)
        fx = cls.fx = cash_tests.ReceiverCashFileTests()
        fx.setUp()
        cls.addClassCleanup(fx.doCleanups)
        ids = fx._wide_store(100)
        deep, fresh, cls.seeded, cls.work = ids[-5], ids[-4:], 0, {}
        acceptance = fx.fixture
        cls.corrected = acceptance._build_base_for_correction()  # its own small store, so the audit also checks one correction follow-up against the engine registry
        acceptance._record_cash(cls.corrected)
        acceptance._reject(cls.corrected, acceptance._record_claim(cls.corrected))
        with cls.corrected._read_snapshot() as connection:
            cls.corrected_obligation = connection.execute("SELECT obligation_id FROM obligations WHERE item_id=?", (expected.H_ITEM_ID,)).fetchone()[0]
        folder = Path(tempfile.mkdtemp(dir=fx.fixture.temp_dir.name))
        sizes = {}
        for index, (size, tag) in enumerate(zip(SIZES["store"], "SL")):
            cls._seed(ids[:-5], size)
            if tag == "L":
                for name, operation in cls._item_operations(deep):
                    sizes.setdefault(("item", name), []).append(_measure(operation))
            for name, operation in cls._store_operations(f"probe-{tag}", fresh[2 * index], fresh[2 * index + 1], folder):
                sizes.setdefault(("store", name), []).append(_measure(operation))
        for rows in SIZES["gate"]:
            sizes.setdefault(("gate", "gate_state_pin"), []).append(_measure(_gate_pin(rows)))
        for (axis, name), (small, large) in sizes.items():
            cls.work[name] = (axis, small, large)
            print(f"HISTORY_GROWTH {name} axis={axis} small={small} large={large} allowed={_allowed(axis):.3f}", flush=True)

    @classmethod
    def _seed(cls, items, total):
        while cls.seeded < total:
            count = min(cash_check.MAX_ROWS, total - cls.seeded)
            value = cls.fx._file_of(items, count, prefix=f"seed-{cls.seeded}")
            cls.fx.store.run_batch(cash._propose(cash_tests.canonical(value), cls.fx.baseline))
            cls.seeded += count

    @classmethod
    def _item_operations(cls, deep):
        """One payment on an item holding 16, then 160, payments; the store barely moves (+144 on 2,560)."""
        for count, tag in ((15, "deep-a"), (143, "deep-b")):
            cls.fx.store.run_batch(cash._propose(cash_tests.canonical(cls.fx._file_of([deep], count, prefix=tag)), cls.fx.baseline))
            yield "item_decision", lambda tag=tag: cls.fx.store.record_payment_evidence(**_payment(deep, f"{tag}-probe"))

    @classmethod
    def _store_operations(cls, tag, item, cash_item, folder):
        """The same operations on items with no payments, at each history size; the open runs last."""
        fx = cls.fx
        store = fx.store
        store.export_history(folder)  # caught up, so the measured export adds this round's segments only
        obligation = fx._query("SELECT obligation_id FROM obligations WHERE item_id=?", item)[0][0]
        yield "decision", lambda: store.record_payment_evidence(**_payment(item, tag))
        yield "reverse", lambda: store.reverse_payment(item_id=item, payment_id=f"{tag}-payment-1", evidence_id=f"{tag}-reversal-1")
        yield "evaluate", lambda: store.evaluate_obligation(item)
        fx.source, fx.baseline = {**fx.source, "capture_id": tag}, fx._manifest()
        prepared = fx._prepare(fx._file_of([cash_item], cash_check.MAX_ITEM_ROWS, prefix=f"{tag}-cash"))
        yield "cash_file", lambda: fx._apply(prepared)
        yield "export", lambda: store.export_history(folder)
        yield "continuity", store.export_continuity
        yield "package", lambda: store.decision_package(item)

        def audit():
            for owner_store, audited in ((store, obligation), (cls.corrected, cls.corrected_obligation)):
                with owner_store._read_snapshot() as connection:
                    independent.verify_obligation_connection(connection, audited, **owner_store._checker_expectations())
        yield "audit", audit
        yield "summary", store.summary
        yield "history", store.history
        yield "open", lambda: fx.fixture._make_owner(path=store.path, clock=store.clock).close()

    def test_growth_is_listed_and_the_list_only_shrinks(self):
        for name, (axis, small, large) in self.work.items():
            grown = {counter for counter, s, l in zip(COUNTERS, small, large) if l > s * _allowed(axis)}
            listed = set(GROWS[name][0].split()) if name in GROWS else set()
            with self.subTest(operation=name):
                self.assertEqual(grown - listed, set(), f"grows with history and is not on GROWS: {small} -> {large}")
                self.assertEqual(listed - grown, set(), f"on GROWS but flat now; delete it, the list only shrinks: {small} -> {large}")
        self.assertEqual(set(GROWS) - set(self.work), set())

    def test_work_stays_at_its_pinned_values(self):
        self.assertEqual(sqlite3.sqlite_version, SQLITE, f"re-measure baseline for SQLite {sqlite3.sqlite_version}")
        self.assertEqual(set(PINNED), set(self.work))
        for name, (_, *measured) in self.work.items():
            for size, pinned in zip(measured, PINNED[name]):
                with self.subTest(operation=name):
                    over = [c for c, m, p in zip(COUNTERS, size, pinned) if m > p + max(p * (MARGIN - 1), 2 if c == "peak_kib" else 0)]
                    self.assertEqual(over, [], f"{size} against {pinned}")

    def test_every_owner_method_is_measured_or_named(self):
        public = {name for name in vars(owner.FinancialOwner) if not name.startswith("_")}
        self.assertEqual(public ^ (MEASURED | {m for names in UNMEASURED.values() for m in names.split()}), set())


def _allowed(axis):
    small, large = SIZES[axis]
    return math.log2(large) / math.log2(small) * SLACK


if __name__ == "__main__":
    unittest.main()
