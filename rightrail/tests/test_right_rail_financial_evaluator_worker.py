"""The live Lean evaluator worker: one process, one frame each way, fail closed (Art. V.1, V.2, IV.2)."""

import hashlib
import json
import sqlite3
import timeit
import unittest
from pathlib import Path
from unittest.mock import patch

from app import minimal_clearance_verifier_process as process
from app import right_rail_financial_engine as engine
from app import right_rail_financial_owner as owner_module
from app import right_rail_financial_semantic_adapter as adapter
from tests import test_right_rail_financial_semantic_adapter as adapter_tests


_VECTORS = Path(__file__).resolve().parents[1] / "artifacts" / "engine-correction" / "vectors"


def _correction_corpus(vector: str) -> dict[str, bytes]:
    """The M4 P1 equivalence corpus over one KAT request (request_unbound.bin: the retired exe's, zero authority digest;
    request.bin: the bound one): its truncations, bit flips, +-1 numeric fields and header edits.  The exe read the request
    without the time-given byte (offset 354, here 01: the time was named), so each input is built on the exe's request
    and then gets that byte, keeping every recorded answer comparable."""
    shipped = (_VECTORS / vector).read_bytes()
    request = shipped[:354] + shipped[355:]
    link_list = request.index(b"BLFIN02") - 6
    corpus = {"vector": request, "empty": b"", "zeros-limit": bytes(4_000_000), "trailing-byte": request + b"\x00",
              "old-magic": b"BLFCMD02" + request[8:], "old-version": request[:8] + b"\x00\x02" + request[10:],
              "phantom-link": request[:link_list] + b"\x00\x01" + request[link_list + 2:]}
    for i in range(len(request)):  # every header byte, then a stride through the embedded input and receipt
        if i < 795 or i % 5 == 0:
            corpus[f"flip-{i}"] = request[:i] + bytes([request[i] ^ 1]) + request[i + 1:]
    for i in range(0, len(request), 61):
        corpus[f"cut-{i}"] = request[:i]
    for off in range(10, 795, 8):  # +-1 on every aligned 8-byte window of the header
        for d in (1, -1):
            v = int.from_bytes(request[off:off + 8], "big") + d
            if v >= 0:
                corpus[f"num-{off}{d:+d}"] = request[:off] + v.to_bytes(8, "big") + request[off + 8:]
    corpus = {key: data[:354] + shipped[354:355] + data[354:] if key not in ("empty", "zeros-limit") and len(data) > 354 else data
              for key, data in corpus.items()}
    assert corpus["vector"] == shipped
    return corpus


class EvaluatorWorkerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.addCleanup(engine._close_evaluator)
        fixture = adapter_tests.RightRailFinancialSemanticAdapterTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.store = fixture._build_base()

    def _wires(self) -> list[tuple[bytes, dict]]:
        """A BLFIN02 input for every obligation, read inside a transaction that is never committed."""

        connection = self.store._connect()
        self.addCleanup(connection.close)
        connection.execute("BEGIN")
        authority = adapter.TrustedAuthorityContext.from_authority(self.store.trusted_authority)
        verification = {"scope": self.store._scope_value(), "owner_id": self.store.owner_id, "mode": self.store.mode}
        wires = [
            adapter.live_evaluation_input(
                connection, obligation_id=row[0], authority_context=authority,
                evaluation_time_ms=self.store.clock.value + 1, verification=verification,
            )
            for row in connection.execute("SELECT obligation_id FROM obligations ORDER BY obligation_id")
        ]
        connection.execute("ROLLBACK")
        return wires

    def _counts(self) -> dict[str, int]:
        connection = sqlite3.connect(self.store.path)
        try:
            tables = [row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
            return {table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] for table in tables}
        finally:
            connection.close()

    def test_rejected_input_fails_closed_without_echo_and_worker_survives(self) -> None:
        wire = self._wires()[0][0]
        engine._evaluate_wire(wire)
        worker = engine._evaluator[0]
        with self.assertRaises(engine.FinancialEngineResultError) as raised:
            engine._evaluate_wire(wire[:-1])
        self.assertEqual(str(raised.exception), "evaluator_input_rejected")
        self.assertIs(engine._evaluator[0], worker)
        self.assertTrue(worker.alive)

    def _with_claims(self, data: dict, amounts: tuple[int, ...]) -> bytes:
        """The input with one open claim of each amount (and its OFFSET_CLAIM evidence): well formed, whatever the sum."""
        role = data["control_pack"]["canonical_fields"]["authorized_roles"][0]
        claims = [{"claim_id": f"zz-claim-{i}", "obligation_id": data["pre_evaluation"]["obligation_id"], "evidence_id": f"zz-claim-ev-{i}",
                   "amount_cents": amount, "owner_role": role, "deadline_ms": 1, "status": "CLAIMED"} for i, amount in enumerate(amounts)]
        extra = [dict(data["evidence"][0], evidence_id=claim["evidence_id"], kind="OFFSET_CLAIM", common_origin_id=claim["claim_id"],
                      amount_cents=claim["amount_cents"], reversal_of=None, supersedes=None) for claim in claims]
        return adapter._encode_blfin02(dict(data, claims=data["claims"] + claims,
                                            evidence=sorted(data["evidence"] + extra, key=lambda row: row["evidence_id"])))

    def test_a_sum_past_the_cent_bound_is_refused_as_total_overflow(self) -> None:
        data, big = self._wires()[0][1], 1 << 62
        engine._evaluate_wire(self._with_claims(data, (big,)))  # one such claim is well formed and decided
        with self.assertRaises(engine.FinancialEngineResultError) as raised:
            engine._evaluate_wire(self._with_claims(data, (big, big)))  # two make 2^63 cents: the worker's answer 02
        self.assertEqual(str(raised.exception), "evaluator_total_overflow")

    def test_broken_frame_ends_the_worker_and_the_next_decision_relaunches(self) -> None:
        wire = self._wires()[0][0]
        expected = engine._evaluate_wire(wire)
        worker = engine._evaluator[0]
        with self.assertRaises(process.VerifierProcessError) as raised:  # one byte over Lean maxWorkerFrameBytes (M + 8)
            worker.exchange(bytes(adapter.MAX_WIRE_BYTES + 9), response_cap_bytes=1024, timeout_seconds=5.0)
        self.assertEqual(str(raised.exception), "worker_exchange")
        self.assertFalse(worker.alive)
        self.assertEqual(engine._evaluate_wire(wire), expected)
        self.assertIsNot(engine._evaluator[0], worker)

    def test_worker_is_replaced_between_requests_by_count_or_commit(self) -> None:
        wire = self._wires()[0][0]
        answer = engine._evaluate_wire(wire)
        self.assertGreater(engine._evaluator[0].commit_bytes(), 0)
        worker = engine._evaluator[0]
        with patch.object(engine, "EVALUATOR_RECYCLE_REQUESTS", 2):
            self.assertEqual(engine._evaluate_wire(wire), answer)  # second request: same answer, then replaced
            self.assertFalse(engine._evaluator)
            self.assertFalse(worker.alive)
            self.assertEqual(engine._evaluate_wire(wire), answer)
            self.assertTrue(engine._evaluator[0].alive)
        worker = engine._evaluator[0]
        with patch.object(engine, "EVALUATOR_RECYCLE_COMMIT_BYTES", 1):
            self.assertEqual(engine._evaluate_wire(wire), answer)
            self.assertFalse(engine._evaluator)
            self.assertFalse(worker.alive)
        self.assertEqual(engine._evaluate_wire(wire), answer)  # and the next request relaunches

    @staticmethod
    def _padded(data: dict, rows: int, text: str, key: str = "0" * 110) -> bytes:
        extra = [dict(data["evidence"][0], evidence_id=f"zz{i:05d}{key}", kind="NOTE", common_origin_id=f"zz{i:05d}{key}",
                      source_id=text, source_version=text, local_ref=text, amount_cents=None, reversal_of=None, supersedes=None)
                 for i in range(rows)]
        return adapter._encode_blfin02(dict(data, evidence=sorted(data["evidence"] + extra, key=lambda row: row["evidence_id"])))

    def test_worker_time_is_linear_in_rows(self) -> None:
        """4x the rows must cost about 4x, not 16x: a borrowed accumulator in the canonical re-encode made 10,000 rows take 16 s."""
        best, data = {}, self._wires()[0][1]
        for rows in (2_500, 9_900):  # the frame holds at most 10,000 evidence rows
            wire = self._padded(data, rows, "x")
            engine._evaluate_wire(wire)  # the worker is warm
            best[rows] = min(timeit.repeat(lambda: engine._evaluate_wire(wire), number=1, repeat=3))
        self.assertLess(best[9_900], 2.5, best)
        self.assertLess(best[9_900] / best[2_500], 8, best)

    def test_large_requests_keep_the_worker_flat(self) -> None:
        """One worker, 20 accepted 600 KB requests then 8 near the 8 MiB ceiling: from each phase's second request its
        commit stays in a 16 MB band.  An earlier pin kept a further 32 MiB segment per request."""
        data, key, long = self._wires()[0][1], "0" * 110, "x" * 500
        padded = lambda rows, text: self._padded(data, rows, text)  # noqa: E731
        base = len(padded(0, ""))
        phases = ((padded(1000, key), 20), (padded((adapter.MAX_WIRE_BYTES - base) // (len(padded(1, long)) - base) - 1, long), 8))
        self.assertGreater(len(phases[1][0]), 8_000_000)
        with patch.object(engine, "EVALUATOR_RECYCLE_COMMIT_BYTES", 1 << 40):
            for wire, calls in phases:
                answers, commits = set(), []
                for _ in range(calls):
                    try:
                        answers.add(engine._evaluate_wire(wire))
                    except engine.FinancialEngineResultError as error:  # the near-ceiling frame is refused, as wire_max was
                        answers.add(str(error))
                    commits.append(engine._evaluator[0].commit_bytes())
                self.assertEqual(len(answers), 1)
                self.assertLess(max(commits[1:]) - commits[1], 16_000_000, [round(c / 1e6) for c in commits])

    def test_unpinned_executable_is_never_run(self) -> None:
        engine._close_evaluator()  # building the fixture store already started one
        with patch.object(engine, "EVALUATOR_ARTIFACT_SHA256", bytes(64)):
            with self.assertRaises(engine.FinancialEngineContainmentError) as raised:
                engine._evaluate_wire(self._wires()[0][0])
        self.assertEqual(str(raised.exception), "evaluator_containment")
        self.assertEqual(engine._evaluator, [])

    def test_payment_is_decided_by_lean_and_stored_as_decided(self) -> None:
        decisions = []
        real = engine.decide_payment_live

        def spy(*args, **kwargs):
            decisions.append(real(*args, **kwargs))
            return decisions[-1]

        with patch.object(engine, "decide_payment_live", spy):
            self.fixture._record_cash(self.store)
        self.assertEqual(len(decisions), 1)
        decided = decisions[0].decided
        connection = sqlite3.connect(self.store.path)
        connection.row_factory = sqlite3.Row
        self.addCleanup(connection.close)
        obligation = connection.execute("SELECT * FROM obligations WHERE obligation_id=?", (decided.obligation_id,)).fetchone()
        evaluation = connection.execute("SELECT * FROM evaluations WHERE obligation_id=? ORDER BY revision DESC", (decided.obligation_id,)).fetchone()
        for row in (obligation, evaluation):
            for field in owner_module._DECIDED_VALUES:
                self.assertEqual(row[field], getattr(decided, field), field)
            for field in ("cash_satisfied", "amount_satisfied", "timely"):
                self.assertEqual(row[field], int(getattr(decided, field)), field)
        self.assertEqual((evaluation["revision"], evaluation["evaluated_at_ms"]), (decided.after_revision, decided.evaluated_at_ms))
        self.assertGreater(decided.received_cash_cents, 0)
        self.store.verify_integrity()

    def test_worker_down_refuses_the_write_and_changes_nothing(self) -> None:
        engine._evaluate_wire(self._wires()[0][0])
        engine._close_evaluator()
        before = self._counts()
        with patch.object(process, "launch_contained_worker", side_effect=process.VerifierProcessError("worker_down")):
            with self.assertRaises(owner_module.FinancialIntegrityError) as raised:
                self.fixture._record_cash(self.store)
        self.assertEqual(str(raised.exception), "lean_payment:evaluator_containment")
        self.assertEqual(self._counts(), before)
        self.store.verify_integrity()
        self.fixture._record_cash(self.store)  # the same write succeeds once the worker can start

    def test_a_result_for_another_obligation_is_refused(self) -> None:
        mine = self.store._obligation_id(adapter_tests.expected.H_ITEM_ID, adapter_tests.expected.PERIOD_ONE_ID)
        other = next(wire for wire, data in self._wires() if data["pre_evaluation"]["obligation_id"] != mine)
        foreign = engine._evaluate_wire(other)
        before = self._counts()
        with patch.object(engine, "_evaluate_wire", return_value=foreign):
            with self.assertRaises(owner_module.FinancialIntegrityError) as raised:
                self.store.evaluate_obligation(adapter_tests.expected.H_ITEM_ID)  # payments bind Lean's answer in lean_payments
        self.assertEqual(str(raised.exception), "lean_evaluation:result_context_binding")
        self.assertEqual((self._counts(), engine._evaluator), (before, []))  # and the worker that gave it is not reused


    @staticmethod
    def _frames() -> dict[str, bytes]:
        """Lean-live M3 step 2 known answers: the raw payment frames of lean-live-m3-v1 16.10 (form B of the record and the
        reverse), the R2 S1 refusal frame of KAT.lean, and the worker's byte-for-byte answers (00 then BLFPRS01 ...)."""
        path = Path(__file__).with_name("fixtures") / "payment_frames.json"
        return {name: bytes.fromhex(hexed) for name, hexed in json.loads(path.read_text(encoding="utf-8")).items()}

    @staticmethod
    def _exchange(frame: bytes) -> bytes:
        with engine._evaluator_lock:
            return engine._running_evaluator().exchange(
                frame, response_cap_bytes=adapter.MAX_WIRE_BYTES + 1, timeout_seconds=engine.EVALUATOR_TIMEOUT_SECONDS)

    def test_payment_frames_are_answered_byte_for_byte_and_evaluator_frames_as_before(self) -> None:
        frames = self._frames()
        self.assertEqual(self._exchange(frames["c1"]), frames["c1_answer"])  # RECORDED
        self.assertEqual(self._exchange(frames["c2"]), frames["c2_answer"])  # REVERSED
        self.assertEqual(self._exchange(frames["s1_refused"]), frames["s1_refused_answer"])  # REFUSED, code 8 (LINK_EXCEEDS_UNPAID)
        self.assertEqual(frames["s1_refused_answer"][-2:], b"\x07\x08")
        self.assertEqual(self._exchange(frames["c1"][:-1]), b"\x01")  # a truncated item is not decoded
        # The answer to the first fixture input from the worker before payment frames existed: the pinned 86299A0D exe
        # (5,724,160 bytes; the engine pin at 1168909 admits no other), guarded dev run m3s2-oldhash-dev-a1-L1 on 2026-10-01,
        # two identical HASH lines.
        old = "4989cc7d8f1ec95ffeef2a4a3a6e1f7504ade818803213815935b711a3d40cc5"
        self.assertEqual(hashlib.sha256(engine._evaluate_wire(self._wires()[0][0])).hexdigest(), old)

    def test_correction_request_is_decided_by_the_worker_as_by_the_retired_exe(self) -> None:
        request, expected = (_VECTORS / "request.bin").read_bytes(), (_VECTORS / "result.expected.bin").read_bytes()
        self.assertEqual(self._exchange(request), b"\x00" + expected)  # the exe's stdout behind tag 0
        self.assertEqual(self._exchange(request[:-1]), b"\x01")  # the exe's exit 72: decode refused

    def test_worker_answers_the_retired_exes_answers_over_the_corpus(self) -> None:
        """Retired exe 874E2A37... (git 99ec957; its answers are the trunk worker 8EB77363's, guarded runs m4q-1 and m4f-40) on each
        corpus input: worker form is 00 + stdout (exit 0), 01 (exit 72), 03 (exit 73; none here).  The fixture holds, per corpus
        (unbound = the exe's zero-digest request, bound = request.bin, which reaches the decision logic and the ACCEPTED encoder),
        the inputs the worker answers differently, by new reason with their old digests and why, and the hash over all old answers."""
        fixture = json.loads((Path(__file__).with_name("fixtures") / "correction_exe_answers.json").read_text(encoding="utf-8"))
        for vector, name in (("request_unbound.bin", "unbound"), ("request.bin", "bound")):
            recorded, corpus = fixture[name], _correction_corpus(vector)
            raw = [self._exchange(data) if data else b"\x01" for data in corpus.values()]
            moved = {key: (reason, old) for reason, group in recorded["changed"].items() for key, old in group.items()}
            digests, new_digests = [], []
            for key, answer in zip(corpus, raw):
                digest = hashlib.sha256(answer).digest()
                if key in moved:
                    result = engine.decode_correction_transition_result(answer[1:]) if answer[:1] == b"\x00" else {}
                    self.assertEqual((result.get("status"), result.get("reject_reason")), ("REJECTED", moved[key][0]), key)
                    new_digests.append(digest)
                    digest = bytes.fromhex(moved[key][1])
                digests.append(digest)
            self.assertEqual((len(corpus), hashlib.sha256(b"".join(new_digests)).hexdigest(), hashlib.sha256(b"".join(digests)).hexdigest()),
                             (recorded["cases"], recorded["changed_sha256"], recorded["combined_sha256"]), name)
            for data, answer in zip(corpus.values(), raw):  # and the engine entry point maps each answer as the worker gave it
                with self.subTest(name, size=len(data), head=data[:10]):
                    if not data.startswith(b"BLFCMD03"):  # refused by the engine before the worker (exe: exit 72)
                        with self.assertRaises(engine.FinancialEngineInputError):
                            engine.run_correction_transition_v1(request=data)
                    elif answer[:1] == b"\x00":
                        self.assertEqual(engine.run_correction_transition_v1(request=data), engine.decode_correction_transition_result(answer[1:]))
                    else:
                        self.assertEqual(answer, b"\x01")
                        with self.assertRaises(engine.FinancialEngineResultError) as raised:
                            engine.run_correction_transition_v1(request=data)
                        self.assertEqual(str(raised.exception), "evaluator_input_rejected")

    @staticmethod
    def _resend_frame(request: bytes, command_at: int, time_given: int) -> bytes:
        """The shipped command as a resend of itself: its stored identity (time-given byte as asked) and the three queries
        that found it."""
        def text(start: int) -> str:
            return request[start + 2:start + 2 + int.from_bytes(request[start:start + 2], "big")].decode()

        action_id, obligation_id = text(73), "obligation:item-h:period-01"
        writer = adapter._WireWriter()
        engine._write_correction_action_lookup(writer, {"kind": "existing", "identity": {
            "action_id": action_id, "action_obligation_id": obligation_id, "determination_id": f"determination:{action_id}",
            "determination_obligation_id": obligation_id, "action_kind": "CORRECTION_PAYMENT_REQUEST", "claim_id": text(57),
            "actor_id": text(97), "actor_role": text(117), "authority_id": text(135), "authority_epoch": 1,
            "authority_digest": request[167:231], "decision": "OFFSET_REJECTED_CORRECTION_AUTHORIZED",
            "input_evaluation_id": text(239), "input_evaluation_result_digest": request[282:346], "expected_revision": 4,
            "decided_at_ms": int.from_bytes(request[command_at - 8:command_at], "big"), "decision_time_given": True}})
        lookup_at = command_at + 1 + 8
        out, at = request[:lookup_at] + writer.finish(label="lookup")[:-1] + bytes([time_given]), lookup_at + 1
        for found in (action_id, f"determination:{action_id}", f"determination:{action_id}"):
            subject_end = at + 3 + int.from_bytes(request[at + 1:at + 3], "big")  # predicate, subject; then complete
            versions = subject_end + 1 + 8 + 1  # matchCount 0 and no result identity: 8 + 1 bytes after complete
            out += request[at:subject_end + 1] + (1).to_bytes(8, "big") + b"\x01" + len(found).to_bytes(2, "big") + found.encode()
            out += request[versions:versions + 72]
            at = versions + 72
        return out + request[at:]

    def test_the_two_time_given_bytes_are_flipped_and_cut_against_the_worker(self) -> None:
        """The command's byte (after decisionAtMs) and a stored identity's byte (after decidedAtMs), on the shipped layout:
        0 / 1 / 2 are read, any other value or a cut frame is refused, and a command that left its time to the owner's
        clock without being dated at the owner's clock is a malformed command."""
        request = (_VECTORS / "request.bin").read_bytes()
        command_at = request.index((0x0000019D419E810A).to_bytes(8, "big")) + 8
        lookup_at = command_at + 1 + 8  # the owner's clock, then the lookup tag
        self.assertEqual((request[command_at], request[lookup_at]), (1, 1))  # named time; lookup absent
        writer = adapter._WireWriter()
        engine._write_correction_action_lookup(writer, {"kind": "existing", "identity": {
            **{key: f"{key}:x" for key in ("action_id", "action_obligation_id", "determination_id", "determination_obligation_id",
                                           "action_kind", "claim_id", "actor_id", "authority_id", "input_evaluation_id")},
            "actor_role": "FINANCE_DECISION", "authority_epoch": 1, "authority_digest": bytes(64), "decision": "OFFSET_AUTHORIZED",
            "input_evaluation_result_digest": bytes(64), "expected_revision": 4, "decided_at_ms": 7, "decision_time_given": True}})
        existing = writer.finish(label="lookup")
        with_lookup = request[:lookup_at] + existing + request[lookup_at + 1:]
        flag_at = lookup_at + len(existing) - 1
        self.assertEqual(with_lookup[flag_at], 2)

        def mutate(frame: bytes, at: int, value: int) -> bytes:
            return frame[:at] + bytes([value]) + frame[at + 1:]

        result = engine.decode_correction_transition_result(self._exchange(mutate(request, command_at, 0))[1:])
        self.assertEqual((result["status"], result["reject_reason"]), ("REJECTED", "INVALID_REQUEST"))
        for value in (2, 255):
            self.assertEqual(self._exchange(mutate(request, command_at, value)), b"\x01", value)
        for value in (0, 1, 2):
            self.assertEqual(self._exchange(mutate(with_lookup, flag_at, value))[:1], b"\x00", value)
        # The shipped command resent as itself: the stored time-given byte alone decides. 1 (time left to the owner's clock)
        # cannot match a command that named its time; 0 (old row) and 2 (named) match it.
        answers = {}
        for value in (0, 1, 2):
            reply = self._exchange(self._resend_frame(request, command_at, value))
            self.assertEqual(reply[:1], b"\x00", value)
            result = engine.decode_correction_transition_result(reply[1:])
            answers[value] = (result["status"], result["reject_reason"])
        self.assertEqual(answers, {0: ("DUPLICATE", None), 1: ("REJECTED", "ACTION_CONFLICT"), 2: ("DUPLICATE", None)})
        for value in (3, 255):
            self.assertEqual(self._exchange(mutate(with_lookup, flag_at, value)), b"\x01", value)
        for frame, at in ((request, command_at), (with_lookup, flag_at)):
            for cut in (at, at + 1, at + 9):
                self.assertEqual(self._exchange(frame[:cut]), b"\x01", cut)

    def test_correction_frame_at_the_cap_is_answered_inside_the_worker_bound(self) -> None:
        """Both 9,900-row frames are decided REJECTED / SCOPE_MISMATCH (a 158-byte result) by one worker that stays live and
        flat.  Pin 8EB77363, guarded run cc-cap-1 (2026-10-02), fresh worker, seconds / commit after: W=63 (5,002,526 B)
        0.70 s / 104.5 MB; the largest valid frame (7,150,826 B) 0.96 s / 138.2 MB.  The bound of 250 MB is ~1.8x that
        and under the 400 MB recycle bound.  Pin 58CDA012 committed ~190 B per frame byte: 964 MB, then 1.38 GB, failing
        closed at the 1 GB cap.  OPEN RESULT-CAP LIMIT: these rejections never
        reach it, but an accepted correction near 7 MB is answered 03, result encoding failed (evaluator_result_rejected)
        on both pins, because its BLFCRES3 result embeds the input."""
        request, data = (_VECTORS / "request.bin").read_bytes(), self._wires()[0][1]
        at = request.index(b"BLFIN02")  # the KAT's sized input (4-byte length before it) is swapped for a 9,900-row one
        rest = request[at + int.from_bytes(request[at - 4:at], "big"):]

        def frame(width: int, key: str = "0" * 110) -> bytes:
            padded = self._padded(data, 9_900, "x" * width, key)
            return request[:at - 4] + len(padded).to_bytes(4, "big") + padded + rest

        fits, largest = frame(63), frame(128, "0" * 121)  # an ID is at most 128 bytes (maxIdBytes)
        self.assertLessEqual(len(largest), engine.MAX_CORRECTION_TRANSITION_BYTES)
        for wire in (fits, largest):
            engine._close_evaluator()
            worker, commits = engine._running_evaluator(), []
            for _ in range(3):
                started = timeit.default_timer()
                result = engine.run_correction_transition_v1(request=wire)
                self.assertLess(timeit.default_timer() - started, engine.EVALUATOR_TIMEOUT_SECONDS)
                self.assertEqual((result["status"], result["reject_reason"]), ("REJECTED", "SCOPE_MISMATCH"))
                commits.append(worker.commit_bytes())
            self.assertEqual(engine._evaluator[:1], [worker])  # not recycled
            self.assertTrue(worker.alive)
            self.assertLess(max(commits), 250_000_000, commits)
            self.assertLess(max(commits[1:]) - commits[1], 16_000_000, commits)

    def test_payment_frames_keep_the_worker_flat(self) -> None:
        frames = self._frames()
        sent = [frames["c1"], frames["c2"], frames["s1_refused"]]
        with patch.object(engine, "EVALUATOR_RECYCLE_COMMIT_BYTES", 1 << 40):
            commits = []
            for i in range(300):
                self._exchange(sent[i % 3])
                commits.append(engine._evaluator[0].commit_bytes())
        self.assertLess(max(commits[3:]) - commits[3], 16_000_000, [round(c / 1e6) for c in commits[::30]])


if __name__ == "__main__":
    unittest.main()
