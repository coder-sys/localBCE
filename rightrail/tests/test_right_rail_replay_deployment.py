"""The replay's deployment opener (app/right_rail_replay_deployment.py): a state's public inputs in a folder, decided into a signed
store of the run's own.  The folder is a hand-over the tests write from the class-harness inputs (the signed grant and key set,
the cases' 834 and exclusion list).  Windows, the pinned engine built.  Synthetic, non-PHI."""

import contextlib
import hashlib
import logging
import re
import io
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from app import right_rail_gate_codec as gate
from app import right_rail_gate_ffs as ffs
from app import right_rail_gate_producer as producer
from app import right_rail_gate_signer as signer
from app import right_rail_reader_leie as leie
from app import right_rail_replay_deployment as opener
from app import right_rail_x12_834 as r834
from tests import _class_cases as cc
from tests import _class_harness as ch
from tests import _gate_authority as au
from tests import _gate_shards as g
from tests import test_right_rail_gate_ffs as tf
from tests import test_right_rail_gate_formats as fx
from tests import test_right_rail_replay_diff as rdt
from tests import test_ruleset_admission as ra
from tests.test_x12 import file_of
from tools import replay_diff as tool

PIN = au.genesis()[0].hex()
DAY = "2027-03-15"
SCOPE = [(fx.PROGRAM, 1 << 1 | 1 << 3, 3, 0)]


def deaths_file(asof, rows, cover="F"):
    """An RRPDTH01 file (conformance/PROVIDER_DEATH_V1.md): a header, one row per provider (NPI, day of death), a trailer."""
    lines = ["HRRPDTH01" + "DEPLOYMENT".ljust(20) + "000000000001" + asof + cover + "DEPLOYMENT".ljust(20)]
    lines += ["D" + npi + day for npi, day in rows] + [f"T{len(rows):09d}"]
    return "".join(line.ljust(120) + "\n" for line in lines).encode()


def tree(folder):
    """Every name under the folder with its size, mtime and SHA3-512."""
    return {str(p.relative_to(folder)): (p.stat().st_size, p.stat().st_mtime_ns, hashlib.sha3_512(p.read_bytes()).hexdigest()) if p.is_file() else None
            for p in sorted(Path(folder).rglob("*"))}


class OpenerTests(ch.Harness):
    def setUp(self):
        super().setUp()
        scratch = os.environ.get("E3_SCRATCH")
        if scratch:
            os.makedirs(scratch, exist_ok=True)
        self.dir = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.dir.cleanup)
        self.tmp = Path(self.dir.name)
        (self.tmp / "work").mkdir()
        self.case = case = cc.Parts(2)
        case.leie = [cc.tl.row(npi=case.npi)]
        case.claim = rdt.with_control(cc.claim_of(case.cid, 2), "B1", "B2")
        self.claims = self.tmp / "claims.837"
        self.claims.write_bytes(case.file837())
        self.remit = self.tmp / "p.835"
        self.remit.write_bytes(self.remittance())
        self.expected = [(f"{case.cid}#B1", "PROVIDER_EXCLUDED"), (f"{case.cid}#B2", "PROVIDER_EXCLUDED")]

    def remittance(self, day="20270315", **kw):
        body = [f"CLP*{self.case.cid}*1*20.00*20.00*0.00*MC*PCN*11*1", "SVC*HC:99213*10.00*10.00**1", "DTM*472*20260115", "REF*6R*B1",
                "SVC*HC:99213*10.00*10.00**1", "DTM*472*20260115", "REF*6R*B2"]
        return file_of([rdt.head("20.00", payee=self.case.npi) + body], kind="835", gs_date=day, **kw)

    def folder(self, name="state", **files):
        """The state's folder; ``files`` replaces any of its files by name (``genesis``, ``grant``, ``step``, ``leie``,
        ``provider_deaths``, ``deployment``; None leaves it out); ``rulesets``, a list of records, are written to ``rulesets/``."""
        root = self.tmp / name
        root.mkdir()
        day, step = au.kstep()
        parts = {"deployment": json.dumps({"tenant": fx.TENANT, "program": fx.PROGRAM, "period": fx.PERIOD, "leie_as_of": DAY, "leie_kind": "full"}).encode(),
                 "genesis": au.genesis()[1], "step": step, "grant": au.grant(SCOPE), "leie": self.case.leie_bytes(),
                 "provider_deaths": deaths_file("20270301", [(cc.tl.make_npi(2), "20270201")])}
        parts.update(files)
        for name_, rel in (("deployment", "deployment.json"), ("genesis", "keyset/genesis"), ("step", f"keyset/steps/{day}"), ("grant", "grant"),
                           ("leie", "leie"), ("provider_deaths", "provider_deaths")):
            if parts[name_] is not None:
                (root / rel).parent.mkdir(exist_ok=True, parents=True)
                (root / rel).write_bytes(parts[name_])
        for n, record in enumerate(files.get("rulesets", ())):
            (root / "rulesets").mkdir(exist_ok=True)
            (root / "rulesets" / f"r{n}").write_bytes(record)
        (root / "834").mkdir()
        if files.get("roster", 1) is not None:
            (root / "834" / "roster.834").write_bytes(files.get("roster", self.case.file834()))
        return root

    def harness_decide(self):
        """The ``decide`` of the class harness's store (eight shards, the test link) on this case's feeds."""
        listed = leie.read_leie(self.case.leie_bytes(), source="deployment", as_of=DAY, kind="full")
        feed = ffs.feeds(20270315, r834.read_834(self.case.file834()), listed, ("2027-03-01", [(cc.tl.make_npi(2), "2027-02-01")]), ch.SECRET)[0]

        @contextlib.contextmanager
        def session(store):
            with mock.patch.object(tempfile, "tempdir", str(store)), self.session() as run:
                yield run
        return tool.gate_decide(session, fx.TENANT, fx.PROGRAM, fx.PERIOD, ch.SECRET, listed, feed)

    def run_tool(self, folder, pin=PIN, out="report.json", decide=None):
        """(exit code, standard error, the report's bytes or None) of the tool on the files with the opener."""
        out, err = self.tmp / out, io.StringIO()
        argv = [str(self.claims), "--835", str(self.remit), "--out", str(out)] + (["--deployment", str(folder), "--keyset-pin", pin] if decide is None else [])
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            code = tool.main(argv, decide, scratch=self.tmp / "work")
        return code, err.getvalue(), out.read_bytes() if out.exists() else None

    def refused(self, folder, words, pin=PIN):
        code, err, report = self.run_tool(folder, pin)
        self.assertEqual((code, report, os.listdir(self.tmp / "work")), (1, None, []), err)
        self.assertRegex(err, words)

    def test_1_end_to_end_gives_the_report_the_harness_store_gives(self):
        folder = self.folder()
        code, err, report = self.run_tool(folder)
        self.assertEqual(code, 0, err)
        diffs = [(d["key"], d["cause"]) for d in json.loads(report)["differences"]]
        self.assertEqual(diffs, self.expected)
        again = self.tmp / "harness.json"
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(tool.main([str(self.claims), "--835", str(self.remit), "--out", str(again)], self.harness_decide(), scratch=self.tmp / "work"), 0)
        self.assertEqual(report, again.read_bytes())  # eight shards there, one here

    def test_1_rule_sets_in_the_folder_are_presented_to_the_engine(self):
        """The state's signed rule sets in ``rulesets/``.  On the rows-file engine the first record is presented with
        every frame sent, and the report is the one without it; with a later version beside it every line holds
        ``ruleset_newer`` and the run is refused.  The pinned engine runs no rule set: every line holds and the run is
        refused.  The folder is read as the host reads it: an entry that is not a file and another tenant's record are
        skipped and named in the report's ``set_aside``, and the run goes on; a file that does not decode holds every
        line ``ruleset_file_bad``, as on a live host, and the run is refused."""
        step = au.keyset_doc(au.keyset_body(1, au.genesis()[0], 20270310, 20270409, extra=ra.POLICY_KEYS))  # adds POLICY keys
        hist = g.ENGINE.with_name("gate_hist3.exe")
        if not hist.is_file():
            raise AssertionError(f"RULE SETS NOT RUN: {hist} missing; run `lake build gate_hist3` in lean/")
        real, frames = opener.decider.RulesWorker.run_frame, []

        def spy(worker, directory, shard, data, *rest, **kw):
            frames.append(data)
            return real(worker, directory, shard, data, *rest, **kw)
        with mock.patch.object(opener.decider, "committed_pin", lambda: hashlib.sha256(hist.read_bytes()).digest()),                 mock.patch.object(opener.decider.RulesWorker, "run_frame", spy):
            for name, records, junk, words in (("first", [tf.RUN], False, None),
                                               ("later", [tf.RUN, tf.V2], False, r"held for configuration: ruleset_newer \(2 lines\)"),
                                               ("junk", [tf.RUN], True, r"held for configuration: ruleset_file_bad \(2 lines\)")):
                with self.subTest(name):
                    frames.clear()
                    folder = self.folder(name, step=step, rulesets=records)
                    (folder / "rulesets" / "sub").mkdir()
                    (folder / "rulesets" / "theirs").write_bytes(ra.sign(tf.rs.with_(tf.RUN_DOC, tenant=fx.OTHER)))
                    if junk:
                        (folder / "rulesets" / "junk").write_bytes(b"not a record")
                    code, err, report = self.run_tool(folder, out=f"{name}.json", decide=opener.replay_decide(folder, PIN, engine=hist))
                    if words is None:
                        self.assertEqual(code, 0, err)
                        self.assertEqual([(d["key"], d["cause"]) for d in json.loads(report)["differences"]], self.expected)
                        self.assertTrue(frames)
                        self.assertEqual([opener.decider._requests(f)[4] for f in frames], [[tf.RUN]] * len(frames))
                        aside = [r for r in json.loads(report)["set_aside"] if r["cause"].startswith("ruleset:")]
                        self.assertEqual(aside, [{"system": "gate", "cause": f"ruleset:{n}:{why}", "count": 1} for n, why in
                                                 (("sub", "not_a_file"), ("theirs", "other_tenant"))])
                    else:
                        self.assertEqual((code, report, frames), (1, None, []), err)
                        self.assertRegex(err, words)
        self.refused(self.folder("pinned", step=step, rulesets=[tf.RUN]), r"held for configuration: grant_ruleset_not_run \(2 lines\)")

    def test_2_the_folder_is_not_touched_even_with_a_live_store_in_it(self):
        folder = self.folder()
        cluster = g.Cluster(str(folder), fx.custody(str(folder)), shards=2)
        cluster.send(0, {1: [1]})
        before = tree(folder)
        self.assertTrue({"s0.sqlite3", "s0.mark", "tenant.floor"} <= set(before) and any(n.startswith("idx0") for n in before))
        code, err, report = self.run_tool(folder)
        self.assertEqual(code, 0, err)
        self.assertEqual(tree(folder), before)

    def test_3_a_missing_file_refuses_before_anything_is_decided(self):
        for name in ("deployment", "genesis", "grant", "leie", "provider_deaths"):
            with self.subTest(name):
                self.refused(self.folder(name + "_gone", **{name: None}), f"deployment_file:{name}")
        self.refused(self.folder("no_roster", roster=None), "deployment_file:834")
        self.refused(self.tmp / "nowhere", "deployment_folder")
        odd = self.folder("odd_steps")
        (odd / "keyset" / "steps" / "tomorrow").write_bytes(b"x")
        self.refused(odd, "deployment_file:keyset_steps")
        self.refused(self.folder("bad_deaths", provider_deaths=deaths_file("20270301", [(cc.tl.make_npi(2), "20270201")], cover="C")), "deployment_file:provider_deaths")
        self.refused(self.folder("junk_deaths", provider_deaths=b"junk"), "deployment_file:provider_deaths")

    def test_4_the_pin_must_be_the_states_and_well_formed(self):
        folder = self.folder()
        other = au.H(au.keyset_body(nb=20270201)).hex()
        self.refused(folder, "grant_head", pin=other)  # the engine cannot connect the grant's key set to a pin that is not its hash
        for bad in ("ab" * 63, "AB" * 64, "00" * 64, "zz" * 64, ""):
            with self.assertRaises(opener.slots.SlotError, msg=bad):
                opener.replay_decide(self.tmp / "never_read", bad)

    def test_5_a_tampered_grant_or_key_set_is_refused(self):
        grant, genesis, (day, step) = au.grant(SCOPE), au.genesis()[1], au.kstep()
        flip = lambda doc, at: doc[:at] + bytes([doc[at] ^ 1]) + doc[at + 1:]  # noqa: E731
        for name, files in (("grant", {"grant": flip(grant, -5)}), ("genesis", {"genesis": flip(genesis, -5)}), ("step", {"step": flip(step, -5)})):
            with self.subTest(name):
                self.refused(self.folder(name + "_flipped", **files), "held for configuration")

    def test_6_a_grant_or_folder_for_another_tenant_or_program_is_refused(self):
        self.refused(self.folder("other_grant", grant=au.grant(SCOPE, tenant=fx.OTHER)), "held for configuration")
        for name, who in (("tenant", fx.OTHER), ("program", "other-program")):
            doc = {"tenant": fx.TENANT, "program": fx.PROGRAM, "period": fx.PERIOD, "leie_as_of": DAY, "leie_kind": "full", name: who}
            self.refused(self.folder("other_" + name, deployment=json.dumps(doc).encode()), "held for configuration")

    def test_7_a_stale_grant_is_refused(self):
        self.refused(self.folder("old_window", grant=au.grant(SCOPE, nb=20270101, na=20270201)), "held for configuration")

    def test_8_an_engine_that_is_not_the_pinned_one_decides_nothing(self):
        engine = self.tmp / "engine.exe"
        engine.write_bytes(g.ENGINE.read_bytes() + b"\x00")
        folder = self.folder()
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            code = tool.main([str(self.claims), "--835", str(self.remit), "--out", str(self.tmp / "r.json")], opener.replay_decide(folder, PIN, engine), scratch=self.tmp / "work")
        self.assertEqual((code, (self.tmp / "r.json").exists(), os.listdir(self.tmp / "work")), (1, False, []))
        self.assertIn("rules_pin_mismatch", err.getvalue())

    def test_9_two_runs_give_the_same_bytes(self):
        folder = self.folder()
        first, second = self.run_tool(folder, out="a.json"), self.run_tool(folder, out="b.json")
        self.assertEqual((first[0], second[0]), (0, 0))
        self.assertEqual(first[2], second[2])

    def test_10_the_run_folder_goes_and_no_key_is_left_anywhere_else(self):
        folder = self.folder()
        before = (tree(folder), sorted(os.listdir(self.tmp)))
        self.assertEqual(self.run_tool(folder)[0], 0)
        self.assertEqual((tree(folder), sorted(os.listdir(self.tmp))), (before[0], sorted(before[1] + ["report.json"])))
        self.assertEqual(os.listdir(self.tmp / "work"), [])
        boom = mock.patch.object(opener.ffs, "decide_claims", side_effect=RuntimeError("boom"))
        with boom, self.assertRaises(RuntimeError):
            decide = opener.replay_decide(folder, PIN)
            tool.report_files([self.remit], [self.claims], decide, None, scratch=self.tmp / "work")
        self.assertEqual((os.listdir(self.tmp / "work"), tree(folder)), ([], before[0]))

    def test_11_what_a_run_seals_is_refused_under_the_deployments_link(self):
        """The run's seal verifies under its own link and certificate and under none a payer holds: the class harness's store, with its
        pinned link and certificate for the same tenant, is the payer here, and its own seal is the control that the frames are right."""
        seen, sealed = {}, []

        class Spy(producer.ShardProducer):
            def __init__(self, *args, **kw):
                seen.update(kw)
                super().__init__(*args, **kw)
        real = ffs.decide_claims

        def spy(*args, **kw):
            out = real(*args, **kw)
            sealed.extend(out[2])
            return out

        def watch(run):
            seen.clear()
            sealed.clear()
            with mock.patch.object(producer, "ShardProducer", Spy), mock.patch.object(ffs, "decide_claims", spy):
                run()
            (signed, tokens, _), = sealed
            return dict(seen), signed, tokens
        frame = lambda link, cert, signed, tokens: (signer.framed(link) + signer.framed(cert) + signer.framed(b"") + signer.framed(signed)  # noqa: E731
                                                     + len(tokens).to_bytes(2, "big") + b"".join(map(signer.framed, tokens)) + (0).to_bytes(8, "big"))
        verify = lambda *parts: signer.gate_verify(1, frame(*parts))  # noqa: E731
        own, signed, tokens = watch(lambda: self.assertEqual(self.run_tool(self.folder())[0], 0))
        payer, payer_signed, payer_tokens = watch(lambda: tool.report_files([self.remit], [self.claims], self.harness_decide(), None, scratch=self.tmp / "work"))
        self.assertEqual(verify(payer["link"], payer["key_cert"], payer_signed, payer_tokens), signer.ACCEPT)  # control: the payer's own seal verifies
        self.assertEqual(verify(own["link"], own["key_cert"], signed, tokens), signer.ACCEPT)  # the run's own link takes its seal
        self.assertNotEqual(payer["link"], own["link"])
        for link, cert in ((payer["link"], payer["key_cert"]), (payer["link"], own["key_cert"])):
            self.assertNotEqual(verify(link, cert, signed, tokens), signer.ACCEPT)

    def test_12_argv_names_data_never_code(self):
        base = [str(self.claims), "--835", str(self.remit)]
        for bad in (["--deployment", str(self.tmp)], ["--keyset-pin", PIN]):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as stop:
                tool.main(base + bad)
            self.assertEqual(stop.exception.code, 2)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(tool.main(base + ["--deployment", "tests.test_right_rail_replay_diff:same", "--keyset-pin", PIN]), 1)
        self.assertIn("deployment_folder", err.getvalue())

    def tool_out(self, folder, out):
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            code = tool.main([str(self.claims), "--835", str(self.remit), "--out", str(out), "--overwrite", "--deployment", str(folder), "--keyset-pin", PIN],
                             scratch=self.tmp / "work")
        return code, err.getvalue()

    def test_13_the_report_never_goes_into_the_deployment_folder(self):
        folder = self.folder()
        before = tree(folder)
        for out in (folder / "grant", folder / "834" / "report.json", folder / "new.json", folder, self.tmp / "state" / ".." / "state" / "x.json"):
            with self.subTest(str(out)):
                code, err = self.tool_out(folder, out)
                self.assertEqual((code, tree(folder), os.listdir(self.tmp / "work")), (1, before, []), err)
                self.assertIn("deployment folder", err)

    def test_14_the_exclusion_list_must_state_its_day_and_be_inside_the_engine_window(self):
        doc = lambda **kw: json.dumps({"tenant": fx.TENANT, "program": fx.PROGRAM, "period": fx.PERIOD, "leie_as_of": DAY, "leie_kind": "full", **kw}).encode()  # noqa: E731
        self.refused(self.folder("old_list", deployment=doc(leie_as_of="2027-02-01")), "feed_window:leie")  # 42 days before the 15th
        self.refused(self.folder("future_list", deployment=doc(leie_as_of="2027-03-16")), "feed_window:leie")
        for name, bad in (("no_day", None), ("not_iso", "20270315"), ("no_calendar_day", "2027-02-30"), ("number", 20270315)):
            with self.subTest(name):
                shape = json.loads(doc())
                shape.pop("leie_as_of")
                shape.update({} if bad is None else {"leie_as_of": bad})
                self.refused(self.folder("list_" + name, deployment=json.dumps(shape).encode()), "deployment_file:deployment")
        self.assertEqual(self.run_tool(self.folder("edge_list", deployment=doc(leie_as_of="2027-02-12")))[0], 0)  # exactly 31 days

    def test_15_a_roster_that_is_refused_or_empty_and_any_feed_outside_its_window_hold_the_run(self):
        self.refused(self.folder("junk_roster", roster=b"junk"), "deployment_file:834")
        self.refused(self.folder("empty_roster", roster=b""), "deployment_file:834")
        self.remit.write_bytes(self.remittance("20270325"))  # the roster is 11 days old: the engine takes 7
        self.refused(self.folder("old_roster", deployment=json.dumps({"tenant": fx.TENANT, "program": fx.PROGRAM, "period": fx.PERIOD, "leie_as_of": "2027-03-25", "leie_kind": "full"}).encode()),
                     "feed_window:834")
        self.remit.write_bytes(self.remittance("20270620"))  # the death list (March 1st) is over 90 days old
        self.refused(self.folder("old_deaths", deployment=json.dumps({"tenant": fx.TENANT, "program": fx.PROGRAM, "period": fx.PERIOD, "leie_as_of": "2027-06-20", "leie_kind": "full"}).encode()),
                     "feed_window:provider_deaths")
        self.remit.write_bytes(self.remittance("20270301"))  # a death list as of the day after the decision day
        self.refused(self.folder("future_deaths", deployment=json.dumps({"tenant": fx.TENANT, "program": fx.PROGRAM, "period": fx.PERIOD, "leie_as_of": "2027-03-01", "leie_kind": "full"}).encode(),
                                 provider_deaths=deaths_file("20270302", [])), "feed_window:provider_deaths")

    def test_16_the_grant_window_and_pin_are_checked_even_when_no_line_would_be_sent(self):
        self.claims.write_bytes(b"junk")  # nothing reads: every claim is set aside, nothing reaches the gate
        self.refused(self.folder(), "no_lines_sent")

    def test_17_the_feeds_set_asides_are_in_the_report(self):
        self.case.leie.append(cc.tl.row(last="NONUMBER"))  # a listed provider with no identifier: the feed sets it aside
        code, err, report = self.run_tool(self.folder())
        self.assertEqual(code, 0, err)
        self.assertIn({"system": "gate", "cause": "feed:no_npi", "count": 1}, json.loads(report)["set_aside"])
        self.assertEqual([(d["key"], d["cause"]) for d in json.loads(report)["differences"]], self.expected)  # no claim was set aside for it

    def test_18_a_producer_or_signer_failure_is_a_refusal_not_a_traceback_and_a_left_store_is_found_whatever_else_failed(self):
        for error in (producer.GateProducerError("producer_boom"), signer.GateSignerError("signer_boom")):
            with self.subTest(type(error).__name__), mock.patch.object(opener.ffs, "decide_claims", side_effect=error):
                code, err, report = self.run_tool(self.folder(type(error).__name__))
                self.assertEqual((code, report, os.listdir(self.tmp / "work")), (1, None, []))
                self.assertIn(f"replay_diff: {error}", err)

        def fail(reads, store):
            (store / "key").write_bytes(b"secret")
            raise ValueError("decide failed")
        with mock.patch.object(tool.shutil, "rmtree"), self.assertRaisesRegex(OSError, "could not be removed"):
            tool.report_files([self.remit], [self.claims], fail, None, scratch=self.tmp / "work")

    def test_19_an_unreadable_835_refuses_the_run_for_its_day_may_be_the_newest(self):
        folder = self.folder()
        (self.tmp / "junk.835").write_bytes(b"junk")
        for name, path in (("missing", self.tmp / "gone.835"), ("junk", self.tmp / "junk.835")):
            err, out = io.StringIO(), self.tmp / (name + ".json")
            with self.subTest(name), contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
                code = tool.main([str(self.claims), "--835", str(self.remit), str(path), "--out", str(out), "--deployment", str(folder), "--keyset-pin", PIN],
                                 scratch=self.tmp / "work")
            self.assertEqual((code, out.exists(), os.listdir(self.tmp / "work")), (1, False, []), err.getvalue())
            self.assertIn("unreadable_835", err.getvalue())

    def test_20_an_835_not_read_whole_or_an_odd_entry_in_its_folder_refuses_the_run(self):
        whole = self.remittance()
        damaged = {"ge_count": self.remittance(ge_count=9), "se_count": self.remittance(se_count=99), "iea_count": self.remittance(iea_count=9),
                   "gs_date": self.remittance("20271340"), "truncated": whole[:-1], "group_unclosed": whole[:whole.rindex(b"GE")],
                   "garbage_tail": whole + b"GARBAGE AFTER THE LAST INTERCHANGE"}
        for name, data in damaged.items():
            with self.subTest(name):
                self.remit.write_bytes(data)
                code, err, report = self.run_tool(self.folder("damaged_" + name))
                self.assertEqual((code, report, os.listdir(self.tmp / "work")), (1, None, []), err)
                self.assertIn("unreadable_835", err)
        newest = self.tmp / "remits"
        newest.mkdir()
        (newest / "a.835").write_bytes(whole)
        (newest / "sub").mkdir()
        self.remit = newest
        self.refused(self.folder("odd_entry"), "unreadable_835")
        self.remit = self.tmp / "gone.835"
        self.refused(self.folder("no_835"), "unreadable_835")

    def test_21_the_exclusion_list_kind_must_be_declared_and_full(self):
        for name, kind in (("none", None), ("supplement", "supplement"), ("reinstatements", "reinstatements"), ("number", 1)):
            with self.subTest(name):
                shape = {"tenant": fx.TENANT, "program": fx.PROGRAM, "period": fx.PERIOD, "leie_as_of": DAY}
                shape.update({} if kind is None else {"leie_kind": kind})
                self.refused(self.folder("kind_" + name, deployment=json.dumps(shape).encode()), "deployment_file:deployment")

    def test_22_a_feed_the_engine_would_not_take_refuses_the_run(self):
        self.refused(self.folder("no_deaths", provider_deaths=deaths_file("20270301", [])), "feed_empty:provider_deaths")
        self.case.leie_raw = cc.tl.HEAD.encode()
        self.refused(self.folder("header_only"), "feed_empty:leie")
        self.case.leie_raw = (",".join(leie.LEIE_COLUMNS) + "\nx,y\n").encode()  # its one row does not read
        self.refused(self.folder("no_readable_row"), "feed_empty:leie")
        self.case.leie_raw = None
        self.refused(self.folder("blind_834", roster=self.case.file834() + b"GARBAGE AFTER THE LAST INTERCHANGE"), "feed_empty:834")
        self.case.filler = cc.t834.member(f"D{self.case.n:07d}", **cc.SPAN)  # nobody in the roster has died
        self.refused(self.folder("no_member_deaths", roster=self.case.file834()), "feed_empty:834_deaths")

    def test_23_the_windows_are_the_engines(self):
        lean = Path(opener.__file__).resolve().parents[1] / "lean" / "BlindLedger" / "Gate" / "Engine3"
        rows = (lean / "RowsStore.lean").read_text("utf-8")
        age = dict(re.findall(r"let (dmf|pd|ex|sp) ← FeedIx\.decode today (\d+)", rows))
        self.assertEqual(sorted(age), ["dmf", "ex", "pd", "sp"])
        self.assertEqual(opener.WINDOWS, {"834": min(int(age["dmf"]), int(age["sp"])), "provider_deaths": int(age["pd"]), "leie": int(age["ex"])})
        reads = re.findall(r"feedW \S+ q\.today (\d+) q\.(dmf|pdeath|excl|span)\.asOf", (lean / "ReadB.lean").read_text("utf-8"))
        self.assertEqual({k: int(v) for v, k in reads}, {"dmf": int(age["dmf"]), "pdeath": int(age["pd"]), "excl": int(age["ex"]), "span": int(age["sp"])})
        self.assertIn("0 < n", rows)  # a feed with no row is unusable: the opener's feed_empty refusal

    def test_24_the_output_guard_holds_for_every_caller_and_by_identity(self):
        folder = self.folder()
        before = tree(folder)
        decide = opener.replay_decide(folder, PIN)
        share = Path("//localhost/" + str(folder.resolve())[0] + "$" + str(folder.resolve())[2:].replace("\\", "/"))  # the same folder by another path
        outs = [folder / "grant", folder, folder / "834" / "r.json"] + ([share / "r.json"] if share.exists() else [])
        for out in outs:
            with self.subTest(str(out)), self.assertRaisesRegex(ValueError, "deployment folder"):
                tool.report_files([self.remit], [self.claims], decide, out, overwrite=True, scratch=self.tmp / "work")
        self.assertEqual((tree(folder), os.listdir(self.tmp / "work")), (before, []))

    def test_25_the_empty_slot_warnings_are_silent_and_the_reader_s_cause_is_kept(self):
        folder = self.folder()
        with self.assertNoLogs("rightrail.slots", logging.WARNING):
            opener.replay_decide(folder, PIN)
        self.assertEqual(opener.slots._log.filters, [])  # the filter is gone: another caller's real warnings are not hidden
        self.refused(self.folder("changed", provider_deaths=deaths_file("20270301", [(cc.tl.make_npi(2), "20270201")], cover="C")), r"deployment_file:provider_deaths:\w+")
        self.refused(self.folder("junk_list", leie=b"junk"), r"deployment_file:leie:\w+")

    def test_26_a_step_name_must_be_ascii_digits(self):
        odd = self.folder("arabic_steps")
        (odd / "keyset" / "steps" / "\u0662\u0660\u0662\u0667\u0660\u0663\u0661\u0665").write_bytes(b"x")
        self.refused(odd, "deployment_file:keyset_steps")

    def test_the_link_encoder_gives_the_test_link_byte_for_byte_and_reads_back(self):
        key = lambda name: fx.keypair(f"{name}-{fx.TENANT}")[0]  # noqa: E731
        sign = lambda name: lambda body: fx.det_sign(f"{name}-{fx.TENANT}", body)  # noqa: E731
        link = gate.encode_link(fx.TENANT, key("root"), gate.sha3_512(gate.encode_key(key("root-next"))), key("witness"),
                                gate.sha3_512(gate.encode_key(key("witness-next"))), gate.sha3_512(b"RR/GATE/TEST-ONLY-APPROVAL/v1\x00"),
                                sign("root"), sign("witness"))
        self.assertEqual(link, fx.link(fx.TENANT))
        read = gate.read_link(link)
        self.assertEqual((read.tenant_id, read.gen, read.root_key, read.witness_key), (fx.TENANT, 0, key("root"), key("witness")))


if __name__ == "__main__":
    unittest.main()
