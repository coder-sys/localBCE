"""Open a deployment's public inputs for the replay difference report (tools/replay_diff.py), and decide a state's claims in a
signed store of the run's own.

``replay_decide(folder, keyset_pin)`` returns the ``decide`` the report takes.  The folder is what a state hands over, read once
and never written: ``deployment.json`` (tenant, program, period, ``leie_as_of`` and ``leie_kind``), ``keyset/genesis`` and ``keyset/steps/<yyyymmdd>`` (the
signed key sets), ``grant`` (the signed APPROVAL/v2), ``834/`` (exactly one file), ``leie`` (a full list), ``provider_deaths``
(an RRPDTH01 file) and, when the state has signed rules, ``rulesets/`` (its signed rule-set records, one per file, read as a live
host reads its rule-set folder: an entry that is not a file, or another tenant's record, is skipped, logged and named in the
report's ``set_aside`` as ``ruleset:<file name>:<why>``; a file that cannot be read or does not decode holds every line, so the
run is refused).  The pinned rules engine is the repository's.  The deployment's own signed store, marks, floor file and
history are never opened: deciding signs frames, raises the floors and seals checkpoints, which on a live store would mint
real tokens for replayed claims and move its anti-rollback state.  The decisions go to a fresh store in the run's own folder, under
signing, verifier and root keys made for the run (ML-DSA-87 through the pinned signer; the seeds never reach Python and go with
the folder), its own link, key certificate and counter (memory only), and a member-key secret of 32 bytes from ``os.urandom``,
held in memory and never written (the report's keys do not use it).  What the run seals verifies under no link a payer holds.

The key-set pin comes from the state out of band (it is the hash of the state's genesis key set), never from the folder it
checks.  The gate decides on what the incumbent could know at its last remittance: the newest 835 file date is its as-of day, and
a checkpoint is sealed at that day's start.  Every remittance, earlier ones included, is judged with the facts known at that day.
The state's word, not checked here because the files do not say it: the exclusion list's day (``leie_as_of``) and kind
(``leie_kind``, which must be ``full``: a supplement says nothing of who is not on it and would let every excluded provider through),
and the death list's sender, scope and sequence (it is read under the replay's own fixed scope).
Only the genesis key set is pinned.  That the folder holds every later key-set step, and that its period is the one under review,
is the state's word, not checked here; the grant's validity window on the as-of day is the only staleness check.  A run in which any
line is held for a configuration cause (no grant for the program, a key set that does not hash to the pin, a bad signature, a grant
outside its window, an engine that is not the pinned one, a rule set the engine cannot run), no line is sent, an 835 cannot be read whole (a file the reader refused, a damaged file, interchange,
group or set, or an entry of the 835 folder that is not a file: its date might be the newest), a feed is older than the engine
accepts (an 834 7 days, provider deaths 90, the exclusion list 31, counted back from the as-of day) or a feed is empty or blind
(``feed_empty``: the engine takes a feed only with at least one row, so it would hold every line) is refused: it would compare
nothing, or compare against a gate that holds every line.  The report's ``set_aside`` also counts the feed rows the readers
set aside, and names the rule-set files the host set aside.  Claims decided before the replay window count only if their 837s are among the inputs."""

import collections
import contextlib
import datetime
import io
import json
import logging
import os
from pathlib import Path

from app import right_rail_deployment_slots as slots
from app import right_rail_gate_codec as gate
from app import right_rail_gate_decide as decider
from app import right_rail_gate_ffs as ffs
from app import right_rail_gate_producer as producer
from app import right_rail_gate_signer as signer
from app import right_rail_reader_leie as leie
from app import right_rail_reader_provider_death as pdeath
from app import right_rail_x12_834 as r834
from app.right_rail_fact_registry import ident
from app.right_rail_reader_lines import ReaderError

ENGINE = Path(__file__).resolve().parents[1] / "lean" / ".lake" / "build" / "bin" / "gate_engine.exe"
EPOCH = 1
RELEASE = gate.sha3_512(b"RR/REPLAY/VERIFIER-RELEASE/v1\x00")  # the run's verifier names itself so
APPROVAL = gate.sha3_512(b"RR/REPLAY/RUN-LINK/v1\x00")  # the link's approval field: audit only, no approval exists for a run
# The provider death list's registry entry (conformance/PROVIDER_DEATH_V1.md): one full file of kind 4 whose rows are named by NPI.
DEATHS = {"src": 11, "cls": 1, "origin": 11, "ids": [[pdeath.PDEATH, [1]]], "gapless": 0, "maxage": 35, "drop": 10, "oneper": 1,
          "scope": b"\x0bDEPLOYMENT" + bytes(9), "name": b"\x0bDEPLOYMENT" + bytes(9), "fseq_rule": 2, "full": 1, "cfrom_rule": 0, "kinds": 1 << pdeath.PDEATH}
# Days a feed may be older than the day decided: Engine3/RowsStore.lean (dateOk, FeedIx.decode) and Engine3/ReadB.lean (feedW).
WINDOWS = {"834": 7, "provider_deaths": 90, "leie": 31}  # the 834 feeds member deaths (90) and enrollment spans (7): the shorter binds
CONFIGURATION = frozenset(row["code"] for row in json.loads(Path(__file__).with_name("cause_actions.json").read_text("utf-8")) if row["kind"] == "configuration")


class ReplayRefused(ValueError):
    """The run is refused before it compares anything; the message is the cause."""


class _Counter:
    """The run's shard counter: a value in memory (the store lives as long as the process)."""

    def __init__(self):
        self.value = None

    def read(self):
        return self.value

    def increment(self):
        self.value = (self.value or 0) + 1
        return self.value


def _read(path, name):
    try:
        return Path(path).read_bytes()
    except OSError:
        raise ReplayRefused(f"deployment_file:{name}") from None


def _files(folder, name):
    try:
        return sorted(Path(folder).iterdir())
    except OSError:
        raise ReplayRefused(f"deployment_file:{name}") from None


class _EmptyByDesign(logging.Filter):
    """Drops the slot module's one warning per empty slot: a run authors only the key-set pin, so the rest are empty by design."""

    def filter(self, record):
        return not record.getMessage().startswith("DEPLOYMENT_SLOT_EMPTY")


def _iso(day):
    if type(day) is not str or len(day) != 10:
        raise ValueError
    return datetime.date.fromisoformat(day)


def _fresh(name, as_of, today):
    """Refuse a feed whose as-of day is after the day decided or older than the engine accepts."""
    try:
        age = (_iso(today) - _iso(as_of)).days
    except ValueError:
        raise ReplayRefused(f"deployment_file:{name}") from None
    if not 0 <= age <= WINDOWS[name]:
        raise ReplayRefused(f"feed_window:{name} (as of {as_of}, decided on {today}, allowed 0 to {WINDOWS[name]} days before)")


def gate_decide(session, tenant, program, period, secret, exclusions, feed):
    """The ``decide`` for a deployment: ``session(store)`` is its context manager over the signed store it opens under ``store``,
    yielding ``run(sent, feed)`` (``right_rail_gate_ffs.decide_claims``, rows first); ``exclusions`` and ``feed`` are its own
    exclusion list and read set (``right_rail_gate_ffs.feeds``); ``paid``, the 835 reads, maps a payer's claim number to its claim."""
    def decide(reads, store, paid=()):
        sent, left = ffs.requests_of(reads, tenant, program, period, secret, exclusions, paid)
        with session(store) as run:
            return sent, left, run(sent, feed)[0] if sent else []
    return decide


def replay_decide(folder, keyset_pin, engine=ENGINE):
    """The ``decide(reads, store, paid)`` of the deployment in ``folder`` (``paid``: the 835 reads, for the as-of day), trusting only
    the key set that hashes to ``keyset_pin``.  A bad pin, a folder, file or setting that cannot be read, and a run held for a
    configuration cause are ``ReplayRefused`` (``deployment_file:<name>`` names the file)."""
    if not slots.SLOTS["GATE_KEYSET_PIN"][4]("replay", keyset_pin):
        raise slots.SlotError("slot_value", "GATE_KEYSET_PIN")  # before any file is read
    folder = Path(folder)
    if not folder.is_dir():
        raise ReplayRefused("deployment_folder")
    try:
        doc = json.loads(_read(folder / "deployment.json", "deployment"))
        tenant, program, period, leie_as_of, leie_kind = (doc[k] for k in ("tenant", "program", "period", "leie_as_of", "leie_kind"))
        if len(doc) != 5 or not all(type(x) is str for x in (tenant, program, period)) or leie_kind != "full":
            raise ValueError
        _iso(leie_as_of)
    except (ValueError, KeyError, TypeError):
        raise ReplayRefused("deployment_file:deployment") from None
    steps = []
    if (folder / "keyset" / "steps").exists():
        for step in _files(folder / "keyset" / "steps", "keyset_steps"):
            if not (len(step.name) == 8 and step.name.isascii() and step.name.isdigit()):
                raise ReplayRefused("deployment_file:keyset_steps")
            steps.append((int(step.name), _read(step, "keyset_steps")))
    keys = decider.Keys(_read(folder / "keyset" / "genesis", "genesis"), tuple(steps))
    rulesets = folder / "rulesets" if (folder / "rulesets").exists() else None  # read by the host as a live deployment's
    grant, exclusions, deaths = _read(folder / "grant", "grant"), _read(folder / "leie", "leie"), _read(folder / "provider_deaths", "provider_deaths")
    only = _files(folder / "834", "834")
    if len(only) != 1 or not only[0].is_file():
        raise ReplayRefused("deployment_file:834")  # one roster: separate files would give offsets that collide
    roster = _read(only[0], "834")
    quiet = _EmptyByDesign()
    slots._log.addFilter(quiet)
    try:
        deployment = slots.Slots({"GATE_KEYSET_PIN": [[tenant, keyset_pin]]})
    finally:
        slots._log.removeFilter(quiet)

    def decide(reads, store, paid):
        if any(read.refused or any(q.unit in ("file", "interchange", "group", "set") for q in read.quarantines) for read in paid):
            # a damaged file has lost its date, which may be the newest, and the as-of day would move without it
            raise ReplayRefused("unreadable_835")
        days = [c.file_at[:10] for read in paid for c in read.claims]
        if not days:
            raise ReplayRefused("no_remittance_date")
        asof = max(days)
        now = int(datetime.datetime.fromisoformat(asof).replace(tzinfo=datetime.timezone.utc).timestamp())
        secret = os.urandom(32)
        _fresh("leie", leie_as_of, asof)
        try:
            listed = leie.read_leie(exclusions, source="deployment", as_of=leie_as_of, kind=leie_kind)
        except ReaderError as error:
            raise ReplayRefused(f"deployment_file:leie:{error.cause}") from None
        (store / "seen").mkdir()
        try:
            death_list = pdeath.read_provider_deaths(io.BytesIO(deaths), DEATHS, scratch=str(store / "seen"), channel=1, key=0, reader=1)[0]
        except ReaderError as error:
            raise ReplayRefused(f"deployment_file:provider_deaths:{error.cause}") from None
        _fresh("provider_deaths", death_list[0], asof)
        enrolled = r834.read_834(roster)
        if enrolled.refused or not enrolled.rows:
            raise ReplayRefused("deployment_file:834" + (":" + enrolled.refused if enrolled.refused else ""))
        _fresh("834", max(r.file_at[:10] for r in enrolled.rows), asof)
        feed, feed_left = ffs.feeds(int(asof.replace("-", "")), enrolled, listed, death_list, secret)
        for name, (head, _) in zip(("834_deaths", "provider_deaths", "leie", "834_spans"), feed[1]):
            if head[0] != 1 or not int.from_bytes(head[5:9], "little"):  # Engine3/RowsStore.lean FeedIx.decode: present, and 0 < n
                raise ReplayRefused(f"feed_empty:{name}")

        @contextlib.contextmanager
        def session(store):
            (store / "keys").mkdir()
            handle = {name: str(store / "keys" / name) for name in ("root", "witness", "verifier", "epoch")}
            public = {name: signer.keygen(path) for name, path in handle.items()}
            sign = lambda name: lambda body: signer.sign(handle[name], body)  # noqa: E731
            link = gate.encode_link(tenant, public["root"], gate.sha3_512(os.urandom(32)), public["witness"], gate.sha3_512(os.urandom(32)),
                                    APPROVAL, sign("root"), sign("witness"))
            body = gate.encode_key_cert(tenant, EPOCH, gate.sha3_512(gate.read_link(link).body), (1,), public["epoch"], public["verifier"])
            cert = gate.attach_signatures(body, sign("root")(body), sign("witness")(body))
            cosign = lambda signed: gate.encode_cosign(RELEASE, sign("verifier")(gate.cosign_message(signed[:-2 - gate.ML_DSA_87_SIGNATURE], RELEASE)))  # noqa: E731
            floor = store / "tenant.floor"
            shard = producer.ShardProducer(store / "s0.sqlite3", mark_path=store / "s0.mark", tenant_id=tenant, shard_id=0, epoch=EPOCH,
                                           handle=handle["epoch"], link=link, key_cert=cert, payer_newest=gate.ZERO_DIGEST, counter=_Counter(),
                                           floors=lambda: decider.TenantAuthority.floors_in(floor, tenant), cosign=cosign)
            try:
                decider.TenantAuthority.provision(floor, tenant, [shard])
                host = decider.TenantAuthority(deployment, tenant, floor, [shard], ruleset_folder=rulesets), decider.RulesWorker(engine)
                try:
                    yield lambda sent, read_set: ffs.decide_claims(sent, read_set, host, {0: shard}, {0: store / "idx0"}, grant, keys, program, now)
                finally:
                    host[1].close()
                    aside.update(host[0].set_aside)
            finally:
                shard.close()
        aside: dict[str, str] = {}  # the rule-set files the host set aside: name -> why
        sent, left, rows = gate_decide(session, tenant, program, period, secret, listed, feed)(reads, store, paid)
        held = collections.Counter(why for _, _, _, reasons in rows for why in reasons if why in CONFIGURATION)
        if held:
            raise ReplayRefused("held for configuration: " + ", ".join(f"{why} ({n} lines)" for why, n in sorted(held.items())))
        if not sent:
            raise ReplayRefused(f"no_lines_sent: all {len(left)} claims were set aside, so the pin, grant and engine were not exercised")
        return sent, left, rows, feed_left, sorted(aside.items())
    decide.wants_835 = True
    decide.folder = folder.resolve()  # the report is never written into it (tools/replay_diff.py)
    return decide
