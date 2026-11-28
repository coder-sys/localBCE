"""The gate's decide layer: one Lean decide per shard batch, synthetic, activation=false.

The history is the shard's store on disk (conformance/FLAT_V1.md), held open by ``gate_engine DIR SHARD``.  The frame is
conformance/FRAME_V1.md's binary request: the tenant's reference feeds (read from the header lines), the shard's authority and the
signed DECIDE-REQUEST/v2 bytes of each payment, unchanged.  The engine reads the lines from those bytes; the host never
re-encodes product data.  The answer is binary too: a 16-byte record per line, the head and state root after the batch, the
grant id, the shard's authority record after the batch, each payment's outcome, reasons, authority, bypass id and
INPUT/v7, and the added rows.  The frame carries the tenant's key-set pin and its grant serial, key-set epoch and rule-set
floors (``TenantAuthority``); an engine store begun under another pin HOLDs every row (``flat_pin``), and so does an answer whose
record names another pin (``keyset_pin``).  The host builds each token
leaf from the request bytes it sent and those, and refuses an answer whose INPUT/v7 is not the one it computes.  The host recomputes one chain step from the signed head and the added rows; a head it
cannot recompute, a refused frame, a grant the engine does not admit or a head the signature does not cover HOLDs every row.
Python holds no policy: every outcome comes from the engine, and ``commit`` builds the leaves from those and from nothing a
caller hands it.  Line identity is per shard.
"""

from __future__ import annotations

import contextlib
import ctypes
import hashlib
import json
import logging
import msvcrt
import os
from pathlib import Path
import re
import shutil
import tempfile
import threading
import time
from typing import NamedTuple, Sequence

from app import minimal_clearance_verifier_process as process
from app import right_rail_deployment_slots as slots

from app import right_rail_gate_chain as flatchain
from app import right_rail_gate_codec as gate
from app import right_rail_gate_mark as marks
from app import right_rail_gate_producer as producer
from app import right_rail_ruleset_codec as rulecodec


class GateDecideError(RuntimeError):
    """``rules_refused``: any other refusal, timeout included, or the worker dying on every attempt; ``rules_missing`` /
    ``rules_pin_mismatch`` / ``rules_pin_missing``: the program is not there, is not the committed pin, or no pin is committed.
    ``request_malformed`` (a request that does not encode, or two for one payment) and ``foreign_tenant`` (a request of
    another tenant than the shard's) are refused and never retried.  The request checks and the program
    checks write nothing.  ``tenant_floor`` (args[1] names the file): the tenant's floor file is missing, empty, cannot be
    written, or is damaged (a whole record that fails its check; a v1-domain or another tenant's file too): a person
    replaces it, and no answer is returned, so nothing is sealed.  ``tenant_shards``: a tenant authority opened with no
    shards, two with one number, or a set other than the one the floor file names, or a decide or commit on a shard it was
    not opened with.  ``authority_unchained`` (args[1] the shard number): that shard's newest sealed row cannot be trusted;
    that shard alone is refused.  ``commit``: ``stale_answer``, a batch was sealed
    or another decide ran since the answer (nothing sealed; decide again); ``grant_floor_risen``, another shard raised or
    sealed the tenant's floors above the answer's (nothing sealed; decide again); ``input_commitment``,
    a request of another program (nothing sealed); ``hold_answer``, a HOLD answer (nothing to seal).  A stored frame
    (``decide``): ``pending_bad:<file>``, the file cannot be read, does not parse, or is not this shard's, this number's, this
    owner's, or, sent again and still sealable, not this program's; ``pending_empty:<file>``, it holds no request; ``pending_refused:<file>:<cause>``, sent again it
    cannot be sealed for a cause in the data (``rules_refused``, ``foreign_tenant``, ``chain_mismatch``, ``keyset_pin``,
    ``empty_batch``, ``input_commitment``).  Each leaves the file where it is, and while its cause stands nothing else is decided on the shard."""


LOG = logging.getLogger(__name__)
ATTEMPTS = 3  # launches one batch may use before it is refused
PROVENANCE = Path(__file__).resolve().parents[1] / "artifacts" / "gate-verify" / "PROVENANCE.txt"


def committed_pin() -> bytes:
    """The SHA-256 the decision program must have: the ``pin gate_engine`` line of PROVENANCE.txt.  No line, no program."""
    for row in PROVENANCE.read_text("utf-8").splitlines():
        words = row.split()
        if len(words) == 3 and words[:2] == ["pin", "gate_engine"] and _HEX64.match(words[2]):
            return bytes.fromhex(words[2])
    raise GateDecideError("rules_pin_missing")


class WorkerDied(GateDecideError):
    """``rules_refused`` because the worker process died or ran past its deadline with no cause the batch explains (killed
    from outside, a broken pipe, a lost process, a stalled machine): a machine fault, the only case ``decide`` sends a batch
    again, to a fresh launch of the same program, and it logs the reason.  A wrong or missing program is a plain
    ``GateDecideError``; a fault of the batch is a ``DataFault``.  Neither is retried."""


class MachineFault(GateDecideError):
    """A machine cause that outlasted its bounded retries, refused once under that cause (args[0]; args[1] names the file
    where the cause gave one): the worker died on each of the ``ATTEMPTS`` launches (``rules_refused``), or died on some and
    the last launch ran past its deadline (``timeout``); the floor file's lock stayed taken or could not be opened (``tenant_floor_busy``); the floor file could not be written
    (``tenant_floor_unwritable``); the
    store's database failed the reservation on each try (``store_unavailable``); the program or the floor file could not be
    read on any try (``rules_unreadable``; ``tenant_floor_unreadable``, args[1] the file); a stored frame that can never seal
    could not be removed (``pending_not_removed``, args[1] the file).  The one ``action``: decide the same
    batch again later."""
    action = "retry_later"


class DataFault(GateDecideError):
    """A batch the pinned program fails the same way on every launch, refused once under its cause (``str``): more requests
    than one checkpoint holds (``batch_too_large``), a frame or answer past its cap (``worker_frame_cap``,
    ``worker_response_cap``), a panic, or out of memory with the Job's peak within a tenth of its cap (``worker_stderr``),
    or every launch past its deadline for a batch of more than one request (``timeout``).  Every cause takes the one ``action``: decide the batch
    again in smaller parts, each request under its own payment id."""
    action = "split_batch"


def _reread(read, cause: str, *args):
    """``read()``, tried again after a short wait while it raises an OSError other than a missing file (a scanner's sharing
    violation, a busy disk): at most ``ATTEMPTS`` tries, then ``MachineFault(cause, *args)``.  A missing file is raised as is."""
    for tries in range(1, ATTEMPTS + 1):
        try:
            return read()
        except FileNotFoundError:
            raise
        except OSError as error:
            if tries == ATTEMPTS:
                raise MachineFault(cause, *args) from error
            time.sleep(0.1 * tries)


# the same frame fails the same way on any launch
_DATA_FAULTS = frozenset(("worker_frame_cap", "worker_response_cap", "worker_stderr"))


class RulesWorker:
    """A long-lived ``gate_engine`` (its process start and arena are paid once, not per batch): u32 BE frames; tag 4
    then the binary request of one batch on the shard's store, answered with the binary answer.  The worker is started on one
    store and holds no history in memory, so it is never recycled.  Any failure closes the worker and raises ``WorkerDied``; the
    next call starts a fresh one (``gen`` counts the launches, ``lost`` the workers that were lost).  The program must hash to the
    pin committed in PROVENANCE.txt; there is no other pin."""

    TIMEOUT_SECONDS = 600.0
    JOB_MEMORY_CAP_BYTES = 1_000_000_000

    def __init__(self, exe: Path) -> None:
        self.pin = committed_pin()  # a program is launched only if its bytes hash to this; never to what is found
        self.exe, self._worker, self._workspace, self._lock, self.gen, self.lost = exe, None, None, threading.RLock(), 0, 0
        self._store = None  # (directory, shard) the running worker serves
        self.release = b""  # SHA3-512 of the bytes the running worker was launched from (the leaf's engine release)

    def _program(self) -> bytes:
        try:
            exe = _reread(self.exe.read_bytes, "rules_unreadable")
        except FileNotFoundError as error:
            raise GateDecideError("rules_missing") from error
        if hashlib.sha256(exe).digest() != self.pin:
            raise GateDecideError("rules_pin_mismatch")
        return exe

    def check(self) -> None:
        """Refuse before anything is reserved if a launch would be refused: a running worker was checked when it launched."""
        with self._lock:
            if self._worker is None or not self._worker.alive:
                self._program()

    def close(self) -> None:
        with self._lock:
            self._close()

    def _close(self) -> None:
        worker, workspace, self._worker, self._workspace = self._worker, self._workspace, None, None
        try:
            if worker is not None:
                worker.close()
        except process.VerifierProcessError as error:  # a child that will not die: logged, the batch still ends with its own typed cause
            LOG.warning("gate rules worker could not be stopped (%s)", error)
        finally:
            if workspace is not None:
                shutil.rmtree(workspace, ignore_errors=True)

    def launched_release(self) -> bytes:
        """The release of the running worker; before the first launch, of the pinned bytes it will launch from."""
        with self._lock:
            return self.release or gate.sha3_512(self._program())

    def run_frame(self, directory: str, shard: int, data: bytes) -> bytes:
        """A tag 4 frame on the store of ``shard`` in ``directory``: the answer bytes.  The engine is started on one store, so a
        call for another one starts another engine."""
        with self._lock:
            if self._worker is not None and (self._store != (directory, shard) or not self._worker.alive):
                if self._store == (directory, shard):
                    LOG.warning("gate rules worker dead between batches: relaunching (launch %d)", self.gen + 1)
                    self.lost += 1
                self._close()
            exe = self._program() if self._worker is None else b""
            try:
                if self._worker is None:
                    self._workspace = Path(tempfile.mkdtemp(prefix="rr-rules-"))
                    self._worker = process.launch_contained_worker(
                        self.exe, workspace=self._workspace, job_memory_cap_bytes=self.JOB_MEMORY_CAP_BYTES,
                        expected_executable_size_bytes=len(exe), expected_executable_sha256=self.pin,
                        arguments=(directory, str(shard)))
                    self.gen, self.release, self._store = self.gen + 1, gate.sha3_512(exe), (directory, shard)
                return self._worker.exchange(b"\x04" + data, response_cap_bytes=process.WORKER_MAX_FRAME_BYTES,
                                             timeout_seconds=self.TIMEOUT_SECONDS)
            except Exception as error:  # a timeout or an OS error is a refusal too, never an untyped escape
                cause = str(error)
                said = self._worker.diagnostic() if cause == "worker_exchange" and self._worker is not None else b""
                if said and (b"out of memory" not in said  # it panicked before it died: the same frame panics again
                             or (self._worker.peak_job_memory() or 0) >= self.JOB_MEMORY_CAP_BYTES * 9 // 10):  # out of memory at its cap
                    cause = "worker_stderr"  # out of memory well below the cap is the machine's, and is retried
                self._close()
                if cause in _DATA_FAULTS:
                    raise DataFault(cause) from error
                self.lost += 1
                raise WorkerDied("rules_refused") from error


class Keys(NamedTuple):
    """The key-set evidence of a frame: the signed key set, and its signed steps as (day, document)."""
    keyset: bytes
    steps: tuple[tuple[int, bytes], ...] = ()


_LOCK_TRIES = 6  # a lock on the floor file is waited for at most about a minute (6 tries of LK_LOCK's 10 s), then ``tenant_floor``


def _floor_domain(tenant: str, version: int = 3) -> bytes:
    """The floor record's domain: it names the tenant, so one tenant's file never reads as another's."""
    return b"RR/GATE/TENANT-FLOOR/v%d\x00" % version + len(tenant.encode()).to_bytes(2, "big") + tenant.encode()


_floors_of = flatchain.floors_of


def _floors(body: bytes) -> flatchain.Floors:
    """The floors of a v3 floor record body."""
    return int.from_bytes(body[:8], "big"), int.from_bytes(body[8:12], "big"), int.from_bytes(body[44:48], "big"), body[48:]
_V2_BODY = 8 + 4 + 32  # a v2 floor record: serial u64, epoch u32, a digest of the tenant's shard numbers
_BODY = _V2_BODY + 4 + flatchain.HEAD  # v3 adds the rule-set version u32 and digest
_KEY = _V2_BODY + 4  # serial, epoch, shard-set digest (fixed per file), rule-set version: each only rises
_SIZE = _BODY + marks.CHECK


def _floor_record(floors: flatchain.Floors, ids: bytes) -> bytes:
    return floors[0].to_bytes(8, "big") + floors[1].to_bytes(4, "big") + ids + floors[2].to_bytes(4, "big") + floors[3]


def _top(floors) -> tuple[int, int, int, bytes | None]:
    """The highest grant serial, key-set epoch and rule-set version among ``floors`` (and none), with the one rule-set
    digest at that version, or None when two differ there (a fork: no digest is chosen)."""
    floors = [_floors_of(None), *floors]
    rsv = max(f[2] for f in floors)
    rs = {f[3] for f in floors if f[2] == rsv}
    return max(f[0] for f in floors), max(f[1] for f in floors), rsv, rs.pop() if len(rs) == 1 else None


def _load(path: Path, tenant: str) -> tuple[bytes, int, bool]:
    """The floor file's newest record body as v3 (serial u64, epoch u32, shard-set digest, rule-set version u32 and
    digest), the byte length up to it, and whether the file is still v2 (its record read as rule-set version 0 and the
    zero digest: v2 predates rule sets).  A partial or all-zero last record is torn and reads as the previous one; a
    whole last record that fails its check, a missing or empty file, is ``tenant_floor`` naming the file; one that still
    cannot be read after ``_reread``'s tries is ``MachineFault`` ``tenant_floor_unreadable``."""
    def read(version: int, body_len: int, key_len: int) -> tuple[bytes | None, int]:
        body, end, torn = marks.read(path, _floor_domain(tenant, version), body_len, key_len)
        size = body_len + marks.CHECK
        if torn and path.stat().st_size % size == 0:  # torn means cut short or zero-filled: a whole record that fails its check is damage
            with open(path, "rb") as handle:
                handle.seek(-size, os.SEEK_END)
                if any(handle.read(size)):
                    raise marks.MarkCorrupt
        return body, end

    def either() -> tuple[bytes | None, int, bool]:
        try:
            body, end = read(3, _BODY, _KEY)
        except marks.MarkCorrupt:
            body, end = None, 0
        if body is not None:
            return body, end, False
        try:  # a file is all v2 or all v3 (the first v3 write replaces a v2 file whole), and no record verifies under both
            old, end = read(2, _V2_BODY, 12)
        except marks.MarkCorrupt:
            old = None
        return (None, 0, False) if old is None else (old + bytes(4) + flatchain.ZERO, end, True)
    try:
        body, end, v2 = _reread(either, "tenant_floor_unreadable", str(path))
    except (marks.MarkCorrupt, OSError) as error:
        raise GateDecideError("tenant_floor", str(path)) from error
    if body is None:  # provisioning wrote a record: none is a file lost or cut to nothing
        raise GateDecideError("tenant_floor", str(path))
    return body, end, v2


def _replace(path: Path, body: bytes, domain: bytes) -> None:
    """Replace the v2 floor file ``path`` with a v3 file of the one record ``body``: written and synced beside it, then
    renamed over it durably, so a crash leaves the v2 file or the v3 one, never part of either, and a raise that returned
    is on disk."""
    new = path.with_name(path.name + ".v3")
    marks.append(new, domain, 0, body)
    _rename_durably(new, path)


def _shards_of(tenant: str, shards: Sequence[producer.ShardProducer]) -> tuple[producer.ShardProducer, ...]:
    """Every shard of the tenant, open: none, or two with one shard number, is ``tenant_shards``; another tenant's is
    ``foreign_tenant``."""
    shards = tuple(shards)
    if not shards or len({s.shard for s in shards}) != len(shards):
        raise GateDecideError("tenant_shards")
    if any(s.tenant != tenant for s in shards):
        raise GateDecideError("foreign_tenant")
    return shards


def _ids(shards: Sequence[producer.ShardProducer]) -> bytes:
    """A digest of the tenant's shard numbers: what the floor record names as the tenant's whole shard set."""
    return hashlib.sha3_256(b"".join(n.to_bytes(4, "big") for n in sorted(s.shard for s in shards))).digest()


def _scan(shards: Sequence[producer.ShardProducer], seen: dict, fault: dict) -> list[flatchain.Floors]:
    """The floors each of ``shards`` has sealed.  ``seen`` keeps each shard's last checked floors (sealed rows only
    append, so they stay true); a closed shard answers from it, and a shard whose newest sealed row is unchained or does
    not decode is put in ``fault`` by number (its cached floors still count)."""
    for s in shards:
        try:
            seen[s.shard] = _floors_of(s.authority())
            fault.pop(s.shard, None)
        except producer.GateProducerError as error:
            if str(error) != "producer_closed":
                fault[s.shard] = str(error)
    return list(seen.values())


@contextlib.contextmanager
def _floor_lock(path: Path):
    """The exclusive lock on the floor file ``path`` (its ``.lock``), held until the block ends: ``_LOCK_TRIES`` tries, then
    ``tenant_floor_busy``."""
    try:  # a transient error (a scanner's sharing violation) is waited out; a missing directory is for a person
        fd = _reread(lambda: os.open(f"{path}.lock", os.O_RDWR | os.O_CREAT | os.O_BINARY), "tenant_floor_busy", str(path))
    except OSError as error:
        raise GateDecideError("tenant_floor", str(path)) from error
    try:
        for attempt in range(_LOCK_TRIES):  # each try waits about 10 s (LK_LOCK): a commit holds it across its floor check and reservation
            try:
                msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
                break
            except OSError as error:
                if attempt == _LOCK_TRIES - 1:
                    raise MachineFault("tenant_floor_busy", str(path)) from error
        try:
            yield
        finally:
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
    finally:
        os.close(fd)


def _record_file(path: Path) -> bytes:
    """A rule-set file's bytes, read to one byte past the largest record (a longer file does not decode)."""
    with open(path, "rb") as f:
        return f.read(rulecodec.MAX_RECORD + 1)


_SET_ASIDE = {"not_a_file": "is not a file", "unreadable": "cannot be read", "does_not_decode": "does not decode as a record",
              "other_tenant": "is another tenant's record"}  # why a rule-set entry is not taken (``TenantAuthority.set_aside``)
_BAD = ("unreadable", "does_not_decode")  # content unknown: it might be a record, so the tenant HOLDs ``ruleset_file_bad``


class TenantAuthority:
    """What every shard of one tenant decides under.  ``pin``: the key-set genesis pin, read from the tenant's
    ``GATE_KEYSET_PIN`` deployment slot (unauthored: 64 zero bytes, which no key set hashes to, so every frame's key set is
    refused and every row HOLDs).  The floors: the highest grant serial, key-set epoch and rule-set version any shard of the
    tenant has admitted, with the rule-set digest at that version, kept in one checked mark file (``right_rail_gate_mark``,
    its domain naming the tenant) at ``floor_path`` as serial u64, epoch u32, a digest of the tenant's shard numbers, then
    the rule-set version u32 and digest (``RR/GATE/TENANT-FLOOR/v3``).  A v2 file (no rule-set fields: written before rule
    sets, so none was admitted) reads as version 0 and the zero digest, and its first write replaces it whole with a v3
    file; nothing writes v2.  ``provision`` creates the file when the tenant is set
    up; after that a missing, empty or corrupt file (a v1-domain file too, or a whole last record that fails its
    check) is ``tenant_floor`` naming the file (args[1]), and nothing is decided or sealed until a person replaces it (the
    authority still opens and logs it, so an answer already sealed is served again); only a
    partial or all-zero last record is torn and reads as the previous one.  ``shards`` must be exactly the tenant's shards
    (``tenant_shards`` otherwise, also for a decide or commit on another shard number), open when the authority is built.
    A tenant's shards run in one process and one thread (a store is opened exclusively by one producer, on its creating
    thread), so the authority reads each producer directly.  Every read (open, decide, commit) takes, for each floor, the
    highest of the file and every shard's newest sealed authority record, and writes the file up to it, so a file rolled back
    or copied from an older backup, before or while an answer is held, cannot lower what is sent or checked here.  A shard's
    record counts only when its batch steps the signed chain; a closed shard counts by the floors last checked (sealed rows
    only append), and a shard whose newest row is unchained or does not decode is refused by itself (``authority_unchained``, args[1] its number) while the others go on.  No check outside the tests replays the whole chain.
    Every frame sends all four (``floor N``, ``kfloor E``, ``rsv``, ``rs``), so a grant serial below one admitted on any
    shard is refused on every shard (``grant_superseded``), so is a key set older than one admitted on any shard
    (``grant_stale_keyset``), and a shard behind the rule-set version is held (``grant_ruleset_stale``).  Two records at
    the highest rule-set version with different digests are a fork: no digest is chosen, the file keeps its own, and every
    frame of the tenant HOLDs ``ruleset_fork`` until a person resolves it.  The file
    only rises, under an exclusive lock on ``floor_path`` + ``.lock`` (one writer at a time; ``tenant_floor_busy`` if the lock
    stays taken).

    ``rulesets``: signed rule-set records given when the authority is built.  ``ruleset_folder``: the deployment's folder
    of the tenant's signed rule-set records, one record per file, any file names, each placed by rename so that no file
    is ever read half written; it is read when the authority is built and again before every frame (``refresh``), so a
    record placed there, or removed, counts from the next frame.  Each entry is read by itself, every time, and named in
    ``set_aside`` (logged once) when it is not taken.  One that is not a file, or is another tenant's record, is
    skipped.  An entry that cannot be looked at, or a file that cannot be read or does not decode as a whole record
    (torn, empty or junk), might be a record
    that changes what is decided, so every frame of the tenant HOLDs ``ruleset_file_bad`` until it is fixed or removed;
    nothing read earlier stands in for it, so a host restarted and a replay of the folder give the same answer.  A
    configured folder that is not there or cannot be listed is never read as empty, which would lift the holds its
    records cause: every frame of the tenant HOLDs ``ruleset_folder_missing`` (logged once) until it is back.  With no
    folder configured (None; an empty path, or one naming the current directory, is refused) there are no folder records.  The records are the given ones
    and the folder's, kept by body digest.  Copies of one digest differ only in their
    signatures, which are checked by the engine, not here, and are compared by their signers' key ids: the copy whose
    signers include every other copy's is kept, and of copies with the same signers (signatures differ byte for byte
    when signing is randomized) the lowest bytes, whatever the order given, with a warning that a damaged copy
    may be why that rule set is refused.  When the signers do not nest, that rule set
    alone is ``ambiguous`` (logged): its lowest copy is kept for shards that already hold it, which only reload it and
    check no signature, and a frame of a shard behind the tenant, which would admit it, HOLDs ``ruleset_copies``; other
    rule sets and the authority go on.  Every frame
    presents the record whose digest the floors carry, the same bytes every time, so a shard holding that rule set, or
    behind the tenant, can run it (conformance/RULESET_V1.md section 9); the engine checks the record itself.  With none
    held for that digest a frame presents nothing, and the engine holds the frames of shards that need one.  While no
    shard of the tenant holds a rule set, a frame presents the tenant's one version-1 record, if it holds one, which the
    shard admits as its first (``present``).  A given record that does not decode, or is another tenant's, is logged
    and never presented."""

    def __init__(self, deployment: slots.Slots, tenant: str, floor_path: Path, shards: Sequence[producer.ShardProducer],
                 rulesets: Sequence[bytes] = (), ruleset_folder: Path | None = None) -> None:
        self.tenant, self.pin, self._path = tenant, bytes.fromhex(deployment.read("GATE_KEYSET_PIN", tenant)), Path(floor_path)
        self._domain, self._shards = _floor_domain(tenant), list(_shards_of(tenant, shards))
        self._ids, self._seen, self._fault = _ids(self._shards), {}, {}
        if ruleset_folder is not None and Path(ruleset_folder) == Path("."):  # Path("") and Path("./") are "." too
            raise ValueError("ruleset_folder: an empty path, or one naming the current directory, names no rule-set folder;"
                             " give the tenant's rule-set folder, or None")
        self._given, self._last, self._good = [], None, {}
        self._folder = None if ruleset_folder is None else Path(ruleset_folder)
        self.rulesets: dict[bytes, bytes] = {}  # body digest -> the copy presented
        self.versions: dict[bytes, int] = {}  # body digest -> its version
        self.ambiguous: set[bytes] = set()  # signers that do not nest: a shard that would admit it HOLDs ``ruleset_copies``
        self.set_aside: dict[str, str] = {}  # the folder's entry name -> why it is not taken (``_SET_ASIDE``)
        self.missing = False  # the folder is configured and cannot be listed: every frame HOLDs ``ruleset_folder_missing``
        for x in rulesets:
            try:
                got = self._parse(bytes(memoryview(x)))  # bytes-like only: never bytes(n) of a number
            except TypeError as error:
                got = repr(error)
            if type(got) is str:
                LOG.warning("tenant %s: a given rule-set record is ignored: %s", tenant, _SET_ASIDE.get(got, got))
            else:
                self._given.append(got)
        self.refresh()
        try:
            self.raise_floors(0, 0)
        except GateDecideError as error:  # the host still opens: sealed answers are served, every frame is refused until replaced
            if error.args[:1] != ("tenant_floor",):
                raise
            LOG.error("tenant %s: the floor file %s cannot be read; nothing is decided until a person replaces it", tenant,
                      self._path)

    def _parse(self, x: bytes) -> tuple[bytes, bytes, dict] | str:
        """(``x``, its body digest, the decoded record) for a record of this tenant; else why it is not taken."""
        try:
            d, rec = rulecodec.digest(x), rulecodec.decode(x)
        except Exception:  # anything that does not decode as a record: never presented
            return "does_not_decode"
        return (x, d, rec) if rec["tenant"] == self.tenant else "other_tenant"

    def refresh(self) -> None:
        """Read ``ruleset_folder`` again, each entry by itself; the records then held count from the next frame.  An
        entry that is not taken is set aside by name (``set_aside``) and logged once.  A folder that cannot be listed
        sets ``missing``, logged once."""
        good: dict[str, tuple] = {}
        if self._folder is not None:
            try:
                paths = sorted(self._folder.iterdir())
            except OSError as error:
                if not self.missing:
                    LOG.error("tenant %s: the rule-set folder %s cannot be listed (%r); every frame of the tenant is held"
                              " (ruleset_folder_missing) until it is restored", self.tenant, self._folder, error)
                self.missing = True
                return
            self.missing, aside = False, {}
            for path in paths:
                kept = self._good.get(path.name)
                try:
                    x = _record_file(path) if path.is_file() else None
                except FileNotFoundError:
                    continue  # removed while the folder is read
                except OSError:  # cannot be looked at or read (a denied stat too): it might hold a record
                    got = "unreadable"
                else:
                    got = "not_a_file" if x is None else kept if kept and kept[0] == x else self._parse(x)
                if type(got) is not str:
                    good[path.name] = got  # kept only to skip decoding the same bytes again
                    continue
                aside[path.name] = got
                if self.set_aside.get(path.name) != got:
                    LOG.warning("tenant %s: rule-set entry %s %s; %s", self.tenant, path.name, _SET_ASIDE[got],
                                "every frame of the tenant is held (ruleset_file_bad) until it is fixed or removed"
                                if got in _BAD else "it is skipped")
            self.set_aside = aside
        self._good = good
        records = self._given + list(good.values())
        if frozenset(x for x, _, _ in records) != self._last:
            self._last = frozenset(x for x, _, _ in records)
            self._take(records)

    def _take(self, records: list[tuple[bytes, bytes, dict]]) -> None:
        copies: dict[bytes, dict[bytes, frozenset]] = {}
        self.versions = {}
        for x, d, rec in records:
            copies.setdefault(d, {})[x] = frozenset(key for key, _ in rec["sigs"])
            self.versions[d] = rec["version"]
        self.rulesets, self.ambiguous = {}, set()
        for d, xs in copies.items():
            top = [x for x, signers in xs.items() if all(other <= signers for other in xs.values())]
            self.rulesets[d] = min(top or xs)  # the copies at the top have the same signers
            if len(top) > 1:
                LOG.warning("tenant %s: rule set %s: copies with the same signers differ in their bytes; the lowest is"
                            " presented. If this rule set is refused, a damaged copy may be the cause: keep one copy",
                            self.tenant, d.hex())
            if not top:
                self.ambiguous.add(d)
                LOG.warning("tenant %s: rule set %s: two different signed copies of the same rule set were supplied; keep only"
                            " the copy with the full set of signatures (ruleset_copies)", self.tenant, d.hex())

    def present(self, floors: flatchain.Floors) -> tuple[bytes | None, str | None]:
        """(the digest of the rule set a frame under ``floors`` presents, or None; the host's hold, or None).  The
        floors' rule set while a shard holds one; while none does, the tenant's one version-1 record, its first
        (conformance/RULESET_V1.md section 9).  Held: ``ruleset_newer``, a record of a version above the one in force
        (and above 1), which the gate cannot run; ``ruleset_choice``, no rule set in force and two version-1 records.
        A version-1 record of another digest once a rule set is in force is never presented.  First, a configured
        folder that cannot be listed holds every frame ``ruleset_folder_missing`` (read as empty, it would lift those
        holds), and a file of it that cannot be read or does not decode ``ruleset_file_bad``."""
        if self.missing:
            return None, "ruleset_folder_missing"
        if any(v in _BAD for v in self.set_aside.values()):
            return None, "ruleset_file_bad"
        if any(v > max(floors[2], 1) for v in self.versions.values()):
            return None, "ruleset_newer"
        if floors[2]:
            return floors[3], None
        first = [d for d, v in self.versions.items() if v == 1]
        if len(first) > 1:
            return None, "ruleset_choice"
        return (first or [None])[0], None

    def member(self, prod: producer.ShardProducer) -> None:
        """Refuse (``tenant_shards``) a shard number the authority was not opened with; a reopened producer of a shard takes
        the place of the one it replaces."""
        for at, kept in enumerate(self._shards):
            if kept.shard == prod.shard:
                self._shards[at] = prod
                return
        raise GateDecideError("tenant_shards")

    def seen(self, prod: producer.ShardProducer) -> flatchain.Floors:
        """The floors shard ``prod`` has sealed, as of the last read (none read: no rule set)."""
        return self._seen.get(prod.shard, (0, 0, 0, flatchain.ZERO))

    def refuse_faulty(self, prod: producer.ShardProducer) -> None:
        """Refuse the shard ``prod`` itself if its newest sealed row is unchained or does not decode (as of the last read)."""
        if prod.shard in self._fault:
            raise GateDecideError(self._fault[prod.shard], prod.shard)

    @staticmethod
    def provision(floor_path: Path, tenant: str, shards: Sequence[producer.ShardProducer]) -> None:
        """Create the tenant's floor file once, when the tenant is set up, at the highest floors any of ``shards`` (every
        shard of the tenant, open) has sealed, under the file's lock; a file as long as a record or longer is never replaced
        (``tenant_floor``, even if its record fails its check: it may be another tenant's), and so is a shorter one that is not
        the start of a record naming these shards (an older 44-byte format), or a whole v2 record; an empty one, or the start
        of such a record (a crash inside an earlier ``provision``), is completed.  Shards forked at their highest rule-set
        version give the file none (version 0, the zero digest): the fork is found again at every read.  A tenant that gains
        or loses a shard is provisioned anew: the new file (at another path) is raised with ``raise_floors(*old)``, ``old``
        the old file's ``floors_in``, to the highest of the old file and every shard's sealed floors, so no reservation the
        old file covered falls below it."""
        path, shards, domain = Path(floor_path), _shards_of(tenant, shards), _floor_domain(tenant)
        seen, fault = {}, {}
        floors = _top(_scan(shards, seen, fault))
        if floors[3] is None:
            floors = (*floors[:2], 0, flatchain.ZERO)
        if fault or len(seen) != len(shards):  # a shard that cannot be read cannot give its floors
            n = next(iter(fault), next(s.shard for s in shards if s.shard not in seen))
            raise GateDecideError(fault.get(n, "producer_closed"), n)
        with _floor_lock(path):
            try:
                try:
                    with open(path, "xb"):
                        pass
                except FileExistsError:
                    old, ids = path.read_bytes(), _ids(shards)
                    if (len(old) >= _SIZE or (any(old) and old[12:_V2_BODY] != ids[:max(len(old) - 12, 0)])
                            or marks.read(path, _floor_domain(tenant, 2), _V2_BODY, 12)[0] is not None):
                        raise  # not empty and not the start of a v3 record of this tenant (a whole one, a v2 one, another tenant's, a shorter older format): left alone
                marks.append(path, domain, 0, _floor_record(floors, _ids(shards)))
            except (OSError, marks.MarkCorrupt) as error:
                raise GateDecideError("tenant_floor", str(path)) from error

    @staticmethod
    def floors_in(floor_path: Path, tenant: str) -> flatchain.Floors:
        """The (grant serial, key-set epoch, rule-set version, rule-set digest) floors in the tenant's floor file alone,
        with no shard open: what a shard producer checks its unsigned reservation against when it reopens first after a
        restart."""
        return _floors(_load(Path(floor_path), tenant)[0])

    def _read(self) -> tuple[flatchain.Floors, int, bool]:
        body, end, v2 = _load(self._path, self.tenant)
        if body[12:_V2_BODY] != self._ids:
            raise GateDecideError("tenant_shards")  # the file names another set of shards than this authority was given
        return _floors(body), end, v2

    def _locked(self):
        return _floor_lock(self._path)

    def _raise(self, serial: int, epoch: int, rsv: int = 0, rs: bytes = flatchain.ZERO) -> tuple[int, int, int, bytes | None]:
        """Under the lock: each floor up to the highest of the file, every shard's sealed record and the given value, and
        the rule-set digest at the highest version (None for a fork, when the file keeps its own rule-set fields), written
        if any rose.  Each only rises, so the record's key (serial, epoch, shard-set digest, rule-set version) does; a v2
        file is replaced whole by its first write."""
        now, end, v2 = self._read()
        up = _top([now, (serial, epoch, rsv, rs), *_scan(self._shards, self._seen, self._fault)])
        kept = up if up[3] is not None else (*up[:2], *now[2:])
        if v2 or kept != now:
            body = _floor_record(kept, self._ids)
            write = (lambda: _replace(self._path, body, self._domain)) if v2 else (lambda: marks.append(self._path, self._domain, end, body))
            try:  # the append cuts to ``end`` first, so a try after a torn write is the same write
                _reread(write, "tenant_floor_unwritable", str(self._path))
            except OSError as error:
                raise GateDecideError("tenant_floor", str(self._path)) from error
        return up

    def raise_floors(self, serial: int, epoch: int, rsv: int = 0, rs: bytes = flatchain.ZERO) -> tuple[int, int, int, bytes | None]:
        """Moves each floor up to the given value, and to every shard's sealed record (a lower one leaves it), and returns
        the four after (the digest None for a fork); ``raise_floors(0, 0)`` reads them."""
        with self._locked():
            return self._raise(serial, epoch, rsv, rs)


class Pay(NamedTuple):
    """One token's leaf fields: the request's own, the engine's outcome, reasons, authority, grant and bypass ids,
    INPUT/v7, which the engine and the host each compute, and an ANSWERED payment's earlier list."""
    outcome: str
    reasons: tuple[str, ...]
    tenant: str
    program: str
    flow: str
    payment_id: str
    member_key: bytes
    payee_ref: str
    cents: int
    period: str
    lines_root: bytes
    input: bytes
    authority: str  # TRANSFER, HOLD or OBSERVE: what the admitted grant lets this payment do
    grant_id: bytes  # the admitted grant's id
    bypass: bytes  # the admitted bypass's id (zero when none released this payment)
    # ANSWERED only: (line id, earlier program, earlier payment id, earlier line id) per repeated line, by line id
    earlier: tuple[tuple[str, str, str, str], ...] = ()


class Rec(NamedTuple):
    """One line's 16-byte record: its position among the covered requests' lines, the outcome, the rule that decided it (0 decided,
    1 released, 2 unresolved, 3 wide, 4 sibling, 5 bypassed), its reason names and the counterpart's store position."""
    index: int
    outcome: str
    rule: int
    reasons: tuple[str, ...]
    chunk: int
    row: int


class Answer(NamedTuple):
    lines: tuple[str, ...]  # a whole-answer HOLD: one ``<payment> HOLD <why>`` row per payment; else empty
    digest: bytes  # the CHAIN/v1 head after the batch: the next header's ``state_digest``
    adds: bytes  # the chain step body: the authority record after the batch (RULES_FLAT_AUTH), then its rows (RULES_ADDS)
    seen: bytes | None  # the shard's last sealed checkpoint digest when the batch was decided
    flat: Path | None = None  # the index directory the batch was decided on
    pre: bytes = b""  # the signed CHAIN/v1 head the batch was decided from (the genesis at the shard's first batch)
    batches: int = 0  # the batch count after it
    attempts: int = 0  # 1 + the workers this batch lost and relaunched, one lost between batches included (1: decided by the worker it found)
    pays: tuple[Pay, ...] = ()  # one ``Pay`` per token, copied from the engine's leaves
    release: bytes = b""  # the deciding worker's SHA3-512 (the leaf's rule version and engine release)
    frame: bytes = b""  # the exact frame the batch was decided on (the producer stores it as the batch's record)
    recs: tuple[Rec, ...] = ()  # one record per line of the covered requests
    owners: tuple[tuple[str, int], ...] = ()  # for each covered line by position (a record's index), (payment id, the line's position in its request)
    retry: bytes = b""  # set on a stored batch sent again by another request: the key its requester's exact retry fetches it by
    # an exact retry of such a batch, sealed: its signed checkpoint, tokens and per token its earlier list (empty unless ANSWERED), nothing else set
    sealed: tuple[bytes, tuple[bytes, ...], tuple[tuple[tuple[str, str, str, str], ...], ...]] | None = None
    worker: "RulesWorker | None" = None  # the worker that decided it: reopened to void the batch if its commit is refused for a risen floor


def _rm(path: Path) -> None:
    for attempt in range(5):  # a just-closed worker or a virus scan may still hold a file for a moment
        try:
            return shutil.rmtree(path) if path.exists() else None
        except OSError as error:
            if attempt == 4:
                raise GateDecideError("flat_cleanup") from error
            time.sleep(0.3)


def _hold(requests: Sequence, reason: str) -> Answer:
    return Answer(tuple(f"{r.payment_id} HOLD {reason}" for r in requests), b"", b"", None)


_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
WORDS = ("OK", "MAGIC", "LENGTH", "DIGEST", "RECORD", "NOT_NEXT", "CONFLICT", "HEAD", "SHARD", "LOCK", "FILES", "IMAGE", "REPLAY",
         "IO", "CORRUPT", "INIT", "KILL", "NUMBER", "FULL", "TREE", "FRAME", "PIN")
OUTCOMES = ("ALLOW", "HOLD", "HUMAN_REVIEW", "ANSWERED")
# Each rule reason's bit in an answer (Lean ``Reason.idx``): a number never moves when a reason is added.
REASON_IDX = {"ALREADY_DECIDED": 0, "CAP_MEMBER_MONTH_DUPLICATE": 1, "COLLIDES_WITH_UNRESOLVED_NEAR": 2,
              "DUPLICATE_OF_UNRESOLVED": 3, "FFS_DUPLICATE_LINE": 4, "FFS_DUPLICATE_UNVERIFIED": 5, "FFS_NEAR_DUPLICATE": 6,
              "MEMBER_DECEASED": 7, "MEMBER_DECEASED_UNVERIFIED": 8, "MEMBER_NOT_ENROLLED": 9,
              "MEMBER_NOT_ENROLLED_UNVERIFIED": 10, "POSTING_CAP": 11, "PROVIDER_DECEASED": 12,
              "PROVIDER_DECEASED_UNVERIFIED": 13, "PROVIDER_EXCLUDED": 14, "PROVIDER_EXCLUDED_UNVERIFIED": 15,
              "SERVICE_DATE_FUTURE": 16, "SERVICE_DATE_INVALID": 17, "STALE_DMF": 18, "STALE_ENROLLMENT": 19,
              "STALE_EXCLUSION": 20, "STALE_PROVIDER_DEATH": 21, "STALE_RELEASED": 22, "STALE_UNRESOLVED": 23,
              "BENEFIT_LEVEL_MISSING": 24, "BENEFIT_LEVEL_MISSING_UNVERIFIED": 25, "PROGRAM_NOT_ELIGIBLE": 26,
              "PROGRAM_NOT_ELIGIBLE_UNVERIFIED": 27, "STALE_ELIGIBILITY": 28}
REASONS = tuple(sorted(REASON_IDX, key=str.encode))  # names in byte order, as reasons are listed
RULE_MASK = (1 << len(REASON_IDX)) - 1
LEAF_ONLY = {62: "UNENCODABLE_PAYMENT", 63: "SCOPE"}  # a leaf's own codes, never in a record
ANSWER_VERSION = 4  # conformance/FRAME_V1.md section 4 (3 is the fact answer's)
AUTHORITIES = ("OBSERVE", "HOLD", "TRANSFER")
FEED_WIDTHS = {"dmf": (33, 4), "pdeath": (21, 4), "excl": (21, 4, 4), "span": (33, 21, 4, 4)}  # conformance/FRAME_V1.md section 2


def _le(n: int, w: int) -> bytes:
    return n.to_bytes(w, "little")


def _blob(b: bytes) -> bytes:
    return _le(len(b), 4) + b


def feed(kind: str, asof: int, rows: Sequence[tuple[int, ...]]) -> tuple[bytes, bytes]:
    """A present feed of ``kind`` (a key of ``FEED_WIDTHS``): its 77-byte descriptor, pinned as Rules/Spec.lean's
    ``pinInput`` (identifiers at 129 bytes, rows sorted), and its rows at their frame widths.  A row that does not fit its
    fields: the feed counts as missing (state 2)."""
    widths = FEED_WIDTHS[kind]
    try:
        body = b"".join(_le(v, w) for r in rows for v, w in zip(r, widths, strict=True))
        canon = sorted(b"".join(v.to_bytes(129 if w > 4 else 4, "big") for v, w in zip(r, widths)) for r in rows)
    except (ValueError, OverflowError):
        return b"\x02" + bytes(76), b""
    head = b"".join(v.to_bytes(4, "big") for v in (list(FEED_WIDTHS).index(kind) + 1, asof, len(rows)))
    pin = hashlib.sha3_512(b"RR/GATE/SNAPSHOT/v1\x00" + head + b"".join(canon)).digest()
    return b"\x01" + _le(asof, 4) + _le(len(rows), 4) + _le(len(rows), 4) + pin, body


def request_frame(feeds: tuple[int, Sequence[tuple[bytes, bytes]]], shard: int, batch: int, asof: int, prev: bytes,
                  pin: bytes, floors: flatchain.Floors, keys: "Keys", grant: bytes, release: bytes, bypasses: Sequence[bytes],
                  bodies: Sequence[bytes], redo: Sequence[int] = (), rulesets: Sequence[bytes] = ()) -> bytes:
    """conformance/FRAME_V1.md section 2: the 82-byte header and the body.  ``pin`` is the tenant's key-set pin and
    ``floors`` its (grant serial, key-set epoch, rule-set version, rule-set digest) floors; ``feeds`` today and the four feeds in ``FEED_WIDTHS`` order, each
    a descriptor and its rows (``feed``; 77 zero bytes and none: absent); ``rulesets`` the signed rule-set records the
    batch presents (conformance/RULESET_V1.md section 9)."""
    today, read = feeds
    body = b"".join([_le(today, 4), _le(asof if batch == 1 else 0, 4), prev, _le(len(redo), 4), *(d for d, _ in read),
                     *(r for _, r in read), *(_le(p, 261) for p in redo),
                     pin, b"\x01" + _le(floors[0], 8), _le(floors[1], 4), _le(floors[2], 4), floors[3], _blob(grant), _blob(keys.keyset), _blob(release),
                     _le(len(keys.steps), 4), *(_le(d, 4) + _blob(doc) for d, doc in keys.steps),
                     _le(len(bypasses), 4), *map(_blob, bypasses), _le(len(rulesets), 4), *map(_blob, rulesets),
                     _le(len(bodies), 4), *map(_blob, bodies)])
    return b"RRDQ" + _le(2, 2) + _le(shard, 4) + _le(batch, 8) + hashlib.sha3_512(b"RR/GATE/FRAME2/v1\x00" + body).digest() + body


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data, self.at = data, 0

    def take(self, n: int) -> bytes:
        if self.at + n > len(self.data):
            raise GateDecideError("rules_refused")
        self.at += n
        return self.data[self.at - n:self.at]

    def num(self, n: int) -> int:
        return int.from_bytes(self.take(n), "little")

    def blob(self, w: int) -> bytes:
        return self.take(self.num(w))


def _names(mask: int, leaf: bool = False) -> tuple[str, ...]:
    """The reasons ``mask`` names, in byte order; with ``leaf`` also the leaf's own codes."""
    names = [n for n in REASONS if mask >> REASON_IDX[n] & 1]
    if leaf:
        names += [n for b, n in LEAF_ONLY.items() if mask >> b & 1]
    return tuple(sorted(names, key=str.encode))


def _requests(frame: bytes) -> tuple[bytes, list[bytes], bytes, list[bytes], list[bytes], flatchain.Floors]:
    """The CONTEXT/v1 digest of a request frame this module wrote (its body before the request count), its
    DECIDE-REQUEST/v2 bytes in order (conformance/FRAME_V1.md section 2), its signed grant, its signed bypasses, its
    signed rule-set records and the floors it asserts (grant serial, key-set epoch, rule-set version and digest)."""
    r = _Reader(frame)
    r.at = 82 + 4 + 4 + 64
    redo = r.num(4)
    descs = [r.take(77) for _ in range(4)]
    r.at += sum(int.from_bytes(d[9:13], "little") * w for d, w in zip(descs, map(sum, FEED_WIDTHS.values()))) + 261 * redo + 64 + 1
    asserted = (r.num(8), r.num(4), r.num(4), r.take(64))
    grant = r.blob(4)
    for _ in range(2):  # key set, release
        r.blob(4)
    for _ in range(r.num(4)):  # the key set's steps
        r.take(4)
        r.blob(4)
    bypasses = [r.blob(4) for _ in range(r.num(4))]
    rulesets = [r.blob(4) for _ in range(r.num(4))]
    context = hashlib.sha3_512(gate.CONTEXT + frame[82:r.at]).digest()
    bodies = [r.blob(4) for _ in range(r.num(4))]
    if r.at != len(frame):
        raise GateDecideError("rules_refused")
    return context, bodies, grant, bypasses, rulesets, asserted


def _approval(x: bytes) -> tuple[int, bytes, frozenset[tuple[bytes, bytes]]] | None:
    """(kind, id, the (program, payment) pairs it may release) of well-formed APPROVAL/v2 bytes ``x``, else None: the id is
    the SHA3-512 of the document before its signature block (Authority.lean ``encDoc``, ``admitBypassR``; CauseRelease.lean
    ``encDoc``, ``admit``).  A bypass names one payment, a cause record (kind 3) the payments it lists, a grant none.  The
    signatures and every other check are the engine's."""
    tag = b"RR/GATE/APPROVAL/v2\x00"
    if not x.startswith(tag):
        return None
    try:
        r = _Reader(x)
        r.at = len(tag)
        kind = r.num(1)
        r.take(64)  # the state digest
        ident = lambda: r.take(int.from_bytes(r.take(2), "big"))
        ident()  # tenant
        r.take(8)
        pays: frozenset[tuple[bytes, bytes]] = frozenset()
        if kind == 1:
            r.take(8)
            for _ in range(int.from_bytes(r.take(1), "big")):
                ident()
                r.take(6)
        elif kind == 2:
            pays = frozenset({(ident(), ident())})
            r.take(68)
        elif kind == 3:
            r.take(1)  # the cause
            program = ident()
            r.take(17)  # the flow mask, the service-date range and the total
            listed = set()
            for _ in range(int.from_bytes(r.take(2), "big")):
                listed.add((program, ident()))
                r.take(72)  # the request digest and the amount
            pays = frozenset(listed)
        else:
            return None
    except GateDecideError:
        return None
    return kind, hashlib.sha3_512(x[:r.at]).digest(), pays


def _pay(body: bytes, context: bytes, leaf: tuple[int, int, int, bytes, bytes, bytes], grant: bytes,
         byps: dict[bytes, frozenset[tuple[bytes, bytes]]]) -> Pay:
    """The token fields of one request: its own fields and lines root read from its bytes, the engine's outcome, reasons,
    authority and bypass id, and the answer's grant id.  The leaf's input must be the INPUT/v7 the host computes from the
    bytes it sent, and a bypass id must be that of a signed bypass or cause record the host sent that names this request's
    program and payment (``byps``: id to the (program, payment) pairs it names).  An earlier list names only this
    request's line ids."""
    outcome, mask, authority, bypass, body_e, inp = leaf
    r = _Reader(body)
    r.at = len(gate.DECIDE_REQUEST)
    big = lambda n: int.from_bytes(r.take(n), "big")
    text = lambda: r.take(big(2)).decode("ascii")
    try:
        tenant, program, flow = text(), text(), gate.FLOWS[big(1) - 1]
        text()  # the command key
        payment, member, payee, cents, period = text(), r.take(gate.MEMBER_KEY), text(), big(8), text()
        n = big(2)
        head = body[:r.at]
        lines = [r.take(big(2)) for _ in range(n)]
        tail = body[r.at:]
        earlier, end = gate.read_earlier(body_e) if body_e else ((), 0)
        if end != len(body_e):
            raise GateDecideError("rules_refused")
    except (UnicodeDecodeError, IndexError, gate.GateCodecError):
        raise GateDecideError("rules_refused") from None
    ids = {line[3:3 + int.from_bytes(line[1:3], "big")].decode("ascii", "replace") for line in lines}
    if any(e[0] not in ids for e in earlier):
        raise GateDecideError("rules_refused")
    if gate.payment_input(context, head, lines, tail) != inp:
        raise GateDecideError("rules_refused")
    if bypass != gate.ZERO_DIGEST and (program.encode(), payment.encode()) not in byps.get(bypass, frozenset()):
        raise GateDecideError("rules_refused")
    return Pay(OUTCOMES[outcome], _names(mask, leaf=True), tenant, program, flow, payment, member, payee, cents, period, gate.lines_root(lines),
               inp, AUTHORITIES[authority], grant, bypass, earlier)


def _answer(data: bytes, frame: bytes) -> tuple[str | None, list[Rec], bytes, bytes, bytes, list[Pay], list[bytes]]:
    """(hold reason or None, records, head, root, authority record, payments, added rows) of an answer to the request
    frame ``frame``.  Each
    payment's token fields are its request's, with the engine's leaf: outcome, reasons, authority, bypass id and the input,
    which must be the host's own."""
    r = _Reader(data)
    if r.take(4) != b"RRDA" or r.num(2) != ANSWER_VERSION:
        raise GateDecideError("rules_refused")
    status, _, _, count, echo = r.num(1), r.num(4), r.num(8), r.num(4), r.take(64)
    if echo != frame[18:82] or status >= len(WORDS):
        raise GateDecideError("rules_refused")
    if status:
        return "flat_" + WORDS[status].lower(), [], b"", b"", b"", [], []
    recs = []
    for _ in range(count):
        i, o, rule, mask, chunk, row = r.num(3), r.num(1), r.num(1), r.num(8), r.num(4), r.num(3)
        if o > 2 or rule > 5 or mask & ~RULE_MASK:
            raise GateDecideError("rules_refused")
        recs.append(Rec(i, OUTCOMES[o], rule, _names(mask), chunk, row))
    head, root, hold, grant, auth = r.take(64), r.take(64), r.take(16), r.take(64), r.take(flatchain.AUTH)
    if any(hold):
        return "grant_" + hold.rstrip(b"\x00").decode("ascii", "replace").lower(), [], head, root, auth, [], []
    for _ in range(r.num(4)):  # notes: the bypasses refused or releasing nothing
        r.blob(2)
    leaves = []
    for _ in range(r.num(4)):
        outcome, mask, authority, flag = r.num(1), r.num(8), r.num(1), r.num(1)
        bypass = r.take(64) if flag == 1 else gate.ZERO_DIGEST
        earlier = r.blob(2) if flag == 2 else b""
        if (outcome > 3 or authority > 2 or mask & ~(RULE_MASK | 3 << 62) or flag > 2 or (flag == 1 and bypass == gate.ZERO_DIGEST)
                or (flag == 2) != (outcome == 3) or (flag == 2 and not earlier)):
            raise GateDecideError("rules_refused")
        leaves.append((outcome, mask, authority, bypass, earlier, r.take(64)))
    adds = [r.blob(2) for _ in range(r.num(4))]
    if r.at != len(data):
        raise GateDecideError("rules_refused")
    context, bodies, signed, bypasses, _, _ = _requests(frame)
    if len(leaves) != len(bodies):  # one leaf per request, in the frame's order
        raise GateDecideError("rules_refused")
    if bodies:  # the leaves' grant id is that of the grant the host sent
        g = _approval(signed)
        if g is None or g[0] != 1 or g[1] != grant:
            raise GateDecideError("rules_refused")
    byps = {a[1]: a[2] for a in map(_approval, bypasses) if a is not None and a[0] in (2, 3)}
    return None, recs, head, root, auth, [_pay(b, context, x, grant, byps) for b, x in zip(bodies, leaves)], adds


def decide(feeds: tuple[int, Sequence[tuple[bytes, bytes]]], asof: int, prod: producer.ShardProducer,
           requests: Sequence[gate.DecideRequest], flat: Path, worker: RulesWorker, grant: bytes, keys: Keys,
           tenant: TenantAuthority, bypasses: Sequence[bytes] = (), seal: tuple[str, int] | None = None) -> Answer:
    """Decide ``requests`` against ``feeds`` (``request_frame``) on the shard's store ``flat`` (a directory), on ``worker``.
    A worker that dies mid-batch is relaunched (logged) and the same frame bytes sent again, at most ``ATTEMPTS`` launches per batch: the store takes the
    batch only at its seal, so a rerun is the same decision; after the last, ``MachineFault`` ``rules_refused``, or
    ``timeout`` when the last launch ran past its deadline.  When every launch ran past its deadline the batch itself is
    too slow: more than one request is ``DataFault`` ``timeout`` (split it); a single request HOLDs ``timeout``, for a
    person.  A fault of the batch itself (``DataFault``: more requests than one checkpoint holds, refused first, before
    anything is read or sent; or one the worker fails on every launch) is refused once, not sent again.  ``tenant`` gives
    the key-set pin, the floors the frame carries and the rule-set record it presents (``TenantAuthority``); once the head checks, they rise to the grant serial, key-set
    epoch and rule set the batch admitted, before the answer is returned; while the tenant's shards are forked at their
    highest rule-set version every line HOLDs ``ruleset_fork``, and while the tenant's records hold a version it cannot
    run, or two first versions, or while its configured rule-set folder cannot be listed, every line HOLDs
    ``ruleset_newer``, ``ruleset_choice`` or ``ruleset_folder_missing`` (``TenantAuthority.present``), a stored frame of
    the shard included: it waits, kept, until the cause is resolved.  While the tenant holds no rule set, a stored frame
    that presents a first record other than the one presented now (removed from the folder, or replaced by another) is
    never sent, whatever floors it asserts (its answer carries the grant's serial, not the frame's), so no shard takes up
    a record the folder no longer gives: every line HOLDs ``ruleset_changed`` and the frame waits, kept.  Putting that
    record back as the only first record makes the tenant take it up for good; once another shard takes up the record
    presented now, the stored frame is sent, its answer (the same version under another digest) HOLDs ``ruleset_fork``
    and its file is dropped, the floors keeping the tenant's record, and this call's frame is decided in the same call.  A
    frame stored presenting none takes up nothing and is
    decided as stored.  A signed head the engine's
    store does not match, a head the adapter cannot recompute, and a grant or key set the engine does not admit (``grant_<why>``)
    HOLD every line.  A bypass the engine does not admit is refused alone, and the rest of the batch is decided.  ``grant`` is the
    signed APPROVAL/v2 grant, ``bypasses`` the signed bypasses; neither is read here.  ``seal``: the program and the time the
    caller seals this batch with.

    Every frame is stored beside ``flat``, one file per batch number signed by the producer's key, before the engine sees it,
    and the file goes only once the batch is sealed or the engine answered that it decided nothing; an unknown outcome (a dead
    worker, an exception after the send, an IO refusal) keeps it.  A stored frame for this number is this request's when the retry key
    (the requests with the grant and every bypass) matches and it asserts the same rule set (version and digest, whatever
    records it or this call presents: the authority may have restarted with other copies, or none), however far the floors have risen since, unless they have risen above its own, when it can never seal and is voided like a refused commit's (the file dropped, and the engine, reopened, cuts the unsealed batch from its log when the next frame's floors have passed it): it is decided as stored, not rebuilt or rewritten, so
    a retry never makes a second payment.  When it comes back held (``ruleset_fork`` aside) and its file was dropped, and
    the frame this call builds differs from it (a record the authority holds since a restart, say), this call's frame is
    stored and decided in the same call, once.  A sealed answer is found by the retry key alone, before any floor is read, so
    neither the rule set nor the floor file changes what an exact retry is given.  Any other stored frame (another
    request's, or these requests under another grant, other bypasses or another rule set) may be a batch the engine
    holds decided and unsealed; a file the owner did not sign is ``pending_bad`` first.  Another request's, whose own
    floors the tenant's have not passed, can still seal: without ``seal`` this request HOLDs ``flat_conflict`` before the
    engine sees anything.  Otherwise it is decided as stored
    first, and voided as above once the floors have passed its
    own, whatever program stored it; while it can still seal it is never replaced and no other frame is sent on this number.  Otherwise:
    without ``seal`` this request HOLDs ``flat_conflict`` (HOLD RETRY), at every number; with it the stored frame is sent
    again and, decided, sealed with its own stored time and release under ``seal``'s program (checked equal to the stored one;
    a frame decided without ``seal`` has neither, and takes ``seal``'s time), its tokens filed for its requester, and this request goes on the next number.  An exact retry of that requester's requests
    is given those tokens and each answered payment's earlier list, byte for byte (``Answer.sealed``)."""
    if len(requests) > gate.MAX_BATCH:
        raise DataFault("batch_too_large")
    if not requests:
        raise GateDecideError("empty_batch")
    if any(type(r) is not gate.DecideRequest for r in requests) or len({r.payment_id for r in requests}) != len(requests):
        raise GateDecideError("request_malformed")
    try:
        bodies = [gate.encode_decide_request(r) for r in requests]
    except gate.GateCodecError as error:
        raise GateDecideError("request_malformed") from error
    k = prod.shard
    if tenant.tenant != prod.tenant or any(r.tenant_id != prod.tenant for r in requests):
        raise GateDecideError("foreign_tenant")
    tenant.member(prod)  # the floors read every shard the authority was opened with, this one included
    retry = _retry_key(bodies, grant, bypasses)
    sealed = prod.answered(retry)
    if sealed:
        return Answer((), b"", b"", None, sealed=sealed)
    try:
        at, quar = prod.flat_head(), prod.sealed_quar()
    except producer.GateProducerError as e:
        if str(e) not in ("quar_torn", "head_unsigned"):
            raise
        return _hold(requests, str(e))
    if quar:
        raise GateDecideError("flat_cut")
    anchor = at[0] if at else None
    seen = prod.tip()
    worker.check()  # a wrong or missing program is refused before anything is decided, and is not retried
    flat = flat.absolute()  # the resident worker runs in its own workspace directory, which goes when it closes
    floors = tenant.raise_floors(0, 0)  # never below what any shard has sealed
    tenant.refuse_faulty(prod)
    if floors[3] is None:
        prod.prepared = None  # as after any decide
        return _hold(requests, "ruleset_fork")
    tenant.refresh()
    rule, why = tenant.present(floors)
    if why:
        prod.prepared = None
        return _hold(requests, why)
    rulesets = (tenant.rulesets[rule],) if rule in tenant.rulesets else ()
    pre = anchor or flatchain.genesis(k, asof, tenant.pin)
    count = at[1] if at else 0
    release = worker.launched_release()
    frame = request_frame(feeds, k, count + 1, asof, pre, tenant.pin, floors, keys, grant, release, bypasses, bodies,
                          rulesets=rulesets)
    shapes = tuple(_Shape(r.payment_id, len(r.lines)) for r in requests)
    pend = _pend(flat, count + 1)
    if count:
        _drop(_pend(flat, count))  # its batch is sealed: left by a stop between that seal and its drop
    stored = _pending(pend, prod, count + 1)

    def void() -> Answer:  # the stored frame was decided under floors the tenant has passed, so it can never seal: reopen, drop it, decide afresh (the engine cuts it then)
        worker.close()
        _drop(pend)
        prod.prepared = None
        if pend.exists():  # never decided again while it stays: the next call voids it and drops it again
            raise MachineFault("pending_not_removed", str(pend))
        return decide(feeds, asof, prod, requests, flat, worker, grant, keys, tenant, bypasses, seal)
    passed = lambda a: a.digest and flatchain.behind(_floors_of(a.adds), floors)  # noqa: E731

    def changed() -> Answer | None:  # the stored frame carries a first record not presented now: never sent
        other = [d for d in stored.presented if d != rule]
        if not other or floors[2]:
            # once the tenant holds a rule set, an answer taking up another record (the same version under another
            # digest) HOLDs ruleset_fork and its file is dropped; its own asserted serial or epoch says nothing, as the
            # answer carries the grant's
            return None
        LOG.warning("tenant %s shard %d: the frame stored as %s carries rule set %s, which the rule-set folder no longer"
                    " gives; it waits (ruleset_changed)", prod.tenant, k, pend, other[0].hex())
        prod.prepared = None  # as after any decide
        return _hold(requests, "ruleset_changed")
    if stored is not None and stored.retry == retry and stored.floors[2:] == floors[2:]:
        if not prod.vouched(stored.record, stored.vouch):
            raise GateDecideError(f"pending_bad:{pend}")  # not the owner's file: its frame is not decided again
        held = changed()
        if held:
            return held
        ans = _decide_frame(prod, tenant, stored.shapes, flat, worker, stored.frame, pre, count, anchor, seen, stored.release,
                            pend, retry)  # the same request: decided as first stored
        if passed(ans):
            return void()
        if ans.digest or pend.exists() or stored.frame == frame or ans.lines[0].endswith(" HOLD ruleset_fork"):
            return ans
        # held (not ruleset_fork), its file dropped, and this call's frame differs from it: this call's frame is stored and decided, once
    elif stored is not None:  # another request's frame, or these requests under another grant, bypasses or rule set
        if not prod.vouched(stored.record, stored.vouch):
            raise GateDecideError(f"pending_bad:{pend}")  # not the owner's file: its floors are not read
        if seal is None and _requests(stored.frame)[1] != bodies and not flatchain.behind(stored.floors, floors):
            # another request's frame under floors the tenant has not passed: an answer to it never asserts less, so it
            # cannot be voided and stays sealable; held before the engine sees anything
            prod.prepared = None  # as after any decide
            return _hold(requests, "flat_conflict")
        held = changed()
        if held:
            return held
        try:
            stale = _decide_frame(prod, tenant, stored.shapes, flat, worker, stored.frame, pre, count, anchor, seen,
                                  stored.release, pend, stored.retry)
        except (WorkerDied, MachineFault):
            raise  # a machine fault: the file stays, and the next call sends it again
        except GateDecideError as error:
            raise GateDecideError(f"pending_refused:{pend}:{error}") from error
        if passed(stale):
            return void()
        if stale.digest and seal is None:  # still sealable: never replaced
            prod.prepared = None
            return _hold(requests, "flat_conflict")
        if stale.digest:
            if stored.program not in (None, seal[0]):  # sealable only by its own program
                prod.prepared = None
                raise GateDecideError(f"pending_bad:{pend}")
            try:
                commit(prod, seal[0], stale, seal[1] if stored.created_at is None else stored.created_at, tenant)
            except MachineFault:
                raise  # the file stays, and the next call sends it again
            except GateDecideError as error:
                raise GateDecideError(f"pending_refused:{pend}:{error}") from error
            return decide(feeds, asof, prod, requests, flat, worker, grant, keys, tenant, bypasses, seal)
        why = stale.lines[0].split(" HOLD ", 1)[1]
        if why in ("chain_mismatch", "keyset_pin"):  # decided, and never sealable
            raise GateDecideError(f"pending_refused:{pend}:{why}")
        if why in _UNKNOWN or pend.exists():  # the file stays (a timeout or a fault of the frame keeps it), and the next call sends it again
            return _hold(requests, why)
        # the engine decided nothing on it, and its file is gone: this call's frame goes on this number
    if rule in tenant.ambiguous and tenant.seen(prod)[3] != rule:  # this shard would admit it, and the copies' signers do not nest
        prod.prepared = None  # as after any decide
        return _hold(requests, "ruleset_copies")
    _store_pending(pend, prod, {"tenant": prod.tenant, "shard": k, "batch": count + 1, "release": release.hex(),
                                "program": seal and seal[0], "created_at": seal and seal[1],
                                "bodies_at": len(frame) - 4 - sum(4 + len(b) for b in bodies),  # the request count, then the requests
                                "frame": frame.hex(), "requests": [list(s) for s in shapes]})
    return _decide_frame(prod, tenant, shapes, flat, worker, frame, pre, count, anchor, seen, release, pend, retry)  # sealed under the retry key


_RETRY_DOMAIN = b"RR/GATE/RETRY-KEY/v2\x00"  # the retry key, SHA3-256, over the requests, the grant and the bypasses (_retry_key)


def _retry_key(bodies: Sequence[bytes], grant: bytes, bypasses: Sequence[bytes]) -> bytes:
    """What an exact resend repeats: its requests and the authority they were decided under (a new grant or bypass decides afresh)."""
    return hashlib.sha3_256(_RETRY_DOMAIN + _le(len(bodies), 4) + b"".join(map(_blob, bodies)) + _blob(grant) + _le(len(bypasses), 4)
                            + b"".join(map(_blob, bypasses))).digest()
_UNKNOWN = ("flat_io", "flat_corrupt", "flat_replay", "flat_lock", "chain_mismatch", "keyset_pin")  # answers after which the engine may hold the frame


class _Shape(NamedTuple):
    """What a decided batch needs of its request after the fact: the payment id and the number of lines."""
    payment_id: str
    lines: int


class _Stored(NamedTuple):
    """A stored frame's file: what ``decide`` wrote, ``floors`` the floors its frame asserts, ``presented`` the body
    digests of the rule-set records it presents, ``record`` the signed bytes and ``vouch`` the producer's signature."""
    frame: bytes
    shapes: tuple[_Shape, ...]
    release: bytes
    program: str | None
    created_at: int | None
    retry: bytes
    floors: flatchain.Floors
    presented: list[bytes]
    record: bytes
    vouch: bytes


def _pend(flat: Path, batch: int) -> Path:
    return flat.with_name(f"{flat.name}.pending.{batch}")


def _record(doc: dict) -> bytes:
    return json.dumps({k: v for k, v in doc.items() if k != "vouch"}, sort_keys=True, separators=(",", ":")).encode("ascii")


def _pending(path: Path, prod: producer.ShardProducer, batch: int) -> _Stored | None:
    """The frame stored for ``batch``, or None when there is no file.  A file that cannot be read or parsed, is another
    tenant's, shard's or number's, or whose frame carries a request of another tenant or not one request per entry, is
    ``pending_bad``; one with no request is ``pending_empty``.  Both name the file and leave it."""
    try:
        doc = json.loads(path.read_bytes())
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as error:  # held by another program, torn or not JSON: never read as absent
        raise GateDecideError(f"pending_bad:{path}") from error
    try:
        frame, shapes = bytes.fromhex(doc["frame"]), tuple(_Shape(i, n) for i, n in doc["requests"])
        if not shapes:
            raise GateDecideError(f"pending_empty:{path}")  # never written by decide; refused, not sealed or dropped
        tenant, r = prod.tenant.encode("ascii"), _Reader(frame)
        own, r.at = gate.DECIDE_REQUEST + len(tenant).to_bytes(2, "big") + tenant, doc["bodies_at"]
        if type(r.at) is not int or r.at < 82:
            raise ValueError
        bodies = [r.blob(4) for _ in range(r.num(4))]
        ok = ((doc["tenant"], doc["shard"], doc["batch"]) == (prod.tenant, prod.shard, batch) and frame[6:18] == _le(prod.shard, 4) + _le(batch, 8)
              and all(type(i) is str and type(n) is int for i, n in shapes) and r.at == len(frame) and len(bodies) == len(shapes)
              and all(b.startswith(own) for b in bodies))  # every request the shard's tenant's, as decide refuses any other
        _, _, grant, bypasses, records, asserted = _requests(frame)
        stored = _Stored(frame, shapes, bytes.fromhex(doc["release"]), doc["program"], doc["created_at"],
                         _retry_key(bodies, grant, bypasses), asserted, [rulecodec.digest(x) for x in records], _record(doc),
                         bytes.fromhex(doc["vouch"]))
    except GateDecideError as error:
        if str(error).startswith("pending_"):
            raise
        raise GateDecideError(f"pending_bad:{path}") from error  # the requests run past the frame
    except (KeyError, TypeError, ValueError, AttributeError) as error:
        raise GateDecideError(f"pending_bad:{path}") from error
    if not ok:
        raise GateDecideError(f"pending_bad:{path}")
    return stored


def _store_pending(path: Path, prod: producer.ShardProducer, doc: dict) -> None:
    """Write ``doc`` with the producer's signature of its record to ``path``, durably (the file and its directory entry)."""
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", encoding="ascii") as f:
        json.dump({**doc, "vouch": prod.vouch(_record(doc)).hex()}, f)
        f.flush()
        os.fsync(f.fileno())
    _rename_durably(tmp, path)


def _rename_durably(tmp: Path, path: Path) -> None:
    """Rename the synced file ``tmp`` over ``path`` so the new directory entry is on disk when this returns."""
    if os.name == "nt":  # Windows cannot sync a directory; the rename itself is written through
        if not ctypes.WinDLL("kernel32", use_last_error=True).MoveFileExW(str(tmp), str(path), 0x1 | 0x8):  # REPLACE_EXISTING | WRITE_THROUGH
            raise ctypes.WinError(ctypes.get_last_error())
    else:
        os.replace(tmp, path)
        _sync_dir(path.parent)


def _sync_dir(path: Path) -> None:
    directory = os.open(path, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _drop(path: Path) -> None:
    """Remove a stored frame's file.  A file that will not go is logged and left: it is removed again the next time."""
    try:
        path.unlink()
    except FileNotFoundError:
        return
    except OSError as error:
        LOG.warning("stored frame %s not removed: %r", path, error)
        return
    if os.name != "nt":
        _sync_dir(path.parent)


def _decide_frame(prod: producer.ShardProducer, tenant: TenantAuthority, shapes: Sequence[_Shape], flat: Path, worker: RulesWorker,
                  frame: bytes, pre: bytes, count: int, anchor: bytes | None, seen: bytes | None, release: bytes, pend: Path,
                  retry: bytes = b"") -> Answer:
    """Send ``frame`` (batch ``count + 1`` on ``flat``, its release ``release``) to the worker, resending it to a relaunched
    one after a death, and the answer prepared on ``prod`` for ``shapes`` (the payment ids and line counts of the frame's
    requests).  An answer that the engine decided nothing (any HOLD but ``_UNKNOWN``) removes the frame's file ``pend``.
    An answer whose authority record names another pin than ``tenant``'s HOLDs ``keyset_pin``; a decided one raises the
    tenant's floors to its record's, and HOLDs ``ruleset_fork`` when the shards are then forked at their highest
    rule-set version (``commit`` would refuse it): the engine is reopened at the signed head and the frame dropped."""
    k = prod.shard
    prod.prepared = None  # a new decide discards any batch an earlier decide prepared
    lost, stalled = worker.lost, 0
    for tries in range(1, ATTEMPTS + 1):
        if anchor is None and flat.exists():  # no seal covers a store here: one left by a batch that was never sealed goes
            worker.close()
            _rm(flat)
        try:
            out = worker.run_frame(str(flat).replace("\\", "/"), k, frame)
            break
        except DataFault as e:  # it fails the same way on every launch: several requests are split, one alone is held for a person
            if len(shapes) > 1:
                raise
            return _hold(shapes, str(e))
        except WorkerDied as e:
            LOG.warning("gate rules worker died (%s: %r): shard %d, attempt %d of %d", type(e).__name__, e.__cause__, k, tries, ATTEMPTS)
            stalled += str(e.__cause__) == "worker_timeout"
            if tries == ATTEMPTS:
                if stalled == ATTEMPTS:  # every launch ran past its deadline: the batch is too slow, so a retry would loop
                    if len(shapes) > 1:
                        raise DataFault("timeout") from e
                    return _hold(shapes, "timeout")  # one request too slow on its own: held for a person
                raise MachineFault("timeout" if str(e.__cause__) == "worker_timeout" else "rules_refused") from e
    why, recs, new, root, auth, pays, adds = _answer(out, frame)
    stored = auth + root + b"".join(adds)  # the chain step body as the producer stores it
    if why is None and auth[:len(tenant.pin)] != tenant.pin:
        why = "keyset_pin"
    if why is None and flatchain.step_adds(pre, stored) != new:
        why = "chain_mismatch"
    if why is not None:
        LOG.warning("shard %d: every row HOLDs (%s)", k, why)
        if why not in _UNKNOWN:
            _drop(pend)
        return _hold(shapes, why)
    if tenant.raise_floors(*_floors_of(stored))[3] is None:  # forked at the highest rule-set version: commit would refuse it
        LOG.warning("shard %d: every row HOLDs (ruleset_fork)", k)
        worker.close()  # reopened at the signed head before the file goes; the engine keeps the unsealed batch until a frame's floors pass it
        _drop(pend)
        return _hold(shapes, "ruleset_fork")
    covered = [r for r, y in zip(shapes, pays) if "SCOPE" not in y.reasons]  # a request no grant entry covers has no lines
    owners = tuple((r.payment_id, i) for r in covered for i in range(r.lines))
    ans = Answer((), new, stored, seen, flat, pre, count + 1, 1 + worker.lost - lost, tuple(pays), release, frame,
                 tuple(recs), owners, retry, None, worker)
    prod.prepared = ans  # the producer seals only this exact answer
    return ans


def commit(prod: producer.ShardProducer, program: str, ans: Answer, created_at: int, tenant: TenantAuthority):
    """Seal the decided batch and return (checkpoint, signed, tokens).  The answer is sealed only while the shard's last seal
    is the one it saw and it is the shard's last prepared answer: a later decide's open discarded its journal, so its seal
    would sign a head no index can reach, and a re-commit of a sealed answer would put its lines in two token sets.  It is
    admitted only while the tenant's floors (the file and every shard's sealed record) are at or below the grant serial,
    key-set epoch and rule set it was decided under (``right_rail_gate_chain.behind``), checked and reserved under the floor
    file's lock, so no decide on another shard raises them in between: after one did, or another shard sealed above them,
    ``grant_floor_risen`` (``ruleset_fork`` while the shards are forked at their highest rule-set version), and the prepared answer is
    discarded (nothing reserved, sealed or released; the caller decides again).  The engine that decided it is then reopened at
    the signed head, and only after that is its stored frame dropped, so the next decide builds a fresh frame under the new
    floors; the engine, pinned or rows-file, cuts the unsealed batch from its log when that frame's floors have passed it.  The lock is let go for the signing, and taken again
    around the seal's last floor check and the signature store: a floor raised before that check voids the reservation,
    ``reservation_below_floor`` (the caller decides again), exactly as a reopen voids one a crash left unsealed; none rises
    between the check and the stored signature.  The tokens
    are exactly the engine's leaves, as the producer holds them from ``decide``: each leaf copies its request's
    fields, the engine's outcome and reason codes, the frame's release as rule version and engine release, and the
    INPUT/v7 the engine and the host each computed, with the engine's authority and grant id.  The caller names only the
    program; no caller supplies an outcome or an authority.  The seal signs the prepared head.  A HOLD answer
    (no state digest) is never sealed.  The answer counts as spent once the floor lock is held, before the floor check; a lock
    that stays taken at that first acquisition (``tenant_floor_busy``) keeps it, so the same answer can be committed again.  A
    failure before the signature may be stored voids the reservation and the producer stays open; a signing failure other than a
    refusal, an interrupt, or any failure once the signature may be stored closes the producer and needs a reopen; a counter read
    error is raised unchanged.  Once the seal is durable the batch's stored frame is removed."""
    if not ans.digest:
        raise GateDecideError("hold_answer")
    if not ans.pays:  # every payment waits: no token, so no seal
        raise GateDecideError("empty_batch")
    if any(y.program != program for y in ans.pays):
        raise GateDecideError("input_commitment")
    if tenant.tenant != prod.tenant:
        raise GateDecideError("foreign_tenant")
    tenant.member(prod)  # as decide: a shard number the authority was not opened with is refused
    if prod.tip() != ans.seen or prod.prepared != ans:
        raise GateDecideError("stale_answer")
    mine = _floors_of(ans.adds)

    @contextlib.contextmanager
    def admitted():
        with tenant._locked():
            prod.prepared = None  # spent once the lock is held: a busy lock keeps the answer for a retry
            top = tenant._raise(0, 0)
            tenant.refuse_faulty(prod)
            if top[3] is None:
                raise GateDecideError("ruleset_fork")
            if flatchain.behind(mine, top):
                raise GateDecideError("grant_floor_risen")
            yield
    try:
        out = prod.commit(program, ans, created_at, admit=admitted, lock=tenant._locked)
    except GateDecideError as error:
        if str(error) == "grant_floor_risen" and ans.worker is not None:  # nothing was sealed or paid: reopen the engine at the signed head, then drop the frame
            ans.worker.close()
            _drop(_pend(ans.flat, ans.batches))
        raise
    except producer.GateProducerError as error:
        if str(error) == "store_unavailable":  # the producer retried what it could
            raise MachineFault("store_unavailable") from error
        raise
    _drop(_pend(ans.flat, ans.batches))
    return out
