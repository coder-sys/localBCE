"""Payment gate wire formats, first slice (founder decision D1, 2026-09-25).

Formats: ``RR/GATE/DECIDE-REQUEST/v1``, ``RR/GATE/DECIDE-RESPONSE/v1``,
``RR/GATE/TOKEN/v1``, ``RR/GATE/CHECKPOINT/v1`` (ML-DSA-87 per-batch variant
only) and the SHA3-512 digest domains ``RR/GATE/DECISION-ID/v1``,
``RR/GATE/INPUT/v1``, ``RR/GATE/MERKLE-NODE/v1`` (the batch token tree),
``RR/GATE/LINES-NODE/v1`` (a payment's lines tree), ``RR/GATE/SHARD/v1``
(a member's shard) and ``RR/GATE/STATE/v1`` (a checkpoint's released and
unresolved sets).

Grammar (the BLFIN02 style): every record starts with its ASCII domain and a
NUL, which is also its explicit version; naturals are fixed-width big-endian
and at most 2^63-1; identifiers are u16-length ASCII; digests are raw 64
bytes; tags are one byte; lists are count-prefixed and bounded.  This adapter
only encodes and assembles a signed batch.  ``lean/BlindLedger/Gate`` holds the
only decoders and is the only place a token is judged (``verifyToken``).
Synthetic, nonpayment, activation=false.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re
from typing import Callable, Final, Sequence


class GateCodecError(ValueError):
    """A value the gate formats cannot carry.  The message is a fixed code."""


DECIDE_REQUEST: Final = b"RR/GATE/DECIDE-REQUEST/v1\x00"
DECIDE_RESPONSE: Final = b"RR/GATE/DECIDE-RESPONSE/v1\x00"
TOKEN: Final = b"RR/GATE/TOKEN/v1\x00"
CHECKPOINT: Final = b"RR/GATE/CHECKPOINT/v1\x00"
DECISION_ID: Final = b"RR/GATE/DECISION-ID/v1\x00"
INPUT: Final = b"RR/GATE/INPUT/v1\x00"
MERKLE_NODE: Final = b"RR/GATE/MERKLE-NODE/v1\x00"
LINES_NODE: Final = b"RR/GATE/LINES-NODE/v1\x00"
SHARD: Final = b"RR/GATE/SHARD/v1\x00"
STATE: Final = b"RR/GATE/STATE/v1\x00"

FLOWS: Final = ("FFS_CYCLE", "FFS_CLAIM", "CAP_820", "SDP", "PLAN_PAY")
RULED: Final = FLOWS[:3]  # decided line by line, so each payment carries a line; SDP and PLAN_PAY: HUMAN_REVIEW
OUTCOMES: Final = ("ALLOW", "HOLD", "HUMAN_REVIEW", "BLOCK")
AUTHORITIES: Final = ("OBSERVE", "HOLD", "TRANSFER")
# PAYMENT_ALREADY_DECIDED: a new command key, under any flow, for a payment
# that already has a decision; the existing decision is returned.  A fenced or
# expired unreleased decision is re-issued (same leaf, current epoch, new seq
# and lifetime; Lean ``reissues``); an ALLOW past its age is re-decided under
# the next revision (Lean ``redecides``).  Otherwise only a state official's
# determination (a later format) can change a decision.
STATUSES: Final = ("DECIDED", "DUPLICATE", "REJECTED", "UNAVAILABLE", "PAYMENT_ALREADY_DECIDED")
TOKEN_STATUSES: Final = ("DECIDED", "DUPLICATE", "PAYMENT_ALREADY_DECIDED")
REJECT_CODES: Final = ("MALFORMED", "COMMAND_KEY_CONFLICT")
SIG_ML_DSA_87_BATCH: Final = 1

DIGEST: Final = 64
MEMBER_KEY: Final = 32  # the member's salted hash (D5 salt vault)
ZERO_DIGEST: Final = bytes(DIGEST)
MAX_NAT: Final = (1 << 63) - 1
MAX_LINES: Final = 65_535  # also bounds a lines tree to depth 16
MAX_LINE_BYTES: Final = 569  # the largest canonical line (encode_line)
MAX_EVIDENCE_REFS: Final = 256
MAX_REASON_CODES: Final = 32
MAX_BATCH: Final = 1_000
MAX_TOKEN_PATH: Final = 10  # ceil(log2(MAX_BATCH))
MAX_TOKEN_LIFETIME: Final = 7 * 24 * 3600  # seconds from issued_at to expires_at
# The payer refuses an older decided_at (Lean maxDecisionAge: the run decided for and one missed).
MAX_DECISION_AGE: Final = {**dict.fromkeys(FLOWS, 14 * 86400), "FFS_CYCLE": 28 * 86400, "CAP_820": 62 * 86400}
MAX_RETRY_AFTER_MS: Final = 3_600_000
MAX_REQUEST_BYTES: Final = 8 * 1024 * 1024
MAX_TOKEN_BYTES: Final = 4 * 1024  # the largest canonical token is 3,900 bytes
ML_DSA_87_SIGNATURE: Final = 4627
ML_DSA_87_PUBLIC_KEY: Final = 2592

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")


def _fail(code: str) -> None:
    raise GateCodecError(code) from None


def sha3_512(data: bytes) -> bytes:
    return hashlib.sha3_512(data).digest()


class _Writer:
    def __init__(self, domain: bytes) -> None:
        self.out = bytearray(domain)

    def int(self, value: object, width: int, label: str, *, low: int = 0, high: int = MAX_NAT) -> None:
        if type(value) is not int or not low <= value <= min(high, (1 << (8 * width)) - 1):
            _fail(label)
        self.out += value.to_bytes(width, "big")

    def tag(self, names: Sequence[str], value: object, label: str) -> None:
        if value not in names:
            _fail(label)
        self.out.append(names.index(value) + 1)

    def ident(self, value: object, label: str, pattern: re.Pattern[str] = _ID) -> None:
        if type(value) is not str or pattern.fullmatch(value) is None:
            _fail(label)
        self.blob(value.encode("ascii"), label)

    def digest(self, value: object, label: str, size: int = DIGEST) -> None:
        if type(value) is not bytes or len(value) != size:
            _fail(label)
        self.out += value

    def blob(self, value: object, label: str, *, size: int = 0xFFFF, low: int = 1) -> None:
        if type(value) is not bytes or not low <= len(value) <= size:
            _fail(label)
        self.int(len(value), 2, label)
        self.out += value


def _sorted_unique(values: Sequence[object], label: str) -> None:
    if any(not a < b for a, b in zip(values, values[1:])):  # type: ignore[operator]
        _fail(label)


# ---------------------------------------------------------------- #12 digests


def decision_id(tenant_id: str, program_id: str, payment_id: str, revision: int) -> bytes:
    """SHA3-512(RR/GATE/DECISION-ID/v1 || tenant || program || payment_id || revision).
    One decision per payment and revision, whatever the command key or flow."""
    w = _Writer(DECISION_ID)
    w.ident(tenant_id, "tenant_id")
    w.ident(program_id, "program_id")
    w.ident(payment_id, "payment_id")
    w.int(revision, 8, "revision")
    return sha3_512(bytes(w.out))


def shard_of(tenant_id: str, member_key: bytes, shard_count: int) -> int:
    """The first four bytes of SHA3-512(RR/GATE/SHARD/v1 || tenant || member_key)
    as a big-endian u32, mod the tenant's shard count (fixed per tenant in v1).
    The payer recomputes it (Lean ``routed``)."""
    if type(shard_count) is not int or not 1 <= shard_count <= 0xFFFF_FFFF:
        _fail("shard_count")
    w = _Writer(SHARD)
    w.ident(tenant_id, "tenant_id")
    w.digest(member_key, "member_key", MEMBER_KEY)
    return int.from_bytes(sha3_512(bytes(w.out))[:4], "big") % shard_count


def input_commitment(request: "DecideRequest", read_set_digest: bytes) -> bytes:
    """SHA3-512(RR/GATE/INPUT/v1 || u32 length || canonical request || read-set digest)."""
    body = encode_decide_request(request)
    w = _Writer(INPUT)
    w.int(len(body), 4, "request")
    w.out += body
    w.digest(read_set_digest, "read_set_digest")
    return sha3_512(bytes(w.out))


def state_digest(released_pin: bytes, unresolved_pin: bytes) -> bytes:
    """SHA3-512(RR/GATE/STATE/v1 || released pin || unresolved pin): the rules'
    released and unresolved sets after a batch, each as its 64-byte snapshot
    pin (``tools/gate_rules_data.py``)."""
    w = _Writer(STATE)
    w.digest(released_pin, "released_pin")
    w.digest(unresolved_pin, "unresolved_pin")
    return sha3_512(bytes(w.out))


def merkle_tree(domain: bytes, leaves: Sequence[bytes]) -> tuple[bytes, list[list[bytes]]]:
    """Root and per-leaf sibling paths (bottom-up) under ``domain``: leaf =
    H(domain || 0 || x), node = H(domain || 1 || l || r).  An odd last node is
    carried up unchanged, never duplicated, so a level with no sibling adds no step."""
    if not 1 <= len(leaves) <= MAX_LINES or any(type(leaf) is not bytes for leaf in leaves):
        _fail("merkle_leaves")
    level = [sha3_512(domain + b"\x00" + leaf) for leaf in leaves]
    position = list(range(len(leaves)))
    paths: list[list[bytes]] = [[] for _ in leaves]
    while len(level) > 1:
        for leaf, index in enumerate(position):
            sibling = index ^ 1
            if sibling < len(level):
                paths[leaf].append(level[sibling])
            position[leaf] = index // 2
        level = [sha3_512(domain + b"\x01" + level[i] + level[i + 1]) if i + 1 < len(level) else level[i]
                 for i in range(0, len(level), 2)]
    return level[0], paths


def lines_root(lines: Sequence[bytes]) -> bytes:
    return merkle_tree(LINES_NODE, lines)[0] if lines else ZERO_DIGEST


# ------------------------------------------------------ #1 DECIDE-REQUEST/v1


def encode_line(flow: str, line_id: str, member_key: bytes, payee_ref: str, rendering: str,
                service_date: int, procedure: str, units: int, cents: int) -> bytes:
    """One canonical line (Lean ``pLine``): a leaf of ``lines_root`` and an
    entry of ``DecideRequest.lines``.  The Lean decoder checks that a request's
    lines share its flow, member and payee and sum to its amount."""
    w = _Writer(b"")
    w.tag(FLOWS, flow, "line_flow")
    w.ident(line_id, "line_id")
    w.digest(member_key, "line_member_key", MEMBER_KEY)
    w.ident(payee_ref, "line_payee_ref")
    w.ident(rendering, "line_rendering")
    w.int(service_date, 4, "line_service_date")
    w.ident(procedure, "line_procedure")
    w.int(units, 4, "line_units")
    w.int(cents, 8, "line_cents")
    return bytes(w.out)


@dataclass(frozen=True)
class DecideRequest:
    tenant_id: str
    program_id: str
    flow: str
    command_key: str
    payment_id: str
    member_key: bytes
    payee_ref: str
    amount_cents: int
    period: str
    lines: tuple[bytes, ...]
    evidence_refs: tuple[bytes, ...]


def encode_decide_request(request: DecideRequest) -> bytes:
    w = _Writer(DECIDE_REQUEST)
    w.ident(request.tenant_id, "tenant_id")
    w.ident(request.program_id, "program_id")
    w.tag(FLOWS, request.flow, "flow")
    w.ident(request.command_key, "command_key")
    w.ident(request.payment_id, "payment_id")
    w.digest(request.member_key, "member_key", MEMBER_KEY)
    w.ident(request.payee_ref, "payee_ref")
    w.int(request.amount_cents, 8, "amount_cents")
    w.ident(request.period, "period")
    if type(request.lines) is not tuple or (request.flow in RULED and not request.lines):
        _fail("lines")
    w.int(len(request.lines), 2, "lines", high=MAX_LINES)
    for line in request.lines:
        w.blob(line, "line", size=MAX_LINE_BYTES)
    refs = request.evidence_refs
    if type(refs) is not tuple:
        _fail("evidence_refs")
    w.int(len(refs), 2, "evidence_refs", high=MAX_EVIDENCE_REFS)
    for ref in refs:
        w.digest(ref, "evidence_ref")
    _sorted_unique(refs, "evidence_refs")
    if len(w.out) > MAX_REQUEST_BYTES:
        _fail("size")
    return bytes(w.out)


# ------------------------------------------------------------ #4 CHECKPOINT/v1


@dataclass(frozen=True)
class Checkpoint:
    tenant_id: str
    program_id: str
    shard_id: int
    seq_from: int
    seq_to: int
    epoch: int
    prev_checkpoint_digest: bytes
    event_head: bytes
    token_root: bytes
    evidence_root: bytes
    state_digest: bytes
    count: int
    created_at: int


_CHECKPOINT_DIGESTS = ("prev_checkpoint_digest", "event_head", "token_root", "evidence_root", "state_digest")


def encode_checkpoint_header(cp: Checkpoint) -> bytes:
    """The exact bytes the epoch's ML-DSA-87 key signs."""
    w = _Writer(CHECKPOINT)
    w.int(SIG_ML_DSA_87_BATCH, 1, "sig_alg")
    w.ident(cp.tenant_id, "tenant_id")
    w.ident(cp.program_id, "program_id")
    w.int(cp.shard_id, 4, "shard_id")
    w.int(cp.seq_from, 8, "seq_from")
    w.int(cp.seq_to, 8, "seq_to")
    w.int(cp.epoch, 8, "epoch")
    for name in _CHECKPOINT_DIGESTS:
        w.digest(getattr(cp, name), name)
    w.int(cp.count, 2, "count", low=1, high=MAX_BATCH)
    w.int(cp.created_at, 8, "created_at")
    if cp.seq_to - cp.seq_from + 1 != cp.count:
        _fail("seq_range")
    if (cp.seq_from == 0) != (cp.prev_checkpoint_digest == ZERO_DIGEST):
        _fail("prev_checkpoint")
    if cp.state_digest == ZERO_DIGEST:
        _fail("state_digest")
    return bytes(w.out)


def checkpoint_digest(cp: Checkpoint) -> bytes:
    """SHA3-512 of the signed header bytes, signature excluded.  Tokens name
    their batch by it, and the next checkpoint's ``prev_checkpoint_digest`` is it."""
    return sha3_512(encode_checkpoint_header(cp))


def encode_checkpoint(cp: Checkpoint, signature: bytes) -> bytes:
    """The signed checkpoint a payer fetches once per batch: header || signature."""
    w = _Writer(encode_checkpoint_header(cp))
    w.blob(signature, "signature", size=ML_DSA_87_SIGNATURE, low=ML_DSA_87_SIGNATURE)
    return bytes(w.out)


# ------------------------------------------------------------------ #3 TOKEN/v1


@dataclass(frozen=True)
class TokenLeaf:
    """Leaf fields in wire order.  The decision id is recomputed from the leaf,
    so it does not travel here."""

    tenant_id: str
    program_id: str
    shard_id: int
    flow: str
    revision: int
    payment_id: str
    member_key: bytes
    payee_ref: str
    amount_cents: int
    period: str
    lines_root: bytes
    outcome: str
    reason_codes: tuple[str, ...]
    authority: str
    grant_id: bytes
    rule_version: bytes
    engine_release: bytes
    input_commitment: bytes
    decided_at: int
    epoch: int
    seq: int
    issued_at: int
    expires_at: int


@dataclass(frozen=True)
class Token:
    leaf: TokenLeaf
    siblings: tuple[bytes, ...]
    checkpoint_digest: bytes


def encode_token_leaf(leaf: TokenLeaf) -> bytes:
    """The canonical leaf; its bytes are what the batch Merkle tree commits to."""
    w = _Writer(TOKEN)
    w.ident(leaf.tenant_id, "tenant_id")
    w.ident(leaf.program_id, "program_id")
    w.int(leaf.shard_id, 4, "shard_id")
    w.tag(FLOWS, leaf.flow, "flow")
    w.int(leaf.revision, 8, "revision")
    w.ident(leaf.payment_id, "payment_id")
    w.digest(leaf.member_key, "member_key", MEMBER_KEY)
    w.ident(leaf.payee_ref, "payee_ref")
    w.int(leaf.amount_cents, 8, "amount_cents")
    w.ident(leaf.period, "period")
    w.digest(leaf.lines_root, "lines_root")
    w.tag(OUTCOMES, leaf.outcome, "outcome")
    if leaf.lines_root == ZERO_DIGEST if leaf.flow in RULED else leaf.outcome != "HUMAN_REVIEW":
        _fail("lines_root")
    if type(leaf.reason_codes) is not tuple:
        _fail("reason_codes")
    w.int(len(leaf.reason_codes), 1, "reason_codes", high=MAX_REASON_CODES)
    for code in leaf.reason_codes:
        w.ident(code, "reason_code", _CODE)
    _sorted_unique(leaf.reason_codes, "reason_codes")
    w.tag(AUTHORITIES, leaf.authority, "authority")
    for name in ("grant_id", "rule_version", "engine_release", "input_commitment"):
        w.digest(getattr(leaf, name), name)
    for name in ("decided_at", "epoch", "seq", "issued_at", "expires_at"):
        w.int(getattr(leaf, name), 8, name)
    if not leaf.decided_at <= leaf.issued_at <= leaf.expires_at <= leaf.issued_at + MAX_TOKEN_LIFETIME:
        _fail("lifetime")
    return bytes(w.out)


def encode_token(token: Token) -> bytes:
    """leaf || path || checkpoint_digest.  The signed checkpoint travels
    separately, once per batch (``encode_checkpoint``)."""
    w = _Writer(encode_token_leaf(token.leaf))
    if type(token.siblings) is not tuple:
        _fail("path")
    w.int(len(token.siblings), 1, "path", high=MAX_TOKEN_PATH)
    for sibling in token.siblings:
        w.digest(sibling, "path")
    w.digest(token.checkpoint_digest, "checkpoint_digest")
    return bytes(w.out)


def sign_batch(
    leaves: Sequence[TokenLeaf],
    *,
    prev_checkpoint_digest: bytes,
    event_head: bytes,
    evidence_root: bytes,
    state_digest: bytes,
    shard_count: int,
    created_at: int,
    sign: Callable[[bytes], bytes],
) -> tuple[Checkpoint, bytes, list[Token]]:
    """One checkpoint and one ML-DSA-87 signature for a whole batch (the batching
    invariant); each payment's token is its leaf plus a Merkle path to token_root.
    Leaves must be one shard writer's consecutive commits: same scope, shard
    and epoch, seq increasing by one, and at most one leaf per payment id across
    flows; each leaf's shard is its member's under ``shard_count``.  Each leaf
    carries the engine release and decision time that decided it, so a
    re-issued leaf keeps its own.  Stateless: the serial, persist-before-publish
    and fork self-check producer rules are unbuilt (Lean checkpoint section).
    ``sign`` is the only signing call (see right_rail_gate_signer)."""
    if not 1 <= len(leaves) <= MAX_BATCH:
        _fail("batch")
    first = leaves[0]
    for index, leaf in enumerate(leaves):
        if (leaf.tenant_id, leaf.program_id, leaf.shard_id, leaf.epoch, leaf.seq) != (
                first.tenant_id, first.program_id, first.shard_id, first.epoch, first.seq + index):
            _fail("batch")
        if shard_of(leaf.tenant_id, leaf.member_key, shard_count) != leaf.shard_id:
            _fail("batch_shard")
    if len({leaf.payment_id for leaf in leaves}) != len(leaves):
        _fail("batch_payment")
    root, paths = merkle_tree(MERKLE_NODE, [encode_token_leaf(leaf) for leaf in leaves])
    checkpoint = Checkpoint(
        first.tenant_id, first.program_id, first.shard_id, first.seq, first.seq + len(leaves) - 1, first.epoch,
        prev_checkpoint_digest, event_head, root, evidence_root, state_digest, len(leaves), created_at,
    )
    digest = checkpoint_digest(checkpoint)
    signature = sign(encode_checkpoint_header(checkpoint))
    return checkpoint, signature, [Token(leaf, tuple(path), digest) for leaf, path in zip(leaves, paths)]


# -------------------------------------------------------- #2 DECIDE-RESPONSE/v1


@dataclass(frozen=True)
class DecideResponse:
    tenant_id: str
    program_id: str
    command_key: str
    status: str
    token: Token | None = None
    reject_code: str | None = None
    retry_after_ms: int | None = None


def encode_decide_response(response: DecideResponse) -> bytes:
    """Outcome and reason codes travel inside the token; the response never
    carries a second copy of them.  The requester's Lean decoder binds the
    response to its request."""
    w = _Writer(DECIDE_RESPONSE)
    w.ident(response.tenant_id, "tenant_id")
    w.ident(response.program_id, "program_id")
    w.ident(response.command_key, "command_key")
    w.tag(STATUSES, response.status, "status")
    carries = (response.token is not None, response.reject_code is not None, response.retry_after_ms is not None)
    if carries != (response.status in TOKEN_STATUSES, response.status == "REJECTED", response.status == "UNAVAILABLE"):
        _fail("status")
    if response.token is not None:
        token = encode_token(response.token)
        w.int(len(token), 4, "token", high=MAX_TOKEN_BYTES)
        w.out += token
    elif response.reject_code is not None:
        w.tag(REJECT_CODES, response.reject_code, "reject_code")
    else:
        w.int(response.retry_after_ms, 4, "retry_after_ms", low=1, high=MAX_RETRY_AFTER_MS)
    return bytes(w.out)
