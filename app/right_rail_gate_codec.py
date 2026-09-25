"""Payment gate wire formats, first slice (founder decision D1, 2026-09-25).

Formats: ``RR/GATE/DECIDE-REQUEST/v1``, ``RR/GATE/DECIDE-RESPONSE/v1``,
``RR/GATE/TOKEN/v1``, ``RR/GATE/CHECKPOINT/v1`` (ML-DSA-87 per-batch variant
only) and the SHA3-512 digest domains ``RR/GATE/DECISION-ID/v1``,
``RR/GATE/INPUT/v1``, ``RR/GATE/MERKLE-NODE/v1`` (the batch token tree) and
``RR/GATE/LINES-NODE/v1`` (a payment's lines tree).

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

FLOWS: Final = ("FFS_CYCLE", "FFS_CLAIM", "CAP_820", "SDP", "PLAN_PAY")
OUTCOMES: Final = ("ALLOW", "HOLD", "HUMAN_REVIEW", "BLOCK")
AUTHORITIES: Final = ("OBSERVE", "HOLD", "TRANSFER")
# PAYMENT_ALREADY_DECIDED: a new command key for a payment that already has a
# decision; the existing token is returned.  Only a state official's
# determination (a later format) can change a decision, never a re-decide.
STATUSES: Final = ("DECIDED", "DUPLICATE", "REJECTED", "UNAVAILABLE", "PAYMENT_ALREADY_DECIDED")
TOKEN_STATUSES: Final = ("DECIDED", "DUPLICATE", "PAYMENT_ALREADY_DECIDED")
REJECT_CODES: Final = ("MALFORMED", "COMMAND_KEY_CONFLICT")
SIG_ML_DSA_87_BATCH: Final = 1

DIGEST: Final = 64
ZERO_DIGEST: Final = bytes(DIGEST)
MAX_NAT: Final = (1 << 63) - 1
MAX_LINES: Final = 65_535  # also bounds a lines tree to depth 16
MAX_LINE_BYTES: Final = 512
MAX_EVIDENCE_REFS: Final = 256
MAX_REASON_CODES: Final = 32
MAX_BATCH: Final = 1_000
MAX_TOKEN_PATH: Final = 10  # ceil(log2(MAX_BATCH))
MAX_TOKEN_LIFETIME: Final = 7 * 24 * 3600  # seconds from issued_at to expires_at
MAX_RETRY_AFTER_MS: Final = 3_600_000
MAX_REQUEST_BYTES: Final = 8 * 1024 * 1024
MAX_TOKEN_BYTES: Final = 4 * 1024  # the largest canonical token is 4,051 bytes
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

    def digest(self, value: object, label: str) -> None:
        if type(value) is not bytes or len(value) != DIGEST:
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


def decision_id(tenant_id: str, program_id: str, flow: str, payment_id: str, revision: int) -> bytes:
    """SHA3-512(RR/GATE/DECISION-ID/v1 || tenant || program || flow || payment_id || revision).
    One decision per payment and revision; the command key only maps to it."""
    w = _Writer(DECISION_ID)
    w.ident(tenant_id, "tenant_id")
    w.ident(program_id, "program_id")
    w.tag(FLOWS, flow, "flow")
    w.ident(payment_id, "payment_id")
    w.int(revision, 8, "revision")
    return sha3_512(bytes(w.out))


def input_commitment(request: "DecideRequest", read_set_digest: bytes) -> bytes:
    """SHA3-512(RR/GATE/INPUT/v1 || u32 length || canonical request || read-set digest)."""
    body = encode_decide_request(request)
    w = _Writer(INPUT)
    w.int(len(body), 4, "request")
    w.out += body
    w.digest(read_set_digest, "read_set_digest")
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


@dataclass(frozen=True)
class DecideRequest:
    tenant_id: str
    program_id: str
    flow: str
    command_key: str
    payment_id: str
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
    w.ident(request.payee_ref, "payee_ref")
    w.int(request.amount_cents, 8, "amount_cents")
    w.ident(request.period, "period")
    if type(request.lines) is not tuple or (request.flow == "FFS_CLAIM" and request.lines):
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
    seq_from: int
    seq_to: int
    epoch: int
    prev_checkpoint_digest: bytes
    event_head: bytes
    token_root: bytes
    evidence_root: bytes
    projections_digest: bytes
    count: int
    created_at: int


_CHECKPOINT_DIGESTS = ("prev_checkpoint_digest", "event_head", "token_root", "evidence_root", "projections_digest")


def encode_checkpoint_header(cp: Checkpoint) -> bytes:
    """The exact bytes the epoch's ML-DSA-87 key signs."""
    w = _Writer(CHECKPOINT)
    w.int(SIG_ML_DSA_87_BATCH, 1, "sig_alg")
    w.ident(cp.tenant_id, "tenant_id")
    w.ident(cp.program_id, "program_id")
    w.int(cp.seq_from, 8, "seq_from")
    w.int(cp.seq_to, 8, "seq_to")
    w.int(cp.epoch, 8, "epoch")
    for name in _CHECKPOINT_DIGESTS:
        w.digest(getattr(cp, name), name)
    w.int(cp.count, 2, "count", low=1, high=MAX_BATCH)
    w.int(cp.created_at, 8, "created_at")
    if cp.seq_to - cp.seq_from + 1 != cp.count:
        _fail("seq_range")
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
    """Leaf fields in design order; ``decision_id`` is derived, never supplied."""

    tenant_id: str
    program_id: str
    flow: str
    revision: int
    supersedes: bytes | None
    payment_id: str
    payee_ref: str
    amount_cents: int
    period: str
    lines_root: bytes
    line_count: int
    outcome: str
    reason_codes: tuple[str, ...]
    authority: str
    grant_id: bytes
    rule_version: bytes
    engine_release: bytes
    input_commitment: bytes
    epoch: int
    seq: int
    issued_at: int
    expires_at: int


@dataclass(frozen=True)
class Token:
    leaf: TokenLeaf
    siblings: tuple[bytes, ...]
    checkpoint_digest: bytes
    epoch_cert_id: bytes


def encode_token_leaf(leaf: TokenLeaf) -> bytes:
    """The canonical leaf; its bytes are what the batch Merkle tree commits to."""
    w = _Writer(TOKEN)
    w.ident(leaf.tenant_id, "tenant_id")
    w.ident(leaf.program_id, "program_id")
    w.tag(FLOWS, leaf.flow, "flow")
    w.digest(decision_id(leaf.tenant_id, leaf.program_id, leaf.flow, leaf.payment_id, leaf.revision), "decision_id")
    w.int(leaf.revision, 8, "revision")
    if (leaf.revision == 0) != (leaf.supersedes is None):
        _fail("supersedes")
    if leaf.supersedes is not None:
        w.out.append(1)
        w.digest(leaf.supersedes, "supersedes")
    else:
        w.out.append(0)
    w.ident(leaf.payment_id, "payment_id")
    w.ident(leaf.payee_ref, "payee_ref")
    w.int(leaf.amount_cents, 8, "amount_cents")
    w.ident(leaf.period, "period")
    w.digest(leaf.lines_root, "lines_root")
    w.int(leaf.line_count, 2, "line_count", high=MAX_LINES)
    if (leaf.line_count == 0) != (leaf.lines_root == ZERO_DIGEST) or (leaf.flow == "FFS_CLAIM" and leaf.line_count):
        _fail("lines_root")
    w.tag(OUTCOMES, leaf.outcome, "outcome")
    if type(leaf.reason_codes) is not tuple:
        _fail("reason_codes")
    w.int(len(leaf.reason_codes), 1, "reason_codes", high=MAX_REASON_CODES)
    for code in leaf.reason_codes:
        w.ident(code, "reason_code", _CODE)
    _sorted_unique(leaf.reason_codes, "reason_codes")
    w.tag(AUTHORITIES, leaf.authority, "authority")
    for name in ("grant_id", "rule_version", "engine_release", "input_commitment"):
        w.digest(getattr(leaf, name), name)
    for name in ("epoch", "seq", "issued_at", "expires_at"):
        w.int(getattr(leaf, name), 8, name)
    if not leaf.issued_at <= leaf.expires_at <= leaf.issued_at + MAX_TOKEN_LIFETIME:
        _fail("lifetime")
    return bytes(w.out)


def encode_token(token: Token) -> bytes:
    """leaf || path || checkpoint_digest || epoch_cert_id.  The signed checkpoint
    travels separately, once per batch (``encode_checkpoint``)."""
    w = _Writer(encode_token_leaf(token.leaf))
    if type(token.siblings) is not tuple:
        _fail("path")
    w.int(len(token.siblings), 1, "path", high=MAX_TOKEN_PATH)
    for sibling in token.siblings:
        w.digest(sibling, "path")
    w.digest(token.checkpoint_digest, "checkpoint_digest")
    w.digest(token.epoch_cert_id, "epoch_cert_id")
    return bytes(w.out)


def sign_batch(
    leaves: Sequence[TokenLeaf],
    *,
    prev_checkpoint_digest: bytes,
    event_head: bytes,
    evidence_root: bytes,
    projections_digest: bytes,
    created_at: int,
    epoch_cert_id: bytes,
    sign: Callable[[bytes], bytes],
) -> tuple[Checkpoint, bytes, list[Token]]:
    """One checkpoint and one ML-DSA-87 signature for a whole batch (the batching
    invariant); each payment's token is its leaf plus a Merkle path to token_root.
    Leaves must be one writer's consecutive commits: same scope and epoch, seq
    increasing by one, and at most one leaf per payment.  ``sign`` is the only
    signing call (see right_rail_gate_signer)."""
    if not 1 <= len(leaves) <= MAX_BATCH:
        _fail("batch")
    first = leaves[0]
    for index, leaf in enumerate(leaves):
        if (leaf.tenant_id, leaf.program_id, leaf.epoch, leaf.seq) != (first.tenant_id, first.program_id, first.epoch, first.seq + index):
            _fail("batch")
    if len({(leaf.flow, leaf.payment_id) for leaf in leaves}) != len(leaves):
        _fail("batch_payment")
    root, paths = merkle_tree(MERKLE_NODE, [encode_token_leaf(leaf) for leaf in leaves])
    checkpoint = Checkpoint(
        first.tenant_id, first.program_id, first.seq, first.seq + len(leaves) - 1, first.epoch,
        prev_checkpoint_digest, event_head, root, evidence_root, projections_digest, len(leaves), created_at,
    )
    digest = checkpoint_digest(checkpoint)
    signature = sign(encode_checkpoint_header(checkpoint))
    return checkpoint, signature, [Token(leaf, tuple(path), digest, epoch_cert_id) for leaf, path in zip(leaves, paths)]


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
    carries a second copy of them."""
    w = _Writer(DECIDE_RESPONSE)
    w.ident(response.tenant_id, "tenant_id")
    w.ident(response.program_id, "program_id")
    w.ident(response.command_key, "command_key")
    w.tag(STATUSES, response.status, "status")
    carries = (response.token is not None, response.reject_code is not None, response.retry_after_ms is not None)
    if carries != (response.status in TOKEN_STATUSES, response.status == "REJECTED", response.status == "UNAVAILABLE"):
        _fail("status")
    if response.token is not None:
        if (response.token.leaf.tenant_id, response.token.leaf.program_id) != (response.tenant_id, response.program_id):
            _fail("token_binding")
        token = encode_token(response.token)
        w.int(len(token), 4, "token", high=MAX_TOKEN_BYTES)
        w.out += token
    elif response.reject_code is not None:
        w.tag(REJECT_CODES, response.reject_code, "reject_code")
    else:
        w.int(response.retry_after_ms, 4, "retry_after_ms", low=1, high=MAX_RETRY_AFTER_MS)
    return bytes(w.out)
