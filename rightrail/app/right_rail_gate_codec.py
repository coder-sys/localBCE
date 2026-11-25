"""Payment gate wire formats.

Formats: ``RR/GATE/DECIDE-REQUEST/v2``, ``RR/GATE/DECIDE-RESPONSE/v2``,
``RR/GATE/TOKEN/v3``, ``RR/GATE/CHECKPOINT/v3`` (ML-DSA-87 per-batch variant
only), ``RR/GATE/KEY-CERT/v2`` (the tenant's root key signs and its witness key countersigns one epoch key and the verifier key, under an authority link; Lean
``Cosign.KeyCert``), the verifier's cosign record ``RR/GATE/VCOSIGN/v1`` and the SHA3-512 digest domains ``RR/GATE/DECISION-ID/v1``,
``RR/GATE/EARLIER/v1`` (the earlier payments an answered payment repeats),
``RR/GATE/MERKLE-NODE/v1`` (the batch token tree),
``RR/GATE/LINES-NODE/v1`` (a payment's lines tree), ``RR/GATE/SHARD/v1``
(a member's shard).

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
from typing import Final, NamedTuple, Sequence


class GateCodecError(ValueError):
    """A value the gate formats cannot carry.  The message is a fixed code."""


DECIDE_REQUEST: Final = b"RR/GATE/DECIDE-REQUEST/v2\x00"
DECIDE_RESPONSE: Final = b"RR/GATE/DECIDE-RESPONSE/v2\x00"
TOKEN: Final = b"RR/GATE/TOKEN/v3\x00"
EARLIER: Final = b"RR/GATE/EARLIER/v1\x00"
CHECKPOINT: Final = b"RR/GATE/CHECKPOINT/v3\x00"
KEY_CERT: Final = b"RR/GATE/KEY-CERT/v2\x00"
VCOSIGN: Final = b"RR/GATE/VCOSIGN/v1\x00"  # the verifier's cosign record, and the domain of what it signs
DECISION_ID: Final = b"RR/GATE/DECISION-ID/v1\x00"
CONTEXT: Final = b"RR/GATE/CONTEXT/v1\x00"
INPUT_V7: Final = b"RR/GATE/INPUT/v7\x00"
MERKLE_NODE: Final = b"RR/GATE/MERKLE-NODE/v1\x00"
LINES_NODE: Final = b"RR/GATE/LINES-NODE/v1\x00"
SHARD: Final = b"RR/GATE/SHARD/v1\x00"
STATE: Final = b"RR/GATE/STATE/v1\x00"

FLOWS: Final = ("FFS_CYCLE", "FFS_CLAIM", "CAP_820", "SDP", "PLAN_PAY")
RULED: Final = FLOWS[:3]  # decided line by line, so each payment carries a line; SDP and PLAN_PAY: HUMAN_REVIEW
# ANSWERED: an exact repeat of a paid line, answered at once with the earlier payments it repeats (Constitution I.4).
OUTCOMES: Final = ("ALLOW", "HOLD", "HUMAN_REVIEW", "BLOCK", "ANSWERED")
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
MEMBER_KEY: Final = 32  # the member's salted hash
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
MAX_TOKEN_BYTES: Final = 4 * 1024  # the largest canonical token is 4,028 bytes (tests/test_gate_exact_duplicate.py)
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


def payment_input(context: bytes, head: bytes, lines: Sequence[bytes], tail: bytes) -> bytes:
    """INPUT/v7 of one DECIDE-REQUEST/v2 (conformance/ENGINE_V3.md section 18), one hash: the batch's CONTEXT/v1 digest,
    the request's bytes before the lines (``head``, after a 4-byte length), the root of its ``lines`` and its bytes
    after them (``tail``)."""
    return sha3_512(INPUT_V7 + context + len(head).to_bytes(4, "big") + head + lines_root(lines) + tail)


# ------------------------------------------------------ #1 DECIDE-REQUEST/v2


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
    contest: bool = False  # the sender disputes an exact repeat: it is decided as any other payment


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
    if type(request.contest) is not bool:
        _fail("contest")
    w.out.append(request.contest)
    if len(w.out) > MAX_REQUEST_BYTES:
        _fail("size")
    return bytes(w.out)


# ------------------------------------------------------------ #4 CHECKPOINT/v3


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
    counter: int  # the shard's TPM counter value this checkpoint takes (the previous value plus one)


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
    w.int(cp.counter, 8, "counter")
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


def attach_signature(body: bytes, signature: bytes) -> bytes:
    """body || u16 length || ML-DSA-87 signature: the signed form of a checkpoint header and of a KEY-CERT body."""
    w = _Writer(body)
    w.blob(signature, "signature", size=ML_DSA_87_SIGNATURE, low=ML_DSA_87_SIGNATURE)
    return bytes(w.out)


def encode_checkpoint(cp: Checkpoint, signature: bytes) -> bytes:
    """The signed checkpoint a payer fetches once per batch: header || signature."""
    return attach_signature(encode_checkpoint_header(cp), signature)


# ------------------------------------------------------------- #5 KEY-CERT/v2, the verifier's cosign record


MAX_KEY_CERT: Final = 16 * 1024  # Lean ``Cosign.maxCertBytes``
KEY_BYTES: Final = 1 + 2 + ML_DSA_87_PUBLIC_KEY  # scheme u8, u16 length, public key (scheme 1 is ML-DSA-87)
COSIGN_RECORD: Final = len(VCOSIGN) + DIGEST + 2 + ML_DSA_87_SIGNATURE  # 4,712 bytes


def encode_key(public_key: bytes) -> bytes:
    """A key as a certificate and an authority link carry it: scheme 1, u16 length, ML-DSA-87 public key."""
    w = _Writer(b"")
    w.int(SIG_ML_DSA_87_BATCH, 1, "scheme")
    w.blob(public_key, "public_key", size=ML_DSA_87_PUBLIC_KEY, low=ML_DSA_87_PUBLIC_KEY)
    return bytes(w.out)


def encode_key_cert(tenant_id: str, epoch: int, link: bytes, chain: Sequence[int], public_key: bytes, verifier_key: bytes) -> bytes:
    """The exact bytes the tenant's root key signs and its witness key countersigns (``attach_signatures`` makes the
    certificate): the epoch's ML-DSA-87 public key for the whole tenant, every program and shard, and the key that
    cosigns its checkpoints, under the authority link whose body digest is ``link``, with the tenant's shard counts
    up to this epoch (``chain``, the last one this epoch's)."""
    w = _Writer(KEY_CERT)
    w.ident(tenant_id, "tenant_id")
    w.int(epoch, 8, "epoch")
    w.digest(link, "link")
    w.int(len(chain), 1, "chain", low=1, high=32)
    for count in chain:
        w.int(count, 4, "shard_count", low=1)
    return bytes(w.out) + encode_key(public_key) + encode_key(verifier_key)


def attach_signatures(body: bytes, root_signature: bytes, witness_signature: bytes) -> bytes:
    """A KEY-CERT/v2 body, then u16 length and the root signature, then u16 length and the witness cosignature."""
    return attach_signature(attach_signature(body, root_signature), witness_signature)


class KeyCert(NamedTuple):
    tenant_id: str
    epoch: int
    link: bytes
    chain: tuple[int, ...]
    key: bytes
    verifier_key: bytes
    body: bytes
    root_signature: bytes
    witness_signature: bytes


def read_key_cert(cert: bytes) -> KeyCert:
    """A KEY-CERT/v2 as Lean ``Cosign.decode`` reads it (the same layout; the registered scheme is ML-DSA-87 alone).
    A certificate Lean would not decode raises ``ValueError``."""
    at = 0

    def take(n: int) -> bytes:
        nonlocal at
        if n > len(cert) - at:
            raise ValueError("key_cert")
        at += n
        return cert[at - n : at]

    def key() -> bytes:
        scheme, size = take(1), int.from_bytes(take(2), "big")
        if scheme != b"\x01" or size != ML_DSA_87_PUBLIC_KEY:
            raise ValueError("key_cert")
        return take(size)

    if len(cert) > MAX_KEY_CERT or take(len(KEY_CERT)) != KEY_CERT:
        raise ValueError("key_cert")
    tenant = take(int.from_bytes(take(2), "big"))
    if _ID.fullmatch(tenant.decode("ascii", "replace")) is None:
        raise ValueError("key_cert")
    epoch, link, chain = int.from_bytes(take(8), "big"), take(DIGEST), tuple(int.from_bytes(take(4), "big") for _ in range(take(1)[0]))
    if epoch > MAX_NAT or not 1 <= len(chain) <= 32 or chain[0] < 1 or any(b <= a or b % a for a, b in zip(chain, chain[1:])) or chain[-1] >= 1 << 32:
        raise ValueError("key_cert")
    epoch_key, verifier_key = key(), key()
    body = cert[:at]
    root_signature, witness_signature = take(int.from_bytes(take(2), "big")), take(int.from_bytes(take(2), "big"))
    if at != len(cert):
        raise ValueError("key_cert")
    return KeyCert(tenant.decode("ascii"), epoch, link, chain, epoch_key, verifier_key, body, root_signature, witness_signature)


def key_cert_shards(cert: bytes) -> int:
    """The shard count a KEY-CERT names for its own epoch: the last of its chain."""
    return read_key_cert(cert).chain[-1]


class Link(NamedTuple):
    """The parts of an AUTHORITY-LINK/v1 a Python caller reads (Lean ``Cosign.pLink``): its tenant, generation, body, the
    root and witness public keys and the two signatures.  The link's identity is the SHA3-512 of ``body``."""
    tenant_id: str
    gen: int
    body: bytes
    root_key: bytes
    witness_key: bytes
    self_signature: bytes
    co_signature: bytes


LINK: Final = b"RR/GATE/AUTHORITY-LINK/v1\x00"
MAX_LINK: Final = 16 * 1024  # Lean ``Cosign.maxLinkBytes``


def read_link(link: bytes) -> Link:
    """An AUTHORITY-LINK/v1 as Lean ``Cosign.decodeLink`` reads it; one Lean would not decode raises ``ValueError``."""
    at = 0

    def take(n: int) -> bytes:
        nonlocal at
        if n > len(link) - at:
            raise ValueError("link")
        at += n
        return link[at - n : at]

    def key() -> bytes:
        scheme, size = take(1), int.from_bytes(take(2), "big")
        if scheme != b"\x01" or size != ML_DSA_87_PUBLIC_KEY:
            raise ValueError("link")
        return take(size)

    if len(link) > MAX_LINK or take(len(LINK)) != LINK:
        raise ValueError("link")
    tenant = take(int.from_bytes(take(2), "big"))
    gen, base, _prev, change = int.from_bytes(take(4), "big"), int.from_bytes(take(4), "big"), take(DIGEST), take(1)[0]
    root = key()
    take(DIGEST)
    witness = key()
    take(DIGEST)
    flag, closed = take(1)[0], int.from_bytes(take(8), "big")
    take(DIGEST)
    body = link[:at]
    self_signature, co_signature = take(int.from_bytes(take(2), "big")), take(int.from_bytes(take(2), "big"))
    if (at != len(link) or _ID.fullmatch(tenant.decode("ascii", "replace")) is None or gen >= 1 << 31 or base > gen
            or change > 2 or flag > 1 or (flag == 0 and closed) or closed > MAX_NAT):
        raise ValueError("link")
    return Link(tenant.decode("ascii"), gen, body, root, witness, self_signature, co_signature)


def encode_link(tenant_id: str, root_key: bytes, root_next: bytes, witness_key: bytes, witness_next: bytes, approval: bytes, sign_root, sign_witness) -> bytes:
    """A genesis AUTHORITY-LINK/v1 (generation 0, nothing closed), the layout ``read_link`` reads: the keys and the digests of
    the keys that will follow them, the digest of the approval it records (Lean carries it and checks only its length), then
    ``sign_root(body)`` and ``sign_witness(body)`` as the two signatures."""
    w = _Writer(LINK)
    w.ident(tenant_id, "tenant_id")
    w.out += bytes(8) + bytes(DIGEST) + b"\x00"  # generation and base 0, no previous link, change 0 (genesis)
    for key, following in ((root_key, root_next), (witness_key, witness_next)):
        w.out += encode_key(key)
        w.digest(following, "next_key")
    w.out += bytes(9)  # nothing closed
    w.digest(approval, "approval")
    return attach_signatures(bytes(w.out), sign_root(bytes(w.out)), sign_witness(bytes(w.out)))


def cosign_message(header: bytes, vrel: bytes) -> bytes:
    """What the verifier signs (Lean ``vcosignMsg``): the VCOSIGN domain, the checkpoint digest, its own release."""
    return VCOSIGN + sha3_512(header) + vrel


def encode_cosign(vrel: bytes, signature: bytes) -> bytes:
    """The cosign record a signed checkpoint may end with: VCOSIGN, the verifier release (64), u16 length, signature."""
    w = _Writer(VCOSIGN)
    w.digest(vrel, "vrel")
    w.blob(signature, "signature", size=ML_DSA_87_SIGNATURE, low=ML_DSA_87_SIGNATURE)
    return bytes(w.out)


# ------------------------------------------------------------------ #3 TOKEN/v3


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
    bypass: bytes  # the admitted bypass's id; zero when none
    rule_version: bytes
    engine_release: bytes
    input_commitment: bytes
    decided_at: int
    epoch: int
    seq: int
    issued_at: int
    expires_at: int
    earlier_root: bytes = ZERO_DIGEST  # on the wire after bypass; nonzero exactly when ANSWERED (``earlier_root``)


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
    w.digest(leaf.grant_id, "grant_id")
    w.digest(leaf.bypass, "bypass")
    if leaf.bypass != ZERO_DIGEST and not (leaf.outcome == "ALLOW" and leaf.flow in RULED):
        _fail("bypass")
    w.digest(leaf.earlier_root, "earlier_root")
    if (leaf.earlier_root == ZERO_DIGEST) != (leaf.outcome != "ANSWERED"):
        _fail("earlier_root")
    for name in ("rule_version", "engine_release", "input_commitment"):
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


def build_batch(
    leaves: Sequence[TokenLeaf],
    *,
    prev_checkpoint_digest: bytes,
    event_head: bytes,
    evidence_root: bytes,
    state_digest: bytes,
    created_at: int,
    counter: int,
) -> tuple[Checkpoint, list[Token]]:
    """One checkpoint for a whole batch; each payment's token is its leaf plus a Merkle path to token_root.
    No key and no judgement: the leaves are one shard writer's consecutive commits, and Lean ``publishOk``
    (run by ``right_rail_gate_signer.seal`` before any signature leaves custody) is the only check."""
    first = leaves[0]
    root, paths = merkle_tree(MERKLE_NODE, [encode_token_leaf(leaf) for leaf in leaves])
    checkpoint = Checkpoint(
        first.tenant_id, first.program_id, first.shard_id, first.seq, first.seq + len(leaves) - 1, first.epoch,
        prev_checkpoint_digest, event_head, root, evidence_root, state_digest, len(leaves), created_at, counter,
    )
    digest = checkpoint_digest(checkpoint)
    return checkpoint, [Token(leaf, tuple(path), digest) for leaf, path in zip(leaves, paths)]


# ---------------------------------------------------------------- EARLIER/v1


def earlier_body(entries: Sequence[tuple[str, str, str, str]]) -> bytes:
    """The list's bytes: a u16 count, then per entry its line id, the earlier program, payment id and line id as
    identifiers; not empty, ascending by line id, at most one entry a line."""
    if type(entries) is not tuple:
        _fail("earlier")
    w = _Writer(b"")
    w.int(len(entries), 2, "earlier", low=1, high=MAX_LINES)
    for entry in entries:
        if type(entry) is not tuple or len(entry) != 4:
            _fail("earlier")
        for value in entry:
            w.ident(value, "earlier")
    _sorted_unique([entry[0].encode("ascii") for entry in entries], "earlier")
    return bytes(w.out)


def earlier_root(entries: Sequence[tuple[str, str, str, str]]) -> bytes:
    """An ANSWERED leaf's ``earlier_root``: SHA3-512 of ``RR/GATE/EARLIER/v1`` and the list's bytes."""
    return sha3_512(EARLIER + earlier_body(entries))


def _field(data: bytes, at: int) -> tuple[bytes, int]:
    """The u16-length-prefixed field of ``data`` at ``at``, and the offset after it."""
    end = at + 2 + int.from_bytes(data[at : at + 2], "big")
    if at + 2 > len(data) or end > len(data):
        _fail("truncated")
    return data[at + 2 : end], end


def read_earlier(data: bytes, at: int = 0) -> tuple[tuple[tuple[str, str, str, str], ...], int]:
    """The earlier list ``earlier_body`` wrote at ``at`` in ``data``, and the offset after it; any other bytes refuse."""
    start, entries = at, []
    if at + 2 > len(data):
        _fail("earlier")
    at += 2
    try:
        for _ in range(int.from_bytes(data[start:at], "big")):
            entry = []
            for _ in range(4):
                value, at = _field(data, at)
                entry.append(value.decode("ascii"))
            entries.append(tuple(entry))
    except UnicodeDecodeError:
        _fail("earlier")
    if earlier_body(tuple(entries)) != data[start:at]:  # canonical: not empty, identifiers, line ids ascending
        _fail("earlier")
    return tuple(entries), at


_TOKEN_EARLIER: Final = {TOKEN: DIGEST, b"RR/GATE/TOKEN/v2\x00": 0}  # earlier-root width by prefix; v2, sealed before 2026-11-16, has none


def _token_head(token: bytes) -> tuple[bytes, bytes, int, str, int]:
    """The program and payment ids of the token bytes ``encode_token`` wrote, the offset of its outcome (after the lines
    root), that outcome and its version's earlier-root width; another prefix, an outcome byte that names none, or ANSWERED
    in a version without an earlier root, refuses."""
    earlier = _TOKEN_EARLIER.get(token[: len(TOKEN)])
    if earlier is None:
        _fail("token")
    program, at = _field(token, _field(token, len(TOKEN))[1])  # tenant, program
    payment, at = _field(token, at + 4 + 1 + 8)  # shard, flow, revision
    at = _field(token, _field(token, at + MEMBER_KEY)[1] + 8)[1] + DIGEST  # payee, amount, period, lines root
    if at >= len(token) or not 1 <= token[at] <= len(OUTCOMES) or not earlier and OUTCOMES[token[at] - 1] == "ANSWERED":
        _fail("outcome")  # ANSWERED came with the earlier root (TOKEN/v3): no v2 token names it
    return program, payment, at, OUTCOMES[token[at] - 1], earlier


def read_token_lines(token: bytes) -> tuple[str, str, bytes, str]:
    """(program id, payment id, lines root, outcome) of the token bytes ``encode_token`` wrote; read, not checked."""
    program, payment, at, outcome, _ = _token_head(token)
    return program.decode("ascii"), payment.decode("ascii"), token[at - DIGEST : at], outcome


def token_leaf(token: bytes) -> bytes:
    """The leaf (``encode_token_leaf`` of the token's own version) the token bytes ``encode_token`` wrote begin with;
    read, not checked."""
    _, _, at, _, earlier = _token_head(token)
    at += 2  # outcome, reason count
    if at > len(token):
        _fail("truncated")
    for _ in range(token[at - 1]):
        at = _field(token, at)[1]
    at += 1 + 5 * DIGEST + earlier + 5 * 8  # authority; grant, bypass, rule version, engine release, input; earlier root; five times
    if at > len(token):
        _fail("truncated")
    return token[:at]


def read_token(token: bytes) -> tuple[str, str, tuple[str, ...], bytes]:
    """(payment id, outcome, reason codes, earlier root) of the token bytes ``encode_token`` wrote, the zero digest for
    a version without one; read, not checked."""
    _, payment, at, outcome, earlier = _token_head(token)
    reasons = []
    at += 2
    for _ in range(token[at - 1]):
        code, at = _field(token, at)
        reasons.append(code.decode("ascii"))
    at += 1 + 2 * DIGEST  # authority, grant, bypass
    return payment.decode("ascii"), outcome, tuple(reasons), token[at : at + DIGEST] if earlier else ZERO_DIGEST


# -------------------------------------------------------- #2 DECIDE-RESPONSE/v2


@dataclass(frozen=True)
class DecideResponse:
    tenant_id: str
    program_id: str
    command_key: str
    status: str
    token: Token | None = None
    reject_code: str | None = None
    retry_after_ms: int | None = None
    earlier: tuple[tuple[str, str, str, str], ...] = ()  # after a carried token; not empty exactly when it is ANSWERED


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
        if response.earlier == () and response.token.leaf.outcome != "ANSWERED":
            w.int(0, 2, "earlier")
        elif response.earlier != () and earlier_root(response.earlier) == response.token.leaf.earlier_root:
            w.out += earlier_body(response.earlier)
        else:
            _fail("earlier")
    elif response.earlier != ():
        _fail("earlier")
    elif response.reject_code is not None:
        w.tag(REJECT_CODES, response.reject_code, "reject_code")
    else:
        w.int(response.retry_after_ms, 4, "retry_after_ms", low=1, high=MAX_RETRY_AFTER_MS)
    return bytes(w.out)
