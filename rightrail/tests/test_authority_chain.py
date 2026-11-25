"""A reader's authority state: AUTHORITY-LINK/v1 links and KEY-CERT/v2 certificates applied in order.

``tests/gate_vectors/authority_chain.vectors`` is produced by ``build_vectors`` (``python -m tests.test_authority_chain``)
with test-only keys and deterministic signatures, and judged by the Lean ``gate_vectors`` executable, which applies
each line with ``Cosign.installLink`` or ``Cosign.installCert``.  ``Reader`` is a second implementation of the same
state, written from the format and the rules alone: it shares no code with the encoder that builds the vectors, its
certificate check is the independent verifier of ``tests.test_key_cert_v2`` and its signature check is the pinned
ML-DSA-87 worker, not Lean.  The story runs through two re-geneses, so a key of either replaced chain is refused in
a later certificate and in a later link.  Synthetic, non-PHI.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass, field, replace
from pathlib import Path
import sqlite3
import subprocess
import sys
from typing import NamedTuple
import unittest

from tests import test_key_cert_v2 as kc
from tests import test_right_rail_gate_formats as fx

VECTORS = Path(__file__).resolve().parent / "gate_vectors" / "authority_chain.vectors"
TAG = b"RR/GATE/AUTHORITY-LINK/v1\x00"
MAX_BYTES, MAX_GEN = 16_384, (1 << 31) - 1
LINK_ANSWERS = ("same", "genesis", "extends", "conflicts", "stale", "refused", "malformed")
sha3 = kc.sha3


# The second implementation.

class Held(NamedTuple):
    """A decoded link; keys are encoded (scheme, length, public key)."""
    tenant: bytes
    gen: int
    base: int
    prev: bytes
    change: int  # 0 genesis, 1 root, 2 witness
    root: bytes
    root_next: bytes
    witness: bytes
    witness_next: bytes
    closed: int | None
    body: bytes
    self_sig: bytes
    co_sig: bytes

    @property
    def digest(self) -> bytes:
        return sha3(self.body)

    def fields(self) -> list[str]:
        return [self.tenant.decode(), str(self.gen), str(self.base), str(self.change), self.digest.hex(),
                "-" if self.closed is None else str(self.closed)]

    def seen(self) -> kc.Link:
        return kc.Link(self.tenant, self.gen, self.digest, self.root, self.root_next, self.witness, self.witness_next,
                       self.closed)


def read_link(data: bytes) -> Held | None:
    at = 0

    def take(n: int) -> bytes:
        nonlocal at
        if n > len(data) - at:
            raise ValueError
        at += n
        return data[at - n : at]

    def num(width: int) -> int:
        return int.from_bytes(take(width), "big")

    def key() -> bytes:
        start = at
        scheme, size = num(1), num(2)
        if kc.KEY_BYTES.get(scheme) != size:
            raise ValueError
        take(size)
        return data[start:at]

    try:
        if len(data) > MAX_BYTES or take(len(TAG)) != TAG:
            raise ValueError
        tenant, gen, base, prev, change = take(num(2)), num(4), num(4), take(64), num(1)
        root, root_next, witness, witness_next = key(), take(64), key(), take(64)
        flag, epoch, _approval = num(1), num(8), take(64)
        if (not kc._ID.fullmatch(tenant) or gen > MAX_GEN or base > gen or change > 2 or flag > 1
                or epoch >= 1 << 63 or (flag == 0 and epoch)):
            raise ValueError
        body = data[:at]
        self_sig, co_sig = take(num(2)), take(num(2))
        if at != len(data):
            raise ValueError
    except ValueError:
        return None
    return Held(tenant, gen, base, prev, change, root, root_next, witness, witness_next, epoch if flag else None, body,
                self_sig, co_sig)


def four_keys(n: Held) -> bool:
    return (n.root != n.witness and n.root_next != n.witness_next
            and not {sha3(n.root), sha3(n.witness)} & {n.root_next, n.witness_next})


def follows(p: Held, base: int, n: Held) -> bool:
    """``n`` validly succeeds ``p``, a link of the chain whose genesis is of generation ``base``."""
    if not (n.tenant == p.tenant and n.gen == p.gen + 1 and n.base == base and n.prev == p.digest and four_keys(n)
            and (n.closed is None or n.closed // kc.GEN_SPAN == p.gen)):
        return False
    if n.change == 1:
        return (sha3(n.root) == p.root_next and (n.witness, n.witness_next) == (p.witness, p.witness_next)
                and kc._signed(n.root, n.body, n.self_sig) and kc._signed(p.witness, n.body, n.co_sig))
    if n.change == 2:
        return (sha3(n.witness) == p.witness_next and (n.root, n.root_next) == (p.root, p.root_next)
                and kc._signed(n.witness, n.body, n.self_sig) and kc._signed(p.root, n.body, n.co_sig))
    return False


class Installed(NamedTuple):
    tenant: bytes
    epoch: int
    counts: list[int]
    key_digests: tuple[str, str]
    body_digest: str


@dataclass
class Reader:
    pins: dict[bytes, bytes] = field(default_factory=dict)
    chain: dict[bytes, list[Held]] = field(default_factory=dict)  # per tenant, newest first, since its latest genesis
    retired: dict[bytes, list[list[Held]]] = field(default_factory=dict)  # per tenant, the chains a genesis replaced
    conflicts: list[tuple[int, Held]] = field(default_factory=list)  # (base of the chain, second successor)
    certs: list[Installed] = field(default_factory=list)
    equivocations: list[tuple[Installed, Installed]] = field(default_factory=list)
    fence: dict[bytes, int] = field(default_factory=dict)

    def held(self, tenant: bytes) -> list[Held]:
        return self.chain.get(tenant, []) + [p for old in self.retired.get(tenant, []) for p in old]

    def _installable(self, n: Held) -> bool:
        """No key the link brings into office served in a held link of the tenant, and no installed certificate of
        the tenant has a key that is a key of the link or that the link commits to."""
        brought = {0: [n.root, n.witness], 1: [n.root], 2: [n.witness]}[n.change]
        if any(k in (p.root, p.witness) for k in brought for p in self.held(n.tenant)):
            return False
        named = {sha3(n.root).hex(), sha3(n.witness).hex(), n.root_next.hex(), n.witness_next.hex()}
        return not any(c.tenant == n.tenant and set(c.key_digests) & named for c in self.certs)

    def _owned(self, c: Installed) -> bool:
        """The tenant's chain holds the link of the certificate's generation, and the certificate is of the head's
        generation or at or below the closing epoch of the next generation's link."""
        chain, gen = self.chain.get(c.tenant, []), c.epoch // kc.GEN_SPAN
        nxt = next((p for p in chain if p.gen == gen + 1), None)
        return any(p.gen == gen for p in chain) and (chain[0].gen <= gen or (
            nxt is not None and nxt.closed is not None and c.epoch <= nxt.closed))

    def _raise(self, tenant: bytes, epoch: int) -> None:
        self.fence[tenant] = max(self.fence.get(tenant, 0), epoch)

    def link(self, data: bytes) -> tuple[str, list[str]]:
        n = read_link(data)
        if n is None:
            return "malformed", []
        return self._link(n), n.fields()

    def _link(self, n: Held) -> str:
        chain = self.chain.get(n.tenant)
        if any(p.digest == n.digest for p in self.held(n.tenant) + [q for _, q in self.conflicts]):
            return "same"
        if n.change == 0:
            if not (n.base == n.gen and n.closed is None and n.digest == self.pins.get(n.tenant) and four_keys(n)
                    and kc._signed(n.root, n.body, n.self_sig) and kc._signed(n.witness, n.body, n.co_sig)
                    and all(p.gen < n.gen for p in self.held(n.tenant)) and self._installable(n)):
                return "refused"
            if chain:
                self.retired.setdefault(n.tenant, []).insert(0, chain)
            self.chain[n.tenant] = [n]
            self._raise(n.tenant, n.gen * kc.GEN_SPAN)
            return "genesis"
        if not chain:
            return "refused"
        base = chain[-1].gen
        if follows(chain[0], base, n):
            if not self._installable(n):
                return "refused"
            chain.insert(0, n)
            self._raise(n.tenant, n.gen * kc.GEN_SPAN)
            return "extends"
        if any(follows(p, base, n) for p in chain[1:]):
            self.conflicts.append((base, n))
            self._raise(n.tenant, n.gen * kc.GEN_SPAN)
            return "conflicts"
        if any(follows(p, old[-1].gen, n) for old in self.retired.get(n.tenant, []) for p in old):
            return "stale"
        return "refused"

    def cert(self, data: bytes) -> str:
        nobody = kc.Link(b"", 0, b"", b"", b"", b"", b"", None)  # no certificate names the empty tenant
        _, f = kc.judge([nobody], data, [])
        if not f:
            return "MALFORMED"
        new = Installed(f[0].encode(), int(f[1]), [int(x) for x in f[3].split(",")], (f[4], f[5]), f[6])
        if any(new.body_digest in (c.body_digest, second.body_digest)
               for c, second in [(c, c) for c in self.certs] + self.equivocations):
            return "same"
        chain = self.chain.get(new.tenant)
        if not chain:
            return "unknownTenant"
        verdict, _ = kc.judge([p.seen() for p in chain], data,
                              [p.seen() for old in self.retired.get(new.tenant, []) for p in old])
        if verdict != "accept":
            return verdict
        if new.epoch < chain[0].gen * kc.GEN_SPAN and not any((c.tenant, c.epoch) == (new.tenant, new.epoch) for c in self.certs):
            return "belowFence"
        self._raise(new.tenant, new.epoch)
        twins = [c for c in self.certs if (c.tenant, c.epoch) == (new.tenant, new.epoch)]
        if twins:
            self.equivocations[:0] = [(c, new) for c in twins]
            return "equivocates"
        for c in self.certs:  # a certificate the chain disowns is kept but decides no fit
            first, later = (c, new) if c.epoch < new.epoch else (new, c)
            if c.tenant == new.tenant and self._owned(c) and later.counts[: len(first.counts)] != first.counts:
                return "unfit"
        self.certs.insert(0, new)
        return "installed"

    def state(self, tenant: bytes, epoch: int) -> list[str]:
        chain = self.chain.get(tenant, [])
        by_link = bool(chain) and any(q.tenant == tenant and base == chain[-1].gen and q.gen <= epoch // kc.GEN_SPAN
                                      for base, q in self.conflicts)
        by_cert = any((c.tenant, c.epoch) == (tenant, epoch) for c, _ in self.equivocations)
        blocked = "+".join(name for name, on in (("link", by_link), ("cert", by_cert)) if on) or "none"
        return [str(self.fence.get(tenant, 0)), blocked, str(len(chain)),
                str(sum(map(len, self.retired.get(tenant, [])))), str(sum(c.tenant == tenant for c in self.certs))]


# The encoder that builds the vectors.

@dataclass(frozen=True)
class Draft:
    """A link before signing.  Keys are test key names; a next key is the name of the key committed to."""
    gen: int
    base: int
    change: int
    root: str
    root_next: str
    witness: str
    witness_next: str
    prev: bytes = bytes(64)
    closed: int | None = None
    tenant: str = "state-a"
    approval: bytes = sha3(b"RR/GATE/TEST-ONLY-APPROVAL/v1\x00")

    def body(self) -> bytes:
        closed = bytes(9) if self.closed is None else b"\x01" + self.closed.to_bytes(8, "big")
        return (TAG + kc.blob(self.tenant.encode()) + self.gen.to_bytes(4, "big") + self.base.to_bytes(4, "big")
                + self.prev + bytes([self.change]) + kc.key(self.root) + sha3(kc.key(self.root_next))
                + kc.key(self.witness) + sha3(kc.key(self.witness_next)) + closed + self.approval)

    def signed(self, by: str, spoil: bool = False) -> bytes:
        """The link with the self signature and cosignature of the two named keys; ``spoil`` breaks both."""
        body, (first, second) = self.body(), by.split()
        sigs = [kc.sign(first, body), kc.sign(second, body)]
        if spoil:
            sigs = [bytes([s[0] ^ 1]) + s[1:] for s in sigs]
        return body + kc.blob(sigs[0]) + kc.blob(sigs[1])


def cert(epoch: int, under: Draft, key: str, verifier: str, by: str, counts: tuple[int, ...] = (1,),
         spoil: bool = False) -> bytes:
    c = kc.Cert(under.tenant, epoch, sha3(under.body()), counts, kc.key(key), kc.key(verifier))
    sigs = [kc.sign(name, c.body()) for name in by.split()]
    if spoil:
        sigs = [bytes([s[0] ^ 1]) + s[1:] for s in sigs]
    return c.body() + kc.blob(sigs[0]) + kc.blob(sigs[1])


def build_vectors() -> str:
    out = ["# One reader's authority state for tenant state-a, through two re-geneses.  Test-only keys; rnd = 0.",
           "# pin <tenant> <digest>: the reader's configured genesis digest for the tenant",
           "# auth-link <same, genesis, extends, conflicts, stale, refused or malformed> <name> <link>, then when it",
           "#   decodes: <tenant> <generation> <base> <change> <body digest> <closing epoch or ->",
           "# auth-cert <same, installed, unfit, equivocates, unknownTenant, belowFence or the refusal> <name> <certificate>",
           "# auth-state <name> <tenant> <epoch> <fence> <what blocks the epoch: link, cert, link+cert or none>",
           "#   <links in the chain> <retired links> <installed certificates>"]
    span = kc.GEN_SPAN

    def pin(d: Draft) -> None:
        out.append(f"pin {d.tenant} {sha3(d.body()).hex()}")

    def link(expect: str, name: str, d: Draft, by: str, spoil: bool = False) -> Draft:
        body = d.body()
        closed = "-" if d.closed is None else str(d.closed)
        out.append(" ".join(["auth-link", expect, name, d.signed(by, spoil).hex(), d.tenant, str(d.gen), str(d.base),
                             str(d.change), sha3(body).hex(), closed]))
        return d

    def certify(expect: str, name: str, data: bytes) -> None:
        out.append(f"auth-cert {expect} {name} {data.hex()}")

    def state(name: str, epoch: int, fence: int, blocked: str, links: int, retired: int, certs: int,
              tenant: str = "state-a") -> None:
        out.append(f"auth-state {name} {tenant} {epoch} {fence} {blocked} {links} {retired} {certs}")

    def after(p: Draft, change: int, new: str, new_next: str, closed: int | None = None) -> Draft:
        """The successor of ``p`` that replaces the root key (change 1) or the witness key (change 2)."""
        moved = ({"root": new, "root_next": new_next} if change == 1 else {"witness": new, "witness_next": new_next})
        return replace(p, gen=p.gen + 1, change=change, prev=sha3(p.body()), closed=closed, **moved)

    # Chain A: genesis at generation 0, a root rotation, a witness rotation.
    g0 = Draft(0, 0, 0, "a-r0", "a-r1", "a-w0", "a-w1")
    certify("unknownTenant", "before-any-link", cert(5, g0, "e5", "v5", "a-r0 a-w0"))
    out.append("auth-link malformed cut-short " + g0.signed("a-r0 a-w0")[:300].hex())
    link("refused", "genesis-without-a-pin", g0, "a-r0 a-w0")
    pin(replace(g0, approval=sha3(b"another approval")))
    link("refused", "genesis-is-not-the-pin", g0, "a-r0 a-w0")
    pin(g0)
    link("refused", "genesis-signatures-broken", g0, "a-r0 a-w0", spoil=True)
    link("refused", "genesis-cosigned-by-its-root", g0, "a-r0 a-r0")
    state("nothing-installed", 0, 0, "none", 0, 0, 0)
    link("genesis", "genesis", g0, "a-r0 a-w0")
    link("same", "held-link-again-with-broken-signatures", g0, "a-r0 a-w0", spoil=True)
    certify("installed", "epoch-5", cert(5, g0, "e5", "v5", "a-r0 a-w0"))
    certify("same", "epoch-5-again-with-broken-signatures", cert(5, g0, "e5", "v5", "a-r0 a-w0", spoil=True))
    certify("installed", "epoch-9", cert(9, g0, "e9", "v9", "a-r0 a-w0"))
    state("genesis-and-two-certificates", 9, 9, "none", 1, 0, 2)
    l1 = after(g0, 1, "a-r1", "a-r2", closed=5)
    l2 = after(l1, 2, "a-w1", "a-w2")
    link("refused", "arrives-before-its-predecessor", l2, "a-w1 a-r1")
    link("refused", "cosigned-by-the-outgoing-root", l1, "a-r1 a-r0")
    link("refused", "commits-to-an-installed-certificate-key", replace(l1, root_next="e5"), "a-r1 a-w0")
    link("refused", "closes-an-epoch-of-another-generation", replace(l1, closed=span), "a-r1 a-w0")
    state("refused-links-change-nothing", 9, 9, "none", 1, 0, 2)
    link("extends", "root-rotation-closing-epoch-5", l1, "a-r1 a-w0")
    state("fence-at-generation-1", span, span, "none", 2, 0, 2)
    certify("same", "epoch-9-is-above-the-closing-bound-and-stays", cert(9, g0, "e9", "v9", "a-r0 a-w0"))
    certify("AFTER_ROTATION", "epoch-6-after-the-rotation", cert(6, g0, "e6", "v6", "a-r0 a-w0"))
    certify("belowFence", "epoch-3-under-the-closing-bound-is-late", cert(3, g0, "e3", "v3", "a-r0 a-w0"))
    link("extends", "witness-rotation", l2, "a-w1 a-r1")
    fork = replace(l1, root_next="a-rx")
    link("conflicts", "second-successor-of-the-genesis", fork, "a-r1 a-w0")
    link("same", "recorded-conflict-again", fork, "a-r1 a-w0")
    state("conflict-blocks-from-generation-1", span, 2 * span, "link", 3, 0, 2)
    state("conflict-leaves-generation-0", 5, 2 * span, "none", 3, 0, 2)

    # First re-genesis: chain B at generation 5 retires chain A.
    b5 = Draft(5, 5, 0, "b-r0", "b-r1", "b-w0", "b-w1", prev=sha3(l2.body()))
    reuse = replace(b5, root="a-w0")
    pin(reuse)
    link("refused", "genesis-with-a-key-of-the-chain-it-replaces", reuse, "a-w0 b-w0")
    low = replace(b5, gen=2, base=2)
    pin(low)
    link("refused", "genesis-not-above-every-held-link", low, "b-r0 b-w0")
    taken = replace(b5, witness_next="e5")
    pin(taken)
    link("refused", "genesis-commits-to-an-installed-certificate-key", taken, "b-r0 b-w0")
    pin(b5)
    link("genesis", "first-re-genesis", b5, "b-r0 b-w0")
    state("re-genesis-lifts-the-conflict", 5 * span, 5 * span, "none", 1, 3, 2)
    l3 = after(l2, 1, "a-r2", "a-r3")
    link("stale", "successor-in-the-replaced-chain", l3, "a-r2 a-w1")
    certify("KEY_REUSE", "epoch-key-was-a-root-of-the-replaced-chain",
            cert(5 * span, b5, "a-r0", "v50", "b-r0 b-w0"))
    certify("installed", "first-epoch-of-generation-5", cert(5 * span, b5, "e50", "v50", "b-r0 b-w0"))
    certify("equivocates", "another-body-for-that-epoch", cert(5 * span, b5, "e51", "v51", "b-r0 b-w0"))
    certify("same", "recorded-equivocation-again", cert(5 * span, b5, "e51", "v51", "b-r0 b-w0"))
    certify("unfit", "shard-counts-do-not-continue", cert(5 * span + 2, b5, "e52", "v52", "b-r0 b-w0", counts=(2,)))
    state("equivocation-blocks-its-epoch", 5 * span, 5 * span + 2, "cert", 1, 3, 3)
    b6 = after(b5, 1, "b-r1", "b-r2", closed=5 * span + 2)
    link("extends", "root-rotation-in-the-second-chain", b6, "b-r1 b-w0")

    # Second re-genesis: chain C at generation 9 retires chain B; both replaced chains still count for key reuse.
    c9 = Draft(9, 9, 0, "c-r0", "a-r1", "c-w0", "c-w1", prev=sha3(b6.body()))
    pin(c9)
    link("genesis", "second-re-genesis", c9, "c-r0 c-w0")
    state("two-chains-retired", 9 * span, 9 * span, "none", 1, 5, 3)
    link("stale", "successor-in-the-first-replaced-chain", l3, "a-r2 a-w1")
    link("stale", "successor-in-the-second-replaced-chain", after(b6, 2, "b-w1", "b-w2"), "b-w1 b-r1")
    certify("KEY_REUSE", "epoch-key-was-a-witness-of-the-first-chain", cert(9 * span, c9, "a-w0", "v90", "c-r0 c-w0"))
    certify("KEY_REUSE", "verifier-key-was-a-root-of-the-second-chain", cert(9 * span, c9, "e90", "b-r1", "c-r0 c-w0"))
    certify("KEY_REUSE", "epoch-key-was-committed-in-the-first-chain", cert(9 * span, c9, "a-w2", "v90", "c-r0 c-w0"))
    certify("installed", "first-epoch-of-generation-9", cert(9 * span, c9, "e90", "v90", "c-r0 c-w0"))
    link("refused", "new-root-was-a-root-of-the-first-chain", after(c9, 1, "a-r1", "c-r2"), "a-r1 c-w0")
    link("extends", "witness-rotation-in-the-third-chain", after(c9, 2, "c-w1", "c-w2"), "c-w1 c-r0")
    state("after-two-re-geneses", 10 * span, 10 * span, "none", 2, 5, 4)
    state("another-tenant-is-untouched", 0, 0, "none", 0, 0, 0, tenant="state-b")

    # A late certificate of the closing generation cannot fix shard counts that the current generation then contradicts.
    k0 = Draft(0, 0, 0, "k-r0", "k-r1", "k-w0", "k-w1", tenant="state-c")
    pin(k0)
    link("genesis", "state-c-genesis", k0, "k-r0 k-w0")
    k1 = after(k0, 1, "k-r1", "k-r2", closed=10)
    link("extends", "state-c-root-rotation", k1, "k-r1 k-w0")
    certify("belowFence", "late-certificate-of-the-closing-generation", cert(3, k0, "ke0", "kv0", "k-r0 k-w0", counts=(1, 7)))
    certify("installed", "current-generation-counts-are-not-contradicted",
            cert(span, k1, "ke1", "kv1", "k-r1 k-w0", counts=(1, 2)))
    state("late-certificate-leaves-no-trace", span, span, "none", 2, 0, 1, tenant="state-c")

    # A certificate a rotation disowns (above its closing bound) is kept, but no longer decides a fit; a re-genesis
    # starts with no counts to fit.
    d0 = Draft(0, 0, 0, "d-r0", "d-r1", "d-w0", "d-w1", tenant="state-d")
    pin(d0)
    link("genesis", "state-d-genesis", d0, "d-r0 d-w0")
    certify("installed", "state-d-epoch-4", cert(4, d0, "de4", "dv4", "d-r0 d-w0"))
    certify("installed", "state-d-epoch-9-before-the-rotation", cert(9, d0, "de9", "dv9", "d-r0 d-w0", counts=(1, 7)))
    d1 = after(d0, 1, "d-r1", "d-r2", closed=5)
    link("extends", "state-d-rotation-closing-epoch-5", d1, "d-r1 d-w0")
    certify("installed", "disowned-epoch-9-decides-no-fit", cert(span, d1, "de1", "dv1", "d-r1 d-w0", counts=(1, 2)))
    certify("unfit", "owned-certificates-still-decide", cert(span + 1, d1, "de2", "dv2", "d-r1 d-w0", counts=(2,)))
    certify("equivocates", "late-certificate-of-an-installed-epoch", cert(4, d0, "de4b", "dv4b", "d-r0 d-w0"))
    state("late-equivocation-blocks-its-epoch", 4, span + 1, "cert", 2, 0, 3, tenant="state-d")
    d3 = Draft(3, 3, 0, "d2-r0", "d2-r1", "d2-w0", "d2-w1", prev=sha3(d1.body()), tenant="state-d")
    pin(d3)
    link("genesis", "state-d-re-genesis", d3, "d2-r0 d2-w0")
    certify("installed", "re-genesis-starts-with-no-counts", cert(3 * span, d3, "de30", "dv30", "d2-r0 d2-w0", counts=(2,)))
    state("state-d-after-re-genesis", 3 * span, 3 * span, "none", 1, 2, 4, tenant="state-d")
    checked = sum(not x.startswith(("#", "pin ")) for x in out)
    return "\n".join(out) + f"\nend {checked}\n"


class AuthorityChainVectorTests(unittest.TestCase):
    def test_python_reproduces_every_vector_byte(self) -> None:
        self.assertEqual(build_vectors(), VECTORS.read_text("ascii"))

    def test_lean_judges_every_vector(self) -> None:
        done = subprocess.run([str(fx.LEAN_VECTORS), str(VECTORS)], capture_output=True, text=True, timeout=1800, check=False)
        self.assertRegex(done.stdout.strip(), r"^GATE_VECTORS=PASS checked=(\d+) expected=\1 failed=0$")

    def test_second_implementation_agrees_on_every_vector(self) -> None:
        reader, seen, sizes, end = Reader(), [], [], None
        for line in VECTORS.read_text("ascii").splitlines():
            kind, *rest = line.split(" ")
            if kind == "pin":
                reader.pins[rest[0].encode()] = bytes.fromhex(rest[1])
            elif kind == "auth-link":
                expect, name, data, *fields = rest
                with self.subTest(name):
                    self.assertEqual(reader.link(bytes.fromhex(data)), (expect, fields))
                seen.append(expect)
                if expect in ("genesis", "extends"):
                    sizes.append(len(data) // 2)
            elif kind == "auth-cert":
                expect, name, data = rest
                with self.subTest(name):
                    self.assertEqual(reader.cert(bytes.fromhex(data)), expect)
                seen.append(expect)
            elif kind == "auth-state":
                name, tenant, epoch, *expect = rest
                with self.subTest(name):
                    self.assertEqual(reader.state(tenant.encode(), int(epoch)), expect)
                seen.append("state")
            elif kind == "end":
                end = int(rest[0])
        self.assertEqual(len(seen), end)
        self.assertLessEqual({*LINK_ANSWERS, "installed", "unfit", "equivocates", "unknownTenant", "belowFence",
                              "KEY_REUSE", "AFTER_ROTATION"}, set(seen))
        self.assertEqual(set(sizes), {5496 + len("state-a") + 2 * 4627})  # an ML-DSA-87 link of this tenant

    def test_second_re_genesis_keeps_both_replaced_chains_for_key_reuse(self) -> None:
        """After two re-geneses the reader holds the links of both replaced chains, and a key of either is refused
        as a certificate key and as a link's new key, while fresh keys are accepted."""
        reader, answers = Reader(), {}
        for line in VECTORS.read_text("ascii").splitlines():
            kind, *rest = line.split(" ")
            if kind == "pin":
                reader.pins[rest[0].encode()] = bytes.fromhex(rest[1])
            elif kind == "auth-link":
                answers[rest[1]] = reader.link(bytes.fromhex(rest[2]))[0]
            elif kind == "auth-cert":
                answers[rest[1]] = reader.cert(bytes.fromhex(rest[2]))
        self.assertEqual([len(old) for old in reader.retired[b"state-a"]], [2, 3])  # newest replaced chain first
        self.assertEqual([p.gen for p in reader.chain[b"state-a"]], [10, 9])
        self.assertEqual({name: answers[name] for name in (
            "second-re-genesis", "epoch-key-was-a-witness-of-the-first-chain",
            "verifier-key-was-a-root-of-the-second-chain", "epoch-key-was-committed-in-the-first-chain",
            "first-epoch-of-generation-9", "new-root-was-a-root-of-the-first-chain",
            "witness-rotation-in-the-third-chain")},
            {"second-re-genesis": "genesis", "epoch-key-was-a-witness-of-the-first-chain": "KEY_REUSE",
             "verifier-key-was-a-root-of-the-second-chain": "KEY_REUSE",
             "epoch-key-was-committed-in-the-first-chain": "KEY_REUSE", "first-epoch-of-generation-9": "installed",
             "new-root-was-a-root-of-the-first-chain": "refused", "witness-rotation-in-the-third-chain": "extends"})


class PayerStoreTests(fx.Scratch):
    def test_the_payer_store_answers_the_rotation_vectors(self) -> None:
        """Tenants state-c and state-d through ``PayerStore``, a genesis as the configured link at open: each answer is
        the vector's, a late certificate is ``cert_refused: BELOW_FENCE``, and the certificates a rotation disowns are not
        carried as fit witnesses."""
        from app import right_rail_gate_payer as payer
        answers = {"installed": "INSTALLED", "unfit": "UNFIT", "equivocates": "EQUIVOCATES", "extends": "EXTENDS"}
        configured, store, tenant, seen = {}, None, "", []
        with self.scratch() as tmp:
            path = Path(tmp) / "payer.sqlite3"
            for kind, *rest in (line.split(" ") for line in VECTORS.read_text("ascii").splitlines()):
                if kind == "auth-link" and len(rest) > 3:
                    tenant = rest[3]
                if tenant not in ("state-c", "state-d") or kind not in ("auth-link", "auth-cert", "auth-state"):
                    continue
                with self.subTest(rest[0] if kind == "auth-state" else rest[1]):
                    if kind == "auth-state":
                        self.assertEqual(store._db.execute("SELECT count(*) FROM certs WHERE tenant=? AND role='INSTALLED'",
                                                           (rest[1],)).fetchone()[0], int(rest[-1]))
                        continue
                    expect, data = rest[0], bytes.fromhex(rest[2])
                    seen.append(expect)
                    if expect == "genesis":  # a new genesis is configured, then installed at open
                        configured[tenant] = data
                        if store is not None:
                            store.close()
                        store = self.track(payer.PayerStore(path, links=configured, grants=()))
                    elif kind == "auth-link":
                        self.assertEqual(store.install_link(data), answers[expect])
                    elif expect in answers:
                        self.assertEqual(store.install_cert(data), answers[expect])
                    else:
                        with self.assertRaisesRegex(payer.GatePayerError, "^cert_refused: BELOW_FENCE$"):
                            store.install_cert(data)
        self.assertEqual(seen.count("belowFence"), 1)
        self.assertLessEqual({"genesis", "extends", "installed", "unfit", "equivocates"}, set(seen))

    def test_a_store_whose_head_chain_is_not_the_configured_genesis_is_refused(self) -> None:
        """A row naming a self-signed genesis above the configured one, written into the file, is refused at open: the
        head's chain must start at the configured pin."""
        from app import right_rail_gate_payer as payer
        with self.scratch() as tmp:
            _, held, _ = fx.custody(tmp)
            path = Path(tmp) / "payer.sqlite3"
            payer.PayerStore(path, links={fx.TENANT: held}, grants=()).close()
            forged = Draft(7, 7, 0, "f-r0", "f-r1", "f-w0", "f-w1", tenant=fx.TENANT).signed("f-r0 f-w0")
            tenant, gen, base, digest, *keys, closed = payer._link_index(forged)
            with contextlib.closing(sqlite3.connect(path, isolation_level=None)) as db:
                db.execute("INSERT INTO links VALUES(?,?,?,?,?,?,?,?,?,?)", (digest, tenant, gen, base, *keys, forged, closed))
            with self.assertRaisesRegex(payer.GatePayerError, f"^link_refused: {fx.TENANT}$"):
                payer.PayerStore(path, links={fx.TENANT: held}, grants=())

    def test_a_link_row_whose_columns_are_not_its_bytes_is_refused_at_open(self) -> None:
        """Fits and witness queries follow the columns, so a row stored under another generation and base than its bytes
        say (a genesis of generation 1000 stored as generation -5, base -1) is refused, not opened."""
        from app import right_rail_gate_payer as payer
        with self.scratch() as tmp:
            _, held, _ = fx.custody(tmp)
            path = Path(tmp) / "payer.sqlite3"
            payer.PayerStore(path, links={fx.TENANT: held}, grants=()).close()
            lie = Draft(1000, 1000, 0, "f-r0", "f-r1", "f-w0", "f-w1", tenant=fx.TENANT).signed("f-r0 f-w0")
            tenant, _, _, digest, *keys, closed = payer._link_index(lie)
            with contextlib.closing(sqlite3.connect(path, isolation_level=None)) as db:
                db.execute("INSERT INTO links VALUES(?,?,?,?,?,?,?,?,?,?)", (digest, tenant, -5, -1, *keys, lie, closed))
            with self.assertRaisesRegex(payer.GatePayerError, f"^link_refused: {fx.TENANT}$"):
                payer.PayerStore(path, links={fx.TENANT: held}, grants=())

    def test_a_store_with_the_genesis_only_among_link_conflicts_is_refused_at_open(self) -> None:
        from app import right_rail_gate_payer as payer
        with self.scratch() as tmp:
            _, held, _ = fx.custody(tmp)
            path = Path(tmp) / "payer.sqlite3"
            payer.PayerStore(path, links={fx.TENANT: held}, grants=()).close()
            tenant, gen, base, digest, *_ = payer._link_index(held)
            with contextlib.closing(sqlite3.connect(path, isolation_level=None)) as db:
                for (name,) in db.execute("SELECT name FROM sqlite_master WHERE type='trigger'").fetchall():
                    db.execute(f"DROP TRIGGER {name}")
                db.execute("DELETE FROM links")
                db.execute("INSERT INTO link_conflicts(tenant, base, gen, digest, link) VALUES(?,?,?,?,?)", (tenant, base, gen, digest, held))
            with self.assertRaisesRegex(payer.GatePayerError, f"^link_refused: {fx.TENANT}$"):
                payer.PayerStore(path, links={fx.TENANT: held}, grants=())

    def test_the_payer_store_agrees_with_the_reader_through_rotations_and_a_re_genesis(self) -> None:
        """Random links and certificates, with rotations of either key and a re-genesis, go through ``PayerStore`` (the SQL
        witness selection under Lean) and through ``Reader``; every answer is the same, and so after a reopen.  Names:
        the reader's ``belowFence`` is Lean's ``belowFence``, the CLI's ``REFUSED BELOW_FENCE`` and the store's
        ``cert_refused: BELOW_FENCE``; a refused link is ``link_refused`` and an undecodable certificate ``cert_rejected``."""
        import random
        from app import right_rail_gate_payer as payer
        span, counts = kc.GEN_SPAN, [(1,), (1, 2), (1, 5), (1, 7), (2,), (2, 3)]

        def cert_answer(store: payer.PayerStore, data: bytes) -> str:
            try:
                return store.install_cert(data).lower()
            except payer.GatePayerError as fault:
                return {"cert_refused: BELOW_FENCE": "belowfence", "cert_rejected": "malformed"}.get(str(fault), str(fault).removeprefix("cert_refused: ").lower())

        def link_answer(store: payer.PayerStore, data: bytes) -> str:
            try:
                return store.install_link(data).lower()
            except payer.GatePayerError as fault:
                return str(fault).split(":")[0].replace("link_refused", "refused").replace("link_rejected", "malformed")

        with self.scratch() as tmp:
            for seed in range(3):
                rng, tenant, mark = random.Random(f"own-{seed}"), "dif-t", f"s{seed}"
                path = Path(tmp) / f"payer{seed}.sqlite3"
                first = Draft(0, 0, 0, f"{mark}-r0", f"{mark}-r1", f"{mark}-w0", f"{mark}-w1", tenant=tenant)
                reader, count = Reader(), 0
                reader.pins[tenant.encode()] = sha3(first.body())
                configured = {tenant: first.signed(f"{mark}-r0 {mark}-w0")}
                self.assertEqual(reader.link(configured[tenant])[0], "genesis")
                store = self.track(payer.PayerStore(path, links=configured, grants=()))
                drafts = [(first, f"{mark}-r0 {mark}-w0")]  # each generation's draft and its certificates' signers

                def step(draft: Draft, by: str, epoch: int) -> None:
                    nonlocal count
                    count += 1
                    data = cert(epoch, draft, f"{mark}e{count}", f"{mark}v{count}", by, counts=rng.choice(counts))
                    expect = reader.cert(data).lower()
                    self.assertEqual(cert_answer(store, data), expect, f"seed {seed}, certificate {count}, epoch {epoch}")

                for _ in range(16):
                    if rng.random() < 0.2 and len(drafts) < 4:
                        prev, _ = drafts[-1]
                        gen = prev.gen + 1
                        closed = rng.choice([None, (gen - 1) * span + rng.randrange(0, 12)])
                        if gen % 2:  # a root rotation, cosigned by the old witness
                            nd = replace(prev, gen=gen, change=1, prev=sha3(prev.body()), closed=closed, root=prev.root_next, root_next=f"{mark}-rn{gen}")
                            by = f"{nd.root} {prev.witness}"
                        else:
                            nd = replace(prev, gen=gen, change=2, prev=sha3(prev.body()), closed=closed, witness=prev.witness_next, witness_next=f"{mark}-wn{gen}")
                            by = f"{nd.witness} {prev.root}"
                        data = nd.signed(by)
                        expect = reader.link(data)[0]
                        self.assertEqual(link_answer(store, data), expect, f"seed {seed}, link of generation {gen}")
                        if expect == "extends":
                            drafts.append((nd, f"{nd.root} {nd.witness}"))
                    else:
                        draft, by = rng.choice(drafts) if rng.random() < 0.6 else drafts[-1]
                        step(draft, by, draft.gen * span + rng.randrange(0, 12))
                if seed == 2:  # a re-genesis: a new configured genesis starts an empty chain, the old one stays as evidence
                    again = Draft(5, 5, 0, f"{mark}-g0", f"{mark}-g1", f"{mark}-h0", f"{mark}-h1", tenant=tenant)
                    reader.pins[tenant.encode()] = sha3(again.body())
                    configured = {tenant: again.signed(f"{mark}-g0 {mark}-h0")}
                    self.assertEqual(reader.link(configured[tenant])[0], "genesis")
                    drafts = [(again, f"{mark}-g0 {mark}-h0")]
                    store.close()
                    store = self.track(payer.PayerStore(path, links=configured, grants=()))
                    step(*drafts[0], 5 * span + 1)
                store.close()
                store = self.track(payer.PayerStore(path, links=configured, grants=()))  # the reopen replays every row
                step(*drafts[-1], drafts[-1][0].gen * span + 13)
                store.close()


if __name__ == "__main__":
    VECTORS.write_text(build_vectors(), "ascii", newline="\n")
    sys.exit(0)
