"""KEY-CERT/v2, the key certificate of one tenant epoch: golden vectors and an independent verifier.

``tests/gate_vectors/key_cert_v2.vectors`` is produced by ``build_vectors`` (``python -m tests.test_key_cert_v2``) with
test-only keys and deterministic signatures, and judged by the Lean ``gate_vectors`` executable.  ``judge`` is a second
decoder and verifier, written from the format alone: it shares no code with the encoder that builds the vectors, and
its signature check is the pinned ML-DSA-87 worker, not Lean.  Python must reproduce every byte of the file, and Lean
and ``judge`` must each give every certificate its listed verdict and decoded fields.  Synthetic, non-PHI.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import functools
from hashlib import sha3_512
from pathlib import Path
import re
import subprocess
import sys
from typing import NamedTuple
import unittest

from app import right_rail_gate_signer as signer
from tests import test_right_rail_gate_formats as fx

VECTORS = Path(__file__).resolve().parent / "gate_vectors" / "key_cert_v2.vectors"
TAG = b"RR/GATE/KEY-CERT/v2\x00"
MAX_BYTES, GEN_SPAN = 16_384, 1 << 32
KEY_BYTES = {1: 2592}  # the registered signature schemes and their public key lengths; 1 is ML-DSA-87
REFUSALS = ("MALFORMED", "WRONG_TENANT", "STALE_KEYSET", "GENERATION_AHEAD", "WRONG_LINK", "KEY_REUSE",
            "AFTER_ROTATION", "BAD_ROOT_SIGNATURE", "BAD_WITNESS_SIGNATURE")
_ID = re.compile(rb"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")


def sha3(data: bytes) -> bytes:
    return sha3_512(data).digest()


class Link(NamedTuple):
    """An authority link as verification reads it; keys are encoded (scheme, length, public key)."""
    tenant: bytes
    gen: int
    digest: bytes
    root: bytes
    root_next: bytes
    witness: bytes
    witness_next: bytes
    closed: int | None  # the last epoch certified under the generation before, recorded by the rotation to this link


def _signed(key: bytes, message: bytes, signature: bytes) -> bool:
    return key[0] == 1 and signer.verify(key[3:], message, signature)


def judge(links: list[Link], data: bytes, retired: list[Link]) -> tuple[str, list[str]]:
    """The verdict on certificate bytes under a tenant's chain of links, newest first, each one generation after the
    next and with root and witness keys that differ (``accept`` or the first refusal that applies), and the decoded
    fields, of which there are none when the bytes do not decode.  The certificate is judged by the link of its own
    generation and its keys by every link and every ``retired`` link (of the tenant's chains a later genesis replaced);
    once a later link exists, only the epochs that the next link records as certified under the certificate's
    generation are accepted."""
    head = links[0]
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
        if KEY_BYTES.get(scheme) != size:
            raise ValueError
        take(size)
        return data[start:at]

    try:
        if len(data) > MAX_BYTES or take(len(TAG)) != TAG:
            raise ValueError
        tenant, epoch, link = take(num(2)), num(8), take(64)
        chain = [num(4) for _ in range(num(1))]
        if (not _ID.fullmatch(tenant) or epoch >= 1 << 63 or not 1 <= len(chain) <= 32 or chain[0] < 1
                or any(b <= a or b % a for a, b in zip(chain, chain[1:]))):
            raise ValueError
        keys = [key(), key()]
        body = data[:at]
        root_sig, co_sig = take(num(2)), take(num(2))
        if at != len(data):
            raise ValueError
    except ValueError:
        return "MALFORMED", []
    fields = [tenant.decode(), str(epoch), link.hex(), ",".join(map(str, chain)), sha3(keys[0]).hex(),
              sha3(keys[1]).hex(), sha3(body).hex(), str(len(root_sig)), str(len(co_sig))]
    if tenant != head.tenant:
        return "WRONG_TENANT", fields
    if epoch // GEN_SPAN > head.gen:
        return "GENERATION_AHEAD", fields
    own = next((p for p in links if p.gen == epoch // GEN_SPAN), None)
    if own is None:
        return "STALE_KEYSET", fields
    if link != own.digest:
        return "WRONG_LINK", fields
    if keys[0] == keys[1] or any(k in (p.root, p.witness) or sha3(k) in (p.root_next, p.witness_next)
                                 for k in keys for p in links + retired):
        return "KEY_REUSE", fields
    if own.gen < head.gen:
        closed = next(p for p in links if p.gen == own.gen + 1).closed
        if closed is None or epoch > closed:
            return "AFTER_ROTATION", fields
    if not _signed(own.root, body, root_sig):
        return "BAD_ROOT_SIGNATURE", fields
    return ("accept" if _signed(own.witness, body, co_sig) else "BAD_WITNESS_SIGNATURE"), fields


# The encoder that builds the vectors.

@functools.cache
def pair(name: str) -> tuple[bytes, bytes]:
    return fx.keypair("key-cert-v2-" + name)


def key(name: str, scheme: int = 1, cut: int = 0, pad: int = 0) -> bytes:
    """The encoded test-only key ``name``; ``cut`` drops bytes from the end of the public key, ``pad`` adds zeros."""
    pk = pair(name)[0][: 2592 - cut] + bytes(pad)
    return bytes([scheme]) + len(pk).to_bytes(2, "big") + pk


@functools.cache
def sign(name: str, message: bytes) -> bytes:
    return fx._kat("kat-sign", pair(name)[1] + bytes(32) + b"\x00\x00" + message, 4627)


def blob(x: bytes) -> bytes:
    return len(x).to_bytes(2, "big") + x


@dataclass(frozen=True)
class Cert:
    tenant: str
    epoch: int
    link: bytes
    chain: tuple[int, ...]
    key: bytes
    verifier_key: bytes
    tag: bytes = TAG

    def body(self) -> bytes:
        return (self.tag + blob(self.tenant.encode()) + self.epoch.to_bytes(8, "big") + self.link
                + bytes([len(self.chain)]) + b"".join(n.to_bytes(4, "big") for n in self.chain) + self.key
                + self.verifier_key)


def link_digest(tenant: str, gen: int) -> bytes:
    """Stands in for the SHA3-512 of an authority link's body."""
    return sha3(f"RR/GATE/TEST-ONLY-LINK/v1\x00{tenant}/{gen}".encode())


def head(tenant: str, gen: int, closed: int | None = None) -> Link:
    """Generation ``gen`` of the test chain: its next keys are the keys of generation ``gen + 1``."""
    return Link(tenant.encode(), gen, link_digest(tenant, gen), key(f"r{gen}"), sha3(key(f"r{gen + 1}")),
                key(f"w{gen}"), sha3(key(f"w{gen + 1}")), closed)


def build_vectors() -> str:
    out = ["# KEY-CERT/v2 under the authority chain of the tenant of the newest link line.  Test-only keys; rnd = 0.",
           "# link <tenant> <generation> <link digest> <root key> <next root key digest> <witness key> <next witness key digest>",
           "#   <last epoch certified under the generation before, or - for none>",
           "# genesis <the same fields>: a new chain of the same tenant from a later generation; the links of the chain",
           "#   it replaces are retired, and their keys are never certified again",
           "# key-cert <accept or refusal> <name> <certificate>, then when it decodes: <tenant> <epoch> <link> <shard counts>",
           "#   <epoch key digest> <verifier key digest> <body digest> <root signature bytes> <cosignature bytes>"]

    def link(h: Link, kind: str = "link") -> Link:
        out.append(f"{kind} {h.tenant.decode()} {h.gen} {h.digest.hex()} {h.root.hex()} {h.root_next.hex()} "
                   f"{h.witness.hex()} {h.witness_next.hex()} {'-' if h.closed is None else h.closed}")
        return h

    def raw(expect: str, name: str, data: bytes, fields: tuple[str, ...] = ()) -> None:
        out.append(" ".join(["key-cert", expect, name, data.hex(), *fields]))

    def case(expect: str, name: str, c: Cert, by: str = "r0 w0", over: Cert | None = None,
             edit=lambda root_sig, co_sig: (root_sig, co_sig)) -> tuple[bytes, tuple[str, ...]]:
        """``c`` signed by the keys ``by`` over the body of ``over`` (default its own); ``edit`` changes the signatures.
        Returns the certificate and its decoded fields."""
        body, (root, witness) = c.body(), by.split()
        root_sig, co_sig = edit(sign(root, (over or c).body()), sign(witness, (over or c).body()))
        made = (body + blob(root_sig) + blob(co_sig), () if expect == "MALFORMED" else (
            c.tenant, str(c.epoch), c.link.hex(), ",".join(map(str, c.chain)), sha3(c.key).hex(),
            sha3(c.verifier_key).hex(), sha3(body).hex(), str(len(root_sig)), str(len(co_sig))))
        raw(expect, name, *made)
        return made

    small = link(head("t", 0))
    case("accept", "smallest", Cert("t", 0, small.digest, (1,), key("e"), key("v")))
    large = link(head("m" * 128, 0))
    case("accept", "largest", Cert("m" * 128, 0, large.digest, tuple(1 << i for i in range(32)), key("e"), key("v")))
    l0 = link(head("state-a", 0))
    base = Cert("state-a", 7, l0.digest, (4, 8, 24), key("e"), key("v"))
    typical = case("accept", "typical", base)
    case("accept", "last-epoch-of-generation", replace(base, epoch=GEN_SPAN - 1))
    case("accept", "genesis-only-no-closing", replace(base, epoch=8))
    for name, c in (("v1-tag", replace(base, tag=b"RR/GATE/KEY-CERT/v1\x00")), ("empty-tenant", replace(base, tenant="")),
                    ("tenant-bad-start", replace(base, tenant=".state-a")), ("tenant-129", replace(base, tenant="a" * 129)),
                    ("epoch-over", replace(base, epoch=1 << 63)), ("no-counts", replace(base, chain=())),
                    ("zero-count", replace(base, chain=(0,))), ("not-a-multiple", replace(base, chain=(4, 6))),
                    ("not-larger", replace(base, chain=(4, 4))),
                    ("32-counts-then-a-repeat", replace(base, chain=tuple(1 << min(i, 31) for i in range(33)))),
                    ("unknown-scheme", replace(base, key=key("e", scheme=2))),
                    ("short-key", replace(base, verifier_key=key("v", cut=1))),
                    ("long-key", replace(base, key=key("e", pad=1)))):
        case("MALFORMED", name, c)
    raw("MALFORMED", "v1-certificate", fx.key_cert("e7"))
    raw("MALFORMED", "tag-only", TAG)
    raw("MALFORMED", "cut-short", typical[0][:-1])
    raw("MALFORMED", "trailing-byte", typical[0] + b"\x00")
    room = bytes(MAX_BYTES - len(typical[0]))
    case("BAD_WITNESS_SIGNATURE", "at-size-bound", base, edit=lambda r, w: (r, w + room))
    case("MALFORMED", "over-size-bound", base, edit=lambda r, w: (r, w + room + b"\x00"))
    case("WRONG_TENANT", "other-tenant", replace(base, tenant="state-b"))
    ahead = case("GENERATION_AHEAD", "next-generation", replace(base, epoch=GEN_SPAN))
    case("WRONG_LINK", "other-link", replace(base, link=link_digest("state-a", 1)))
    case("KEY_REUSE", "one-key-twice", replace(base, verifier_key=base.key))
    case("KEY_REUSE", "key-reuse-with-bad-signatures", replace(base, key=key("r0")), edit=lambda r, w: (b"", b""))
    for field in ("key", "verifier_key"):
        for other, role in (("r0", "root"), ("w0", "witness"), ("r1", "next-root"), ("w1", "next-witness")):
            case("KEY_REUSE", f"{field.replace('_', '-')}-is-{role}", replace(base, **{field: key(other)}))
    case("BAD_ROOT_SIGNATURE", "root-signature-bit", base, edit=lambda r, w: (fx._flip(r, 0), w))
    case("BAD_ROOT_SIGNATURE", "signatures-swapped", base, edit=lambda r, w: (w, r))
    case("BAD_ROOT_SIGNATURE", "no-root-signature", base, edit=lambda r, w: (b"", w))
    case("BAD_ROOT_SIGNATURE", "signed-for-epoch-7", replace(base, epoch=8), over=base)
    case("BAD_WITNESS_SIGNATURE", "cosignature-bit", base, edit=lambda r, w: (r, fx._flip(w, 0)))
    case("BAD_WITNESS_SIGNATURE", "root-only", base, edit=lambda r, w: (r, b""))
    case("BAD_WITNESS_SIGNATURE", "root-signed-twice", base, by="r0 r0")
    l1 = link(head("state-a", 1, closed=7))  # generation 0 closed at epoch 7
    raw("accept", "old-generation-own-link", *typical)
    case("BAD_ROOT_SIGNATURE", "old-generation-signed-by-newer-keys", base, by="r1 w1")
    case("AFTER_ROTATION", "old-generation-after-closing", replace(base, epoch=8))
    case("WRONG_LINK", "after-closing-names-newer-link", replace(base, epoch=8, link=l1.digest))
    case("AFTER_ROTATION", "after-closing-unsigned", replace(base, epoch=8), edit=lambda r, w: (b"", b""))
    case("KEY_REUSE", "key-reuse-after-closing", replace(base, epoch=8, key=key("r0")))
    case("WRONG_LINK", "old-epoch-names-newer-link", replace(base, link=l1.digest), by="r1 w1")
    case("WRONG_LINK", "old-epoch-names-newer-link-unsigned", replace(base, link=l1.digest), edit=lambda r, w: (b"", b""))
    case("accept", "generation-1", replace(base, epoch=GEN_SPAN, link=l1.digest), by="r1 w1")
    raw("WRONG_LINK", "generation-1-old-link", *ahead)
    case("BAD_ROOT_SIGNATURE", "replaced-root-key", replace(base, epoch=GEN_SPAN, link=l1.digest))
    case("BAD_WITNESS_SIGNATURE", "replaced-witness-key", replace(base, epoch=GEN_SPAN, link=l1.digest), by="r1 w0")
    l2 = link(head("state-a", 2, closed=GEN_SPAN))  # generation 0 is two links back, generation 1 one
    later = replace(base, epoch=2 * GEN_SPAN, link=l2.digest)
    case("accept", "generation-2", later, by="r2 w2")
    for field, other, was in (("key", "r0", "root-two-links-back"), ("verifier_key", "w0", "witness-two-links-back"),
                              ("key", "w1", "witness-one-link-back"), ("verifier_key", "r1", "root-one-link-back")):
        case("KEY_REUSE", f"{field.replace('_', '-')}-was-{was}", replace(later, **{field: key(other)}), by="r2 w2")
    raw("accept", "old-generation-two-links-newer", *typical)
    case("AFTER_ROTATION", "old-generation-after-closing-two-links-newer", replace(base, epoch=8))
    case("accept", "generation-1-one-link-newer", replace(base, epoch=GEN_SPAN, link=l1.digest), by="r1 w1")
    case("AFTER_ROTATION", "generation-1-after-closing", replace(base, epoch=GEN_SPAN + 1, link=l1.digest), by="r1 w1")
    # One role rotates per link, so a key that only an earlier link committed to is not also a later root or witness.
    def role(gen: int, root: str, root_next: str, witness: str, witness_next: str, closed: int | None) -> Link:
        return link(Link(b"role-a", gen, link_digest("role-a", gen), key(root), sha3(key(root_next)), key(witness),
                         sha3(key(witness_next)), closed))
    role(0, "ra0", "rx0", "wa0", "wx0", None)
    role(1, "ra1", "rx1", "wa0", "wx0", None)  # the root rotates; generation 0 certified nothing
    rl = role(2, "ra1", "rx1", "wa1", "wx1", GEN_SPAN)  # the witness rotates
    held = replace(base, tenant="role-a", epoch=2 * GEN_SPAN, link=rl.digest)
    case("accept", "role-chain", held, by="ra1 wa1")
    for field, other, was in (("key", "rx0", "only-an-earlier-next-root"),
                              ("verifier_key", "wx0", "only-an-earlier-next-witness"),
                              ("key", "ra0", "only-an-earlier-root"), ("verifier_key", "wa0", "only-an-earlier-witness")):
        case("KEY_REUSE", f"{field.replace('_', '-')}-is-{was}", replace(held, **{field: key(other)}), by="ra1 wa1")
    case("accept", "role-chain-generation-1", replace(held, epoch=GEN_SPAN, link=link_digest("role-a", 1)), by="ra1 wa0")
    case("AFTER_ROTATION", "nothing-certified-before-rotation", replace(held, epoch=0, link=link_digest("role-a", 0)),
         by="ra0 wa0")
    top = (1 << 31) - 1
    big = link(head("big", top))
    case("accept", "largest-epoch", Cert("big", (1 << 63) - 1, big.digest, (1,), key("e"), key("v")), by=f"r{top} w{top}")
    late = link(head("late", 2))
    case("accept", "chain-starts-at-generation-2", Cert("late", 2 * GEN_SPAN, late.digest, (1,), key("e"), key("v")), by="r2 w2")
    for epoch, gen in ((GEN_SPAN, 1), (0, 0)):
        case("STALE_KEYSET", f"before-the-first-link-{gen}",
             Cert("late", epoch, link_digest("late", gen), (1,), key("e"), key("v")), by="r2 w2")
    # A new genesis replaces the chain: its certificates are judged by no link, and its keys never come back.
    old = case("accept", "before-re-genesis", Cert("regen", 7, link(head("regen", 0)).digest, (1,), key("e"), key("v")))
    r1 = link(head("regen", 1, closed=7))
    fresh = link(Link(b"regen", 3, link_digest("regen", 3), key("ga"), sha3(key("gb")), key("gw"), sha3(key("gx")), None),
                 "genesis")
    new = Cert("regen", 3 * GEN_SPAN, fresh.digest, (1,), key("e"), key("v"))
    case("accept", "after-re-genesis", new, by="ga gw")
    raw("STALE_KEYSET", "replaced-chain-late-certificate", *old)
    case("STALE_KEYSET", "replaced-chain-head-generation", replace(new, epoch=GEN_SPAN, link=r1.digest), by="r1 w1")
    for field, other, was in (("key", "r0", "root"), ("verifier_key", "w1", "witness"), ("key", "r2", "next-root"),
                              ("verifier_key", "w2", "next-witness")):
        case("KEY_REUSE", f"{field.replace('_', '-')}-was-a-replaced-{was}", replace(new, **{field: key(other)}),
             by="ga gw")
    checked = sum(x.startswith("key-cert ") for x in out)
    return "\n".join(out) + f"\nend {checked}\n"


class KeyCertV2VectorTests(unittest.TestCase):
    def test_python_reproduces_every_vector_byte(self) -> None:
        self.assertEqual(build_vectors(), VECTORS.read_text("ascii"))

    def test_lean_judges_every_vector(self) -> None:
        done = subprocess.run([str(fx.LEAN_VECTORS), str(VECTORS)], capture_output=True, text=True, timeout=1800, check=False)
        self.assertRegex(done.stdout.strip(), r"^GATE_VECTORS=PASS checked=(\d+) expected=\1 failed=0$")

    def test_independent_verifier_agrees_on_every_vector(self) -> None:
        links, retired, seen, sizes, end = [], [], [], [], None  # the current tenant's chain, newest first
        for line in VECTORS.read_text("ascii").splitlines():
            kind, *rest = line.split(" ")
            if kind in ("link", "genesis"):
                new = Link(rest[0].encode(), int(rest[1]), *map(bytes.fromhex, rest[2:7]),
                           None if rest[7] == "-" else int(rest[7]))
                self.assertNotEqual(new.root, new.witness)
                same = bool(links) and links[0].tenant == new.tenant
                if kind == "genesis":
                    self.assertTrue(same and new.gen > links[0].gen)
                    links, retired = [new], links + retired
                elif same:
                    self.assertEqual(new.gen, links[0].gen + 1)
                    links.insert(0, new)
                else:
                    links, retired = [new], []
            elif kind == "key-cert":
                expect, name, data, *fields = rest
                with self.subTest(name):
                    self.assertEqual(judge(links, bytes.fromhex(data), retired), (expect, fields))
                seen.append(expect)
                if expect == "accept":
                    sizes.append(len(data) // 2)
            elif kind == "end":
                end = int(rest[0])
        self.assertEqual(len(seen), end)
        self.assertEqual(set(seen), {"accept", *REFUSALS})
        self.assertEqual((min(sizes), max(sizes)), (14_548, 14_799))  # the ML-DSA-87 certificate size range


if __name__ == "__main__":
    VECTORS.write_text(build_vectors(), "ascii", newline="\n")
    sys.exit(0)
