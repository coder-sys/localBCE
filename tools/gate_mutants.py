"""Mutation check of the gate spec against its golden vectors (test-only).

Each mutant weakens one conjunct of ``BlindLedger/Gate/Spec.lean``, rebuilds
``gate_vectors`` and must make the vectors FAIL; the spec is then restored
byte for byte and must PASS.  Run only under the v4 guard:
``python tools/gate_mutants.py <lean dir> <vectors file> <lake.exe>``.
"""

import hashlib
from pathlib import Path
import subprocess
import sys

MUTANTS = [
    ("1 leaf: FFS_CLAIM has no lines root", "  need (flow != .FFS_CLAIM || linesRoot == zeroDigest)\n", ""),
    ("1 leaf: reason codes ascending", "  need (ascending reasonCodes)\n", ""),
    ("1 leaf: issued <= expires", "need (issuedAt ≤ expiresAt && expiresAt", "need (expiresAt"),
    ("1 leaf: lifetime <= 7 days", " && expiresAt ≤ issuedAt + maxTokenLifetime)", ")"),
    ("1 checkpoint: state digest zero", "  expect zeroDigest\n", "  let _ ← digest\n"),
    ("1 checkpoint: sig_alg is 1", "  let _ ← nat 1 1 1\n", "  let _ ← nat 1\n"),
    ("1 checkpoint: count matches seq range", "  need (seqTo + 1 == seqFrom + count)\n", ""),
    ("2 checkpoint stored", "    match batchOf s t with\n    | none => false", "    match batchOf s t with\n    | none => true"),
    ("3 tenant", "cp.tenantId == t.leaf.tenantId && ", ""),
    ("3 program", "cp.programId == t.leaf.programId &&", ""),
    ("3 shard", "cp.shardId == t.leaf.shardId && ", ""),
    ("3 epoch", "cp.epoch == t.leaf.epoch && ", ""),
    ("3 seqFrom <= seq", "cp.seqFrom ≤ t.leaf.seq &&", ""),
    ("3 Merkle path", " &&\n    verifyPath c.hash (domain \"MERKLE-NODE\") t.leafBytes (t.leaf.seq - cp.seqFrom) cp.count\n      t.siblings cp.tokenRoot", ""),
    ("4 fence", ": Bool := s.fence t.leaf.tenantId ≤ t.leaf.epoch", ": Bool := true"),
    ("5 not before issue", "t.leaf.issuedAt ≤ s.now + clockSkew && ", ""),
    ("5 not expired", " && s.now < t.leaf.expiresAt + clockSkew", ""),
    ("5 clockSkew 299", "def clockSkew : Nat := 300", "def clockSkew : Nat := 299"),
    ("5 clockSkew 301", "def clockSkew : Nat := 300", "def clockSkew : Nat := 301"),
    ("6 tenant", "l.tenantId == p.tenantId && ", ""),
    ("6 program", "l.programId == p.programId && ", ""),
    ("6 flow", "l.flow == p.flow &&", ""),
    ("6 payment id", "l.paymentId == p.paymentId && ", ""),
    ("6 member key", "l.memberKey == p.memberKey && ", ""),
    ("6 payee", " && l.payeeRef == p.payeeRef", ""),
    ("6 amount", "l.amountCents == p.amountCents &&", ""),
    ("6 period", "l.period == p.period && ", ""),
    ("6 lines root", " && linesRoot c.hash p.lines == l.linesRoot", ""),
    ("7 route", "t.leaf.shardId == shardOf c.hash p.tenantId p.memberKey e.shardCount", "true"),
    ("7 shard count from any tenant", "s.certs.find? (·.tenantId == p.tenantId)", "s.certs.head?"),
    ("8 allows", ": Bool := t.leaf.outcome == .ALLOW", ": Bool := true"),
    ("9 grant id", "g.grantId == t.leaf.grantId &&\n    ", ""),
    ("9 rule version", "g.ruleVersions.contains t.leaf.ruleVersion && ", ""),
    ("9 leaf engine release", " && g.engineReleases.contains t.leaf.engineRelease", ""),
    ("10 unreleased", ": Bool := !s.released.contains (payKey t)", ": Bool := true"),
    ("10 release key has flow", "(t.leaf.tenantId, t.leaf.programId, t.leaf.paymentId)",
     "(t.leaf.tenantId, t.leaf.programId ++ [t.leaf.flow.tag], t.leaf.paymentId)"),
    ("11 fork blocks release", "  !s.forked.any fun f =>", "  true || s.forked.any fun f =>"),
    ("install: cert chain", "c.certChainOk e && ", ""),
    ("install: shard count >= 1", "0 < e.shardCount &&\n      ", ""),
    ("install: shard count fixed per tenant",
     " &&\n      s.certs.all (fun x => x.tenantId != e.tenantId || x.shardCount == e.shardCount)", ""),
    ("install: raises fence", ", fence := raiseFence s.fence e.tenantId e.epoch }", " }"),
    ("store: cert tenant", "e.tenantId == x.checkpoint.tenantId && ", ""),
    ("store: cert epoch", "e.epoch == x.checkpoint.epoch &&", ""),
    ("store: signature", " &&\n        c.sigOk e.publicKey x.header x.signature", ""),
    ("store: fork recorded, not stored", "| some old => some { s with forked := (old, new) :: s.forked }",
     "| some _ => some { s with checkpoints := new :: s.checkpoints }"),
    ("fork: different digest", "a.digest != b.digest && ", ""),
    ("fork: tenant", "a.checkpoint.tenantId == b.checkpoint.tenantId &&", ""),
    ("fork: shard", "a.checkpoint.shardId == b.checkpoint.shardId && ", ""),
    ("fork: epoch", "a.checkpoint.epoch == b.checkpoint.epoch &&", ""),
    ("fork: overlap from", "a.checkpoint.seqFrom ≤ b.checkpoint.seqTo && ", ""),
    ("fork: overlap to", " && b.checkpoint.seqFrom ≤ a.checkpoint.seqTo", ""),
    ("response: head tenant", "  need (tenantId == r.tenantId)\n", ""),
    ("response: head program", "  need (programId == r.programId)\n", ""),
    ("response: head command key", "  need (commandKey == r.commandKey)\n", ""),
    ("response: leaf tenant", "      need (t.leaf.tenantId == r.tenantId)\n", ""),
    ("response: leaf program", "      need (t.leaf.programId == r.programId)\n", ""),
    ("response: leaf payment", "      need (t.leaf.paymentId == r.paymentId)\n", ""),
    ("response: leaf member key", "      need (t.leaf.memberKey == r.memberKey)\n", ""),
    ("response: leaf payee", "      need (t.leaf.payeeRef == r.payeeRef)\n", ""),
    ("response: leaf amount", "      need (t.leaf.amountCents == r.amountCents)\n", ""),
    ("response: leaf period", "      need (t.leaf.period == r.period)\n", ""),
    ("response: leaf lines root", "      need (t.leaf.linesRoot == linesRoot H r.lines)\n", ""),
    ("response: leaf flow", "      need (status == .PAYMENT_ALREADY_DECIDED || t.leaf.flow == r.flow)\n", ""),
    ("response: already-decided flow exemption", "status == .PAYMENT_ALREADY_DECIDED || ", ""),
    ("reissue: latest revision only", "old.revision == latest &&\n    ", ""),
    ("reissue: same decision", "decide ({ new with epoch := old.epoch, seq := old.seq, issuedAt := old.issuedAt,\n"
     "                       expiresAt := old.expiresAt } = old) &&\n    ", ""),
    ("reissue: epoch not older", "old.epoch ≤ new.epoch && ", ""),
    ("reissue: later seq", " && old.seq < new.seq", ""),
]


def vectors(lean: Path, path: str, lake: str) -> str:
    build = subprocess.run([lake, "-d", str(lean), "build", "gate_vectors"], capture_output=True, text=True)
    if build.returncode:
        return "BUILD_ERROR"
    exe = lean / ".lake" / "build" / "bin" / "gate_vectors.exe"
    out = subprocess.run([str(exe), path], capture_output=True, text=True).stdout.splitlines()
    first = [line.split("line=")[1].split()[0] for line in out if "MISMATCH" in line][:3]
    return out[-1].split()[0] + (" first_lines=" + ",".join(first) if first else "")


def main(lean_dir: str, path: str, lake: str) -> int:
    lean = Path(lean_dir)
    spec = lean / "BlindLedger" / "Gate" / "Spec.lean"
    original = spec.read_bytes()
    text = original.decode("utf-8")
    killed = 0
    try:
        for name, old, new in MUTANTS:
            if text.count(old) != 1:
                print(f"MUTANT {name}: SCRIPT_ERROR occurrences={text.count(old)}")
                continue
            spec.write_bytes(text.replace(old, new).encode("utf-8"))
            result = vectors(lean, path, lake)
            killed += result.startswith("GATE_VECTORS=FAIL")
            print(f"MUTANT {name}: {result}", flush=True)
    finally:
        spec.write_bytes(original)
    restored = vectors(lean, path, lake)
    print(f"RESTORED sha256={hashlib.sha256(spec.read_bytes()).hexdigest()} {restored}")
    print(f"MUTANTS total={len(MUTANTS)} killed={killed}")
    return 0 if restored == "GATE_VECTORS=PASS" and killed == len(MUTANTS) else 1


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
