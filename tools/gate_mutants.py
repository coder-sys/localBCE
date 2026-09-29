"""Mutation check of the gate spec against its golden vectors (test-only).

Each mutant weakens one conjunct of ``BlindLedger/Gate/Spec.lean``, rebuilds
``gate_vectors`` and must make the vectors FAIL; the spec is then restored
byte for byte and must PASS.  The optional ``start:stop`` slices the list,
for batches.  Run only under the guard:
``python tools/gate_mutants.py <lean dir> <vectors file> <lake.exe> [start:stop]``.
"""

import hashlib
from pathlib import Path
import subprocess
import sys

MUTANTS = [
    ("1 parse: no trailing bytes", "| some (x, []) => some x", "| some (x, _) => some x"),
    ("1 identifiers", "  need (identOk bs)\n", ""),
    ("1 request: lines canonical", "  need (ls.length == lines.length)\n", ""),
    ("1 request: line flow", "l.flow == flow && ", ""),
    ("1 request: line member", "l.memberKey == memberKey && ", ""),
    ("1 request: line payee", " && l.payeeRef == payeeRef", ""),
    ("1 request: lines sum to amount", "  need (lines.isEmpty || ls.foldl (· + ·.cents) 0 == amountCents)\n", ""),
    ("1 line bytes 568", "def maxLineBytes : Nat := 569", "def maxLineBytes : Nat := 568"),
    ("1 request: ruled flow has lines", "  need (!flow.ruled || !lines.isEmpty)\n", ""),
    ("1 FFS_CYCLE unruled", "f == .FFS_CYCLE || ", ""),
    ("1 FFS_CLAIM unruled", "f == .FFS_CLAIM || ", ""),
    ("1 CAP_820 unruled", " || f == .CAP_820", ""),
    ("1 leaf: ruled flow has a lines root", "then linesRoot != zeroDigest else", "then true else"),
    ("1 leaf: unruled flow is HUMAN_REVIEW", "else outcome == .HUMAN_REVIEW", "else true"),
    ("1 leaf: reason codes ascending", "  need (ascending reasonCodes)\n", ""),
    ("1 leaf: decided <= issued", "need (decidedAt ≤ issuedAt && ", "need ("),
    ("1 leaf: issued <= expires", "issuedAt && issuedAt ≤ expiresAt && expiresAt", "issuedAt && expiresAt"),
    ("1 leaf: lifetime <= 7 days", " && expiresAt ≤ issuedAt + maxTokenLifetime)", ")"),
    ("1 checkpoint: state digest nonzero", "  need (stateDigest != zeroDigest)\n", ""),
    ("1 checkpoint: sig_alg is 1", "  let _ ← nat 1 1 1\n", "  let _ ← nat 1\n"),
    ("1 checkpoint: count matches seq range", "  need (seqTo + 1 == seqFrom + count)\n", ""),
    ("1 checkpoint: epoch's first has zero prev", "  need ((seqFrom == 0) == (prevCheckpoint == zeroDigest))\n", ""),
    ("2 checkpoint stored", "    match batchOf s t with\n    | none => false", "    match batchOf s t with\n    | none => true"),
    ("3 tenant", "cp.tenantId == t.leaf.tenantId && ", ""),
    ("3 program", "cp.programId == t.leaf.programId &&", ""),
    ("3 shard", "cp.shardId == t.leaf.shardId && ", ""),
    ("3 epoch", "cp.epoch == t.leaf.epoch && ", ""),
    ("3 seqFrom <= seq", "cp.seqFrom ≤ t.leaf.seq &&", ""),
    ("3 Merkle index < count", "index < count && ", ""),
    ("3 Merkle path", " &&\n    verifyPath c.hash (domain \"MERKLE-NODE\") t.leafBytes (t.leaf.seq - cp.seqFrom) cp.count\n      t.siblings cp.tokenRoot", ""),
    ("4 fence", ": Bool := s.fence t.leaf.tenantId ≤ t.leaf.epoch", ": Bool := true"),
    ("5 not before issue", "t.leaf.issuedAt ≤ s.now + clockSkew && ", ""),
    ("5 not expired", " && s.now < t.leaf.expiresAt + clockSkew", ""),
    ("5 decision age", " &&\n    s.now < t.leaf.decidedAt + maxDecisionAge t.leaf.flow + clockSkew", ""),
    ("5 decision age not per flow", "maxDecisionAge t.leaf.flow", "maxDecisionAge .FFS_CLAIM"),
    ("5 FFS_CYCLE age -1 s", "| .FFS_CYCLE => 28 * 24 * 3600", "| .FFS_CYCLE => 28 * 24 * 3600 - 1"),
    ("5 CAP_820 age +1 s", "| .CAP_820 => 62 * 24 * 3600", "| .CAP_820 => 62 * 24 * 3600 + 1"),
    ("5 FFS_CLAIM age +1 s", "| _ => 14 * 24 * 3600", "| _ => 14 * 24 * 3600 + 1"),
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
    ("7 route", "t.leaf.shardId == shardOf c.hash p.tenantId p.memberKey n", "true"),
    ("7 shard count from any tenant", "s.certs.find? (·.tenantId == tenant)", "s.certs.head?"),
    ("8 allows", ": Bool := t.leaf.outcome == .ALLOW", ": Bool := true"),
    ("9 grant id", "g.grantId == t.leaf.grantId &&\n    ", ""),
    ("9 rule version", "g.ruleVersions.contains t.leaf.ruleVersion && ", ""),
    ("9 leaf engine release", " && g.engineReleases.contains t.leaf.engineRelease", ""),
    ("10 unreleased", ": Bool := !s.released.contains (payKey t)", ": Bool := true"),
    ("10 release key has flow", "PayKey := (t.leaf.tenantId, t.leaf.programId, t.leaf.paymentId)",
     "PayKey := (t.leaf.tenantId, t.leaf.programId ++ [t.leaf.flow.tag], t.leaf.paymentId)"),
    ("10 release key has epoch", "PayKey := (t.leaf.tenantId, t.leaf.programId, t.leaf.paymentId)",
     "PayKey := (t.leaf.tenantId, t.leaf.programId ++ [UInt8.ofNat t.leaf.epoch], t.leaf.paymentId)"),
    ("11 fork blocks release", ": Bool := !blocked s t.leaf.tenantId t.leaf.epoch", ": Bool := true"),
    ("11 fork blocks every shard", ": Bool := !blocked s t.leaf.tenantId t.leaf.epoch",
     ": Bool := !s.forked.any fun f => f.1.checkpoint.shardId == t.leaf.shardId &&\n"
     "  f.1.checkpoint.tenantId == t.leaf.tenantId && f.1.checkpoint.epoch == t.leaf.epoch"),
    ("11 fork blocks only its tenant", "f.1.checkpoint.tenantId == tenant && ", ""),
    ("12 pinned member key", "s.pins.lookup (t.leaf.tenantId, t.leaf.programId, t.leaf.paymentId) == some t.leaf.memberKey",
     "true"),
    ("12 unsent payment fails open", "s.pins.lookup (t.leaf.tenantId, t.leaf.programId, t.leaf.paymentId) == some t.leaf.memberKey",
     "s.pins.all fun x => x.1 != (t.leaf.tenantId, t.leaf.programId, t.leaf.paymentId) || x.2 == t.leaf.memberKey"),
    ("send: pins", "| none => .ok { s with pins := (p.key, p.memberKey) :: s.pins }", "| none => .ok s"),
    ("send: write-once", "| some m => if m == p.memberKey then .ok s else .error .member_key_changed",
     "| some _ => .ok { s with pins := (p.key, p.memberKey) :: s.pins }"),
    ("install: cert chain", "if c.certChainOk e then", "if true then"),
    ("install: shard count >= 1", "0 < e.shardCount && ", ""),
    ("install: shard count u32", " && e.shardCount < 2 ^ 32", ""),
    ("install: shard count fixed per tenant", "x.shardCount == e.shardCount && ", ""),
    ("install: one certificate per tenant and epoch", " && x.epoch != e.epoch", ""),
    ("install: equivocation unrecorded", "(s.certs.filter fun x => x.tenantId == e.tenantId && x.epoch == e.epoch &&\n"
     "                x != e).map (·, e) ++ s.equivocations", "s.equivocations"),
    ("install: same certificate is equivocation", " &&\n                x != e)", ")"),
    ("install: equivocation across tenants", "fun x => x.tenantId == e.tenantId && x.epoch", "fun x => x.epoch"),
    ("install: equivocation across epochs", "x.tenantId == e.tenantId && x.epoch == e.epoch &&\n",
     "x.tenantId == e.tenantId &&\n"),
    ("11 equivocation blocks release", " ||\n    s.equivocations.any fun q => q.1.tenantId == tenant && q.1.epoch == epoch", ""),
    ("11 equivocation blocks every tenant", "q.1.tenantId == tenant && ", ""),
    ("11 equivocation blocks every epoch", " && q.1.epoch == epoch", ""),
    ("install: raises fence", "              fence := raiseFence s.fence e.tenantId e.epoch,\n", ""),
    ("install: refused cert raises fence", "fence := raiseFence s.fence e.tenantId e.epoch,",
     "fence := if fits s e then raiseFence s.fence e.tenantId e.epoch else s.fence,"),
    ("install: installed cert raises fence", "fence := raiseFence s.fence e.tenantId e.epoch,",
     "fence := if fits s e then s.fence else raiseFence s.fence e.tenantId e.epoch,"),
    ("store: cert tenant", "e.tenantId == x.checkpoint.tenantId && ", ""),
    ("store: cert epoch", "e.epoch == x.checkpoint.epoch &&", ""),
    ("store: signature", " &&\n        c.sigOk e.publicKey x.header x.signature", ""),
    ("store: fork recorded, not stored", "| some old => some { s with forked := (old, new) :: s.forked }",
     "| some _ => some { s with checkpoints := new :: s.checkpoints }"),
    ("store: blocked epoch refused", "if blocked s x.checkpoint.tenantId x.checkpoint.epoch then none\n        else ", ""),
    ("fork: different digest", "a.digest != b.digest && ", ""),
    ("fork: tenant", "a.checkpoint.tenantId == b.checkpoint.tenantId &&", ""),
    ("fork: shard", "a.checkpoint.shardId == b.checkpoint.shardId && ", ""),
    ("fork: epoch", "a.checkpoint.epoch == b.checkpoint.epoch &&", ""),
    ("fork: overlap from", "a.checkpoint.seqFrom ≤ b.checkpoint.seqTo && ", ""),
    ("fork: overlap to", " && b.checkpoint.seqFrom ≤ a.checkpoint.seqTo", ""),
    ("fork: unlinked previous", " ||\n      misLinked a b", ""),
    ("fork: unlinked next", " || misLinked b a", ""),
    ("link: adjacent but unlinked only", ") != (b.checkpoint.prevCheckpoint == a.digest)",
     ") && (b.checkpoint.prevCheckpoint != a.digest)"),
    ("link: linked but not adjacent only", "(a.checkpoint.seqTo + 1 == b.checkpoint.seqFrom) != (",
     "(a.checkpoint.seqTo + 1 != b.checkpoint.seqFrom) && ("),
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
    ("response: cross-flow lines accepted", "      need (t.leaf.linesRoot == linesRoot H r.lines)\n",
     "      need (status == .PAYMENT_ALREADY_DECIDED || t.leaf.linesRoot == linesRoot H r.lines)\n"),
    ("reissue: decision time kept", "issuedAt := old.issuedAt,", "issuedAt := old.issuedAt, decidedAt := old.decidedAt,"),
    ("reissue: latest revision only", "old.revision == latest &&\n    ", ""),
    ("reissue: same decision", "decide ({ new with epoch := old.epoch, seq := old.seq, issuedAt := old.issuedAt,\n"
     "                       expiresAt := old.expiresAt } = old) &&\n    ", ""),
    ("reissue: later epoch", "old.epoch < new.epoch || ", ""),
    ("reissue: seq only within the epoch", "old.epoch == new.epoch && ", ""),
    ("reissue: later seq", " && old.seq < new.seq", ""),
    ("reissue: within the epoch", " || old.epoch == new.epoch && old.seq < new.seq", ""),
    ("redecide: latest revision only", "old.revision == latest && new.revision", "new.revision"),
    ("redecide: next revision", "new.revision == latest + 1 && ", ""),
    ("redecide: any later revision", "new.revision == latest + 1", "latest < new.revision"),
    ("redecide: only an ALLOW", "old.outcome == .ALLOW &&\n    old.decidedAt", "\n    old.decidedAt"),
    ("redecide: before its age", "old.decidedAt + maxDecisionAge old.flow + 2 * clockSkew ≤ new.decidedAt &&\n    ", ""),
    ("redecide: one clock skew", "old.flow + 2 * clockSkew", "old.flow + clockSkew"),
    ("redecide: age not per flow", "maxDecisionAge old.flow", "maxDecisionAge .FFS_CLAIM"),
    ("redecide: tenant", "old.tenantId == new.tenantId && old.programId", "old.programId"),
    ("redecide: program", "old.programId == new.programId && old.shardId", "old.shardId"),
    ("redecide: shard", "old.shardId == new.shardId &&\n", "\n"),
    ("redecide: flow", "old.flow == new.flow && old.paymentId", "old.paymentId"),
    ("redecide: payment", "old.paymentId == new.paymentId && ", ""),
    ("redecide: member key", "old.memberKey == new.memberKey &&\n", "\n"),
    ("redecide: payee", "old.payeeRef == new.payeeRef && ", ""),
    ("redecide: amount", "old.amountCents == new.amountCents && ", ""),
    ("redecide: period", "old.period == new.period &&\n", "\n"),
    ("redecide: lines root", " &&\n    old.linesRoot == new.linesRoot", ""),
]


def vectors(lean: Path, path: str, lake: str) -> str:
    build = subprocess.run([lake, "-d", str(lean), "build", "gate_vectors"], capture_output=True, text=True)
    if build.returncode:
        return "BUILD_ERROR"
    exe = lean / ".lake" / "build" / "bin" / "gate_vectors.exe"
    out = subprocess.run([str(exe), path], capture_output=True, text=True).stdout.splitlines()
    first = [line.split("line=")[1].split()[0] for line in out if "MISMATCH" in line][:3]
    return out[-1].split()[0] + (" first_lines=" + ",".join(first) if first else "")


def main(lean_dir: str, path: str, lake: str, window: str = ":") -> int:
    lean = Path(lean_dir)
    spec = lean / "BlindLedger" / "Gate" / "Spec.lean"
    original = spec.read_bytes()
    text = original.decode("utf-8")
    killed = 0
    run = MUTANTS[slice(*(int(x) if x else None for x in window.split(":")))]
    try:
        for name, old, new in run:
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
    print(f"MUTANTS total={len(run)} killed={killed}")
    return 0 if restored == "GATE_VECTORS=PASS" and killed == len(run) else 1


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
