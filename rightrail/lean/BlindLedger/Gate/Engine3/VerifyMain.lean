import BlindLedger.Gate.Engine3.Verify
import BlindLedger.Gate.Engine3.PipeIO

/-! `gate_verify3 DIR SHARD rows-offline|rows-tail [VDIR [IDLE_MS [BATCHES]]]`: the checker (conformance/ENGINE_V3.md
    section 10) of a store `DIR` of `gate_hist3` (rows files) on its own history (Verify.lean `checkFrame`), resumed from
    its last state (`resume`).  A store that does
    not resume, or a fault of it, prints a `VSTORE_REFUSED` line with the cause, and the store is rebuilt from the log.
    `rows-offline` checks the whole log as it is; `rows-tail` follows it as the engine writes, and ends when no frame has come for `IDLE_MS` (default 3000).  `VDIR` (default `DIR.verify`) is the verifier's
    own store.  With `BATCHES` the log must hold exactly that many whole frames (a cut log is a mismatch); without it a
    log with no whole frame verifies nothing and is refused.  The store's `facts` file must then be the records its fact
    frames derive, byte for byte.
    Exit 0 and a `VERIFIED` line with the cost; 3 and a `VERIFY_MISMATCH`, `VERIFY_COUNT` or `TORN_TAIL` (bytes after
    the last whole frame, with their offset and batch number) line; 64 usage; 4 no log or
    no whole frame.
    A test run with RR_V3_SKIP=answer is diagnostic only: exit 2, never VERIFIED.
    Synthetic, nonpayment, non-PHI, activation=false. -/

open BlindLedger.Gate.Engine3 BlindLedger.Gate.Engine3.Verify

def secs (ns : Nat) : Float := ns.toFloat / 1e9

/-- The `VERIFIED` line for `n` batches and `l` lines, and the costs of the `l - l0` lines of this start. -/
def report (c : Ctx) (n l0 l wall : Nat) : IO Unit := do
  let a ← c.prof.get
  let k := l - l0
  let us := fun (x : Nat) => if k == 0 then 0.0 else x.toFloat / 1e3 / k.toFloat
  let path := a[5]! - a[12]!
  let cores := a[6]! + a[7]! + a[8]! + a[9]!
  let label := if !c.skip.isEmpty then "DIAGNOSTIC_INCOMPLETE" else "VERIFIED"
  IO.println s!"{label} shard {c.shard} batches {n} lines {l} (this start {k}) wall {secs wall}s lines/s {k.toFloat / secs wall} (frames only {k.toFloat / secs a[5]!})"
  IO.println s!"us/line frame path: fetch {us a[0]!} decide {us a[1]!} puts {us a[11]!} root {us a[4]!} other {us (path - a[0]! - a[1]! - a[11]! - a[4]!)} waits {us a[12]!}"
  IO.println s!"us/line other cores: answer {us a[6]!} batch digest {us a[7]!} frame decode {us a[8]!} answer check {us a[9]!}"
  IO.println s!"us/line busy: frame path {us path} other cores {us cores} total {us (path + cores)}"
  -- the step's own clocks (Step.lean `phases`), summed over the frames: the frame path's inside, and the sampled second decision (slot 27, on the frame path)
  let ph ← BlindLedger.Gate.Engine3.Run.phases.get
  let nm := #[(5, "admit+setup"), (1, "byte read path"), (17, "feeds"), (18, "probes+round2+layout"), (20, "store lines+rows"), (21, "key digests"),
    (10, "key hashing"), (19, "decideRows"), (2, "spawn"), (3, "puts"), (27, "second decision by decideBatchIdx (1 in 64 frames; reads included)")]
  IO.println s!"us/line step phases (21, 17, 18, 20 inside byte read path): {nm.toList.map fun (i, s) => s!"{s} {us ph[i]!}"}"

/-- The frames of the log from `pos0` (state `v0`, `lines0` lines before it), checked by `vf` (one pass offline; in tail
    mode until no frame has come for `idle` ms), `save`d after every run of them: the state, the log position, the lines
    checked in all, and the time of the last frame; or the first mismatch. -/
def follow {σ : Type} (c : Ctx) (vf : Option σ → Except String Pre → IO (Except Mismatch (σ × Task (Except Mismatch Nat))))
    (num : σ → Nat) (log : UInt32) (logP : String) (tail : Bool) (idle : Nat) (v0 : Option σ) (pos0 lines0 : Nat)
    (save : σ → Nat → Nat → IO σ) : IO (Except Mismatch (Option σ × Nat × Nat × Nat)) := do
  let prog := (← IO.getEnv "RR_V3_PROGRESS").isSome
  let mut v := v0
  let mut pos := pos0
  let mut lines := lines0
  let mut last ← IO.monoNanosNow
  for _ in [0:100000000] do
    -- the state moves into `pump` (see `pump`)
    let v1 := v
    v := none
    match ← pump c vf num log logP v1 pos with
    | .error m => return .error m
    | .ok (v', pos', k) =>
      lines := lines + k
      let mut v' := v'
      if pos' != pos then
        last ← IO.monoNanosNow
        -- the saved state replaces the one saved, which is dropped first so no second reference keeps its facts' bytes shared
        if let some x := v' then
          v' := none
          v' := some (← save x pos' lines)
        if prog then  -- bench only: the stage clocks after this pump, for the history bench (tests/gate_bench.py --e3)
          IO.println s!"PROGRESS {(v'.map num).getD 0} {lines} {(← c.prof.get).toList}"
          (← IO.getStdout).flush
      v := v'; pos := pos'
    if !tail then break
    if (← IO.monoNanosNow) - last > idle * 1000000 then break
    IO.sleep 2
  return .ok (v, pos, lines, last)

/-- The checker's history in `vdir`, rebuilt from nothing (`vlast` and `vfacts` removed first): a new key, so every record of an
    earlier build is cut. -/
def rebuild (c : Ctx) : IO (VC × ByteArray) := do
  let lp := s!"{c.vdir}/vlast"
  if ← System.FilePath.pathExists lp then IO.FS.removeFile lp
  let fp := s!"{c.vdir}/vfacts"
  if ← System.FilePath.pathExists fp then IO.FS.removeFile fp
  let k ← VStore.newKey s!"{c.vdir}/vkey"
  match ← VMirror.load c.vdir k c.shard with
  | .ok m => return (⟨m, ⟨0, 0, 0⟩, ⟨0, 0, 0⟩, .empty, .empty, 0, {}, BlindLedger.Gate.FactFrame.Refs.none BlindLedger.Gate.FactFrame.sha, .empty, .empty, none⟩, k)
  | .error e => throw (IO.userError s!"checker store: {e}")

/-- `follow` on the checker's history, resumed from `vlast` when it and the store agree (`resume`).  A store that
    cannot resume (except at a first start, with no key and no last state) or that faults while it is read is reported
    with the cause, rebuilt, and the log checked again from batch 1; a store that faults on three builds in a row is an
    error.  The lines checked before this start come back with the rest. -/
def followC (c : Ctx) (log : UInt32) (logP : String) (tail : Bool) (idle : Nat) :
    IO (Except Mismatch (Option VC × Nat × Nat × Nat × Nat)) := do
  let refused (why : String) : IO Unit := IO.println s!"VSTORE_REFUSED({c.shard}) {why}: rebuilt from the log"
  let first := !(← System.FilePath.pathExists s!"{c.vdir}/vkey") && !(← System.FilePath.pathExists s!"{c.vdir}/vlast")
  let size := (← System.FilePath.metadata logP).byteSize.toNat
  -- the state is handed to `follow` through a cell, so no closure keeps a second reference to it (see `pump`)
  let start ← IO.mkRef (← if first then pure none else match ← resume c log size with
    | .ok x => pure (some x)
    | .error why => do refused why; pure none)
  for _ in [0:3] do
    try
      let (v, k, pos, l0) ← match ← start.swap none with
        | some x => pure x
        | none => do let (v, k) ← rebuild c; pure (v, k, 0, 0)
      return (← follow c (checkFrame c) (·.n) log logP tail idle (some v) pos l0 (saveLast c k)).map
        fun (v, p, l, last) => (v, p, l0, l, last)
    catch e =>
      let s := toString e
      if !s.startsWith VMirror.faultTag then throw e
      refused s
  throw (IO.userError "checker store: a fault on every build")

def main (args : List String) : IO UInt32 := do
  Run.allocLoad
  Run.lazyCommit
  let dir :: sh :: mode0 :: rest := args | return 64
  let some shard := sh.toNat? | return 64
  if mode0 != "rows-offline" && mode0 != "rows-tail" then return 64
  let vdir := rest.headD s!"{dir}.verify"
  let some idle := (rest.getD 1 "3000").toNat? | return 64
  let some expect := (rest[2]?).mapM String.toNat? | return 64
  let rawSkip := (← IO.getEnv "RR_V3_SKIP").getD ""
  let skip := rawSkip.splitOn "," |>.filter (· != "")
  if (!rawSkip.isEmpty && skip.isEmpty) || skip.any (· != "answer") then
    IO.eprintln "VERIFY_BAD_SKIP: expected answer"
    return 64
  IO.FS.createDirAll vdir
  let logP := s!"{dir}/log"
  let t0 ← IO.monoNanosNow
  -- the engine creates `key` and then `log`; tail mode waits for them
  for _ in [0:600] do
    if (← System.FilePath.pathExists logP) || mode0 == "rows-offline" then break
    IO.sleep 100
  let ok := (← System.FilePath.pathExists logP) && (← System.FilePath.pathExists s!"{dir}/key")
  if !ok then return 4
  let .ok sec ← BlindLedger.Gate.Engine3.readKey dir | return 4
  let log ← BlindLedger.Gate.Flat.Io.pgOpen logP
  if log == 0xFFFFFFFF then return 4
  let prof ← IO.mkRef (Array.replicate 13 0)
  let c : Ctx := ⟨vdir, sec, shard, skip, prof⟩
  let tail := mode0 == "rows-tail"
  -- the batches, the facts derived, the log position, the lines checked before this start and in all, and the time of the
  -- last frame
  let r : Except Mismatch (Nat × BlindLedger.Gate.FactFrame.Facts × Nat × Nat × Nat × Nat) ←
    pure <| (← followC c log logP tail idle).map fun (v, pos, l0, l, last) =>
      ((v.map (·.n)).getD 0, (v.map (·.fs)).getD {}, pos, l0, l, last)
  let (n, fs, pos, l0, l, last) ← match r with
    | .error m => IO.println m.show; return 3
    | .ok x => pure x
  let now ← IO.monoNanosNow
  -- bytes after the last whole frame are a log not fully checked: never VERIFIED
  let size := (← System.FilePath.metadata logP).byteSize.toNat
  if pos < size then
    IO.println s!"TORN_TAIL({shard}) batch {n + 1} offset {pos}: {size - pos} bytes after the last whole frame"
    return 3
  if expect.any (· != n) then IO.println s!"VERIFY_COUNT({shard}) expected {expect.getD 0} batches, log has {n}"; return 3
  if expect.isNone && n == 0 then IO.println s!"VERIFY_EMPTY({shard}): no whole frame in the log"; return 4
  -- the store's `facts` file must be the records the log's fact frames derive, or a prefix of them, or them and bytes past
  match ← factsDiff c dir fs with
  | .error m => IO.println m.show; return 3
  | .ok note => if let some s := note then IO.println s
  -- tail mode: the wall time ends at the last frame, not after the idle wait
  report c n l0 l (if tail then last - t0 else now - t0)
  return if skip.isEmpty then 0 else 2
