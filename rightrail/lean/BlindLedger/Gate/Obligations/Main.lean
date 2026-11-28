import BlindLedger.Gate.Obligations.Check
import BlindLedger.Gate.Obligations.RunDigest
import BlindLedger.Gate.Flat.Io
import BlindLedger.Gate.Engine3.Sha3Fused
import BlindLedger.Financial.Payment.Cursor

open BlindLedger.Gate.Obligations
open BlindLedger.Gate.FactCodec
open BlindLedger.Gate.Flat.Io
open BlindLedger.Financial (Cursor.decodeFinancialInput Cursor.parsePaymentRequest)

/-! `obligations_shard`: the obligations shard as a program.  Its log is a file of 256-byte records; its tables are
    in memory and hold one record number per command id, case and obligation.  A command reads the records it needs
    from the file.

    `run FRAMES LOG ANSWERS DISPATCH` opens LOG (creating it when absent) for this run alone, applies the commands of
    FRAMES in order to a shard whose card has `dispatch` = DISPATCH (0 or 1), appends their records to LOG, checks LOG
    with the checker, and only when it checks writes a run-end record (unless the log already ends at one) holding the
    SHA3-512 of the bytes of its run, as read back, chained to the digest of the run-end record before it (`spanDig`),
    syncs LOG, closes it and writes one answer per
    command to ANSWERS (to a temporary file, then renamed).  An ANSWERS file left by an earlier run is deleted first.
    When the check fails the run's records are added to the file `LOG.cut-<record>` and cut off, so LOG is as it was,
    no answer is written and the exit code is 1.  When LOG cannot be closed no answer is written and the exit code is
    1.  A second run on a LOG in use refuses with exit code 75 and writes nothing.  `check LOG` checks a log alone.
    `bench PACK ITEM ID N LOG` applies the pack of PACK to a new LOG, then the commands of ITEM, which are
    one obligation's, once for each of N obligations (ID, that obligation's item id, is replaced by N ids of the same
    length), one command of every obligation before the next command of any, and reports what the commands read and
    wrote and how long they took; it then waits for a line on its input, so the process can be measured.

    Opening a log checks it.  A log whose end does not check because the log ends early (a command that was being
    written when the program stopped, bytes that are not a whole record, records that are all zero) is cut back to the
    end of the last command that checks: the bytes cut are first added to the file `LOG.cut-<record>`, then a repair
    record is written at the cut.  No answer was given for a command cut this way: only records after the last
    commit point (a run-end or repair record) are cut, and answers are given only after the run-end record after
    them is on disk.  The end cut must also have ended early (`cutOk`).  When the check stops at or before a commit
    point (a run-end record whose digest is not its run's is one), when a command record follows the place the check
    stopped, or when the last command's records are all there and do not check, the log was changed: the program
    stops with `CORRUPT` and leaves the log as it is.

    A frame: kind u8, time u64, payload length u32 (big-endian), payload, then two class bytes (kind 1) or a request
    id with a u16 length (kind 12).  Kind 1 is a control pack, the pack of the BLFIN02 payload; kind 2 opens the
    obligation of its BLFIN02 payload, whose own time must be the frame's; kind 5 is a payment or reversal, the
    command, expected revision and item of its BLFPAY01 payload; kind 12 evaluates the item of its BLFIN02 payload. -/

/-- The big-endian number in bytes `i` to `i + w - 1`.  It reads no byte outside `b`. -/
def beAt (b : ByteArray) (i w : Nat) : Nat := (b.extract i (i + w)).foldl (fun a x => a * 256 + x.toNat) 0

/-- The source every frame is read from: number 1, registered at class 1. -/
def registry : Array Nat := #[0, 1]

/-- The command of a frame.  The payload is read by the decoders that work on an array of bytes, which are Lean's
    decoders (`Cursor.decodeFinancialInput_eq`; `Cursor.parsePaymentRequest_eq`, for a payload that holds more than
    its magic and kind). -/
def cmdOfFrame (kind atMs : Nat) (payload : ByteArray) (extra : Bytes) : Option Cmd :=
  let base (act : Act) (scope : Bytes) (exprev : Option Nat) : Cmd :=
    { act, scope, atMs, exprev, actor := zeros 32, role := 0, attr := 2, src := 1 }
  match kind with
  | 1 => do
    let i ← Cursor.decodeFinancialInput payload
    let o ← extra[0]?
    let d ← extra[1]?
    pure (base (.pack i.pack ⟨o.toNat, d.toNat⟩) (scopeOfCtx i.context) none)
  | 2 => do
    let i ← Cursor.decodeFinancialInput payload
    pure (base (.population i) (scopeOfCtx i.context) none)
  | 5 => do
    let r ← if BlindLedger.Financial.Payment.paymentMagic.length + 1 ≤ payload.size
      then Cursor.parsePaymentRequest payload
      else BlindLedger.Financial.Payment.parsePaymentRequest payload.toList
    pure (base (.payment r.input.context.itemId r.command) (scopeOfCtx r.input.context) r.expectedRevision)
  | 12 => do
    let i ← Cursor.decodeFinancialInput payload
    let id ← String.fromUTF8? ⟨extra.toArray⟩
    pure (base (.evaluate i.context.itemId id) (scopeOfCtx i.context) none)
  | k => some (base (.other k) [] none)

/-- The frame at byte `i`: its command and the byte after it.  Each length is compared with the size of `b` before
    the bytes it covers are read. -/
def frameAt (b : ByteArray) (i : Nat) : Except String (Cmd × Nat) :=
  if i + 13 > b.size then .error s!"frame at byte {i}: short header" else
  let kind := beAt b i 1
  let p := i + 13 + beAt b (i + 9) 4
  -- After the payload: two class bytes (kind 1), or a request id after its two length bytes (kind 12).
  let fixed := if kind = 1 ∨ kind = 12 then 2 else 0
  if p + fixed > b.size then .error s!"frame at byte {i}: short payload" else
  let next := p + fixed + (if kind = 12 then beAt b p 2 else 0)
  if next > b.size then .error s!"frame at byte {i}: short request id" else
  match cmdOfFrame kind (beAt b (i + 1) 8) (b.extract (i + 13) p)
      (b.extract (if kind = 12 then p + 2 else p) next).toList with
  | some c => .ok (c, next)
  | none => .error s!"frame at byte {i}: payload does not decode"

/-- Every frame of `b`: its command and the bytes it spans. -/
def readFrames (b : ByteArray) (i : Nat := 0) (acc : Array (Cmd × Nat × Nat) := #[]) :
    Except String (Array (Cmd × Nat × Nat)) :=
  if i = b.size then .ok acc else
  match frameAt b i with
  | .error e => .error e
  | .ok (c, next) =>
    if _h : i < next ∧ next ≤ b.size then readFrames b next (acc.push (c, i, next))
    else .error s!"frame at byte {i}: it does not end inside the file"
termination_by b.size - i
decreasing_by omega

def dispText : Disp → String
  | .admitted i => s!"admitted {i}"
  | .already => "already"
  | .duplicate i => s!"duplicate {i}"
  | .conflict => "conflict"
  | .refused c => s!"refused {reprStr c}"

def fail {α : Type} (m : String) : IO α := throw (IO.userError m)

/-- Opens (creating if absent) the file at the UTF-8 `path` for reading and writing, in binary mode, with no sharing:
    `_wsopen` with `_SH_DENYRW`, so a second open of it, by this or another process, fails.  `0xFFFFFFFE`: it fails
    for `EACCES` (the file is in use, or may not be opened); `0xFFFFFFFF`: it fails otherwise. -/
@[extern c inline "({ extern int rr_mb(unsigned, unsigned, const char*, int, unsigned short*, int) __asm__(\"MultiByteToWideChar\"); extern int rr_wsopen(const unsigned short*, int, int, int) __asm__(\"_wsopen\"); extern int* rr_errno(void) __asm__(\"_errno\"); unsigned short w[32768]; *rr_errno() = 0; int fd = rr_mb(65001, 0, lean_string_cstr(#1), -1, w, 32768) ? rr_wsopen(w, 0x8102, 0x10, 0x180) : -1; lean_io_result_mk_ok(lean_box_uint32(fd >= 0 ? (uint32_t)fd : *rr_errno() == 13 ? 0xFFFFFFFEu : 0xFFFFFFFFu)); })"]
opaque BlindLedger.Gate.Obligations.openExclusive (path : @& String) : IO UInt32

/-- Run a file operation whose status is 0 on success. -/
def must (what : String) (op : IO UInt32) : IO Unit := do
  if (← op) != 0 then fail what

def nowNs : IO Nat := IO.monoNanosNow

/-- Where the commands' time went, in nanoseconds: in reading records from the file; in rebuilding from those
    records what a command is decided on; in deciding it and setting the tables; and in writing its records. -/
structure Stages where
  file : Nat := 0
  load : Nat := 0
  decide : Nat := 0
  write : Nat := 0

/-- The shard: its tables, and its log as an open file.  `reads` and `writes` count records. -/
structure Run where
  s : Store
  fd : UInt32
  reads : Nat := 0
  writes : Nat := 0
  ns : Stages := {}

/-- Record `i` of the log file, when the file holds all of it. -/
def fetch (fd : UInt32) (i : Nat) : IO (Option Bytes) := do
  let b ← pgReadAt fd (i * recBytes).toUInt64 recBytes.toUSize
  pure (if b.size = recBytes then some b.toList else none)

/-- A read of the log against the file: the value, `k` plus the number of records read from the file, and `ns` plus
    the time those reads took.  `last` is the record read just before: a record asked for twice in a row (an
    obligation's newest state row, found by its table and then first in its chain) is read from the file once. -/
def Rd.runIO {α : Type} (fd : UInt32) : Rd α → Nat → Nat → Nat × Option Bytes → IO (α × Nat × Nat)
  | .done a, k, ns, _ => pure (a, k, ns)
  | .need i f, k, ns, last =>
    if last.1 = i then Rd.runIO fd (f last.2) k ns last else do
      let t0 ← nowNs
      let b ← fetch fd i
      let t1 ← nowNs
      Rd.runIO fd (f b) (k + 1) (ns + (t1 - t0)) (i, b)

/-- A command decided and the tables set, computed when this action runs: a pure value may be computed after the
    clock reads around it, which would time nothing. -/
@[noinline] def decideRun (s : Store) (c : Cmd) (l : Loaded) : IO (Disp × List Bytes × Store) :=
  pure (applyView s (viewWith s c l) c)

/-- Apply one command: read its records from the file, decide it, and append what it writes.  The run is taken
    apart first, so the store's tables are not shared and grow in place, not by a copy. -/
def Run.step (r : Run) (c : Cmd) : IO (Disp × Run) := do
  let { s, fd, reads, writes, ns } := r
  let at_ := s.n
  let t0 ← nowNs
  -- Record `at_` is past the end of the log and reads as absent, which is what `last` starts as.
  let (l, k, file) ← Rd.runIO fd (loadRd s c) 0 0 (at_, none)
  let t1 ← nowNs
  let (d, bs, s) ← decideRun s c l
  let t2 ← nowNs
  if !bs.isEmpty then
    must "the log could not be written"
      (pgWrite fd (at_ * recBytes).toUInt64 (bs.foldl (fun a b => b.foldl ByteArray.push a) ByteArray.empty))
  let t3 ← nowNs
  pure (d, { s, fd, reads := reads + k, writes := writes + bs.length,
             ns := ⟨ns.file + file, ns.load + (t1 - t0 - file), ns.decide + (t2 - t1), ns.write + (t3 - t2)⟩ })

/-- The checker's answer on the first `n` records of `b`, computed when this action runs. -/
@[noinline] def checkRun (b : ByteArray) (n : Nat) : IO Checked := pure (checkLog (recOf b n) (digOf b) n)

/-- The checker's answer on the `m` records of `tail`, carried on from its state `st` after the first `base` records,
    `cmds` of them commands, which are those of `old`; computed when this action runs.  Each record is checked once. -/
@[noinline] def checkOn (old tail : ByteArray) (st : Chk) (base cmds m : Nat) : IO Checked :=
  pure (checkLog (recAt old tail base m) (digAt old tail base) (base + m) st base cmds)

/-- The bytes of the file `fd` from byte `off` to its end, read `chunk` bytes at a time until a read gives none.  When
    `reads` reads do not reach the end it fails: a part of the file is never taken for the whole. -/
def readSpan (fd : UInt32) (off chunk reads : Nat) : IO ByteArray := do
  let mut out := ByteArray.empty
  for _ in [0:reads] do
    let b ← pgReadAt fd (off + out.size).toUInt64 chunk.toUSize
    if b.isEmpty then return out
    out := out ++ b
  fail s!"the log is longer than {reads} reads of {chunk} bytes"

/-- The number of whole records of `b` among its first `n` once the all-zero records at their end, which are a write
    that did not reach the disk, are not counted. -/
def wholeRecs (b : ByteArray) : Nat → Nat
  | 0 => 0
  | n + 1 => if (b.extract (n * recBytes) ((n + 1) * recBytes)).data.all (· == 0) then wholeRecs b n else n + 1

/-- Add `cut` to the file `side`, which is synced and closed. -/
def setAside (side : String) (cut : ByteArray) : IO Unit := do
  let sfd ← pgOpen side
  if sfd == 0xFFFFFFFF then fail s!"{side} could not be opened"
  must s!"{side} could not be written" (pgWrite sfd (← System.FilePath.metadata side).byteSize cut)
  must s!"{side} could not be synced" (pgSync sfd)
  must s!"{side} could not be closed" (pgClose sfd)

/-- The log at `path`, opened for this run alone. -/
def holdLog (path : String) : IO UInt32 := do
  let fd ← openExclusive path
  if fd == 0xFFFFFFFE then fail s!"BUSY: the log {path} is in use by another run, or may not be opened; nothing was written"
  if fd == 0xFFFFFFFF then fail s!"the log {path} could not be opened"
  pure fd

/-- A log opened for a run: the run, the bytes the log held, and their check, whose state is the one after the last
    good record: the run's own check starts there. -/
structure Opened where
  run : Run
  old : ByteArray
  checked : Checked

/-- Open the log held as `fd`, with its tables rebuilt from its records, cutting an end that ended early.  A log that
    does not check and whose end did not end early is refused, and left as it is. -/
def openLog (path : String) (fd : UInt32) (card : Card) (chunk reads : Nat) : IO Opened := do
  let old ← readSpan fd 0 chunk reads
  let n := wholeRecs old (old.size / recBytes)
  let checked ← checkRun old n
  let keep := checked.good * recBytes
  if keep ≠ old.size ∧ !cutOk (recOf old n) n checked then
    let _ ← pgClose fd
    fail s!"CORRUPT: {checked.err.getD ""}; the log is not cut there (a commit point or a command record follows, or the last command's records are all there); {path} is left as it is"
  let mut s := Store.empty card registry
  for i in [0:checked.good] do
    s := s.scan (old.extract (i * recBytes) ((i + 1) * recBytes)).toList
  if keep = old.size then return { run := { s, fd }, old, checked }
  -- The bytes cut are kept, never only removed: they are added to the side file before the log is cut.
  let cut := old.extract keep old.size
  setAside s!"{path}.cut-{checked.good}" cut
  must "the log could not be cut" (pgTrunc fd keep.toUInt64)
  let some rep := encFull (full repairC ⟨checked.good, cut.size⟩ ⟨0, 1⟩) | fail "the repair record does not fit"
  must "the repair record could not be written" (pgWrite fd keep.toUInt64 (rep.foldl ByteArray.push ByteArray.empty))
  must "the log could not be synced" (pgSync fd)
  IO.println s!"repaired: cut {cut.size} bytes at record {checked.good}, kept in {path}.cut-{checked.good}: {checked.err.getD "the last record is not whole"}"
  -- The repair record is checked with the run's records, from the state after the last good record.
  pure { run := { s := s.scan rep, fd }, old, checked }

/-- Report the check of a log of `n` whole records followed by `extra` bytes, which took `ns`; 0 when it checks. -/
def verdict (checked : Checked) (n extra ns : Nat) : IO UInt32 := do
  match checked.err with
  | some e => IO.println s!"check failed: {e}; good_records={checked.good}"; return 1
  | none =>
    if extra = 0 then
      IO.println s!"check ok commands={checked.cmds} records={n} check_ns={ns}"
      return 0
    IO.println s!"check failed: {extra} bytes after the last whole record; good_records={checked.good}"
    return 1

def checkMode (logPath : String) : IO UInt32 := do
  let b ← IO.FS.readBinFile logPath
  let n := b.size / recBytes
  let t0 ← nowNs
  let checked ← checkRun b n
  let t1 ← nowNs
  verdict checked n (b.size - n * recBytes) (t1 - t0)

def framesOf (path : String) : IO (ByteArray × Array (Cmd × Nat × Nat)) := do
  let b ← IO.FS.readBinFile path
  match readFrames b with
  | .ok c => pure (b, c)
  | .error e => fail s!"{path}: {e}"

/-- Run the commands of `frames` on the log, reading the log `chunk` bytes at a time, in at most `reads` reads. -/
def runMode (frames logPath answersPath : String) (dispatch : Bool) (chunk reads : Nat) : IO UInt32 := do
  let fd ← holdLog logPath
  -- An answer file of an earlier run is never taken for this run's, whatever ends the run; it is removed while the
  -- log is held.
  if (← System.FilePath.pathExists answersPath) then IO.FS.removeFile answersPath
  let (_, cmds) ← framesOf frames
  let { run, old, checked } ← openLog logPath fd { live := false, carry := false, dispatch, egress := false } chunk reads
  let mut r := run
  let start := r.s.n
  let mut answers : Array String := #[]
  let t0 ← nowNs
  for (c, _, _) in cmds do
    let (d, r') ← r.step c
    r := r'
    answers := answers.push (dispText d)
  let t1 ← nowNs
  must "the log could not be synced" (pgSync r.fd)
  IO.println s!"commands={cmds.size} records={r.s.n} reads={r.reads} writes={r.writes} engine_ns={t1 - t0}"
  -- The records are on disk and checked before any answer is given: the bytes from the last good record on, read
  -- back from the file and checked once each, from the checker's state after that record.
  -- The reads are as many as the records the run put after `base` take, and the empty read after them: the bound on
  -- reads is met when the log is opened, before anything is written.
  let base := checked.good
  let tail ← readSpan r.fd (base * recBytes) chunk ((r.s.n - base) * recBytes / chunk + 2)
  let m := tail.size / recBytes
  let t2 ← nowNs
  let res ← checkOn old tail checked.st base checked.cmds m
  let t3 ← nowNs
  if (← verdict res (base + m) (tail.size - m * recBytes) (t3 - t2)) ≠ 0 then
    setAside s!"{logPath}.cut-{start}" (tail.extract ((start - base) * recBytes) tail.size)
    must "the log could not be cut" (pgTrunc r.fd (start * recBytes).toUInt64)
    must "the log could not be synced" (pgSync r.fd)
    must "the log could not be closed" (pgClose r.fd)
    IO.eprintln s!"REJECTED: the records of this run do not check; they are in {logPath}.cut-{start} and the log is as it was; no answer was given"
    return 1
  -- The commit point: a run-end record after the records just checked, with the digest of the bytes of its run as
  -- read back, synced before any answer is given.  None is needed when the log already ends at one (the run wrote
  -- nothing); a repair record is not one, and the run-end record after it closes the run that starts there.
  let total := base + m
  if res.st.span ≠ total then
    let some e := encFull (full endC ⟨total, digAt old tail base res.st.span res.st.prev total⟩ ⟨0, 1⟩)
      | fail "the run-end record does not fit"
    must "the run-end record could not be written"
      (pgWrite r.fd (total * recBytes).toUInt64 (e.foldl ByteArray.push ByteArray.empty))
    must "the log could not be synced" (pgSync r.fd)
  -- The answers are on disk before they take the answer file's name, and the log is closed before that: a close
  -- that fails leaves no answer file, and the exit code is 1.
  let tmp := s!"{answersPath}.tmp"
  if (← System.FilePath.pathExists tmp) then IO.FS.removeFile tmp
  setAside tmp (String.intercalate "\n" answers.toList ++ "\n").toUTF8
  if (← pgClose r.fd) != 0 then
    IO.FS.removeFile tmp
    fail "the log could not be closed; no answer was given"
  IO.FS.rename tmp answersPath
  return 0

/-- Whether `pat` is at byte `i` of `b`, comparing its first `k` bytes; `i + k` is within `b`. -/
def matchAt (b pat : ByteArray) (i : Nat) : Nat → Bool
  | 0 => true
  | k + 1 => b[i + k]! == pat[k]! && matchAt b pat i k

/-- `b` with `rep`, which is as long as `pat`, written over every place `pat` is at. -/
def substAll (b pat rep : ByteArray) : ByteArray := Id.run do
  let mut out := b
  for i in [0:b.size + 1 - pat.size] do
    if matchAt b pat i pat.size then out := rep.copySlice 0 out i pat.size
  return out

/-- An id as long as `id`: its last four bytes are the number `j` in base 36. -/
def idOf (id : ByteArray) (j : Nat) : ByteArray :=
  (List.range 4).foldl (fun a k =>
    let x := j / 36 ^ k % 36
    a.set! (id.size - 1 - k) (if x < 10 then 48 + x else 87 + x).toUInt8) id

def benchMode (packPath itemPath item : String) (n : Nat) (logPath : String) : IO UInt32 := do
  if (← System.FilePath.pathExists logPath) then fail s!"{logPath} exists; the measurement needs a new log"
  if item.toUTF8.size < 4 ∨ 36 ^ 4 < n then fail "the item id is under four bytes, or more obligations than its ids"
  let (_, packs) ← framesOf packPath
  let (tb, spans) ← framesOf itemPath
  let mut r := (← openLog logPath (← holdLog logPath)
    { live := false, carry := false, dispatch := false, egress := false } 16777216 65536).run
  for (c, _, _) in packs do
    r := (← r.step c).2
  r := { r with reads := 0, writes := 0, ns := {} }
  let mut build := 0
  let mut admitted := 0
  let mut duplicate := 0
  let mut phases : Array Nat := #[]
  for (_, a, b) in spans do
    let frame := tb.extract a b
    let mut ns := 0
    for j in [0:n] do
      let tb0 ← nowNs
      let c ← match frameAt (substAll frame item.toUTF8 (idOf item.toUTF8 j)) 0 with
        | .ok (c, _) => pure c
        | .error e => fail e
      let t0 ← nowNs
      build := build + (t0 - tb0)
      let (d, r') ← r.step c
      let t1 ← nowNs
      r := r'
      ns := ns + (t1 - t0)
      match d with
      | .admitted _ => admitted := admitted + 1
      | .duplicate _ => duplicate := duplicate + 1
      | _ => pure ()
    phases := phases.push ns
  let t0 ← nowNs
  must "the log could not be synced" (pgSync r.fd)
  let t1 ← nowNs
  IO.println s!"obligations={n} commands={n * spans.size} admitted={admitted} duplicate={duplicate} engine_ns={phases.foldl (· + ·) 0} phase_ns={phases} file_ns={r.ns.file} load_ns={r.ns.load} decide_ns={r.ns.decide} write_ns={r.ns.write} build_ns={build} sync_ns={t1 - t0} reads={r.reads} writes={r.writes} records={r.s.n} ident_slots={r.s.ident.size}"
  (← IO.getStdout).flush
  -- The tables are still held while the caller measures the process.
  let _ ← (← IO.getStdin).getLine
  IO.println s!"held obligations={r.s.obl.fold (fun a _ l => a + l.length) 0}"
  must "the log could not be closed" (pgClose r.fd)
  return 0

def main (args : List String) : IO UInt32 := do
  try
    match args with
    | ["run", f, l, a, d] => runMode f l a (d == "1") 16777216 65536
    | ["run", f, l, a, d, k, m] =>
      match k.toNat?, m.toNat? with
      -- A read size of 0, or one that does not fit a read, would read nothing and take the log for empty.
      | some k, some m =>
        if k = 0 ∨ 1073741824 < k then fail "the read size is not from 1 byte to 1 GiB" else runMode f l a (d == "1") k m
      | _, _ => fail "the read size and the read count are not numbers"
    | ["check", l] => checkMode l
    | ["bench", p, f, item, n, l] => benchMode p f item n.toNat! l
    | _ =>
      IO.eprintln "usage: obligations_shard run FRAMES LOG ANSWERS DISPATCH [READ_BYTES READS] | check LOG | bench PACK ITEM ID N LOG"
      return 2
  catch e =>
    IO.eprintln (toString e)
    return if (toString e).startsWith "BUSY" then 75 else 1
