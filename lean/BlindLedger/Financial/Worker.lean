import BlindLedger.Financial.FastDecode
import BlindLedger.Financial.Evaluation

namespace BlindLedger.Financial

/-! Evaluator worker frames. On the pipe each frame is a u32 big-endian length
    and its bytes. A request frame is one BLFIN02 input. A response frame is one
    outcome: tag 0 then the BLFRES02 result, or the single byte 1 (decode),
    2 (evaluation) or 3 (encoding) rejection. The worker adds no policy; it decodes with the length-free twin
    `Fast.decodeFinancialInput`, proved equal to `decodeFinancialInput`. -/

inductive WorkerOutcome where
  | evaluated (result : Bytes)
  | decodeRejected
  | evaluationRejected
  | encodingRejected
deriving DecidableEq, Repr

def evaluateWire (wire : Bytes) : WorkerOutcome :=
  match Fast.decodeFinancialInput wire with
  | none => .decodeRejected
  | some input =>
      match evaluate input with
      | none => .evaluationRejected
      | some result =>
          match encodeFinancialResult result with
          | none => .encodingRejected
          | some output => .evaluated output

def encodeWorkerOutcome : WorkerOutcome → Bytes
  | .evaluated result => UInt8.ofNat 0 :: result
  | .decodeRejected => [UInt8.ofNat 1]
  | .evaluationRejected => [UInt8.ofNat 2]
  | .encodingRejected => [UInt8.ofNat 3]

def decodeWorkerOutcome : Bytes → Option WorkerOutcome
  | [] => none
  | tag :: rest =>
      if tag.toNat = 0 then some (.evaluated rest)
      else if rest ≠ [] then none
      else if tag.toNat = 1 then some .decodeRejected
      else if tag.toNat = 2 then some .evaluationRejected
      else if tag.toNat = 3 then some .encodingRejected
      else none

/-- The worker's whole policy: one BLFIN02 frame in, one outcome frame out. -/
def workerRespond (wire : Bytes) : Bytes := encodeWorkerOutcome (evaluateWire wire)

/-- The frame arrives as a `ByteArray`; `Fast.decodeFinancialInputBA` is proved equal to the list
    decoder on `wire.toList`, so this is `workerRespond` without a second large list. -/
def workerRespondBA (wire : ByteArray) : Bytes :=
  encodeWorkerOutcome
    (match Fast.decodeFinancialInputBA wire with
      | none => .decodeRejected
      | some input =>
          match evaluate input with
          | none => .evaluationRejected
          | some result =>
              match encodeFinancialResult result with
              | none => .encodingRejected
              | some output => .evaluated output)

theorem workerRespondBA_eq (wire : ByteArray) : workerRespondBA wire = workerRespond wire.toList := by
  unfold workerRespondBA workerRespond evaluateWire
  rw [Fast.decodeFinancialInputBA_eq]

def maxWorkerFrameBytes : Nat := maxTotalEncodedBytes + 1

end BlindLedger.Financial
