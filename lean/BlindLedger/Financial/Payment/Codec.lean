import BlindLedger.Financial.Payment.Types

namespace BlindLedger.Financial.Payment

open BlindLedger.Financial

/-! Lean-live M3 (docs: rrb/designs/lean-live-m3-v1.md, section 3.1): the form-A item.
    `BLFPAY01`, form byte 1, u32 n and one canonical BLFIN02 input, the receipts, the two
    foreign-id flags, the expected revision and the command.  As in BLFCMD03, the decoder
    parses and then requires that the request re-encodes to exactly the input bytes, so
    canonicality needs no per-reader inverse.  Nothing calls this yet. -/

def paymentMagic : Bytes := "BLFPAY01".toUTF8.toList

def encodeReceipt (k : Receipt) : Bytes :=
  encodeString k.paymentId ++ natBE 8 k.recordedRevision ++ encodeOptionString k.paysActionId

def readReceipt (bytes : Bytes) : Option (Receipt × Bytes) := do
  let (paymentId, rest) ← readString bytes
  let (recordedRevision, rest) ← readNatBE 8 rest
  let (paysActionId, rest) ← readOptionString rest
  pure ({ paymentId, recordedRevision, paysActionId }, rest)

/-- Bit 0: foreign payment id.  Bit 1: foreign evidence id. -/
def encodeForeign (f : Foreign) : Bytes :=
  [UInt8.ofNat ((if f.paymentId then 1 else 0) + (if f.evidenceId then 2 else 0))]

def readForeign (bytes : Bytes) : Option (Foreign × Bytes) := do
  let (flags, rest) ← readByte bytes
  if flags.toNat < 4 then some ({ paymentId := flags.toNat % 2 = 1, evidenceId := flags.toNat / 2 = 1 }, rest)
  else none

def encodeCommand : Command → Bytes
  | .record c => UInt8.ofNat 1 :: (encodeString c.paymentId ++ encodeString c.evidenceId ++
      encodeString c.commonOriginId ++ encodeString c.sourceId ++ encodeString c.sourceVersion ++
      encodeOptionString c.localRef ++ natBE 8 c.amountCents ++ natBE 8 c.eventAt ++
      encodeOptionString c.paysActionId)
  | .reverse c => UInt8.ofNat 2 :: (encodeString c.paymentId ++ encodeString c.evidenceId ++
      encodeOptionString c.commonOriginId ++ encodeOptionNat c.eventAt)

def readCommand (bytes : Bytes) : Option (Command × Bytes) := do
  let (tag, rest) ← readByte bytes
  if tag.toNat = 1 then do
    let (paymentId, rest) ← readString rest
    let (evidenceId, rest) ← readString rest
    let (commonOriginId, rest) ← readString rest
    let (sourceId, rest) ← readString rest
    let (sourceVersion, rest) ← readString rest
    let (localRef, rest) ← readOptionString rest
    let (amountCents, rest) ← readNatBE 8 rest
    let (eventAt, rest) ← readNatBE 8 rest
    let (paysActionId, rest) ← readOptionString rest
    pure (.record ⟨paymentId, evidenceId, commonOriginId, sourceId, sourceVersion, localRef,
      amountCents, eventAt, paysActionId⟩, rest)
  else if tag.toNat = 2 then do
    let (paymentId, rest) ← readString rest
    let (evidenceId, rest) ← readString rest
    let (commonOriginId, rest) ← readOptionString rest
    let (eventAt, rest) ← readOptionNat rest
    pure (.reverse ⟨paymentId, evidenceId, commonOriginId, eventAt⟩, rest)
  else none

/-- `inputBytes` is written as the u32 length of the embedded BLFIN02. -/
def encodePaymentRequest (r : PaymentRequest) : Bytes :=
  paymentMagic ++ [UInt8.ofNat 1] ++ natBE 4 r.inputBytes ++ rawEncodeFinancialInput r.input ++
    encodeList encodeReceipt r.receipts ++ encodeForeign r.foreign ++
    encodeOptionNat r.expectedRevision ++ encodeCommand r.command

def parsePaymentRequest (w : Bytes) : Option PaymentRequest := do
  let (n, rest) ← readNatBE 4 (w.drop (paymentMagic.length + 1))
  let input ← decodeFinancialInput (rest.take n)
  let (receipts, rest) ← readList readReceipt (rest.drop n)
  let (foreign, rest) ← readForeign rest
  let (expectedRevision, rest) ← readOptionNat rest
  let (command, _) ← readCommand rest
  pure { input, inputBytes := n, receipts, foreign, expectedRevision, command }

def decodePaymentRequest (w : Bytes) : Option PaymentRequest :=
  (parsePaymentRequest w).filter fun r => requestWellFormed r &&
    r.inputBytes == (rawEncodeFinancialInput r.input).length && encodePaymentRequest r == w

end BlindLedger.Financial.Payment
