import Admission.Lifecycle

namespace BlindLedger.Admission

/-
  Versioned, bounded binary framing for the pure Queue lifecycle relation.
  This module is exported only to the separate lifecycle sidecar binary. It
  does not change Admission.Main or the existing admission wire protocol.
-/

abbrev LifecycleKernelBytes := List UInt8

def lifecycleKernelInputMagic : LifecycleKernelBytes :=
  [66, 76, 81, 76, 73, 78, 48, 49].map UInt8.ofNat

def lifecycleKernelOutputMagic : LifecycleKernelBytes :=
  [66, 76, 81, 76, 79, 85, 48, 49].map UInt8.ofNat

def lifecycleKernelWireVersion : Nat := 1
def lifecycleKernelMaxFrameBytes : Nat := 16_384
def lifecycleKernelMaxFlagsBytes : Nat := 4_096
def lifecycleKernelMaxStringBytes : Nat := 96

def lifecycleKernelU16LE (value : Nat) : LifecycleKernelBytes :=
  [UInt8.ofNat (value % 256), UInt8.ofNat ((value / 256) % 256)]

def lifecycleKernelU64LE (value : Nat) : LifecycleKernelBytes :=
  (List.range 8).map fun index =>
    UInt8.ofNat ((value / (2 ^ (index * 8))) % 256)

def lifecycleKernelReadBytes (length : Nat) (input : LifecycleKernelBytes) :
    Except String (LifecycleKernelBytes × LifecycleKernelBytes) :=
  if input.length < length then
    .error "short"
  else
    .ok (input.take length, input.drop length)

def lifecycleKernelReadU8 (input : LifecycleKernelBytes) :
    Except String (Nat × LifecycleKernelBytes) := do
  let (bytes, rest) ← lifecycleKernelReadBytes 1 input
  match bytes with
  | [value] => pure (value.toNat, rest)
  | _ => throw "u8"

def lifecycleKernelReadU16 (input : LifecycleKernelBytes) :
    Except String (Nat × LifecycleKernelBytes) := do
  let (bytes, rest) ← lifecycleKernelReadBytes 2 input
  match bytes with
  | [low, high] =>
      pure (low.toNat + high.toNat * 256, rest)
  | _ => throw "u16"

def lifecycleKernelU64Value : LifecycleKernelBytes → Nat → Nat
  | [], _ => 0
  | value :: rest, index =>
      value.toNat * (2 ^ (index * 8)) + lifecycleKernelU64Value rest (index + 1)

def lifecycleKernelReadU64 (input : LifecycleKernelBytes) :
    Except String (Nat × LifecycleKernelBytes) := do
  let (bytes, rest) ← lifecycleKernelReadBytes 8 input
  let value := lifecycleKernelU64Value bytes 0
  pure (value, rest)

def lifecycleKernelReadString (input : LifecycleKernelBytes) :
    Except String (String × LifecycleKernelBytes) := do
  let (length, rest) ← lifecycleKernelReadU8 input
  if length > lifecycleKernelMaxStringBytes then
    throw "string-bound"
  let (bytes, tail) ← lifecycleKernelReadBytes length rest
  if !bytes.all (fun item => item.toNat < 128) then
    throw "string-ascii"
  let value := String.ofList (bytes.map fun item => Char.ofNat item.toNat)
  pure (value, tail)

def lifecycleKernelReadFlags (input : LifecycleKernelBytes) :
    Except String (LifecycleBytes × LifecycleKernelBytes) := do
  let (length, rest) ← lifecycleKernelReadU16 input
  if length > lifecycleKernelMaxFlagsBytes then
    throw "flags-bound"
  lifecycleKernelReadBytes length rest

def lifecycleKernelReadBool (input : LifecycleKernelBytes) :
    Except String (Bool × LifecycleKernelBytes) := do
  let (value, rest) ← lifecycleKernelReadU8 input
  match value with
  | 0 => pure (false, rest)
  | 1 => pure (true, rest)
  | _ => throw "bool"

def lifecycleKernelReadOptionBytes
    (length : Nat) (input : LifecycleKernelBytes) :
    Except String (Option LifecycleBytes × LifecycleKernelBytes) := do
  let (tag, rest) ← lifecycleKernelReadU8 input
  match tag with
  | 0 => pure (none, rest)
  | 1 =>
      let (bytes, tail) ← lifecycleKernelReadBytes length rest
      pure (some bytes, tail)
  | _ => throw "option-bytes"

def lifecycleKernelReadOptionNat (input : LifecycleKernelBytes) :
    Except String (Option Nat × LifecycleKernelBytes) := do
  let (tag, rest) ← lifecycleKernelReadU8 input
  match tag with
  | 0 => pure (none, rest)
  | 1 =>
      let (value, tail) ← lifecycleKernelReadU64 rest
      pure (some value, tail)
  | _ => throw "option-nat"

def lifecycleKernelReadOptionString (input : LifecycleKernelBytes) :
    Except String (Option String × LifecycleKernelBytes) := do
  let (tag, rest) ← lifecycleKernelReadU8 input
  match tag with
  | 0 => pure (none, rest)
  | 1 =>
      let (value, tail) ← lifecycleKernelReadString rest
      pure (some value, tail)
  | _ => throw "option-string"

def lifecycleKernelEncodeString (value : String) : LifecycleKernelBytes :=
  let bytes := value.toUTF8.toList
  UInt8.ofNat bytes.length :: bytes

def lifecycleKernelEncodeOptionBytes
    (value : Option LifecycleBytes) : LifecycleKernelBytes :=
  match value with
  | none => [UInt8.ofNat 0]
  | some bytes => UInt8.ofNat 1 :: bytes

def lifecycleKernelEncodeOptionNat (value : Option Nat) : LifecycleKernelBytes :=
  match value with
  | none => [UInt8.ofNat 0]
  | some number => UInt8.ofNat 1 :: lifecycleKernelU64LE number

def lifecycleKernelEncodeOptionString (value : Option String) : LifecycleKernelBytes :=
  match value with
  | none => [UInt8.ofNat 0]
  | some text => UInt8.ofNat 1 :: lifecycleKernelEncodeString text

def lifecycleKernelEncodeFlags (value : LifecycleBytes) : LifecycleKernelBytes :=
  lifecycleKernelU16LE value.length ++ value

def lifecycleKernelReadConfig (input : LifecycleKernelBytes) :
    Except String (LifecycleConfig × LifecycleKernelBytes) := do
  let (schemaVersion, r1) ← lifecycleKernelReadU64 input
  let (profileEpoch, r2) ← lifecycleKernelReadU64 r1
  let (profileToken, r3) ← lifecycleKernelReadString r2
  let (sourceAuthProfile, r4) ← lifecycleKernelReadString r3
  let (compositionVersion, r5) ← lifecycleKernelReadU64 r4
  let (sourceKeyEpoch, r6) ← lifecycleKernelReadU64 r5
  let (admissionTimeoutMs, r7) ← lifecycleKernelReadU64 r6
  let (leaseDurationMs, r8) ← lifecycleKernelReadU64 r7
  let (queueId, r9) ← lifecycleKernelReadString r8
  let (configDigest, r10) ← lifecycleKernelReadBytes 64 r9
  pure ({ schemaVersion := schemaVersion
          profileEpoch := profileEpoch
          profileToken := profileToken
          sourceAuthProfile := sourceAuthProfile
          compositionVersion := compositionVersion
          sourceKeyEpoch := sourceKeyEpoch
          admissionTimeoutMs := admissionTimeoutMs
          leaseDurationMs := leaseDurationMs
          queueId := queueId
          configDigest := configDigest }, r10)

def lifecycleKernelEncodeConfig (config : LifecycleConfig) : LifecycleKernelBytes :=
  lifecycleKernelU64LE config.schemaVersion ++
    lifecycleKernelU64LE config.profileEpoch ++
    lifecycleKernelEncodeString config.profileToken ++
    lifecycleKernelEncodeString config.sourceAuthProfile ++
    lifecycleKernelU64LE config.compositionVersion ++
    lifecycleKernelU64LE config.sourceKeyEpoch ++
    lifecycleKernelU64LE config.admissionTimeoutMs ++
    lifecycleKernelU64LE config.leaseDurationMs ++
    lifecycleKernelEncodeString config.queueId ++ config.configDigest

def lifecycleKernelReadIdentity (input : LifecycleKernelBytes) :
    Except String (LifecycleIdentity × LifecycleKernelBytes) := do
  let (batchId, r1) ← lifecycleKernelReadBytes 32 input
  let (batchRoot, r2) ← lifecycleKernelReadBytes 64 r1
  let (sessionRef, r3) ← lifecycleKernelReadBytes 64 r2
  let (publicCoin, r4) ← lifecycleKernelReadBytes 96 r3
  let (proofContext, r5) ← lifecycleKernelReadBytes 64 r4
  let (identityDigest, r6) ← lifecycleKernelReadBytes 64 r5
  let (assertionIdentifier, r7) ← lifecycleKernelReadString r6
  let (assertionVersion, r8) ← lifecycleKernelReadU64 r7
  let (stateProfileVersion, r9) ← lifecycleKernelReadString r8
  let (approvedSourceRegistryRoot, r10) ← lifecycleKernelReadOptionBytes 64 r9
  let (qualificationFlags, r11) ← lifecycleKernelReadFlags r10
  let (memberCount, r12) ← lifecycleKernelReadU64 r11
  let (admissionSeq, r13) ← lifecycleKernelReadU64 r12
  pure ({ batchId := batchId
          batchRoot := batchRoot
          sessionRef := sessionRef
          publicCoin := publicCoin
          proofContext := proofContext
          identityDigest := identityDigest
          assertionIdentifier := assertionIdentifier
          assertionVersion := assertionVersion
          stateProfileVersion := stateProfileVersion
          approvedSourceRegistryRoot := approvedSourceRegistryRoot
          qualificationFlags := qualificationFlags
          memberCount := memberCount
          admissionSeq := admissionSeq }, r13)

def lifecycleKernelEncodeIdentity (identity : LifecycleIdentity) : LifecycleKernelBytes :=
  identity.batchId ++ identity.batchRoot ++ identity.sessionRef ++ identity.publicCoin ++
    identity.proofContext ++ identity.identityDigest ++
    lifecycleKernelEncodeString identity.assertionIdentifier ++
    lifecycleKernelU64LE identity.assertionVersion ++
    lifecycleKernelEncodeString identity.stateProfileVersion ++
    lifecycleKernelEncodeOptionBytes identity.approvedSourceRegistryRoot ++
    lifecycleKernelEncodeFlags identity.qualificationFlags ++
    lifecycleKernelU64LE identity.memberCount ++ lifecycleKernelU64LE identity.admissionSeq

def lifecycleKernelDecodeBatch (value : Nat) : Option BatchPhase :=
  decodeBatch (UInt8.ofNat value)

def lifecycleKernelDecodeSource (value : Nat) : Option SourcePhase :=
  decodeSource (UInt8.ofNat value)

def lifecycleKernelDecodeVerifier (value : Nat) : Option VerifierPhase :=
  decodeVerifier (UInt8.ofNat value)

def lifecycleKernelDecodeTerminal (value : Nat) : Option TerminalKind :=
  decodeTerminal (UInt8.ofNat value)

def lifecycleKernelEncodeCounter (counter : LifecycleCounter) : LifecycleKernelBytes :=
  lifecycleKernelU64LE counter.used ++ lifecycleKernelU64LE counter.cap

def lifecycleKernelReadCounter (input : LifecycleKernelBytes) :
    Except String (LifecycleCounter × LifecycleKernelBytes) := do
  let (used, r1) ← lifecycleKernelReadU64 input
  let (cap, r2) ← lifecycleKernelReadU64 r1
  pure ({ used := used, cap := cap }, r2)

def lifecycleKernelReadAccounting (input : LifecycleKernelBytes) :
    Except String (LifecycleAccounting × LifecycleKernelBytes) := do
  let (proof, r1) ← lifecycleKernelReadCounter input
  let (sourceA, r2) ← lifecycleKernelReadCounter r1
  let (sourceS, r3) ← lifecycleKernelReadCounter r2
  let (sourceM, r4) ← lifecycleKernelReadCounter r3
  let (sourceU, r5) ← lifecycleKernelReadCounter r4
  let (verifierV, r6) ← lifecycleKernelReadCounter r5
  pure ({ proof := proof
          sourceA := sourceA
          sourceS := sourceS
          sourceM := sourceM
          sourceU := sourceU
          verifierV := verifierV }, r6)

def lifecycleKernelEncodeAccounting (accounting : LifecycleAccounting) : LifecycleKernelBytes :=
  lifecycleKernelEncodeCounter accounting.proof ++
    lifecycleKernelEncodeCounter accounting.sourceA ++
    lifecycleKernelEncodeCounter accounting.sourceS ++
    lifecycleKernelEncodeCounter accounting.sourceM ++
    lifecycleKernelEncodeCounter accounting.sourceU ++
    lifecycleKernelEncodeCounter accounting.verifierV

def lifecycleKernelDecodeAttemptStatus (value : Nat) : Option LifecycleAttemptStatus :=
  match value with
  | 0 => some .reserved
  | 1 => some .accepted
  | 2 => some .rejected
  | 3 => some .held
  | _ => none

def lifecycleKernelEncodeAttemptStatus (value : LifecycleAttemptStatus) : UInt8 :=
  match value with
  | .reserved => UInt8.ofNat 0
  | .accepted => UInt8.ofNat 1
  | .rejected => UInt8.ofNat 2
  | .held => UInt8.ofNat 3

def lifecycleKernelReadState (input : LifecycleKernelBytes) :
    Except String (LifecycleState × LifecycleKernelBytes) := do
  let (config, r1) ← lifecycleKernelReadConfig input
  let (identity, r2) ← lifecycleKernelReadIdentity r1
  let (batchCode, r3) ← lifecycleKernelReadU8 r2
  let batch ← match lifecycleKernelDecodeBatch batchCode with
    | some value => pure value
    | none => throw "batch-enum"
  let (sourceCode, r4) ← lifecycleKernelReadU8 r3
  let source ← match lifecycleKernelDecodeSource sourceCode with
    | some value => pure value
    | none => throw "source-enum"
  let (verifierCode, r5) ← lifecycleKernelReadU8 r4
  let verifier ← match lifecycleKernelDecodeVerifier verifierCode with
    | some value => pure value
    | none => throw "verifier-enum"
  let (terminalCode, r6) ← lifecycleKernelReadU8 r5
  let terminal ← match lifecycleKernelDecodeTerminal terminalCode with
    | some value => pure value
    | none => throw "terminal-enum"
  let (validFromMs, r7) ← lifecycleKernelReadU64 r6
  let (validUntilMs, r8) ← lifecycleKernelReadU64 r7
  let (nextEligibleMs, r9) ← lifecycleKernelReadU64 r8
  let (updatedMs, r10) ← lifecycleKernelReadU64 r9
  let (attempt, r11) ← lifecycleKernelReadU64 r10
  let (attemptId, r12) ← lifecycleKernelReadU64 r11
  let (attemptStatusCode, r13) ← lifecycleKernelReadU8 r12
  let attemptStatus ← match lifecycleKernelDecodeAttemptStatus attemptStatusCode with
    | some value => pure value
    | none => throw "attempt-enum"
  let (verifierVUpper, r14) ← lifecycleKernelReadU64 r13
  let (globalLiveLeaseCount, r15) ← lifecycleKernelReadU64 r14
  let (liveLeaseCount, r16) ← lifecycleKernelReadU64 r15
  let (leaseExpiresMs, r17) ← lifecycleKernelReadU64 r16
  let (claimSequence, r18) ← lifecycleKernelReadU64 r17
  let (transitionSequence, r19) ← lifecycleKernelReadU64 r18
  let (reservationBefore, r20) ← lifecycleKernelReadU64 r19
  let (reservationAfter, r21) ← lifecycleKernelReadU64 r20
  let (proofAttemptsPerBatch, r22) ← lifecycleKernelReadU64 r21
  let (attemptSourceKeyEpoch, r23) ← lifecycleKernelReadU64 r22
  let (handoffAttached, r24) ← lifecycleKernelReadBool r23
  let (accounting, r25) ← lifecycleKernelReadAccounting r24
  pure ({ config := config
          identity := identity
          batch := batch
          source := source
          verifier := verifier
          terminal := terminal
          validFromMs := validFromMs
          validUntilMs := validUntilMs
          nextEligibleMs := nextEligibleMs
          updatedMs := updatedMs
          attempt := attempt
          attemptId := attemptId
          attemptStatus := attemptStatus
          verifierVUpper := verifierVUpper
          globalLiveLeaseCount := globalLiveLeaseCount
          liveLeaseCount := liveLeaseCount
          leaseExpiresMs := leaseExpiresMs
          claimSequence := claimSequence
          transitionSequence := transitionSequence
          reservationBefore := reservationBefore
          reservationAfter := reservationAfter
          proofAttemptsPerBatch := proofAttemptsPerBatch
          attemptSourceKeyEpoch := attemptSourceKeyEpoch
          handoffAttached := handoffAttached
          accounting := accounting }, r25)

def lifecycleKernelEncodeState (state : LifecycleState) : LifecycleKernelBytes :=
  lifecycleKernelEncodeConfig state.config ++
    lifecycleKernelEncodeIdentity state.identity ++
    [batchCode state.batch, sourceCode state.source, verifierCode state.verifier,
      terminalCode state.terminal] ++
    lifecycleKernelU64LE state.validFromMs ++
    lifecycleKernelU64LE state.validUntilMs ++
    lifecycleKernelU64LE state.nextEligibleMs ++
    lifecycleKernelU64LE state.updatedMs ++
    lifecycleKernelU64LE state.attempt ++ lifecycleKernelU64LE state.attemptId ++
    [lifecycleKernelEncodeAttemptStatus state.attemptStatus] ++
    lifecycleKernelU64LE state.verifierVUpper ++
    lifecycleKernelU64LE state.globalLiveLeaseCount ++
    lifecycleKernelU64LE state.liveLeaseCount ++
    lifecycleKernelU64LE state.leaseExpiresMs ++
    lifecycleKernelU64LE state.claimSequence ++
    lifecycleKernelU64LE state.transitionSequence ++
    lifecycleKernelU64LE state.reservationBefore ++
    lifecycleKernelU64LE state.reservationAfter ++
    lifecycleKernelU64LE state.proofAttemptsPerBatch ++
    lifecycleKernelU64LE state.attemptSourceKeyEpoch ++
    [UInt8.ofNat (if state.handoffAttached then 1 else 0)] ++
    lifecycleKernelEncodeAccounting state.accounting

def lifecycleKernelDecodeOp (value : Nat) : Option LifecycleOp :=
  match value with
  | 1 => some .submitHandoff
  | 2 => some .claimNextBatch
  | _ => none

structure LifecycleKernelRequest where
  op : LifecycleOp
  nowMs : Nat
  state : LifecycleState

def lifecycleKernelReadRequest (input : LifecycleKernelBytes) : Except String LifecycleKernelRequest := do
  if input.length > lifecycleKernelMaxFrameBytes then
    throw "frame-bound"
  let (magic, r1) ← lifecycleKernelReadBytes 8 input
  if magic != lifecycleKernelInputMagic then
    throw "magic"
  let (version, r2) ← lifecycleKernelReadU8 r1
  if version != lifecycleKernelWireVersion then
    throw "version"
  let (opCode, r3) ← lifecycleKernelReadU8 r2
  let op ← match lifecycleKernelDecodeOp opCode with
    | some value => pure value
    | none => throw "operation"
  let (nowMs, r4) ← lifecycleKernelReadU64 r3
  let (state, r5) ← lifecycleKernelReadState r4
  if !r5.isEmpty then
    throw "trailing"
  pure { op := op, nowMs := nowMs, state := state }

def lifecycleKernelEncodeEventKind (value : LifecycleEventKind) : UInt8 :=
  match value with
  | .batchIssued => UInt8.ofNat 1
  | .handoffSubmitted => UInt8.ofNat 2
  | .verificationStarted => UInt8.ofNat 3

def lifecycleKernelDecodeEventKind (value : Nat) : Option LifecycleEventKind :=
  match value with
  | 1 => some .batchIssued
  | 2 => some .handoffSubmitted
  | 3 => some .verificationStarted
  | _ => none

def lifecycleKernelEncodeEventStatus (value : LifecycleEventStatus) : UInt8 :=
  match value with
  | .awaitingHandoff => UInt8.ofNat 0
  | .queued => UInt8.ofNat 1
  | .leased => UInt8.ofNat 2
  | .held => UInt8.ofNat 3

def lifecycleKernelDecodeEventStatus (value : Nat) : Option LifecycleEventStatus :=
  match value with
  | 0 => some .awaitingHandoff
  | 1 => some .queued
  | 2 => some .leased
  | 3 => some .held
  | _ => none

def lifecycleKernelReadEvent (input : LifecycleKernelBytes) :
    Except String (LifecycleEvent × LifecycleKernelBytes) := do
  let (schemaVersion, r1) ← lifecycleKernelReadU64 input
  let (sequence, r2) ← lifecycleKernelReadU64 r1
  let (kindCode, r3) ← lifecycleKernelReadU8 r2
  let kind ← match lifecycleKernelDecodeEventKind kindCode with
    | some value => pure value
    | none => throw "event-kind"
  let (batchId, r4) ← lifecycleKernelReadBytes 32 r3
  let (statusCode, r5) ← lifecycleKernelReadU8 r4
  let status ← match lifecycleKernelDecodeEventStatus statusCode with
    | some value => pure value
    | none => throw "event-status"
  let (errorCode, r6) ← lifecycleKernelReadOptionString r5
  let (attempt, r7) ← lifecycleKernelReadU64 r6
  let (atMs, r8) ← lifecycleKernelReadU64 r7
  let (memberCount, r9) ← lifecycleKernelReadU64 r8
  let (receiptId, r10) ← lifecycleKernelReadOptionBytes 32 r9
  let (identityDigest, r11) ← lifecycleKernelReadOptionBytes 64 r10
  let (reservationBefore, r12) ← lifecycleKernelReadOptionNat r11
  let (reservationAfter, r13) ← lifecycleKernelReadOptionNat r12
  pure ({ schemaVersion := schemaVersion
          sequence := sequence
          kind := kind
          batchId := batchId
          status := status
          errorCode := errorCode
          attempt := attempt
          atMs := atMs
          memberCount := memberCount
          receiptId := receiptId
          identityDigest := identityDigest
          reservationBefore := reservationBefore
          reservationAfter := reservationAfter }, r13)

def lifecycleKernelEncodeEvent (event : LifecycleEvent) : LifecycleKernelBytes :=
  lifecycleKernelU64LE event.schemaVersion ++
    lifecycleKernelU64LE event.sequence ++
    [lifecycleKernelEncodeEventKind event.kind] ++ event.batchId ++
    [lifecycleKernelEncodeEventStatus event.status] ++
    lifecycleKernelEncodeOptionString event.errorCode ++
    lifecycleKernelU64LE event.attempt ++ lifecycleKernelU64LE event.atMs ++
    lifecycleKernelU64LE event.memberCount ++
    lifecycleKernelEncodeOptionBytes event.receiptId ++
    lifecycleKernelEncodeOptionBytes event.identityDigest ++
    lifecycleKernelEncodeOptionNat event.reservationBefore ++
    lifecycleKernelEncodeOptionNat event.reservationAfter

def lifecycleKernelHexNibble (value : Char) : Option Nat :=
  let code := value.toNat
  if 48 ≤ code && code ≤ 57 then some (code - 48)
  else if 97 ≤ code && code ≤ 102 then some (code - 87)
  else none

def lifecycleKernelDecodeHexPairsAux :
    List Char → LifecycleKernelBytes → Option LifecycleKernelBytes
  | [], reversed => some reversed.reverse
  | high :: low :: rest, reversed =>
      match lifecycleKernelHexNibble high, lifecycleKernelHexNibble low with
      | some highValue, some lowValue =>
          lifecycleKernelDecodeHexPairsAux rest
            (UInt8.ofNat (highValue * 16 + lowValue) :: reversed)
      | _, _ => none
  | _, _ => none

def lifecycleKernelDecodeHexPairs (input : List Char) : Option LifecycleKernelBytes :=
  lifecycleKernelDecodeHexPairsAux input []

def lifecycleKernelHexDigit (value : Nat) : Char :=
  Char.ofNat (if value < 10 then 48 + value else 87 + value)

def lifecycleKernelEncodeHex (bytes : LifecycleKernelBytes) : String :=
  String.ofList (bytes.flatMap fun item =>
    [lifecycleKernelHexDigit (item.toNat / 16), lifecycleKernelHexDigit (item.toNat % 16)])

def lifecycleKernelMalformed (code : Nat) : LifecycleKernelBytes :=
  lifecycleKernelOutputMagic ++
    [UInt8.ofNat lifecycleKernelWireVersion, UInt8.ofNat 2] ++
    lifecycleKernelU16LE 0 ++ [UInt8.ofNat code]

def lifecycleKernelResponsePrefix
    (status : Nat) (request : LifecycleKernelBytes) : LifecycleKernelBytes :=
  lifecycleKernelOutputMagic ++
    [UInt8.ofNat lifecycleKernelWireVersion, UInt8.ofNat status] ++
    lifecycleKernelU16LE request.length ++ request

def lifecycleKernelRunBytes (input : LifecycleKernelBytes) : LifecycleKernelBytes :=
  if input.length > lifecycleKernelMaxFrameBytes then
    lifecycleKernelMalformed 1
  else
    match lifecycleKernelReadRequest input with
    | .error _ => lifecycleKernelMalformed 1
    | .ok request =>
        if !(decide (request.state.WellFormed)) then
          lifecycleKernelMalformed 2
        else
          match lifecycleStep request.op request.state request.nowMs with
          | .error _ => lifecycleKernelResponsePrefix 1 input ++ [UInt8.ofNat 1]
          | .ok transition =>
              lifecycleKernelResponsePrefix 0 input ++
                lifecycleKernelEncodeState transition.after ++
                lifecycleKernelEncodeEvent transition.event

def lifecycleKernelRunHex (input : String) : String :=
  if input.length > lifecycleKernelMaxFrameBytes * 2 || input.length % 2 != 0 then
    lifecycleKernelEncodeHex (lifecycleKernelMalformed 1)
  else
    match lifecycleKernelDecodeHexPairs input.toList with
    | none => lifecycleKernelEncodeHex (lifecycleKernelMalformed 1)
    | some bytes => lifecycleKernelEncodeHex (lifecycleKernelRunBytes bytes)

@[export blind_ledger_lifecycle_run_hex]
def blindLedgerLifecycleRunHex (input : String) : ByteArray :=
  (lifecycleKernelRunHex input).toUTF8

@[export blind_ledger_lifecycle_run_hex_size]
def blindLedgerLifecycleRunHexSize (output : ByteArray) : UInt64 :=
  output.size.toUInt64

@[export blind_ledger_lifecycle_output_byte]
def blindLedgerLifecycleOutputByte (output : ByteArray) (index : UInt64) : UInt32 :=
  UInt32.ofNat (output.get! index.toNat).toNat

end BlindLedger.Admission
