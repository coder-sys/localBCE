import BlindLedger.Sha3

/-!
  Exact-width semantic boundary for the existing native-v3 plaintext continuity
  bundle.  This module intentionally does not import the historical one-byte
  model in `BlindLedger.Kernel`: the production-shaped bundle carries opaque
  64-byte identities and 64-bit chronology values.  The kernel checks the
  existing `BLCBND02` grammar and the semantic bindings which are independent
  of the database and of the cryptographic producer.

  Hashes and signatures remain native/source-auth responsibilities.  Their
  resulting fixed-width values are carried as opaque bytes and are never
  truncated, re-hashed into a smaller identity, or mapped into the old model.
  Every cross-record equality, fixed profile identity, width, order, and state
  transition required by the continuity contract is checked here.
 -/

namespace BlindLedger.Semantic

def appendAll : List Bytes → Bytes
  | [] => ByteArray.empty
  | head :: tail => ByteArray.append head (appendAll tail)

def domainBytes (text : String) : Bytes :=
  ByteArray.append text.toUTF8 (ByteArray.mk #[UInt8.ofNat 0])

def digest (domain : String) (parts : List Bytes) : Bytes :=
  sha3_512 (appendAll (domainBytes domain :: parts))

def oneByte (value : Nat) : Bytes := ByteArray.mk #[UInt8.ofNat value]

def u16 (n : Nat) : Bytes :=
  ByteArray.mk #[UInt8.ofNat ((n / 256) % 256), UInt8.ofNat (n % 256)]

def u32 (n : Nat) : Bytes :=
  ByteArray.mk #[
    UInt8.ofNat ((n / 16_777_216) % 256),
    UInt8.ofNat ((n / 65_536) % 256),
    UInt8.ofNat ((n / 256) % 256),
    UInt8.ofNat (n % 256)]

def u64 (n : Nat) : Bytes :=
  ByteArray.mk #[
    UInt8.ofNat ((n / 72_057_594_037_927_936) % 256),
    UInt8.ofNat ((n / 281_474_976_710_656) % 256),
    UInt8.ofNat ((n / 1_099_511_627_776) % 256),
    UInt8.ofNat ((n / 4_294_967_296) % 256),
    UInt8.ofNat ((n / 16_777_216) % 256),
    UInt8.ofNat ((n / 65_536) % 256),
    UInt8.ofNat ((n / 256) % 256),
    UInt8.ofNat (n % 256)]

def lengthPrefixed (value : Bytes) : Bytes :=
  appendAll [u32 value.size, value]

def natBE (bytes : Bytes) : Nat :=
  bytes.toList.foldl (fun acc byte => acc * 256 + byte.toNat) 0

def zeros (n : Nat) : Bytes :=
  List.replicate n (UInt8.ofNat 0) |>.toByteArray

def allZero (bytes : Bytes) : Bool :=
  bytes.toList.all (fun byte => byte.toNat = 0)

def nonzero64 (bytes : Bytes) : Bool :=
  bytes.size = 64 && !allZero bytes

def equal (left right : Bytes) : Bool := decide (left = right)

def bytesLT : Bytes → Bytes → Bool
  | left, right =>
      let rec go : List UInt8 → List UInt8 → Bool
        | [], [] => false
        | [], _ :: _ => true
        | _ :: _, [] => false
        | leftHead :: leftTail, rightHead :: rightTail =>
            if leftHead.toNat < rightHead.toNat then true
            else if leftHead.toNat > rightHead.toNat then false
            else go leftTail rightTail
      go left.toList right.toList

def strictlyAscending : List Bytes → Bool
  | [] => true
  | [_] => true
  | first :: second :: rest => bytesLT first second && strictlyAscending (second :: rest)

def hexNibble (byte : UInt8) : Option UInt8 :=
  let n := byte.toNat
  if 48 ≤ n && n ≤ 57 then
    some (UInt8.ofNat (n - 48))
  else if 65 ≤ n && n ≤ 70 then
    some (UInt8.ofNat (n - 55))
  else if 97 ≤ n && n ≤ 102 then
    some (UInt8.ofNat (n - 87))
  else
    none

def hexPairs : List UInt8 → Option Bytes
  | [] => some ByteArray.empty
  | first :: second :: rest => do
      let high ← hexNibble first
      let low ← hexNibble second
      let tail ← hexPairs rest
      pure (ByteArray.append
        (ByteArray.mk #[UInt8.ofNat (high.toNat * 16 + low.toNat)]) tail)
  | _ => none

/- `hexPairs` is written in the same direction as the source literals below;
   the small helper keeps the constants readable without introducing another
   wire representation. -/
def hexBytes (text : String) : Bytes :=
  match hexPairs text.toUTF8.toList with
  | some bytes => bytes
  | none => ByteArray.empty

def MAGIC_BUNDLE : Bytes := "BLCBND02".toUTF8
def MAGIC_RECEIPT : Bytes := "BLCREC02".toUTF8
def MAGIC_REQUEST : Bytes := "BLCRQT02".toUTF8
def MAGIC_FACT_SET : Bytes := "BLCFST02".toUTF8
def MAGIC_FACT : Bytes := "BLCFAC02".toUTF8
def MAGIC_COMPLETENESS : Bytes := "BLCCMP02".toUTF8
def MAGIC_CONTROL_SET : Bytes := "BLCSET02".toUTF8
def MAGIC_STATE : Bytes := "BLCSTA02".toUTF8
def MAGIC_DECISION : Bytes := "BLCDCS02".toUTF8
def MAGIC_ACCESS : Bytes := "BLCACS02".toUTF8
def MAGIC_JOIN : Bytes := "BLCJON02".toUTF8
def MAGIC_AUTH : Bytes := "BLNV3EA1".toUTF8
def SENTINEL : Bytes := ByteArray.append (ByteArray.mk #[UInt8.ofNat 224]) (zeros 63)
def NULL_SUITE : Bytes := zeros 64

def MODE_ID : Bytes := hexBytes "86bbd7f04861486674f17d1b35a216bac87a66f29877675cbad5d55fda7a2cebfbeefc11ecce37d4c07787c2878db7ee97ec2be2672044f254800580f25654df"
def EVALUATOR_ID : Bytes := hexBytes "3c22febd7155fb9a30c469250bb46efbeb24d656bdbd03a85dccb2dd441a175147115cdf7ef5b752066be0860c17476ec2f8fbcffd884fa478a52906327fc87b"
def RULE_ID : Bytes := hexBytes "abd3fa90adec7bf4fb698ecc64484110b27fafd02c9419e7dfad6ce6cc79fd8d16171275a38de25a7b995bcd9043322c4f2363655cc01c6d0f5279e0f270d663"
def CONTROL_SET_ID : Bytes := hexBytes "27b5816c0a3454c2435d09879d6af9415d8d5473147a6a170ee930e755fe89e524940f45ca14b0365e4babd8d784e7bc403f3637ff7bcaa7e40f52896636456e"
def SYNTHETIC_PROVIDER_ID : Bytes := hexBytes "ac54ce37aeca3dde82c71b447f5741db4d437c583e5e27d39b1c7fea7e58192605e40bad60bb81d445a0f4ff090d6a260b226a5b5278855d09d90a5d5891a976"
def SYNTHETIC_CREDENTIAL_ID : Bytes := hexBytes "6bda44f70cf7e9e66359e2a846477f4932d5a05840bf04358a9bb343b25c8e19fd26a6fa2477fd2d6da144898d8756ada706088275c8be47b4ed607eaa8d445a"
def SYNTHETIC_ENROLLMENT_ID : Bytes := hexBytes "57dfe434d966dad91bb91f577adc37b4819bedb7e630212cd947e72bceeaa4aca322945491422692bb8ef530155a7006bda937ea15a33ece3c3311dcf44cd505"
def SYNTHETIC_FEED_ID : Bytes := hexBytes "30bfd3cb3740ccfb1f3e568173bc99b1cf85e3b1edeaa5e00d1c3944d028b36d3cceb4ce914f2942be74d56100f39d9230a49c949e6ab3a975c5959a2126867f"
def TRUSTED_AUTHORIZER_ID : Bytes := hexBytes "eca69ef2f378fad1e2ec30bdf5996db6e616d3b97ba3936d0995e02da8d7c066ecf731aedc6cc1c817f151576ed25a4302c4619f618fcf308c936d210238f955"
def EXPECTED_REASON_ID : Bytes := hexBytes "34fb2b676660466408f638a5ad68a901525c21b0827c3155edffb1bdc145f03cd46f905eae05106929985b855aa4472af3b6af66fb8b40c321b81ec9f19efdf9"
def EXPECTED_AMOUNT_SCOPE : Bytes := hexBytes "8aa3f8894f11694b93e82a37fffff3da7865641d10755c71e8f94bbbce46cd29b314b3b68de17e61d8df702376aea9ce259a16e647fd449f207d6cffe177c52a"
def PROFILE_ID : Bytes := hexBytes "8b07c423294e2d2cecf320e495b56c31b5ecbd75f28cee5b166785e0de872619a0149b1e3dacd195207c7c2f34a9b46a8843ef8dd1c6fbac613aa66111d4163c"
/- These two identities are the fixed direct-state-owned database seam values.
   They use the same unlength-prefixed SHA3-512 identity construction as the
   State owner, and are surfaced explicitly so the consumer cannot silently
   substitute a local schema or program identity. -/
def DATABASE_SCHEMA_ID : Bytes :=
  digest "BL/DIRECT-STATE-OWNED/IDENTITY/v1"
    ["direct-state-owned-clearance-schema-v1".toUTF8]
def DATABASE_PROGRAM_ID : Bytes :=
  digest "BL/DIRECT-STATE-OWNED/IDENTITY/v1"
    ["verifier-owned-plaintext-continuity-program-v1".toUTF8]
def PHASE0_BINDING : Bytes := hexBytes "b55b99adcb9085039947a09e718169fe4b882c49f8a1bb7b8fc221ed518555203ed51565280ba0f25228a9f3f735b205a0abe6620c68c2e8963d4e8635aa8808"
def STATE_CONTEXT : Bytes := hexBytes "a464dece8a1be0b9a4d1499beaade7a5f7effb87d8b8e8916620fa7eb635266ee06072067f3d4a822e68fde18f6327c407707af03af7fcdb39070f7c9fbeaa19"
def EMPTY_AUDIT : Bytes := hexBytes "b4dff4a68b4435ab3b15b816518e3c11df264e6b121c2274d05bf52d80e999360b101980a4854b620616bda00e0282b44d12ab36434ea378ad44596383e58f89"
def EMPTY_ROOT : Bytes := hexBytes "4f97f86a80481f29420ecd226970092e5d65a45564d9eec16cfd1277206831c20dd98eb274a880115858bc2a994e37a2328dbc0e1e5d12c34f5a489930e2a9f3"
def INITIAL_STATE_ID : Bytes := hexBytes "a9e2183c5922cc48d11fe7247ecab282d00c14eb4a9a9ba7fd7a50771d98b33656bdbf6fcf9a25c84067faf2aa659eafc809c7ca0142c416e9a5902fb8a5dda3"

def STATE_AFTER_MARKER : Nat := 1
def EPOCH : Nat := 7
def EFFECTIVE_START : Nat := 6000
def EFFECTIVE_END : Nat := 9000

def CONTROL_SET_DOMAIN : String := "BL/NATIVE-V3/CONTINUITY/CONTROL-SET/v2"
def SUBJECT_KEY_DOMAIN : String := "BL/NATIVE-V3/CONTINUITY/SUBJECT-KEY/v2"
def REASON_DOMAIN : String := "BL/NATIVE-V3/CONTINUITY/REASON/v2"
def JOIN_DOMAIN : String := "BL/NATIVE-V3/CONTINUITY/DECISION-ACCESS-JOIN/v2"

def CONTROL_SCOPE : Bytes := "provider-credential-enrollment-continuity-v1".toUTF8
def CONFLICT_POLICY : Bytes := "priority-then-human-review".toUTF8
def DIRECTIVE_MAPPING : Bytes := ByteArray.mk #[1, 2, 3, 4, 5]

def controlSetBytes : Bytes := appendAll [
  MAGIC_CONTROL_SET,
  u16 2,
  u16 0,
  oneByte 1,
  zeros 3,
  MODE_ID,
  EVALUATOR_ID,
  RULE_ID,
  u32 100,
  u16 CONTROL_SCOPE.size,
  CONTROL_SCOPE,
  u64 EFFECTIVE_START,
  u64 EFFECTIVE_END,
  u16 CONFLICT_POLICY.size,
  CONFLICT_POLICY,
  oneByte DIRECTIVE_MAPPING.size,
  DIRECTIVE_MAPPING,
  zeros 3]

def controlSetIdDerived : Bytes := digest CONTROL_SET_DOMAIN [controlSetBytes]

def factId (raw : Bytes) : Bytes :=
  digest "BL/NATIVE-V3/CONTINUITY/FACT-ID/v2" [raw.extract 0 (raw.size - 64)]

def sourceRoot (raw : Bytes) : Bytes :=
  digest "BL/NATIVE-V3/CONTINUITY/SOURCE-ROOT/v2" [raw]

def completenessId (raw : Bytes) : Bytes :=
  digest "BL/NATIVE-V3/CONTINUITY/COMPLETENESS/v2" [raw]

def requestId (raw : Bytes) : Bytes :=
  digest "BL/NATIVE-V3/CONTINUITY/REQUEST-ID/v2" [raw]

def stateId (raw : Bytes) : Bytes :=
  digest "BL/NATIVE-V3/CONTINUITY/STATE-ID/v2" [raw]

def receiptId (body : Bytes) : Bytes :=
  digest "BL/NATIVE-V3/CONTINUITY/RECEIPT-ID/v2" [body]

def bundleId (raw : Bytes) : Bytes :=
  digest "BL/NATIVE-V3/CONTINUITY/BUNDLE/v2" [raw]

def chronologyId (raw : Bytes) : Bytes :=
  digest "BL/NATIVE-V3/CONTINUITY/CHRONOLOGY/v2" [raw]

def replayId (requestRaw before source control : Bytes) : Bytes :=
  digest "BL/NATIVE-V3/CONTINUITY/REPLAY/v2" [requestRaw, before, source, control]

def decisionId (requestRaw before source completeness : Bytes) (policy directive : Nat) (exception : Bytes) : Bytes :=
  digest "BL/NATIVE-V3/CONTINUITY/DECISION-ID/v2"
    [requestRaw, before, source, completeness, ByteArray.mk #[UInt8.ofNat policy, UInt8.ofNat directive], exception]

def pathId (control rule source completeness reason : Bytes) (policy directive : Nat) (exception : Bytes) : Bytes :=
  digest "BL/NATIVE-V3/CONTINUITY/DECISION-PATH/v2"
    [control, rule, source, completeness, reason,
      ByteArray.mk #[UInt8.ofNat policy, UInt8.ofNat directive], exception]

def auditAfter (before decision : Bytes) (directive : Nat) : Bytes :=
  digest "BL/NATIVE-V3/CONTINUITY/AUDIT-HEAD/v2"
    [before, decision, oneByte directive]

def continuityAfter (before source decision : Bytes) : Bytes :=
  digest "BL/NATIVE-V3/CONTINUITY/ROOT/v2" [before, source, decision]

def authorizationBody (raw : Bytes) : Bytes :=
  ByteArray.append (raw.extract 0 12) (raw.extract 76 420)

def authorizationId (body : Bytes) : Bytes :=
  digest "BL/NATIVE-V3/EXCEPTION-AUTHORIZATION-ID/v1" [body]

def authorizationSignature (signer body : Bytes) : Bytes :=
  digest "BL/NATIVE-V3/SYNTHETIC-AUTHORIZATION-SEAL/v1" [signer, body]

def adapterBinding (source : Bytes) : Bytes :=
  digest "BL/NATIVE-V3/CONTINUITY/PLAINTEXT-ADAPTER/v2" [PROFILE_ID, PHASE0_BINDING, source]

def stateContext : Bytes :=
  digest "BL/NATIVE-V3/CONTINUITY/STATE-CONTEXT/v2" [PROFILE_ID, MODE_ID]

def initialStateRaw : Bytes := appendAll [
  MAGIC_STATE, u16 2, u16 0, stateContext, u64 0, u32 0, zeros 4, EMPTY_AUDIT, EMPTY_ROOT]

def initialStateId : Bytes := stateId initialStateRaw

def sourceAddress (provider : Bytes) : Bytes :=
  digest "BL/NATIVE-V3/CONTINUITY/STATE-ADDRESS/v2"
    ["credential-enrollment-source".toUTF8, provider]

def auditAddress (provider : Bytes) : Bytes :=
  digest "BL/NATIVE-V3/CONTINUITY/STATE-ADDRESS/v2"
    ["continuity-audit-head".toUTF8, provider]

structure Cursor where
  data : Bytes
  offset : Nat

def take? (cursor : Cursor) (length : Nat) : Option (Bytes × Cursor) :=
  if cursor.offset + length ≤ cursor.data.size then
    let next := cursor.offset + length
    some (cursor.data.extract cursor.offset next, { cursor with offset := next })
  else
    none

def readNat? (cursor : Cursor) (length : Nat) : Option (Nat × Cursor) := do
  let (bytes, next) ← take? cursor length
  pure (natBE bytes, next)

def readBytes? (cursor : Cursor) (length : Nat) : Option (Bytes × Cursor) :=
  take? cursor length

def expect? (cursor : Cursor) (expected : Bytes) : Option Cursor := do
  let (actual, next) ← take? cursor expected.size
  if equal actual expected then pure next else none

def header? (data : Bytes) (magic : Bytes) : Option Cursor := do
  if data.size < 12 then none else
  let cursor := { data := data, offset := 0 }
  let cursor ← expect? cursor magic
  let (version, cursor) ← readNat? cursor 2
  let (reserved, cursor) ← readNat? cursor 2
  if version = 2 && reserved = 0 then pure cursor else none

def headerVersion? (data : Bytes) (magic : Bytes) (expectedVersion : Nat) : Option Cursor := do
  if data.size < 12 then none else
  let cursor := { data := data, offset := 0 }
  let cursor ← expect? cursor magic
  let (version, cursor) ← readNat? cursor 2
  let (reserved, cursor) ← readNat? cursor 2
  if version = expectedVersion && reserved = 0 then pure cursor else none

def finish? (cursor : Cursor) : Option Unit :=
  if cursor.offset = cursor.data.size then some () else none

def n64? (cursor : Cursor) (count : Nat) : Option (List Bytes × Cursor) :=
  match count with
  | 0 => some ([], cursor)
  | count + 1 => do
      let (head, cursor) ← readBytes? cursor 64
      let (tail, cursor) ← n64? cursor count
      pure (head :: tail, cursor)

def requestCanonical
    (provider credential enrollment attempt epochRaw sequenceRaw eventRaw observationRaw
      ruleEffectiveRaw decisionRaw expectedBefore : Bytes) : Bytes :=
  appendAll [MAGIC_REQUEST, u16 2, u16 0, provider, credential, enrollment, attempt,
    epochRaw, sequenceRaw, eventRaw, observationRaw, ruleEffectiveRaw, decisionRaw,
    expectedBefore]

structure RequestRaw where
  raw : Bytes
  provider : Bytes
  credential : Bytes
  enrollment : Bytes
  attempt : Bytes
  epochRaw : Bytes
  sequenceRaw : Bytes
  eventRaw : Bytes
  observationRaw : Bytes
  ruleEffectiveRaw : Bytes
  decisionRaw : Bytes
  epoch : Nat
  sequence : Nat
  event : Nat
  observation : Nat
  ruleEffective : Nat
  decision : Nat
  expectedBefore : Bytes
  canonicalProof : requestCanonical provider credential enrollment attempt epochRaw
    sequenceRaw eventRaw observationRaw ruleEffectiveRaw decisionRaw expectedBefore = raw

def parseRequest? (data : Bytes) : Option RequestRaw := do
  if data.size ≠ 380 then none else
  let cursor ← header? data "BLCRQT02".toUTF8
  let (provider, cursor) ← readBytes? cursor 64
  let (credential, cursor) ← readBytes? cursor 64
  let (enrollment, cursor) ← readBytes? cursor 64
  let (attempt, cursor) ← readBytes? cursor 64
  let (epochRaw, cursor) ← readBytes? cursor 8
  let (sequenceRaw, cursor) ← readBytes? cursor 8
  let (eventRaw, cursor) ← readBytes? cursor 8
  let (observationRaw, cursor) ← readBytes? cursor 8
  let (ruleEffectiveRaw, cursor) ← readBytes? cursor 8
  let (decisionRaw, cursor) ← readBytes? cursor 8
  let (expectedBefore, cursor) ← readBytes? cursor 64
  let _ ← finish? cursor
  if h : requestCanonical provider credential enrollment attempt epochRaw sequenceRaw
      eventRaw observationRaw ruleEffectiveRaw decisionRaw expectedBefore = data then
    pure
      { raw := data
        provider := provider
        credential := credential
        enrollment := enrollment
        attempt := attempt
        epochRaw := epochRaw
        sequenceRaw := sequenceRaw
        eventRaw := eventRaw
        observationRaw := observationRaw
        ruleEffectiveRaw := ruleEffectiveRaw
        decisionRaw := decisionRaw
        epoch := natBE epochRaw
        sequence := natBE sequenceRaw
        event := natBE eventRaw
        observation := natBE observationRaw
        ruleEffective := natBE ruleEffectiveRaw
        decision := natBE decisionRaw
        expectedBefore := expectedBefore
        canonicalProof := h }
  else none

def requestEncode (value : RequestRaw) : Bytes :=
  requestCanonical value.provider value.credential value.enrollment value.attempt
    value.epochRaw value.sequenceRaw value.eventRaw value.observationRaw
    value.ruleEffectiveRaw value.decisionRaw value.expectedBefore

def factCanonical
    (provider credential enrollment feed : Bytes) (status issued expires terminated observed : Nat)
    (recordId : Bytes) : Bytes :=
  appendAll [MAGIC_FACT, u16 2, u16 0, provider, credential, enrollment, feed,
    oneByte status, zeros 7, u64 issued, u64 expires, u64 terminated, u64 observed, recordId]

structure FactRaw where
  raw : Bytes
  provider : Bytes
  credential : Bytes
  enrollment : Bytes
  feed : Bytes
  status : Nat
  issued : Nat
  expires : Nat
  terminated : Nat
  observed : Nat
  recordId : Bytes
  canonicalProof : factCanonical provider credential enrollment feed status issued expires
    terminated observed recordId = raw

def factSetCanonical (feed : Bytes) (facts : List FactRaw) : Bytes :=
  appendAll ([MAGIC_FACT_SET, u16 2, u16 0, feed, u32 facts.length] ++
    facts.map (fun fact => lengthPrefixed fact.raw))

structure FactSetRaw where
  raw : Bytes
  feed : Bytes
  facts : List FactRaw
  canonicalProof : factSetCanonical feed facts = raw

def factSetEncode (value : FactSetRaw) : Bytes :=
  factSetCanonical value.feed value.facts

def parseFact? (data : Bytes) : Option FactRaw := do
  if data.size ≠ 372 then none else
  let cursor ← header? data "BLCFAC02".toUTF8
  let (provider, cursor) ← readBytes? cursor 64
  let (credential, cursor) ← readBytes? cursor 64
  let (enrollment, cursor) ← readBytes? cursor 64
  let (feed, cursor) ← readBytes? cursor 64
  let (statusBytes, cursor) ← readBytes? cursor 1
  let status := natBE statusBytes
  let (reserved, cursor) ← readBytes? cursor 7
  let (issued, cursor) ← readNat? cursor 8
  let (expires, cursor) ← readNat? cursor 8
  let (terminated, cursor) ← readNat? cursor 8
  let (observed, cursor) ← readNat? cursor 8
  let (recordId, cursor) ← readBytes? cursor 64
  let _ ← finish? cursor
  if reserved.size = 7 && allZero reserved && equal recordId (factId data) then
    if h : factCanonical provider credential enrollment feed status issued expires terminated
        observed recordId = data then
      pure
        { raw := data
          provider := provider
          credential := credential
          enrollment := enrollment
          feed := feed
          status := status
          issued := issued
          expires := expires
          terminated := terminated
          observed := observed
          recordId := recordId
          canonicalProof := h }
    else none
  else none

def factEncode (value : FactRaw) : Bytes :=
  factCanonical value.provider value.credential value.enrollment value.feed value.status
    value.issued value.expires value.terminated value.observed value.recordId

def parseFactsLoop? (cursor : Cursor) (remaining : Nat) : Option (List FactRaw × Cursor) :=
  match remaining with
  | 0 => some ([], cursor)
  | remaining + 1 => do
      let (length, cursor) ← readNat? cursor 4
      if length ≠ 372 then none else
      let (raw, cursor) ← readBytes? cursor length
      let fact ← parseFact? raw
      let (tail, cursor) ← parseFactsLoop? cursor remaining
      pure (fact :: tail, cursor)

def parseFactSet? (data : Bytes) : Option FactSetRaw := do
  let cursor ← header? data "BLCFST02".toUTF8
  let (feed, cursor) ← readBytes? cursor 64
  let (count, cursor) ← readNat? cursor 4
  if count > 8 then none else
  let (facts, cursor) ← parseFactsLoop? cursor count
  let _ ← finish? cursor
  if !strictlyAscending (facts.map (fun fact => fact.recordId)) then none else
  if h : factSetCanonical feed facts = data then
    pure { raw := data, feed := feed, facts := facts, canonicalProof := h }
  else none

def completenessCanonical (feed provider scope : Bytes) (observation : Nat)
    (complete : Bool) (absence : List Bytes) : Bytes :=
  appendAll ([MAGIC_COMPLETENESS, u16 2, u16 0, feed, provider, scope,
    u64 observation, oneByte (if complete then 1 else 0), zeros 7, u32 absence.length] ++ absence)

structure CompletenessRaw where
  raw : Bytes
  feed : Bytes
  provider : Bytes
  scope : Bytes
  observation : Nat
  complete : Bool
  absence : List Bytes
  id : Bytes
  canonicalProof : completenessCanonical feed provider scope observation complete absence = raw

def parseCompleteness? (data : Bytes) : Option CompletenessRaw := do
  let cursor ← header? data "BLCCMP02".toUTF8
  let (feed, cursor) ← readBytes? cursor 64
  let (provider, cursor) ← readBytes? cursor 64
  let (scope, cursor) ← readBytes? cursor 64
  let (observation, cursor) ← readNat? cursor 8
  let (completeRaw, cursor) ← readBytes? cursor 1
  let (reserved, cursor) ← readBytes? cursor 7
  let (count, cursor) ← readNat? cursor 4
  if count > 8 || completeRaw.size ≠ 1 || reserved.size ≠ 7 || !allZero reserved then none else
  if completeRaw.toList ≠ [UInt8.ofNat 0] && completeRaw.toList ≠ [UInt8.ofNat 1] then none else
  let complete := natBE completeRaw = 1
  let (absence, cursor) ← n64? cursor count
  let _ ← finish? cursor
  if !complete && absence ≠ [] then none else
  if !absence.all nonzero64 then none else
  if !strictlyAscending absence then none else
  if h : completenessCanonical feed provider scope observation complete absence = data then
    pure
      { raw := data
        feed := feed
        provider := provider
        scope := scope
        observation := observation
        complete := complete
        absence := absence
        id := completenessId data
        canonicalProof := h }
  else none

def completenessEncode (value : CompletenessRaw) : Bytes :=
  completenessCanonical value.feed value.provider value.scope value.observation value.complete
    value.absence

def exceptionCanonical
    (authorization signer subject rule reason amount : Bytes)
    (effectiveAt expiresAt policy : Nat) (signature : Bytes) : Bytes :=
  appendAll [MAGIC_AUTH, u16 1, u16 0, authorization, signer, subject, rule, reason, amount,
    u64 effectiveAt, u64 expiresAt, oneByte policy, zeros 7, signature]

structure ExceptionRaw where
  raw : Bytes
  authorization : Bytes
  signer : Bytes
  subject : Bytes
  rule : Bytes
  reason : Bytes
  amount : Bytes
  effectiveAt : Nat
  expiresAt : Nat
  policy : Nat
  signature : Bytes
  canonicalProof : exceptionCanonical authorization signer subject rule reason amount effectiveAt
    expiresAt policy signature = raw

def parseException? (data : Bytes) : Option (Option ExceptionRaw) :=
  if equal data SENTINEL then some none else do
    if data.size ≠ 484 then none else
    let cursor ← headerVersion? data "BLNV3EA1".toUTF8 1
    let (authorization, cursor) ← readBytes? cursor 64
    let (signer, cursor) ← readBytes? cursor 64
    let (subject, cursor) ← readBytes? cursor 64
    let (rule, cursor) ← readBytes? cursor 64
    let (reason, cursor) ← readBytes? cursor 64
    let (amount, cursor) ← readBytes? cursor 64
    let (effectiveAt, cursor) ← readNat? cursor 8
    let (expiresAt, cursor) ← readNat? cursor 8
    let (policyRaw, cursor) ← readBytes? cursor 1
    let (reserved, cursor) ← readBytes? cursor 7
    let (signature, cursor) ← readBytes? cursor 64
    let _ ← finish? cursor
    let policy := natBE policyRaw
    if policy ∈ [1, 2, 3, 4] && allZero reserved then
      if h : exceptionCanonical authorization signer subject rule reason amount effectiveAt
          expiresAt policy signature = data then
        pure (some
          { raw := data
            authorization := authorization
            signer := signer
            subject := subject
            rule := rule
            reason := reason
            amount := amount
            effectiveAt := effectiveAt
            expiresAt := expiresAt
            policy := policy
            signature := signature
            canonicalProof := h })
      else none
    else none

def exceptionEncode : Option ExceptionRaw → Bytes
  | none => SENTINEL
  | some value =>
      exceptionCanonical value.authorization value.signer value.subject value.rule value.reason
        value.amount value.effectiveAt value.expiresAt value.policy value.signature

def stateCanonical (context : Bytes) (sequence rowCount : Nat)
    (audit root : Bytes) : Bytes :=
  appendAll [MAGIC_STATE, u16 2, u16 0, context, u64 sequence,
    u32 rowCount, zeros 4, audit, root]

structure StateRaw where
  raw : Bytes
  context : Bytes
  sequence : Nat
  rowCount : Nat
  audit : Bytes
  root : Bytes
  id : Bytes
  canonicalProof : stateCanonical context sequence rowCount audit root = raw

def parseState? (data : Bytes) : Option StateRaw := do
  if data.size ≠ 220 then none else
  let cursor ← header? data "BLCSTA02".toUTF8
  let (context, cursor) ← readBytes? cursor 64
  let (sequence, cursor) ← readNat? cursor 8
  let (rowCount, cursor) ← readNat? cursor 4
  let (reserved, cursor) ← readBytes? cursor 4
  let (audit, cursor) ← readBytes? cursor 64
  let (root, cursor) ← readBytes? cursor 64
  let _ ← finish? cursor
  if allZero reserved && nonzero64 context && ((sequence = 0 && rowCount = 0) ||
      (sequence = 1 && rowCount = 1)) && nonzero64 audit && nonzero64 root then
    if h : stateCanonical context sequence rowCount audit root = data then
      pure
        { raw := data
          context := context
          sequence := sequence
          rowCount := rowCount
          audit := audit
          root := root
          id := stateId data
          canonicalProof := h }
    else none
  else none

def stateEncode (value : StateRaw) : Bytes :=
  stateCanonical value.context value.sequence value.rowCount value.audit value.root

def decisionCanonical
    (decisionId attemptId provider credential enrollment mode control rule sourceRoot phase0
      completenessId chronologyId replayId exceptionId beforeId afterId pathId reasonId requestId : Bytes)
    (policy directive event observation ruleEffective decision : Nat) : Bytes :=
  appendAll [MAGIC_DECISION, u16 2, u16 0, u32 0, u32 1,
    decisionId, attemptId, provider, credential, enrollment, mode, control, rule, sourceRoot,
    phase0, completenessId, chronologyId, replayId, exceptionId, beforeId, afterId, pathId,
    reasonId, requestId, oneByte policy, oneByte directive, oneByte 0, oneByte 0, zeros 4,
    u64 event, u64 observation, u64 ruleEffective, u64 decision]

structure DecisionRaw where
  raw : Bytes
  decisionId : Bytes
  attemptId : Bytes
  provider : Bytes
  credential : Bytes
  enrollment : Bytes
  mode : Bytes
  control : Bytes
  rule : Bytes
  sourceRoot : Bytes
  phase0 : Bytes
  completenessId : Bytes
  chronologyId : Bytes
  replayId : Bytes
  exceptionId : Bytes
  beforeId : Bytes
  afterId : Bytes
  pathId : Bytes
  reasonId : Bytes
  requestId : Bytes
  policy : Nat
  directive : Nat
  event : Nat
  observation : Nat
  ruleEffective : Nat
  decision : Nat
  canonicalProof : decisionCanonical decisionId attemptId provider credential enrollment mode
    control rule sourceRoot phase0 completenessId chronologyId replayId exceptionId beforeId afterId
    pathId reasonId requestId policy directive event observation ruleEffective decision = raw

def parseDecision? (data : Bytes) : Option DecisionRaw := do
  if data.size ≠ 1276 then none else
  let cursor ← header? data "BLCDCS02".toUTF8
  let (index, cursor) ← readNat? cursor 4
  let (count, cursor) ← readNat? cursor 4
  if index ≠ 0 || count ≠ 1 then none else
  let (decisionId, cursor) ← readBytes? cursor 64
  let (attemptId, cursor) ← readBytes? cursor 64
  let (provider, cursor) ← readBytes? cursor 64
  let (credential, cursor) ← readBytes? cursor 64
  let (enrollment, cursor) ← readBytes? cursor 64
  let (mode, cursor) ← readBytes? cursor 64
  let (control, cursor) ← readBytes? cursor 64
  let (rule, cursor) ← readBytes? cursor 64
  let (sourceRoot, cursor) ← readBytes? cursor 64
  let (phase0, cursor) ← readBytes? cursor 64
  let (completenessId, cursor) ← readBytes? cursor 64
  let (chronologyId, cursor) ← readBytes? cursor 64
  let (replayId, cursor) ← readBytes? cursor 64
  let (exceptionId, cursor) ← readBytes? cursor 64
  let (beforeId, cursor) ← readBytes? cursor 64
  let (afterId, cursor) ← readBytes? cursor 64
  let (pathId, cursor) ← readBytes? cursor 64
  let (reasonId, cursor) ← readBytes? cursor 64
  let (requestId, cursor) ← readBytes? cursor 64
  let (flags, cursor) ← readBytes? cursor 4
  let (reserved, cursor) ← readBytes? cursor 4
  let (event, cursor) ← readNat? cursor 8
  let (observation, cursor) ← readNat? cursor 8
  let (ruleEffective, cursor) ← readNat? cursor 8
  let (decision, cursor) ← readNat? cursor 8
  let _ ← finish? cursor
  match flags.toList with
  | [policy, directive, economic, proof] =>
      if economic.toNat = 0 && proof.toNat = 0 && allZero reserved then
        if h : decisionCanonical decisionId attemptId provider credential enrollment mode control rule
            sourceRoot phase0 completenessId chronologyId replayId exceptionId beforeId afterId pathId
            reasonId requestId policy.toNat directive.toNat event observation ruleEffective decision = data then
          pure
            { raw := data
              decisionId := decisionId
              attemptId := attemptId
              provider := provider
              credential := credential
              enrollment := enrollment
              mode := mode
              control := control
              rule := rule
              sourceRoot := sourceRoot
              phase0 := phase0
              completenessId := completenessId
              chronologyId := chronologyId
              replayId := replayId
              exceptionId := exceptionId
              beforeId := beforeId
              afterId := afterId
              pathId := pathId
              reasonId := reasonId
              requestId := requestId
              policy := policy.toNat
              directive := directive.toNat
              event := event
              observation := observation
              ruleEffective := ruleEffective
              decision := decision
              canonicalProof := h }
        else none
      else none
  | _ => none

def decisionEncode (value : DecisionRaw) : Bytes :=
  decisionCanonical value.decisionId value.attemptId value.provider value.credential value.enrollment
    value.mode value.control value.rule value.sourceRoot value.phase0 value.completenessId
    value.chronologyId value.replayId value.exceptionId value.beforeId value.afterId value.pathId
    value.reasonId value.requestId value.policy value.directive value.event value.observation
    value.ruleEffective value.decision

def accessCanonical
    (decisionId : Bytes) (decisionIndex accessIndex accessCount time : Nat)
    (address key before after : Bytes) (mode : Nat) : Bytes :=
  appendAll [MAGIC_ACCESS, u16 2, u16 0, decisionId, u32 decisionIndex, u32 accessIndex,
    u32 accessCount, u64 time, address, key, before, after, oneByte mode, zeros 7]

structure AccessRaw where
  raw : Bytes
  decisionId : Bytes
  decisionIndex : Nat
  accessIndex : Nat
  accessCount : Nat
  time : Nat
  address : Bytes
  key : Bytes
  before : Bytes
  after : Bytes
  mode : Nat
  canonicalProof : accessCanonical decisionId decisionIndex accessIndex accessCount time address
    key before after mode = raw

def parseAccess? (data : Bytes) : Option AccessRaw := do
  if data.size ≠ 360 then none else
  let cursor ← header? data "BLCACS02".toUTF8
  let (decisionId, cursor) ← readBytes? cursor 64
  let (decisionIndex, cursor) ← readNat? cursor 4
  let (accessIndex, cursor) ← readNat? cursor 4
  let (accessCount, cursor) ← readNat? cursor 4
  let (time, cursor) ← readNat? cursor 8
  let (address, cursor) ← readBytes? cursor 64
  let (key, cursor) ← readBytes? cursor 64
  let (before, cursor) ← readBytes? cursor 64
  let (after, cursor) ← readBytes? cursor 64
  let (modeRaw, cursor) ← readBytes? cursor 1
  let (reserved, cursor) ← readBytes? cursor 7
  let _ ← finish? cursor
  if modeRaw.size = 1 && allZero reserved then
    if h : accessCanonical decisionId decisionIndex accessIndex accessCount time address key before
        after (natBE modeRaw) = data then
      pure
        { raw := data
          decisionId := decisionId
          decisionIndex := decisionIndex
          accessIndex := accessIndex
          accessCount := accessCount
          time := time
          address := address
          key := key
          before := before
          after := after
          mode := natBE modeRaw
          canonicalProof := h }
    else none
  else none

def accessEncode (value : AccessRaw) : Bytes :=
  accessCanonical value.decisionId value.decisionIndex value.accessIndex value.accessCount value.time
    value.address value.key value.before value.after value.mode

def joinCanonical (decision firstAccess secondAccess : Bytes) : Bytes :=
  appendAll [
    MAGIC_JOIN, u16 2, u16 0, u32 1, u32 2,
    lengthPrefixed decision, lengthPrefixed firstAccess, lengthPrefixed secondAccess]

def joinBytes (decision : DecisionRaw) (firstAccess secondAccess : AccessRaw) : Bytes :=
  appendAll [MAGIC_JOIN, u16 2, u16 0, u32 1, u32 2,
    lengthPrefixed decision.raw, lengthPrefixed firstAccess.raw,
    lengthPrefixed secondAccess.raw]

def receiptCanonical
    (adapter control decisionId joinId beforeId afterId phase0 : Bytes)
    (decision : DecisionRaw) (firstAccess secondAccess : AccessRaw) (id : Bytes) : Bytes :=
  appendAll [MAGIC_RECEIPT, u16 2, u16 0, ByteArray.mk #[0, 0, 0, 1], zeros 4, NULL_SUITE,
    adapter, control, decisionId, joinId, beforeId, afterId, phase0,
    u32 decision.raw.size, decision.raw, u32 2,
    u32 firstAccess.raw.size, firstAccess.raw, u32 secondAccess.raw.size, secondAccess.raw, id]

structure ReceiptRaw where
  raw : Bytes
  body : Bytes
  id : Bytes
  adapter : Bytes
  control : Bytes
  decisionId : Bytes
  joinId : Bytes
  beforeId : Bytes
  afterId : Bytes
  phase0 : Bytes
  decision : DecisionRaw
  firstAccess : AccessRaw
  secondAccess : AccessRaw
  canonicalProof : receiptCanonical adapter control decisionId joinId beforeId afterId phase0
    decision firstAccess secondAccess id = raw

def parseReceipt? (data : Bytes) : Option ReceiptRaw := do
  if data.size < 64 then none else
  let body := data.extract 0 (data.size - 64)
  let cursor ← header? body "BLCREC02".toUTF8
  let (markers, cursor) ← readBytes? cursor 4
  let (reserved, cursor) ← readBytes? cursor 4
  let (suite, cursor) ← readBytes? cursor 64
  let (adapter, cursor) ← readBytes? cursor 64
  let (control, cursor) ← readBytes? cursor 64
  let (decisionId, cursor) ← readBytes? cursor 64
  let (joinId, cursor) ← readBytes? cursor 64
  let (beforeId, cursor) ← readBytes? cursor 64
  let (afterId, cursor) ← readBytes? cursor 64
  let (phase0, cursor) ← readBytes? cursor 64
  let (decisionLength, cursor) ← readNat? cursor 4
  if decisionLength ≠ 1276 || markers.toList ≠ [0, 0, 0, 1] || !allZero reserved || !equal suite NULL_SUITE then none else
  let (decisionRaw, cursor) ← readBytes? cursor decisionLength
  let decision ← parseDecision? decisionRaw
  let (accessCount, cursor) ← readNat? cursor 4
  if accessCount ≠ 2 then none else
  let (firstLength, cursor) ← readNat? cursor 4
  if firstLength ≠ 360 then none else
  let (firstRaw, cursor) ← readBytes? cursor firstLength
  let firstAccess ← parseAccess? firstRaw
  let (secondLength, cursor) ← readNat? cursor 4
  if secondLength ≠ 360 then none else
  let (secondRaw, cursor) ← readBytes? cursor secondLength
  let secondAccess ← parseAccess? secondRaw
  let _ ← finish? cursor
  let id := data.extract (data.size - 64) data.size
  if h : receiptCanonical adapter control decisionId joinId beforeId afterId phase0 decision
      firstAccess secondAccess id = data then
    pure
      { body := body
        raw := data
        id := id
        adapter := adapter
        control := control
        decisionId := decisionId
        joinId := joinId
        beforeId := beforeId
        afterId := afterId
        phase0 := phase0
        decision := decision
        firstAccess := firstAccess
        secondAccess := secondAccess
        canonicalProof := h }
  else none

def receiptEncode (value : ReceiptRaw) : Bytes :=
  receiptCanonical value.adapter value.control value.decisionId value.joinId value.beforeId
    value.afterId value.phase0 value.decision value.firstAccess value.secondAccess value.id

def bundleCanonical
    (receipt request facts completeness exception before after : Bytes) : Bytes :=
  appendAll [MAGIC_BUNDLE, u16 2, u16 0, lengthPrefixed receipt, lengthPrefixed request,
    lengthPrefixed facts, lengthPrefixed completeness, lengthPrefixed exception,
    lengthPrefixed before, lengthPrefixed after]

structure PartsRaw where
  raw : Bytes
  receipt : Bytes
  request : Bytes
  facts : Bytes
  completeness : Bytes
  exception : Bytes
  before : Bytes
  after : Bytes
  canonicalProof : bundleCanonical receipt request facts completeness exception before after = raw

def part? (cursor : Cursor) (cap : Nat) : Option (Bytes × Cursor) := do
  let (length, cursor) ← readNat? cursor 4
  if length > cap then none else readBytes? cursor length

def parseBundle? (data : Bytes) : Option PartsRaw := do
  if data.size > 1_000_000 then none else
  let cursor ← header? data "BLCBND02".toUTF8
  let (receipt, cursor) ← part? cursor 8192
  let (request, cursor) ← part? cursor 380
  let (facts, cursor) ← part? cursor 4096
  let (completeness, cursor) ← part? cursor 4096
  let (exception, cursor) ← part? cursor 484
  let (before, cursor) ← part? cursor 220
  let (after, cursor) ← part? cursor 220
  let _ ← finish? cursor
  if h : bundleCanonical receipt request facts completeness exception before after = data then
    pure
      { raw := data
        receipt := receipt
        request := request
        facts := facts
        completeness := completeness
        exception := exception
        before := before
        after := after
        canonicalProof := h }
  else none

def bundleEncode (value : PartsRaw) : Bytes :=
  bundleCanonical value.receipt value.request value.facts value.completeness value.exception
    value.before value.after

inductive Reason where
  | valid
  | missing
  | expired
  | ambiguous
  | staleRule
  | controlInterval
deriving DecidableEq, Repr

structure Outcome where
  policy : Nat
  directive : Nat
  reason : Reason
  exceptionId : Bytes
  deriving DecidableEq

structure SemanticResult where
  policy : Nat
  directive : Nat
  reason : Reason
  reasonId : Bytes
  attemptId : Bytes
  profileId : Bytes
  schemaId : Bytes
  programId : Bytes
  modeId : Bytes
  evaluatorId : Bytes
  ruleId : Bytes
  phase0Binding : Bytes
  eventTime : Nat
  observationTime : Nat
  ruleEffectiveTime : Nat
  decisionTime : Nat
  continuityEpoch : Nat
  sequenceBefore : Nat
  sequenceAfter : Nat
  beforeAuditHead : Bytes
  beforeContinuityRoot : Bytes
  afterAuditHead : Bytes
  afterContinuityRoot : Bytes
  requestId : Bytes
  decisionId : Bytes
  controlSetId : Bytes
  sourceRoot : Bytes
  completenessId : Bytes
  exceptionId : Bytes
  beforeStateId : Bytes
  afterStateId : Bytes
  receiptId : Bytes
  joinId : Bytes
  chronologyId : Bytes
  replayId : Bytes
  decisionPathId : Bytes
  auditHeadAfter : Bytes
  continuityRootAfter : Bytes
  proofSessionAccepted : Bool
  economicMutation : Bool
  replayStateful : Bool

def exactProofSessionAccepted : Bool := false

def exactEconomicMutation : Bool := false

/- The executable boundary supplies no durable consumed-attempt registry.  A
   caller must therefore treat replay as a deterministic, stateless
   evaluation until the database/state owner supplies that registry. -/
def exactReplayStateful : Bool := false

def subjectKey (provider credential enrollment : Bytes) : Bytes :=
  digest SUBJECT_KEY_DOMAIN [provider, credential, enrollment]

def reasonIdOf : Reason → Bytes
  | .valid => digest REASON_DOMAIN ["valid-continuity".toUTF8]
  | .missing => digest REASON_DOMAIN ["authoritative-absence".toUTF8]
  | .expired => digest REASON_DOMAIN ["expired-or-terminated".toUTF8]
  | .ambiguous => digest REASON_DOMAIN ["incomplete-or-ambiguous".toUTF8]
  | .staleRule => digest REASON_DOMAIN ["stale-rule-interval".toUTF8]
  | .controlInterval => digest REASON_DOMAIN ["control-set-decision-time".toUTF8]

def directivePolicy (directive : Nat) : Option Nat :=
  match directive with
  | 1 => some 1
  | 2 => some 2
  | 3 => some 3
  | 4 => some 4
  | 5 => some 4
  | _ => none

def require (condition : Bool) (error : String) : Except String Unit :=
  if condition then .ok () else .error error

def requireProof (condition : Bool) (error : String) : Except String (PLift (condition = true)) :=
  if h : condition then .ok ⟨h⟩ else .error error

/-!
  The executable evaluator below consumes this exact-width domain.  The raw
  parser intentionally keeps every field as bytes so the canonical wire
  representation is available for identity derivation.  `ExactSemanticInput`
  is the typed boundary: it can only be constructed after every identity is
  64 bytes and every chronology value is the lossless big-endian decode of
  exactly eight bytes.  No value is reduced to the legacy one-byte model.
 -/

def width64 (value : Bytes) : Bool := value.size = 64

def width8 (value : Bytes) : Bool := value.size = 8

def u64Canonical (raw : Bytes) (value : Nat) : Bool :=
  width8 raw && equal (u64 value) raw

def allWidth64 : List Bytes → Bool
  | [] => true
  | value :: rest => width64 value && allWidth64 rest

def factWidths : List FactRaw → Bool
  | [] => true
  | fact :: rest =>
      allWidth64 [fact.provider, fact.credential, fact.enrollment, fact.feed, fact.recordId] &&
        factWidths rest

def exceptionWidths : Option ExceptionRaw → Bool
  | none => true
  | some authorization =>
      allWidth64 [authorization.authorization, authorization.signer,
        authorization.subject, authorization.rule, authorization.reason,
        authorization.amount, authorization.signature]

def exactSemanticWidths
    (request : RequestRaw) (factSet : FactSetRaw)
    (completeness : CompletenessRaw) (exception : Option ExceptionRaw) : Bool :=
  allWidth64 [request.provider, request.credential, request.enrollment, request.attempt,
    factSet.feed, completeness.feed, completeness.provider, completeness.scope] &&
    factWidths factSet.facts &&
    completeness.absence.all width64 &&
    exceptionWidths exception &&
    u64Canonical request.epochRaw request.epoch &&
    u64Canonical request.sequenceRaw request.sequence &&
    u64Canonical request.eventRaw request.event &&
    u64Canonical request.observationRaw request.observation &&
    u64Canonical request.ruleEffectiveRaw request.ruleEffective &&
    u64Canonical request.decisionRaw request.decision

structure ExactSemanticInput where
  request : RequestRaw
  factSet : FactSetRaw
  completeness : CompletenessRaw
  exception : Option ExceptionRaw
  controlSetId : Bytes
  widthProof : exactSemanticWidths request factSet completeness exception = true

def exactSemanticInput?
    (request : RequestRaw) (factSet : FactSetRaw)
    (completeness : CompletenessRaw) (exception : Option ExceptionRaw)
  (controlSetId : Bytes) : Option ExactSemanticInput :=
  if h : exactSemanticWidths request factSet completeness exception = true then
    some (ExactSemanticInput.mk request factSet completeness exception controlSetId h)
  else
    none

def fixedIdentities : Bool :=
  [MODE_ID, EVALUATOR_ID, RULE_ID, CONTROL_SET_ID, SYNTHETIC_PROVIDER_ID,
   SYNTHETIC_CREDENTIAL_ID, SYNTHETIC_ENROLLMENT_ID, SYNTHETIC_FEED_ID,
   TRUSTED_AUTHORIZER_ID, EXPECTED_REASON_ID, EXPECTED_AMOUNT_SCOPE, PROFILE_ID,
   DATABASE_SCHEMA_ID, DATABASE_PROGRAM_ID, PHASE0_BINDING, STATE_CONTEXT,
   EMPTY_AUDIT, EMPTY_ROOT, INITIAL_STATE_ID].all
    (fun value => value.size = 64 && !allZero value)

def sameSubject (request : RequestRaw) (fact : FactRaw) : Bool :=
  equal request.provider fact.provider && equal request.credential fact.credential &&
    equal request.enrollment fact.enrollment

def factSubjectKey (fact : FactRaw) : Bytes :=
  subjectKey fact.provider fact.credential fact.enrollment

def anyFactConflicts (facts : List FactRaw) (absence : List Bytes) : Bool :=
  facts.any (fun fact => absence.any (fun key => equal (factSubjectKey fact) key))

def factValid (request : RequestRaw) (factSet : FactSetRaw) (fact : FactRaw) : Bool :=
  equal fact.provider SYNTHETIC_PROVIDER_ID &&
    equal fact.credential SYNTHETIC_CREDENTIAL_ID &&
    equal fact.enrollment SYNTHETIC_ENROLLMENT_ID &&
    equal fact.feed factSet.feed && nonzero64 fact.recordId &&
    fact.issued < fact.expires && fact.observed = request.observation &&
    match fact.status with
    | 1 => fact.terminated = 0 && fact.issued ≤ fact.observed && fact.observed < fact.expires
    | 2 => fact.terminated = 0 && fact.expires ≤ fact.observed
    | 3 => fact.issued ≤ fact.terminated && fact.terminated ≤ fact.observed
    | _ => false

def factCountFor (request : RequestRaw) : List FactRaw → Nat
  | [] => 0
  | fact :: rest => (if sameSubject request fact then 1 else 0) + factCountFor request rest

def firstMatchingStatus (request : RequestRaw) : List FactRaw → Option Nat
  | [] => none
  | fact :: rest => if sameSubject request fact then some fact.status else firstMatchingStatus request rest

def strictChronology (request : RequestRaw) : Bool :=
  request.ruleEffective < request.event && request.event < request.observation &&
    request.observation < request.decision

def exactAuthoritativeAbsence (input : ExactSemanticInput) : Bool :=
  input.completeness.complete &&
    equal input.completeness.scope
      (subjectKey input.request.provider input.request.credential input.request.enrollment) &&
    input.completeness.absence.any (fun value => equal value input.completeness.scope)

def exactAbsenceDirective (input : ExactSemanticInput) : Nat :=
  if exactAuthoritativeAbsence input then 2 else 3

def exactExceptionScope
    (input : ExactSemanticInput) (base : Outcome) (authorization : ExceptionRaw) : Bool :=
  let body := authorizationBody authorization.raw
  equal authorization.authorization (authorizationId body) &&
    equal authorization.signature (authorizationSignature authorization.signer body) &&
    base.policy = 4 && equal authorization.signer TRUSTED_AUTHORIZER_ID &&
    equal authorization.subject input.request.credential &&
    equal authorization.rule RULE_ID && equal authorization.reason EXPECTED_REASON_ID &&
    equal authorization.amount EXPECTED_AMOUNT_SCOPE && authorization.policy = 4 &&
    authorization.effectiveAt ≤ input.request.ruleEffective &&
    authorization.effectiveAt < authorization.expiresAt &&
    input.request.decision < authorization.expiresAt &&
    nonzero64 authorization.authorization && nonzero64 authorization.signature

def exactApplyException
    (input : ExactSemanticInput) (base : Outcome) (authorization : ExceptionRaw) :
    Option Outcome :=
  if exactExceptionScope input base authorization then
    some { base with
      policy := 4
      directive := 5
      exceptionId := authorization.authorization }
  else
    none

def exactRequestBinding (input : ExactSemanticInput) : Bool :=
  equal input.request.provider SYNTHETIC_PROVIDER_ID &&
    equal input.request.credential SYNTHETIC_CREDENTIAL_ID &&
    equal input.request.enrollment SYNTHETIC_ENROLLMENT_ID &&
    nonzero64 input.request.attempt && input.request.epoch = EPOCH &&
    input.request.sequence = 0 && strictChronology input.request

def exactFactBinding (input : ExactSemanticInput) : Bool :=
  equal input.factSet.feed SYNTHETIC_FEED_ID &&
    input.factSet.facts.all (factValid input.request input.factSet)

def exactCompletenessBinding (input : ExactSemanticInput) : Bool :=
  equal input.completeness.feed SYNTHETIC_FEED_ID &&
    equal input.completeness.provider input.request.provider &&
    equal input.completeness.scope
      (subjectKey input.request.provider input.request.credential input.request.enrollment) &&
    nonzero64 input.completeness.scope &&
    input.completeness.observation = input.request.observation &&
    !input.factSet.facts.any (fun fact =>
      input.completeness.absence.any (fun value =>
        equal value (subjectKey fact.provider fact.credential fact.enrollment)))

def exactBaseOutcome (input : ExactSemanticInput) : Except String Outcome :=
  if equal input.controlSetId CONTROL_SET_ID = false then
    .error "control-set"
  else if exactRequestBinding input = false then
    .error "request-binding"
  else if exactFactBinding input = false then
    .error "fact-binding"
  else if exactCompletenessBinding input = false then
    .error "completeness-binding"
  else
    let request := input.request
    let factSet := input.factSet
    let matching := factCountFor request factSet.facts
    if !(EFFECTIVE_START ≤ request.ruleEffective && request.ruleEffective < EFFECTIVE_END) then
      pure { policy := 3, directive := 3, reason := .staleRule, exceptionId := SENTINEL }
    else if !(EFFECTIVE_START ≤ request.decision && request.decision < EFFECTIVE_END) then
      pure { policy := 3, directive := 3, reason := .controlInterval, exceptionId := SENTINEL }
    else if matching > 1 then
      pure { policy := 3, directive := 3, reason := .ambiguous, exceptionId := SENTINEL }
    else
      match firstMatchingStatus request factSet.facts with
      | none =>
          if exactAuthoritativeAbsence input then
            pure { policy := 2, directive := 2, reason := .missing, exceptionId := SENTINEL }
          else
            pure { policy := 3, directive := 3, reason := .ambiguous, exceptionId := SENTINEL }
      | some status =>
          if status = 1 then
            pure { policy := 1, directive := 1, reason := .valid, exceptionId := SENTINEL }
          else if status = 2 || status = 3 then
            pure { policy := 4, directive := 4, reason := .expired, exceptionId := SENTINEL }
          else
            .error "fact-status"

def exactEvaluate (input : ExactSemanticInput) : Except String Outcome := do
  let base ← exactBaseOutcome input
  match input.exception with
  | none =>
      let expectedPolicy ← match directivePolicy base.directive with
        | some value => .ok value
        | none => .error "directive"
      require (base.policy = expectedPolicy && equal base.exceptionId SENTINEL)
        "policy-directive"
      pure base
  | some authorization =>
      match exactApplyException input base authorization with
      | some value => pure value
      | none => .error "exception-scope"

def exactAbsenceOutcomeGuard (input : ExactSemanticInput) (base : Outcome) : Bool :=
  if base.directive = 2 then exactAuthoritativeAbsence input else true

def exactExceptionOutcomeGuard
    (input : ExactSemanticInput) (base outcome : Outcome)
    (exception : Option ExceptionRaw) : Bool :=
  match exception with
  | none => true
  | some authorization =>
      exactExceptionScope input base authorization &&
        equal outcome.exceptionId authorization.authorization

def exactBaseDirectiveGuard (base outcome : Outcome) : Bool :=
  if outcome.directive = 2 then base.directive = 2 else true

structure ExactLedgerState where
  context : Bytes
  sequence : Nat
  rowCount : Nat
  lastAttempt : Option Bytes
  audit : Bytes
  root : Bytes

def stateRawOf (state : ExactLedgerState) : StateRaw :=
  let raw := stateCanonical state.context state.sequence state.rowCount state.audit state.root
  { raw := raw
    context := state.context
    sequence := state.sequence
    rowCount := state.rowCount
    audit := state.audit
    root := state.root
    id := stateId raw
    canonicalProof := rfl }

def exactStateOf (state : StateRaw) (lastAttempt : Option Bytes) : ExactLedgerState :=
  { context := state.context
    sequence := state.sequence
    rowCount := state.rowCount
    lastAttempt := lastAttempt
    audit := state.audit
    root := state.root }

def exactAdvance
    (state : ExactLedgerState) (attempt decision source : Bytes) (directive : Nat) :
    Option ExactLedgerState :=
  if !nonzero64 attempt || !nonzero64 decision || !nonzero64 source then
    none
  else if state.lastAttempt = some attempt then
    none
  else if directive ∉ [1, 2, 3, 4, 5] then
    none
  else
    some
      { context := state.context
        sequence := state.sequence + 1
        rowCount := state.rowCount + 1
        lastAttempt := some attempt
        audit := auditAfter state.audit decision directive
        root := continuityAfter state.root source decision }

def exactDerivedIdentityGuard : Bool :=
  equal controlSetIdDerived CONTROL_SET_ID && equal stateContext STATE_CONTEXT &&
    equal initialStateId INITIAL_STATE_ID

def exactBeforeStateGuard (request : RequestRaw) (before : StateRaw) : Bool :=
  equal before.raw initialStateRaw && equal before.id INITIAL_STATE_ID &&
    equal before.context STATE_CONTEXT && before.sequence = 0 && before.rowCount = 0 &&
    equal before.audit EMPTY_AUDIT && equal before.root EMPTY_ROOT &&
    equal request.expectedBefore before.id && nonzero64 before.audit

def exactAfterStateGuard (after : StateRaw) : Bool :=
  equal after.context STATE_CONTEXT && after.sequence = 1 && after.rowCount = 1 &&
    nonzero64 after.root && nonzero64 after.audit

def exactReceiptGuard
    (receipt : ReceiptRaw) (before after : StateRaw) (controlSetId sourceRoot : Bytes) : Bool :=
  equal receipt.id (receiptId receipt.body) && equal receipt.adapter (adapterBinding sourceRoot) &&
    equal receipt.control controlSetId && equal receipt.phase0 PHASE0_BINDING &&
    equal receipt.decisionId receipt.decision.decisionId &&
    equal receipt.beforeId before.id && equal receipt.decision.beforeId before.id &&
    equal receipt.afterId receipt.decision.afterId && equal receipt.afterId after.id &&
    equal receipt.firstAccess.decisionId receipt.decision.decisionId &&
    equal receipt.secondAccess.decisionId receipt.decision.decisionId &&
    nonzero64 receipt.decision.decisionId

def exactDecisionGuard
    (decision : DecisionRaw) (request : RequestRaw) (before : StateRaw)
    (controlSetId sourceRoot completenessId chronologyIdValue replayIdValue requestIdValue : Bytes) : Bool :=
  equal decision.provider request.provider && equal decision.credential request.credential &&
    equal decision.enrollment request.enrollment && equal decision.mode MODE_ID &&
    equal decision.control controlSetId && equal decision.rule RULE_ID &&
    equal decision.phase0 PHASE0_BINDING && equal decision.sourceRoot sourceRoot &&
    equal decision.completenessId completenessId && equal decision.chronologyId chronologyIdValue &&
    nonzero64 decision.replayId && nonzero64 decision.pathId && nonzero64 decision.reasonId &&
    equal decision.replayId replayIdValue && equal decision.requestId requestIdValue &&
    decision.attemptId = request.attempt && equal decision.beforeId before.id &&
    decision.event = request.event && decision.observation = request.observation &&
    decision.ruleEffective = request.ruleEffective && decision.decision = request.decision

def exactTransitionGuard (after : StateRaw) (transitioned : ExactLedgerState) : Bool :=
  let expectedAfter := stateRawOf transitioned
  equal after.audit expectedAfter.audit && equal after.root expectedAfter.root &&
    equal after.context expectedAfter.context && after.sequence = expectedAfter.sequence &&
    after.rowCount = expectedAfter.rowCount && equal after.id expectedAfter.id &&
    equal expectedAfter.raw after.raw

def exactAccessJoinGuard
    (request : RequestRaw) (before after : StateRaw) (decision : DecisionRaw)
    (receipt : ReceiptRaw) (sourceRoot : Bytes) : Bool :=
  receipt.firstAccess.decisionIndex = 0 && receipt.firstAccess.accessIndex = 0 &&
    receipt.firstAccess.accessCount = 2 && receipt.firstAccess.mode = 1 &&
    receipt.firstAccess.time = request.observation &&
    equal receipt.firstAccess.before receipt.firstAccess.after &&
    equal receipt.firstAccess.address (sourceAddress request.provider) &&
    equal receipt.firstAccess.key (subjectKey request.provider request.credential request.enrollment) &&
    equal receipt.firstAccess.before sourceRoot && equal receipt.firstAccess.after sourceRoot &&
    receipt.secondAccess.decisionIndex = 0 && receipt.secondAccess.accessIndex = 1 &&
    receipt.secondAccess.accessCount = 2 && receipt.secondAccess.mode = 2 &&
    receipt.secondAccess.time = request.decision &&
    equal receipt.secondAccess.address (auditAddress request.provider) &&
    equal receipt.secondAccess.key decision.decisionId &&
    equal receipt.secondAccess.before before.audit && equal receipt.secondAccess.after after.audit &&
    !equal receipt.secondAccess.before receipt.secondAccess.after &&
    equal receipt.joinId (digest "BL/NATIVE-V3/CONTINUITY/DECISION-ACCESS-JOIN/v2"
      [joinCanonical decision.raw receipt.firstAccess.raw receipt.secondAccess.raw])

def exactPolicyDirectiveGuard
    (outcome : Outcome) (decision : DecisionRaw) (requestRaw : Bytes) (before after : StateRaw)
    (controlSetId sourceRoot completenessId : Bytes) (expectedPolicy : Nat) : Bool :=
  outcome.policy = expectedPolicy && equal decision.exceptionId outcome.exceptionId &&
    decision.policy = outcome.policy && decision.directive = outcome.directive &&
    equal decision.reasonId (reasonIdOf outcome.reason) &&
    equal decision.pathId (pathId controlSetId RULE_ID sourceRoot completenessId
      (reasonIdOf outcome.reason) outcome.policy outcome.directive outcome.exceptionId) &&
    equal decision.decisionId (decisionId requestRaw before.id sourceRoot completenessId
      outcome.policy outcome.directive outcome.exceptionId) &&
    equal decision.afterId after.id &&
    equal after.audit (auditAfter before.audit decision.decisionId outcome.directive) &&
    equal after.root (continuityAfter before.root sourceRoot decision.decisionId)

/-!
  `ExactExecutionTrace` is the executable seam for the formal boundary.  A
  successful trace retains the parsed records, the typed semantic input, the
  evaluator result, and the exact state transition that produced the returned
  result.  The proof fields are carried by construction from the successful
  `match` branches below; they are not reconstructed from the output line.
  The native adapter consumes only `result`, but the theorem module can now
  state properties about the path actually used by `SemanticExecutable`.
 -/
structure ExactExecutionTrace (parts : PartsRaw) where
  request : RequestRaw
  factSet : FactSetRaw
  completeness : CompletenessRaw
  exception : Option ExceptionRaw
  before : StateRaw
  after : StateRaw
  receipt : ReceiptRaw
  semanticInput : ExactSemanticInput
  baseOutcome : Outcome
  outcome : Outcome
  transitioned : ExactLedgerState
  result : SemanticResult
  fixedIdentityProof : fixedIdentities = true
  derivedIdentityProof : exactDerivedIdentityGuard = true
  beforeStateProof : exactBeforeStateGuard request before = true
  afterStateProof : exactAfterStateGuard after = true
  receiptBindingProof :
    exactReceiptGuard receipt before after controlSetIdDerived (sourceRoot parts.facts) = true
  decisionBindingProof :
    exactDecisionGuard receipt.decision request before controlSetIdDerived
      (sourceRoot parts.facts) (completenessId completeness.raw) (chronologyId request.raw)
      (replayId request.raw before.id (sourceRoot parts.facts) controlSetIdDerived)
      (requestId request.raw) = true
  transitionBindingProof : exactTransitionGuard after transitioned = true
  accessJoinProof :
    exactAccessJoinGuard request before after receipt.decision receipt (sourceRoot parts.facts) = true
  policyDirectiveProof :
    ∃ expectedPolicy, directivePolicy outcome.directive = some expectedPolicy ∧
      exactPolicyDirectiveGuard outcome receipt.decision request.raw before after controlSetIdDerived
        (sourceRoot parts.facts) (completenessId completeness.raw) expectedPolicy = true
  resultOutcomeProof :
      result.policy = outcome.policy ∧ result.directive = outcome.directive ∧
      result.reason = outcome.reason ∧ result.reasonId = reasonIdOf outcome.reason ∧
      result.exceptionId = outcome.exceptionId
  resultIdentityProof :
    result.requestId = requestId request.raw ∧
      result.decisionId = receipt.decision.decisionId ∧
      result.controlSetId = controlSetIdDerived ∧
      result.sourceRoot = sourceRoot parts.facts ∧
      result.completenessId = completenessId completeness.raw ∧
      result.exceptionId = outcome.exceptionId ∧
      result.beforeStateId = before.id ∧ result.afterStateId = after.id ∧
      result.receiptId = receipt.id ∧ result.joinId = receipt.joinId ∧
      result.chronologyId = chronologyId request.raw ∧
      result.replayId = replayId request.raw before.id (sourceRoot parts.facts) controlSetIdDerived ∧
      result.decisionPathId = receipt.decision.pathId ∧
      result.auditHeadAfter = after.audit ∧ result.continuityRootAfter = after.root
  resultStateProof :
    result.attemptId = request.attempt ∧ result.profileId = PROFILE_ID ∧
      result.schemaId = DATABASE_SCHEMA_ID ∧ result.programId = DATABASE_PROGRAM_ID ∧
      result.modeId = receipt.decision.mode ∧ result.evaluatorId = EVALUATOR_ID ∧
      result.ruleId = receipt.decision.rule ∧ result.phase0Binding = receipt.phase0 ∧
      result.eventTime = request.event ∧ result.observationTime = request.observation ∧
      result.ruleEffectiveTime = request.ruleEffective ∧ result.decisionTime = request.decision ∧
      result.continuityEpoch = request.epoch ∧ result.sequenceBefore = before.sequence ∧
      result.sequenceAfter = after.sequence ∧ result.beforeAuditHead = before.audit ∧
      result.beforeContinuityRoot = before.root ∧ result.afterAuditHead = after.audit ∧
      result.afterContinuityRoot = after.root
  resultReceiptStateProof :
    result.receiptId = receipt.id ∧ result.joinId = receipt.joinId ∧
      result.beforeStateId = before.id ∧ result.afterStateId = after.id ∧
      result.auditHeadAfter = after.audit ∧ result.continuityRootAfter = after.root
  resultFlagsProof :
    result.proofSessionAccepted = false ∧
      result.economicMutation = false ∧ result.replayStateful = false
  requestParseProof : parseRequest? parts.request = some request
  factSetParseProof : parseFactSet? parts.facts = some factSet
  completenessParseProof : parseCompleteness? parts.completeness = some completeness
  exceptionParseProof : parseException? parts.exception = some exception
  beforeParseProof : parseState? parts.before = some before
  afterParseProof : parseState? parts.after = some after
  receiptParseProof : parseReceipt? parts.receipt = some receipt
  semanticInputProof :
    exactSemanticInput? request factSet completeness exception controlSetIdDerived =
      some semanticInput
  requestBindingProof : exactRequestBinding semanticInput = true
  factBindingProof : exactFactBinding semanticInput = true
  completenessBindingProof : exactCompletenessBinding semanticInput = true
  baseEvaluationProof : exactBaseOutcome semanticInput = .ok baseOutcome
  absenceOutcomeProof : exactAbsenceOutcomeGuard semanticInput baseOutcome = true
  baseDirectiveProof : exactBaseDirectiveGuard baseOutcome outcome = true
  evaluationProof : exactEvaluate semanticInput = .ok outcome
  exceptionOutcomeProof :
    exactExceptionOutcomeGuard semanticInput baseOutcome outcome exception = true
  transitionProof :
    exactAdvance (exactStateOf before none) request.attempt
        receipt.decision.decisionId (sourceRoot parts.facts) outcome.directive =
      some transitioned

def verifyPartsTrace (parts : PartsRaw) : Except String (ExactExecutionTrace parts) := do
  let fixedIdentityProofValue ← requireProof fixedIdentities "fixed-constant-width"
  let fixedIdentityProof := fixedIdentityProofValue.down
  let requestValue : { value : RequestRaw // parseRequest? parts.request = some value } ←
      match h : parseRequest? parts.request with
      | some value => pure ⟨value, h⟩
      | none => .error "request-grammar"
  let request := requestValue.val
  let requestParseProof := requestValue.property
  let factSetValue : { value : FactSetRaw // parseFactSet? parts.facts = some value } ←
      match h : parseFactSet? parts.facts with
      | some value => pure ⟨value, h⟩
      | none => .error "fact-set-grammar"
  let factSet := factSetValue.val
  let factSetParseProof := factSetValue.property
  let completenessValue :
      { value : CompletenessRaw // parseCompleteness? parts.completeness = some value } ←
      match h : parseCompleteness? parts.completeness with
      | some value => pure ⟨value, h⟩
      | none => .error "completeness-grammar"
  let completeness := completenessValue.val
  let completenessParseProof := completenessValue.property
  let exceptionValue :
      { value : Option ExceptionRaw // parseException? parts.exception = some value } ←
      match h : parseException? parts.exception with
      | some value => pure ⟨value, h⟩
      | none => .error "exception-grammar"
  let exception := exceptionValue.val
  let exceptionParseProof := exceptionValue.property
  let beforeValue : { value : StateRaw // parseState? parts.before = some value } ←
      match h : parseState? parts.before with
      | some value => pure ⟨value, h⟩
      | none => .error "before-state-grammar"
  let before := beforeValue.val
  let beforeParseProof := beforeValue.property
  let afterValue : { value : StateRaw // parseState? parts.after = some value } ←
      match h : parseState? parts.after with
      | some value => pure ⟨value, h⟩
      | none => .error "after-state-grammar"
  let after := afterValue.val
  let afterParseProof := afterValue.property
  let receiptValue : { value : ReceiptRaw // parseReceipt? parts.receipt = some value } ←
      match h : parseReceipt? parts.receipt with
      | some value => pure ⟨value, h⟩
      | none => .error "receipt-grammar"
  let receipt := receiptValue.val
  let receiptParseProof := receiptValue.property
  let controlSetIdValue := controlSetIdDerived
  let sourceRootValue := sourceRoot parts.facts
  let requestIdValue := requestId request.raw
  let completenessIdValue := completenessId completeness.raw
  let chronologyIdValue := chronologyId request.raw
  let replayIdValue := replayId request.raw before.id sourceRootValue controlSetIdValue
  let derivedIdentityProofValue ← requireProof exactDerivedIdentityGuard "fixed-derived-identities"
  let derivedIdentityProof := derivedIdentityProofValue.down
  let semanticInputValue :
      { value : ExactSemanticInput //
        exactSemanticInput? request factSet completeness exception controlSetIdValue =
          some value } ←
      match h : exactSemanticInput? request factSet completeness exception controlSetIdValue with
      | some value => pure ⟨value, h⟩
      | none => .error "exact-width-domain"
  let semanticInput := semanticInputValue.val
  let semanticInputProof := semanticInputValue.property
  let requestBindingProofValue ← requireProof (exactRequestBinding semanticInput) "request-binding"
  let requestBindingProof := requestBindingProofValue.down
  let factBindingProofValue ← requireProof (exactFactBinding semanticInput) "fact-binding"
  let factBindingProof := factBindingProofValue.down
  let completenessBindingProofValue ←
    requireProof (exactCompletenessBinding semanticInput) "completeness-binding"
  let completenessBindingProof := completenessBindingProofValue.down
  let baseEvaluated : { value : Outcome // exactBaseOutcome semanticInput = .ok value } ←
    match h : exactBaseOutcome semanticInput with
    | .ok base => pure ⟨base, h⟩
    | .error error => .error error
  let baseOutcome := baseEvaluated.val
  let baseEvaluationProof := baseEvaluated.property
  let absenceOutcomeProofValue ←
    requireProof (exactAbsenceOutcomeGuard semanticInput baseOutcome) "absence-binding"
  let absenceOutcomeProof := absenceOutcomeProofValue.down
  let evaluated : { value : Outcome // exactEvaluate semanticInput = .ok value } ←
      match h : exactEvaluate semanticInput with
    | .ok outcome =>
        pure ⟨outcome, h⟩
    | .error error => .error error
  let outcome := evaluated.val
  let evaluationProof := evaluated.property
  let exceptionOutcomeProofValue ← requireProof
    (exactExceptionOutcomeGuard semanticInput baseOutcome outcome exception) "exception-scope"
  let exceptionOutcomeProof := exceptionOutcomeProofValue.down
  let baseDirectiveProofValue ← requireProof
    (exactBaseDirectiveGuard baseOutcome outcome) "base-directive-binding"
  let baseDirectiveProof := baseDirectiveProofValue.down
  let beforeStateProofValue ← requireProof (exactBeforeStateGuard request before) "before-state-binding"
  let beforeStateProof := beforeStateProofValue.down
  let afterStateProofValue ← requireProof (exactAfterStateGuard after) "after-state-binding"
  let afterStateProof := afterStateProofValue.down
  let decision := receipt.decision
  let receiptBindingProofValue ← requireProof
    (exactReceiptGuard receipt before after controlSetIdValue sourceRootValue) "receipt-binding"
  let receiptBindingProof := receiptBindingProofValue.down
  let decisionBindingProofValue ← requireProof
    (exactDecisionGuard decision request before controlSetIdValue sourceRootValue completenessIdValue
      chronologyIdValue replayIdValue requestIdValue) "decision-binding"
  let decisionBindingProof := decisionBindingProofValue.down
  let transitionInput := exactAdvance (exactStateOf before none) request.attempt
      decision.decisionId sourceRootValue outcome.directive
  let transitionedPair : { value : ExactLedgerState // transitionInput = some value } ←
      match h : transitionInput with
    | some value =>
        pure ⟨value, h⟩
    | none => .error "state-transition"
  let transitioned := transitionedPair.val
  let transitionBindingProofValue ← requireProof (exactTransitionGuard after transitioned)
    "state-transition"
  let transitionBindingProof := transitionBindingProofValue.down
  let accessJoinProofValue ← requireProof
    (exactAccessJoinGuard request before after decision receipt sourceRootValue) "access-join"
  let accessJoinProof := accessJoinProofValue.down
  let expectedPolicyValue : { value : Nat // directivePolicy outcome.directive = some value } ←
    match h : directivePolicy outcome.directive with
    | some value => pure ⟨value, h⟩
    | none => .error "directive"
  let expectedPolicy := expectedPolicyValue.val
  let expectedPolicyProof := expectedPolicyValue.property
  let policyDirectiveProofValue ← requireProof
    (exactPolicyDirectiveGuard outcome decision request.raw before after controlSetIdValue
      sourceRootValue completenessIdValue expectedPolicy) "policy-directive"
  let policyDirectiveProof := policyDirectiveProofValue.down
  let result : SemanticResult := {
    policy := outcome.policy
    directive := outcome.directive
    reason := outcome.reason
    reasonId := reasonIdOf outcome.reason
    attemptId := request.attempt
    profileId := PROFILE_ID
    schemaId := DATABASE_SCHEMA_ID
    programId := DATABASE_PROGRAM_ID
    modeId := decision.mode
    evaluatorId := EVALUATOR_ID
    ruleId := decision.rule
    phase0Binding := receipt.phase0
    eventTime := request.event
    observationTime := request.observation
    ruleEffectiveTime := request.ruleEffective
    decisionTime := request.decision
    continuityEpoch := request.epoch
    sequenceBefore := before.sequence
    sequenceAfter := after.sequence
    beforeAuditHead := before.audit
    beforeContinuityRoot := before.root
    afterAuditHead := after.audit
    afterContinuityRoot := after.root
    requestId := requestIdValue
    decisionId := decision.decisionId
    controlSetId := controlSetIdValue
    sourceRoot := sourceRootValue
    completenessId := completenessIdValue
    exceptionId := outcome.exceptionId
    beforeStateId := before.id
    afterStateId := after.id
    receiptId := receipt.id
    joinId := receipt.joinId
    chronologyId := chronologyIdValue
    replayId := replayIdValue
    decisionPathId := decision.pathId
    auditHeadAfter := after.audit
    continuityRootAfter := after.root
    proofSessionAccepted := exactProofSessionAccepted
    economicMutation := exactEconomicMutation
    replayStateful := exactReplayStateful }
  pure {
    request := request
    factSet := factSet
    completeness := completeness
    exception := exception
    before := before
    after := after
    receipt := receipt
    semanticInput := semanticInput
    baseOutcome := baseOutcome
    outcome := outcome
    transitioned := transitioned
    result := result
    requestParseProof := requestParseProof
    factSetParseProof := factSetParseProof
    completenessParseProof := completenessParseProof
    exceptionParseProof := exceptionParseProof
    beforeParseProof := beforeParseProof
    afterParseProof := afterParseProof
    receiptParseProof := receiptParseProof
    semanticInputProof := semanticInputProof
    requestBindingProof := requestBindingProof
    factBindingProof := factBindingProof
    completenessBindingProof := completenessBindingProof
    baseEvaluationProof := baseEvaluationProof
    absenceOutcomeProof := absenceOutcomeProof
    baseDirectiveProof := baseDirectiveProof
    evaluationProof := evaluationProof
    exceptionOutcomeProof := exceptionOutcomeProof
    transitionProof := by
      simpa [transitionInput, decision, sourceRootValue] using transitionedPair.property
    fixedIdentityProof := fixedIdentityProof
    derivedIdentityProof := by
      simpa [exactDerivedIdentityGuard, controlSetIdValue] using derivedIdentityProof
    beforeStateProof := beforeStateProof
    afterStateProof := afterStateProof
    receiptBindingProof := by
      simpa [controlSetIdValue, sourceRootValue] using receiptBindingProof
    decisionBindingProof := by
      simpa [controlSetIdValue, sourceRootValue, completenessIdValue, chronologyIdValue,
        replayIdValue, requestIdValue] using decisionBindingProof
    transitionBindingProof := transitionBindingProof
    accessJoinProof := by
      simpa [sourceRootValue] using accessJoinProof
    policyDirectiveProof := ⟨expectedPolicy, expectedPolicyProof, by
      simpa [controlSetIdValue, sourceRootValue, completenessIdValue] using policyDirectiveProof⟩
    resultOutcomeProof := by
      simp [result]
    resultIdentityProof := by
      simp [result, decision, controlSetIdValue, sourceRootValue, requestIdValue, completenessIdValue,
        chronologyIdValue, replayIdValue]
    resultStateProof := by
      simp [result, decision]
    resultReceiptStateProof := by
      simp [result]
    resultFlagsProof := by
      simp [result, exactProofSessionAccepted, exactEconomicMutation, exactReplayStateful] }

def verifyParts (parts : PartsRaw) : Except String SemanticResult := do
  let trace ← verifyPartsTrace parts
  pure trace.result

def verifyResult (data : Bytes) : Except String SemanticResult := do
  let parts ← match parseBundle? data with | some value => .ok value | none => .error "bundle-grammar"
  verifyParts parts

def verify (data : Bytes) : Except String Outcome := do
  let result ← verifyResult data
  pure {
    policy := result.policy
    directive := result.directive
    reason := result.reason
    exceptionId := result.exceptionId }

theorem directive_policy_total (directive : Nat) (h : directive ∈ [1, 2, 3, 4, 5]) :
    ∃ policy, directivePolicy directive = some policy := by
  simp only [List.mem_cons, List.not_mem_nil, or_false] at h
  rcases h with h | h | h | h | h
  · subst directive
    exact ⟨1, rfl⟩
  · subst directive
    exact ⟨2, rfl⟩
  · subst directive
    exact ⟨3, rfl⟩
  · subst directive
    exact ⟨4, rfl⟩
  · subst directive
    exact ⟨4, rfl⟩

end BlindLedger.Semantic
