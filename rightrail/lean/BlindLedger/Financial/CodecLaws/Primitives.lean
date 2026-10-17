import BlindLedger.Financial.Codec

namespace BlindLedger.Financial

/-!
  Generic laws for the financial codec boundary.

  The Engine handoff fixes the active wire grammar at v2 (`BLFIN02` and
  `BLFRES02`).  Version tags, field order, actor-bearing authority records,
  payment reversal evidence, determination actor fields, and the v2
  `CANCELLED` tags remain owned by `Codec.lean`/`Types.lean`; this file does
  not redeclare a codec or evaluator.  The laws below are the reusable
  bounded combinator layer that the v2 records compose.

  The numeric bounds are exact for the current seam: u64 values are less than
  `256^8`, u16 lengths/counts are less than `256^2`, IDs are at most
  `maxIdBytes = 128` UTF-8 bytes, free text is at most `maxTextBytes = 512`
  UTF-8 bytes, digests have exactly `digestBytes = 64` bytes, and row counts
  are at most `maxRows = 10_000`.  String laws retain the UTF-8 validity
  premise at the parser boundary instead of treating a host-language string
  conversion as a proof of the wire contract.
 -/

def natFits (width value : Nat) : Prop := value < 256 ^ width

def stringWireAdmissible (value : String) : Prop :=
  value.toUTF8.toList.length < 256 ^ 2 ∧
    String.fromUTF8? (value.toUTF8.toList.toByteArray) = some value

def digestWireAdmissible (value : Bytes) : Prop := value.length = digestBytes

def listCountAdmissible {α : Type} (values : List α) : Prop :=
  values.length ≤ maxRows ∧ values.length < 256 ^ 2

theorem maxIdBytes_fits_u16 : maxIdBytes < 256 ^ 2 := by
  decide

theorem maxTextBytes_fits_u16 : maxTextBytes < 256 ^ 2 := by
  decide

theorem maxRows_fits_u16 : maxRows < 256 ^ 2 := by
  decide

theorem maxCents_fits_u64 : maxCents < 256 ^ 8 := by
  decide

theorem maxTime_fits_u64 : maxTime < 256 ^ 8 := by
  decide

theorem maxRevision_fits_u64 : maxRevision < 256 ^ 8 := by
  decide

theorem financial_v2_bounds :
    maxIdBytes ≤ 128 ∧
      maxTextBytes ≤ 512 ∧
      maxRows ≤ 10_000 ∧
      digestBytes = 64 ∧
      maxCents < 256 ^ 8 ∧
      maxTime < 256 ^ 8 ∧
      maxRevision < 256 ^ 8 := by
  decide

theorem readMagic_rejects_nonprefix
    (bytes : Bytes)
    (hPrefix : ¬ financialCodecMagic.isPrefixOf bytes) :
    readMagic bytes = none := by
  simp [readMagic, hPrefix]

theorem readResultMagic_rejects_nonprefix
    (bytes : Bytes)
    (hPrefix : ¬ financialResultCodecMagic.isPrefixOf bytes) :
    readResultMagic bytes = none := by
  simp [readResultMagic, hPrefix]

/-! `String.fromUTF8?` is total only after its validity check.  This proves
    the native String-side property; `stringWireAdmissible` additionally
    exposes the exact list-to-byte-array value consumed by `readString`. -/

theorem string_fromUTF8_toUTF8 (value : String) :
    String.fromUTF8? value.toUTF8 = some value := by
  unfold String.fromUTF8?
  split
  · rename_i hValid
    apply congrArg some
    apply (String.toByteArray_inj).mp
    rfl
  · rename_i hInvalid
    exact (hInvalid (by simpa [String.toUTF8_eq_toByteArray] using value.isValidUTF8)).elim

/-! Fixed-width big-endian naturals are canonical only inside their exact
    capacity.  This is the central value/byte roundtrip used by u16 lengths,
    u64 amounts/times/revisions, and option payloads. -/

theorem readNatBE_natBE_append
    (width value : Nat) (rest : Bytes)
    (hValue : value < 256 ^ width) :
    readNatBE width (natBE width value ++ rest) = some (value, rest) := by
  induction width generalizing value rest with
  | zero =>
      have hZero : value = 0 := by
        have hLess : value < 1 := by simpa using hValue
        omega
      subst value
      rfl
  | succ width ih =>
      have hDiv : value / 256 < 256 ^ width := by
        apply (Nat.div_lt_iff_lt_mul (by decide : 0 < 256)).2
        simpa [Nat.pow_succ] using hValue
      simp only [natBE, List.append_assoc, readNatBE]
      rw [ih (value / 256) ([UInt8.ofNat (value % 256)] ++ rest) hDiv]
      simp [readByte, Nat.div_add_mod' value 256]

theorem readNatBE_rejects_nonempty_tail
    (width value : Nat) (tail : Bytes)
    (hValue : value < 256 ^ width)
    (hTail : tail ≠ []) :
    readNatBE width (natBE width value ++ tail) ≠ some (value, []) := by
  rw [readNatBE_natBE_append width value tail hValue]
  intro hEqual
  apply hTail
  exact congrArg Prod.snd (Option.some.inj hEqual)

theorem natBE_injective_of_fits
    (width left right : Nat)
    (hLeft : left < 256 ^ width)
    (hRight : right < 256 ^ width)
    (hWire : natBE width left = natBE width right) :
    left = right := by
  have hRead :
      readNatBE width (natBE width left) =
        readNatBE width (natBE width right) :=
    congrArg (fun bytes => readNatBE width bytes) hWire
  have hLeftRead :
      readNatBE width (natBE width left) = some (left, []) := by
    simpa using (readNatBE_natBE_append width left [] hLeft)
  have hRightRead :
      readNatBE width (natBE width right) = some (right, []) := by
    simpa using (readNatBE_natBE_append width right [] hRight)
  rw [hLeftRead, hRightRead] at hRead
  exact congrArg Prod.fst (Option.some.inj hRead)

/-! UTF-8 strings use the actual two-byte length prefix.  The validity
    premise is explicit because the parser is required to reject malformed
    UTF-8 rather than silently repair it. -/

theorem readString_encodeString_append
    (value : String) (rest : Bytes)
    (hValue : stringWireAdmissible value) :
    readString (encodeString value ++ rest) = some (value, rest) := by
  unfold readString encodeString
  simp only [List.append_assoc]
  rw [readNatBE_natBE_append 2 value.toUTF8.toList.length
    (value.toUTF8.toList ++ rest) hValue.1]
  have hUtf8 :
      String.fromUTF8? value.toByteArray.toList.toByteArray = some value := by
    simpa [String.toUTF8_eq_toByteArray] using hValue.2
  simp [hUtf8]

theorem readString_rejects_nonempty_tail
    (value : String) (tail : Bytes)
    (hValue : stringWireAdmissible value)
    (hTail : tail ≠ []) :
    readString (encodeString value ++ tail) ≠ some (value, []) := by
  rw [readString_encodeString_append value tail hValue]
  intro hEqual
  apply hTail
  exact congrArg Prod.snd (Option.some.inj hEqual)

theorem encodeString_injective_of_admissible
    (left right : String)
    (hLeft : stringWireAdmissible left)
    (hRight : stringWireAdmissible right)
    (hWire : encodeString left = encodeString right) :
    left = right := by
  have hRead :
      readString (encodeString left) =
        readString (encodeString right) :=
    congrArg (fun bytes => readString bytes) hWire
  have hLeftRead :
      readString (encodeString left) = some (left, []) := by
    simpa using (readString_encodeString_append left [] hLeft)
  have hRightRead :
      readString (encodeString right) = some (right, []) := by
    simpa using (readString_encodeString_append right [] hRight)
  rw [hLeftRead, hRightRead] at hRead
  exact congrArg Prod.fst (Option.some.inj hRead)

/-! Fixed-width digest slices are exact, not merely prefixes. -/

theorem readDigest_encodeDigest_append
    (value rest : Bytes)
    (hValue : digestWireAdmissible value) :
    readDigest (encodeDigest value ++ rest) = some (value, rest) := by
  unfold readDigest encodeDigest
  have hLength : value.length ≤ (value ++ rest).length := by simp
  have hLength' : digestBytes ≤ (value ++ rest).length := by
    rw [← hValue]
    exact hLength
  have hTake : (value ++ rest).take digestBytes = value := by
    rw [← hValue]
    exact List.take_append_length
  have hDrop : (value ++ rest).drop digestBytes = rest := by
    rw [← hValue]
    exact List.drop_append_length
  have hTotalLength : digestBytes ≤ value.length + rest.length := by
    simpa only [List.length_append] using hLength'
  simp [List.length_append, hTotalLength, hTake, hDrop]

theorem readDigest_rejects_nonempty_tail
    (value tail : Bytes)
    (hValue : digestWireAdmissible value)
    (hTail : tail ≠ []) :
    readDigest (encodeDigest value ++ tail) ≠ some (value, []) := by
  rw [readDigest_encodeDigest_append value tail hValue]
  intro hEqual
  apply hTail
  exact congrArg Prod.snd (Option.some.inj hEqual)

theorem encodeDigest_injective (left right : Bytes)
    (hWire : encodeDigest left = encodeDigest right) : left = right := by
  exact hWire

/-! Boolean and option tags are explicit one-byte enums. -/

theorem readBool_encodeBool_append (value : Bool) (rest : Bytes) :
    readBool (encodeBool value ++ rest) = some (value, rest) := by
  cases value <;> simp [encodeBool, readBool, readByte]

theorem encodeBool_injective : Function.Injective encodeBool := by
  intro left right hWire
  cases left <;> cases right <;> simp_all [encodeBool]

def optionNatWireAdmissible : Option Nat → Prop
  | none => True
  | some value => value < 256 ^ 8

def optionStringWireAdmissible : Option String → Prop
  | none => True
  | some value => stringWireAdmissible value

theorem readOptionNat_encodeOptionNat_append
    (value : Option Nat) (rest : Bytes)
    (hValue : optionNatWireAdmissible value) :
    readOptionNat (encodeOptionNat value ++ rest) = some (value, rest) := by
  cases value with
  | none =>
      simp [encodeOptionNat, readOptionNat, readByte]
  | some value =>
      have hValue' : value < 256 ^ 8 := by
        simpa [optionNatWireAdmissible] using hValue
      simp [encodeOptionNat, readOptionNat, readByte,
        readNatBE_natBE_append 8 value rest hValue']

theorem readOptionString_encodeOptionString_append
    (value : Option String) (rest : Bytes)
    (hValue : optionStringWireAdmissible value) :
    readOptionString (encodeOptionString value ++ rest) = some (value, rest) := by
  cases value with
  | none =>
      simp [encodeOptionString, readOptionString, readByte]
  | some value =>
      have hValue' : stringWireAdmissible value := by
        simpa [optionStringWireAdmissible] using hValue
      simp [encodeOptionString, readOptionString, readByte,
        readString_encodeString_append value rest hValue']

/-! Enum codecs are proven by their actual constructor/tag tables, including
    the v2 `CANCELLED` tags for Action and Delivery. -/

theorem decodeMode_encodeMode (value : OwnerMode) :
    decodeMode (encodeMode value) = some value := by
  cases value <;> simp [encodeMode, decodeMode]

theorem decodeProvenance_encodeProvenance (value : Provenance) :
    decodeProvenance (encodeProvenance value) = some value := by
  cases value <;> simp [encodeProvenance, decodeProvenance]

theorem decodePackStatus_encodePackStatus (value : PackStatus) :
    decodePackStatus (encodePackStatus value) = some value := by
  cases value <;> simp [encodePackStatus, decodePackStatus]

theorem decodePaymentStatus_encodePaymentStatus (value : PaymentStatus) :
    decodePaymentStatus (encodePaymentStatus value) = some value := by
  cases value <;> simp [encodePaymentStatus, decodePaymentStatus]

theorem decodeClaimStatus_encodeClaimStatus (value : ClaimStatus) :
    decodeClaimStatus (encodeClaimStatus value) = some value := by
  cases value <;> simp [encodeClaimStatus, decodeClaimStatus]

theorem decodeDecision_encodeDecision (value : DeterminationDecision) :
    decodeDecision (encodeDecision value) = some value := by
  cases value <;> simp [encodeDecision, decodeDecision]

theorem decodeCaseStatus_encodeCaseStatus (value : CaseStatus) :
    decodeCaseStatus (encodeCaseStatus value) = some value := by
  cases value <;> simp [encodeCaseStatus, decodeCaseStatus]

theorem decodeVerificationStatus_encodeVerificationStatus (value : VerificationStatus) :
    decodeVerificationStatus (encodeVerificationStatus value) = some value := by
  cases value <;> simp [encodeVerificationStatus, decodeVerificationStatus]

theorem decodeActionStatus_encodeActionStatus (value : ActionStatus) :
    decodeActionStatus (encodeActionStatus value) = some value := by
  cases value <;> simp [encodeActionStatus, decodeActionStatus]

theorem decodeDeliveryStatus_encodeDeliveryStatus (value : DeliveryStatus) :
    decodeDeliveryStatus (encodeDeliveryStatus value) = some value := by
  cases value <;> simp [encodeDeliveryStatus, decodeDeliveryStatus]

/-! List combinators are proved from the parser law of each actual element
    codec.  The membership form is important: bounded financial lists need
    only prove the u64/UTF-8/digest law for values actually present, not for
    every unconstrained host-language value. -/

theorem readMany_flatMap_append_of_mem
    {α : Type}
    (encode : α → Bytes)
    (parse : Bytes → Option (α × Bytes))
    (values : List α) (rest : Bytes)
    (hParse : ∀ value, value ∈ values →
      ∀ tail, parse (encode value ++ tail) = some (value, tail)) :
    readMany parse values.length (values.flatMap encode ++ rest) = some (values, rest) := by
  have go : ∀ (values : List α) (rest : Bytes),
      (∀ value, value ∈ values →
        ∀ tail, parse (encode value ++ tail) = some (value, tail)) →
      readMany parse values.length (values.flatMap encode ++ rest) = some (values, rest) := by
    intro values
    induction values with
    | nil =>
        intro rest hParse
        rfl
    | cons value values ih =>
        intro rest hParse
        have hHead : ∀ tail, parse (encode value ++ tail) = some (value, tail) := by
          intro tail
          exact hParse value (by simp) tail
        have hTail : ∀ next, next ∈ values →
            ∀ tail, parse (encode next ++ tail) = some (next, tail) := by
          intro next hNext tail
          exact hParse next (by simp [hNext]) tail
        simp [List.flatMap_cons, List.append_assoc, readMany, hHead,
          ih rest hTail]
  exact go values rest hParse

theorem readList_encodeList_append_of_mem
    {α : Type}
    (encode : α → Bytes)
    (parse : Bytes → Option (α × Bytes))
    (values : List α) (rest : Bytes)
    (hCount : values.length ≤ maxRows)
    (hWidth : values.length < 256 ^ 2)
    (hParse : ∀ value, value ∈ values →
      ∀ tail, parse (encode value ++ tail) = some (value, tail)) :
    readList parse (encodeList encode values ++ rest) = some (values, rest) := by
  unfold readList encodeList
  simp only [List.append_assoc]
  rw [readNatBE_natBE_append 2 values.length
    (values.flatMap encode ++ rest) hWidth]
  simp [Nat.not_lt.mpr hCount]
  exact readMany_flatMap_append_of_mem encode parse values rest hParse

theorem readList_encodeList_append
    {α : Type}
    (encode : α → Bytes)
    (parse : Bytes → Option (α × Bytes))
    (values : List α) (rest : Bytes)
    (hCount : values.length ≤ maxRows)
    (hWidth : values.length < 256 ^ 2)
    (hParse : ∀ value tail, parse (encode value ++ tail) = some (value, tail)) :
    readList parse (encodeList encode values ++ rest) = some (values, rest) := by
  apply readList_encodeList_append_of_mem encode parse values rest hCount hWidth
  intro value _ tail
  exact hParse value tail

theorem readList_encodeList_rejects_nonempty_tail_of_mem
    {α : Type}
    (encode : α → Bytes)
    (parse : Bytes → Option (α × Bytes))
    (values : List α) (tail : Bytes)
    (hCount : values.length ≤ maxRows)
    (hWidth : values.length < 256 ^ 2)
    (hParse : ∀ value, value ∈ values →
      ∀ rest, parse (encode value ++ rest) = some (value, rest))
    (hTail : tail ≠ []) :
    readList parse (encodeList encode values ++ tail) ≠ some (values, []) := by
  rw [readList_encodeList_append_of_mem encode parse values tail hCount hWidth hParse]
  intro hEqual
  apply hTail
  exact congrArg Prod.snd (Option.some.inj hEqual)

theorem encodeList_injective_of_parse_roundtrip
    {α : Type}
    (encode : α → Bytes)
    (parse : Bytes → Option (α × Bytes))
    (left right : List α)
    (hLeftCount : left.length ≤ maxRows)
    (hRightCount : right.length ≤ maxRows)
    (hParse : ∀ value tail, parse (encode value ++ tail) = some (value, tail))
    (hWire : encodeList encode left = encodeList encode right) :
    left = right := by
  have hLeftWidth : left.length < 256 ^ 2 :=
    Nat.lt_of_le_of_lt hLeftCount maxRows_fits_u16
  have hRightWidth : right.length < 256 ^ 2 :=
    Nat.lt_of_le_of_lt hRightCount maxRows_fits_u16
  have hRead :
      readList parse (encodeList encode left) =
        readList parse (encodeList encode right) :=
    congrArg (fun bytes : Bytes => readList (α := α) parse bytes) hWire
  have hLeftRead :
      readList parse (encodeList encode left) = some (left, []) := by
    simpa using
      (readList_encodeList_append encode parse left [] hLeftCount hLeftWidth hParse)
  have hRightRead :
      readList parse (encodeList encode right) = some (right, []) := by
    simpa using
      (readList_encodeList_append encode parse right [] hRightCount hRightWidth hParse)
  rw [hLeftRead, hRightRead] at hRead
  exact congrArg Prod.fst (Option.some.inj hRead)

theorem readList_encodeString_append
    (values : List String) (rest : Bytes)
    (hCount : values.length ≤ maxRows)
    (hValues : ∀ value, value ∈ values → stringWireAdmissible value) :
    readList readString (encodeList encodeString values ++ rest) = some (values, rest) := by
  apply readList_encodeList_append_of_mem encodeString readString values rest hCount
    (Nat.lt_of_le_of_lt hCount maxRows_fits_u16)
  intro value hValue tail
  exact readString_encodeString_append value tail (hValues value hValue)

theorem encodeStringList_injective_of_admissible
    (left right : List String)
    (hLeftCount : left.length ≤ maxRows)
    (hRightCount : right.length ≤ maxRows)
    (hValues : ∀ value, value ∈ left ∨ value ∈ right → stringWireAdmissible value)
    (hWire : encodeList encodeString left = encodeList encodeString right) :
    left = right := by
  have hLeft : ∀ value, value ∈ left → stringWireAdmissible value := by
    intro value hValue
    exact hValues value (Or.inl hValue)
  have hRight : ∀ value, value ∈ right → stringWireAdmissible value := by
    intro value hValue
    exact hValues value (Or.inr hValue)
  have hRead :
      readList readString (encodeList encodeString left) =
        readList readString (encodeList encodeString right) :=
    congrArg (fun bytes => readList readString bytes) hWire
  have hLeftRead :
      readList readString (encodeList encodeString left) = some (left, []) := by
    simpa using (readList_encodeString_append left [] hLeftCount hLeft)
  have hRightRead :
      readList readString (encodeList encodeString right) = some (right, []) := by
    simpa using (readList_encodeString_append right [] hRightCount hRight)
  rw [hLeftRead, hRightRead] at hRead
  exact congrArg Prod.fst (Option.some.inj hRead)


end BlindLedger.Financial
