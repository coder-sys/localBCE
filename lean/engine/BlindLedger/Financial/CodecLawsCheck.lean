import BlindLedger.Financial.CodecLaws

namespace BlindLedger.Financial

/-! Source-level dependency inspection for the generic v2 codec laws.

    The `#print axioms` commands expose the actual proof constants and their
    dependencies.  The `#check` commands below keep the check target tied to
    theorem constants rather than to a list of status strings or a native
    decision fixture.
 -/

#print axioms BlindLedger.Financial.string_fromUTF8_toUTF8
#print axioms BlindLedger.Financial.readNatBE_natBE_append
#print axioms BlindLedger.Financial.readNatBE_rejects_nonempty_tail
#print axioms BlindLedger.Financial.natBE_injective_of_fits
#print axioms BlindLedger.Financial.readString_encodeString_append
#print axioms BlindLedger.Financial.readString_rejects_nonempty_tail
#print axioms BlindLedger.Financial.encodeString_injective_of_admissible
#print axioms BlindLedger.Financial.readDigest_encodeDigest_append
#print axioms BlindLedger.Financial.readDigest_rejects_nonempty_tail
#print axioms BlindLedger.Financial.readBool_encodeBool_append
#print axioms BlindLedger.Financial.readOptionNat_encodeOptionNat_append
#print axioms BlindLedger.Financial.readOptionString_encodeOptionString_append
#print axioms BlindLedger.Financial.decodeMode_encodeMode
#print axioms BlindLedger.Financial.decodeProvenance_encodeProvenance
#print axioms BlindLedger.Financial.decodePackStatus_encodePackStatus
#print axioms BlindLedger.Financial.decodePaymentStatus_encodePaymentStatus
#print axioms BlindLedger.Financial.decodeClaimStatus_encodeClaimStatus
#print axioms BlindLedger.Financial.decodeDecision_encodeDecision
#print axioms BlindLedger.Financial.decodeCaseStatus_encodeCaseStatus
#print axioms BlindLedger.Financial.decodeVerificationStatus_encodeVerificationStatus
#print axioms BlindLedger.Financial.decodeActionStatus_encodeActionStatus
#print axioms BlindLedger.Financial.decodeDeliveryStatus_encodeDeliveryStatus
#print axioms BlindLedger.Financial.readMany_flatMap_append_of_mem
#print axioms BlindLedger.Financial.readList_encodeList_append_of_mem
#print axioms BlindLedger.Financial.readList_encodeList_rejects_nonempty_tail_of_mem
#print axioms BlindLedger.Financial.encodeList_injective_of_parse_roundtrip
#print axioms BlindLedger.Financial.readList_encodeString_append
#print axioms BlindLedger.Financial.encodeStringList_injective_of_admissible
#print axioms BlindLedger.Financial.readMagic_rejects_nonprefix
#print axioms BlindLedger.Financial.readResultMagic_rejects_nonprefix
#print axioms BlindLedger.Financial.readMagic_accepts_prefix
#print axioms BlindLedger.Financial.readResultMagic_accepts_prefix
#print axioms BlindLedger.Financial.rawEncodeFinancialInput_eq_magic_append
#print axioms BlindLedger.Financial.decodeFinancialInput_of_parsed
#print axioms BlindLedger.Financial.parseFinancialInput_rawEncode_append
#print axioms BlindLedger.Financial.decodeContext_encodeContext_append
#print axioms BlindLedger.Financial.decodeAuthorityActor_encodeAuthorityActor_append
#print axioms BlindLedger.Financial.decodeAuthority_encodeAuthority_append
#print axioms BlindLedger.Financial.decodeControlPack_encodeControlPack_append
#print axioms BlindLedger.Financial.decodeObligation_encodeObligation_append
#print axioms BlindLedger.Financial.decodePayment_encodePayment_append
#print axioms BlindLedger.Financial.decodeClaim_encodeClaim_append
#print axioms BlindLedger.Financial.decodeDetermination_encodeDetermination_append
#print axioms BlindLedger.Financial.decodeEvidence_encodeEvidence_append
#print axioms BlindLedger.Financial.decodeConflict_encodeConflict_append
#print axioms BlindLedger.Financial.decodeCase_encodeCase_append
#print axioms BlindLedger.Financial.decodeAction_encodeAction_append
#print axioms BlindLedger.Financial.encodeFinancialInput_rawEncode
#print axioms BlindLedger.Financial.decodeFinancialInput_rawEncode
#print axioms BlindLedger.Financial.decodeFinancialInput_rawEncode_rejects_nonempty_tail
#print axioms BlindLedger.Financial.encodeFinancialResult_rawEncode
#print axioms BlindLedger.Financial.rawEncodeFinancialResult_eq_magic_append
#print axioms BlindLedger.Financial.decodeFinancialResult_of_parsed
#print axioms BlindLedger.Financial.parseFinancialResult_rawEncode_append
#print axioms BlindLedger.Financial.decodeFinancialResult_rawEncode
#print axioms BlindLedger.Financial.decodeFinancialResult_rawEncode_rejects_nonempty_tail
#print axioms BlindLedger.Financial.decodeFinancialInput_of_encodeFinancialInput
#print axioms BlindLedger.Financial.decodeFinancialResult_of_encodeFinancialResult
#print axioms BlindLedger.Financial.rawEncodeFinancialInput_injective_of_admissible
#print axioms BlindLedger.Financial.rawEncodeFinancialResult_injective_of_admissible
#print axioms BlindLedger.Financial.encodeFinancialInput_injective_of_admissible
#print axioms BlindLedger.Financial.encodeFinancialResult_injective_of_admissible

#check BlindLedger.Financial.readNatBE_natBE_append
#check BlindLedger.Financial.readNatBE_rejects_nonempty_tail
#check BlindLedger.Financial.natBE_injective_of_fits
#check BlindLedger.Financial.readString_encodeString_append
#check BlindLedger.Financial.readDigest_encodeDigest_append
#check BlindLedger.Financial.encodeDigest_injective
#check BlindLedger.Financial.encodeBool_injective
#check BlindLedger.Financial.decodeActionStatus_encodeActionStatus
#check BlindLedger.Financial.decodeDeliveryStatus_encodeDeliveryStatus
#check BlindLedger.Financial.readList_encodeList_append_of_mem
#check BlindLedger.Financial.readList_encodeList_rejects_nonempty_tail_of_mem
#check BlindLedger.Financial.encodeList_injective_of_parse_roundtrip
#check BlindLedger.Financial.readMagic_rejects_nonprefix
#check BlindLedger.Financial.readResultMagic_rejects_nonprefix
#check BlindLedger.Financial.readMagic_accepts_prefix
#check BlindLedger.Financial.readResultMagic_accepts_prefix
#check BlindLedger.Financial.rawEncodeFinancialInput_eq_magic_append
#check BlindLedger.Financial.decodeFinancialInput_of_parsed
#check BlindLedger.Financial.parseFinancialInput_rawEncode_append
#check BlindLedger.Financial.decodeContext_encodeContext_append
#check BlindLedger.Financial.decodeAuthorityActor_encodeAuthorityActor_append
#check BlindLedger.Financial.decodeAuthority_encodeAuthority_append
#check BlindLedger.Financial.decodeControlPack_encodeControlPack_append
#check BlindLedger.Financial.decodeObligation_encodeObligation_append
#check BlindLedger.Financial.decodePayment_encodePayment_append
#check BlindLedger.Financial.decodeClaim_encodeClaim_append
#check BlindLedger.Financial.decodeDetermination_encodeDetermination_append
#check BlindLedger.Financial.decodeEvidence_encodeEvidence_append
#check BlindLedger.Financial.decodeConflict_encodeConflict_append
#check BlindLedger.Financial.decodeCase_encodeCase_append
#check BlindLedger.Financial.decodeAction_encodeAction_append
#check BlindLedger.Financial.encodeFinancialInput_rawEncode
#check BlindLedger.Financial.decodeFinancialInput_of_parsed
#check BlindLedger.Financial.parseFinancialInput_rawEncode_append
#check BlindLedger.Financial.decodeFinancialInput_rawEncode
#check BlindLedger.Financial.decodeFinancialInput_rawEncode_rejects_nonempty_tail
#check BlindLedger.Financial.encodeFinancialResult_rawEncode
#check BlindLedger.Financial.rawEncodeFinancialResult_eq_magic_append
#check BlindLedger.Financial.decodeFinancialResult_of_parsed
#check BlindLedger.Financial.parseFinancialResult_rawEncode_append
#check BlindLedger.Financial.decodeFinancialResult_rawEncode
#check BlindLedger.Financial.decodeFinancialResult_rawEncode_rejects_nonempty_tail
#check BlindLedger.Financial.decodeFinancialInput_of_encodeFinancialInput
#check BlindLedger.Financial.decodeFinancialResult_of_encodeFinancialResult
#check BlindLedger.Financial.rawEncodeFinancialInput_injective_of_admissible
#check BlindLedger.Financial.rawEncodeFinancialResult_injective_of_admissible
#check BlindLedger.Financial.encodeFinancialInput_injective_of_admissible
#check BlindLedger.Financial.encodeFinancialResult_injective_of_admissible

theorem codecLawsProofManifest :
    (∀ (width value : Nat) (rest : Bytes),
      value < 256 ^ width →
        readNatBE width (natBE width value ++ rest) = some (value, rest)) ∧
    (∀ (value : String) (rest : Bytes),
      stringWireAdmissible value →
        readString (encodeString value ++ rest) = some (value, rest)) ∧
    (∀ (value rest : Bytes),
      digestWireAdmissible value →
        readDigest (encodeDigest value ++ rest) = some (value, rest)) := by
  exact ⟨readNatBE_natBE_append, readString_encodeString_append,
    readDigest_encodeDigest_append⟩

theorem codecLawsNoTrailingManifest :
    (∀ (width value : Nat) (tail : Bytes),
      value < 256 ^ width → tail ≠ [] →
        readNatBE width (natBE width value ++ tail) ≠ some (value, [])) ∧
    (∀ (value : String) (tail : Bytes),
      stringWireAdmissible value → tail ≠ [] →
        readString (encodeString value ++ tail) ≠ some (value, [])) ∧
    (∀ (value tail : Bytes),
      digestWireAdmissible value → tail ≠ [] →
        readDigest (encodeDigest value ++ tail) ≠ some (value, [])) := by
  exact ⟨readNatBE_rejects_nonempty_tail, readString_rejects_nonempty_tail,
    readDigest_rejects_nonempty_tail⟩

theorem codecLawsWholeWireManifest :
    (∀ input, financialInputWireAdmissible input →
      encodeFinancialInput input = some (rawEncodeFinancialInput input)) ∧
    (∀ input, financialInputWireAdmissible input →
      decodeFinancialInput (rawEncodeFinancialInput input) = some input) ∧
    (∀ input tail, financialInputWireAdmissible input → tail ≠ [] →
      decodeFinancialInput (rawEncodeFinancialInput input ++ tail) = none) ∧
    (∀ result, financialResultWireAdmissible result →
      encodeFinancialResult result = some (rawEncodeFinancialResult result)) ∧
    (∀ result, financialResultWireAdmissible result →
      decodeFinancialResult (rawEncodeFinancialResult result) = some result) ∧
    (∀ result tail, financialResultWireAdmissible result → tail ≠ [] →
      decodeFinancialResult (rawEncodeFinancialResult result ++ tail) = none) ∧
    (∀ left right, financialInputWireAdmissible left →
      financialInputWireAdmissible right →
      rawEncodeFinancialInput left = rawEncodeFinancialInput right → left = right) ∧
    (∀ left right, financialResultWireAdmissible left →
      financialResultWireAdmissible right →
      rawEncodeFinancialResult left = rawEncodeFinancialResult right → left = right) := by
  exact ⟨encodeFinancialInput_rawEncode, decodeFinancialInput_rawEncode,
    decodeFinancialInput_rawEncode_rejects_nonempty_tail,
    encodeFinancialResult_rawEncode, decodeFinancialResult_rawEncode,
    decodeFinancialResult_rawEncode_rejects_nonempty_tail,
    rawEncodeFinancialInput_injective_of_admissible,
    rawEncodeFinancialResult_injective_of_admissible⟩

#print axioms codecLawsProofManifest
#print axioms codecLawsNoTrailingManifest
#print axioms codecLawsWholeWireManifest
#check codecLawsProofManifest
#check codecLawsNoTrailingManifest
#check codecLawsWholeWireManifest

end BlindLedger.Financial
