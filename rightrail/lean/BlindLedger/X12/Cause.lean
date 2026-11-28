/-! The one place that names every unit, repair, cause and detail sentence of the X12 reader.  Events carry a cause by
    its number (`causeNumbers`), not by its name. -/

namespace BlindLedger.X12

/-- The smallest unit that holds a fault. -/
inductive Level | file | interchange | group | set | loop | segment
  deriving DecidableEq

def Level.name : Level → String
  | .file => "file" | .interchange => "interchange" | .group => "group" | .set => "set" | .loop => "loop" | .segment => "segment"

/-- The lossless repairs, counted by rule. -/
inductive Rule | bom | whitespace | badIsaStamp | badUtf8

def Rule.name : Rule → String
  | .bom => "bom" | .whitespace => "whitespace" | .badIsaStamp => "bad_isa_stamp" | .badUtf8 => "bad_utf8"

inductive Cause
  | isaUnframed | noInterchange | ieaMissing | duplicateControl | unterminatedSegment | segmentTooLong | badSegmentId
  | repeatedElement | stOutsideGroup | setUnclosed | seControlMismatch | seCountMismatch | badSt | badFileDatetime
  | groupUnclosed | geWithoutGs | geControlMismatch | geCountMismatch | ieaControlMismatch | ieaCountMismatch
  | segmentOutsideSet | seWithoutSt | not834 | not837 | not835 | not820
  -- retired: nothing emits it; it keeps its number so that no later cause moves
  | retiredUnitTooLarge
  -- the 837, 835 and 834 readers
  | headerWithoutHl | unknownSegment | badHl | repeatedSegment | noClaimId | badTotalCharge | noFrequencyCode
  | noRenderingNpi | badLineCharge | badUnits | noRevenueCode | badDate | badServiceDate | noSvSegment | noServiceLines
  | noBillingNpi | noSubscriber | missingOriginalRef | totalUnchecked | totalMismatch
  | headerLate | badClp | badSvc | badPlb | badCas | casWithoutTarget | badAmount | noPaymentHeader
  | badIns | badDeathDate | repeatedLoop | emptyMemberId | memberIdConflict | noMemberId | unreadSegment
  deriving DecidableEq

def Cause.name : Cause → String
  | .isaUnframed => "isa_unframed" | .noInterchange => "no_interchange" | .ieaMissing => "iea_missing"
  | .duplicateControl => "duplicate_control" | .unterminatedSegment => "unterminated_segment"
  | .segmentTooLong => "segment_too_long" | .badSegmentId => "bad_segment_id" | .repeatedElement => "repeated_element"
  | .stOutsideGroup => "st_outside_group" | .setUnclosed => "set_unclosed" | .seControlMismatch => "se_control_mismatch"
  | .seCountMismatch => "se_count_mismatch" | .badSt => "bad_st" | .badFileDatetime => "bad_file_datetime"
  | .groupUnclosed => "group_unclosed" | .geWithoutGs => "ge_without_gs" | .geControlMismatch => "ge_control_mismatch"
  | .geCountMismatch => "ge_count_mismatch" | .ieaControlMismatch => "iea_control_mismatch"
  | .ieaCountMismatch => "iea_count_mismatch" | .segmentOutsideSet => "segment_outside_set" | .seWithoutSt => "se_without_st"
  | .not834 => "not_834" | .not837 => "not_837" | .not835 => "not_835" | .not820 => "not_820"
  | .retiredUnitTooLarge => "unit_too_large"
  | .headerWithoutHl => "header_without_hl" | .unknownSegment => "unknown_segment" | .badHl => "bad_hl"
  | .repeatedSegment => "repeated_segment" | .noClaimId => "no_claim_id" | .badTotalCharge => "bad_total_charge"
  | .noFrequencyCode => "no_frequency_code" | .noRenderingNpi => "no_rendering_npi" | .badLineCharge => "bad_line_charge"
  | .badUnits => "bad_units" | .noRevenueCode => "no_revenue_code" | .badDate => "bad_date"
  | .badServiceDate => "bad_service_date" | .noSvSegment => "no_sv_segment" | .noServiceLines => "no_service_lines"
  | .noBillingNpi => "no_billing_npi" | .noSubscriber => "no_subscriber" | .missingOriginalRef => "missing_original_ref"
  | .totalUnchecked => "total_unchecked" | .totalMismatch => "total_mismatch"
  | .headerLate => "header_late" | .badClp => "bad_clp" | .badSvc => "bad_svc" | .badPlb => "bad_plb" | .badCas => "bad_cas"
  | .casWithoutTarget => "cas_without_target" | .badAmount => "bad_amount" | .noPaymentHeader => "no_payment_header"
  | .badIns => "bad_ins" | .badDeathDate => "bad_death_date" | .repeatedLoop => "repeated_loop"
  | .emptyMemberId => "empty_member_id" | .memberIdConflict => "member_id_conflict" | .noMemberId => "no_member_id"
  | .unreadSegment => "unread_segment"

/-- Every cause with the number events carry for it (its constructor index).  A number is never given to another cause:
    a cause that is no longer emitted keeps its slot, and a new cause goes at the end. -/
def causeNumbers : List (Cause × Nat) := [
    (.isaUnframed, 0), (.noInterchange, 1), (.ieaMissing, 2), (.duplicateControl, 3), (.unterminatedSegment, 4),
    (.segmentTooLong, 5), (.badSegmentId, 6), (.repeatedElement, 7), (.stOutsideGroup, 8), (.setUnclosed, 9),
    (.seControlMismatch, 10), (.seCountMismatch, 11), (.badSt, 12), (.badFileDatetime, 13), (.groupUnclosed, 14),
    (.geWithoutGs, 15), (.geControlMismatch, 16), (.geCountMismatch, 17), (.ieaControlMismatch, 18),
    (.ieaCountMismatch, 19), (.segmentOutsideSet, 20), (.seWithoutSt, 21), (.not834, 22), (.not837, 23),
    (.not835, 24), (.not820, 25), (.retiredUnitTooLarge, 26), (.headerWithoutHl, 27), (.unknownSegment, 28),
    (.badHl, 29),
    (.repeatedSegment, 30), (.noClaimId, 31), (.badTotalCharge, 32), (.noFrequencyCode, 33), (.noRenderingNpi, 34),
    (.badLineCharge, 35), (.badUnits, 36), (.noRevenueCode, 37), (.badDate, 38), (.badServiceDate, 39),
    (.noSvSegment, 40), (.noServiceLines, 41), (.noBillingNpi, 42), (.noSubscriber, 43), (.missingOriginalRef, 44),
    (.totalUnchecked, 45), (.totalMismatch, 46), (.headerLate, 47), (.badClp, 48), (.badSvc, 49), (.badPlb, 50),
    (.badCas, 51), (.casWithoutTarget, 52), (.badAmount, 53), (.noPaymentHeader, 54), (.badIns, 55),
    (.badDeathDate, 56), (.repeatedLoop, 57), (.emptyMemberId, 58), (.memberIdConflict, 59), (.noMemberId, 60),
    (.unreadSegment, 61)]

theorem causeNumbers_pinned : causeNumbers.all (fun p => p.1.ctorIdx == p.2) = true := by decide
/-- A set-aside's detail is a sentence with up to two blanks, `{a}` and `{b}`; each blank is a range word. -/
inductive Form
  | none | text | restOfFile | noTerm | nextStBeforeSe | fileEndsBeforeSe | geBeforeSe | nextGsBeforeGe | ieaBeforeGe
  | fileEndsBeforeGe | gs0405 | gs06
  -- the 837, 835 and 834 readers
  | hlParts | nm182 | refF8 | ref6r | dtp472 | dtm472 | totals837 | totals835 | insDetail | insDates | idConflict | nameLoop
  | dtpOutside | in835 | bpr16 | bpr02 | kept835 | keyed | emptyId | serviceLost | adjustmentLost

def Form.template : Form → String
  | .none => "" | .text => "{a}" | .restOfFile => "rest of file after the last good interchange"
  | .noTerm => "last segment has no terminator" | .nextStBeforeSe => "next ST before SE"
  | .fileEndsBeforeSe => "file ends before SE" | .geBeforeSe => "GE before SE" | .nextGsBeforeGe => "next GS before GE"
  | .ieaBeforeGe => "IEA before GE" | .fileEndsBeforeGe => "file ends before GE" | .gs0405 => "GS04/GS05" | .gs06 => "GS06"
  | .hlParts => "HL01, HL02 or HL03" | .nm182 => "NM1*82" | .refF8 => "REF*F8" | .ref6r => "REF*6R" | .dtp472 => "DTP*472"
  | .dtm472 => "DTM*472" | .totals837 => "CLM02={a} lines={b}" | .totals835 => "BPR02={a} claims={b} plb={c}"
  | .insDetail => "INS01 or INS03 missing or invalid" | .insDates => "INS11/INS12"
  | .idConflict => "NM1 and REF*0F name different members" | .nameLoop => "{a} in the member name loop"
  | .dtpOutside => "DTP*{a} outside its loop" | .in835 => "835 {a}" | .bpr16 => "BPR16" | .bpr02 => "BPR02"
  | .kept835 => "{a} claims kept without BPR or TRN02" | .keyed => "{a} {b}"
  | .emptyId => "no REF*0F and no NM1 member identifier" | .serviceLost => "a service line was quarantined"
  | .adjustmentLost => "a claim or provider adjustment was quarantined"

end BlindLedger.X12
