import BlindLedger.Financial.Codec
import BlindLedger.Financial.CodecLaws.Records

/-! Stable import surface for the complete bounded v2 financial codec-law suite.
    Primitive and record parser laws are compiled in dependency order before the
    whole-wire input/result theorems declared here. -/

namespace BlindLedger.Financial
theorem rawEncodeFinancialInput_eq_magic_append (input : FinancialInput) :
    rawEncodeFinancialInput input =
      financialCodecMagic ++
        (encodeContext input.context ++ encodeAuthority input.authority ++
          encodeControlPack input.pack ++ encodeObligation input.obligation ++
          natBE 8 input.beforeRevision ++ natBE 8 input.evaluatedAt ++
          encodeList encodePayment input.payments ++
          encodeList encodeClaim input.claims ++
          encodeList encodeDetermination input.determinations ++
          encodeList encodeEvidence input.evidence ++
          encodeList encodeConflict input.conflicts ++
          encodeList encodeCase input.cases ++
          encodeList encodeAction input.actions) := by
  simp [rawEncodeFinancialInput, List.append_assoc]

theorem encodeFinancialInput_rawEncode
    (input : FinancialInput)
    (hInput : financialInputWireAdmissible input) :
    encodeFinancialInput input = some (rawEncodeFinancialInput input) := by
  rcases hInput with
    ⟨hWellFormed, hContext, hAuthority, hPack, hObligation, hBeforeRevision,
      hEvaluatedAt, hPayments, hClaims, hDeterminations, hEvidence, hConflicts,
      hCases, hActions, hRawSize⟩
  simp [encodeFinancialInput, hWellFormed, hRawSize]

theorem decodeFinancialInput_of_parsed
    (bytes : Bytes) (input : FinancialInput) (remaining : Bytes)
    (hSize : bytes.length ≤ maxTotalEncodedBytes)
    (hParsed : ∀ {α : Type} (finish : FinancialInput → Bytes → Option α),
      (do
        let rest ← readMagic bytes
        let (context, rest) ← decodeContext rest
        let (authority, rest) ← decodeAuthority rest
        let (pack, rest) ← decodeControlPack rest
        let (obligation, rest) ← decodeObligation rest
        let (beforeRevision, rest) ← readNatBE 8 rest
        let (evaluatedAt, rest) ← readNatBE 8 rest
        let (payments, rest) ← readList decodePayment rest
        let (claims, rest) ← readList decodeClaim rest
        let (determinations, rest) ← readList decodeDetermination rest
        let (evidence, rest) ← readList decodeEvidence rest
        let (conflicts, rest) ← readList decodeConflict rest
        let (cases, rest) ← readList decodeCase rest
        let (actions, rest) ← readList decodeAction rest
        finish
          { context := context
            authority := authority
            pack := pack
            obligation := obligation
            beforeRevision := beforeRevision
            evaluatedAt := evaluatedAt
            payments := payments
            claims := claims
            determinations := determinations
            evidence := evidence
            conflicts := conflicts
            cases := cases
            actions := actions }
          rest) = finish input remaining)
    (hFinal : remaining = [] →
      financialInputWellFormed input = true ∧
        encodeFinancialInput input = some bytes) :
    decodeFinancialInput bytes =
      if remaining = [] then some input else none := by
  have hSize' : ¬ bytes.length > maxTotalEncodedBytes := Nat.not_lt.mpr hSize
  let finish : FinancialInput → Bytes → Option FinancialInput := fun candidate rest =>
    if rest.isEmpty then
      if financialInputWellFormed candidate then
        match encodeFinancialInput candidate with
        | some canonical => if canonical = bytes then some candidate else none
        | none => none
      else none
    else none
  have hDone := hParsed (α := FinancialInput) finish
  by_cases hRemaining : remaining = []
  · subst remaining
    rcases hFinal rfl with ⟨hWellFormed, hCanonical⟩
    unfold decodeFinancialInput
    simp only [if_neg hSize']
    change (do
      let rest ← readMagic bytes
      let (context, rest) ← decodeContext rest
      let (authority, rest) ← decodeAuthority rest
      let (pack, rest) ← decodeControlPack rest
      let (obligation, rest) ← decodeObligation rest
      let (beforeRevision, rest) ← readNatBE 8 rest
      let (evaluatedAt, rest) ← readNatBE 8 rest
      let (payments, rest) ← readList decodePayment rest
      let (claims, rest) ← readList decodeClaim rest
      let (determinations, rest) ← readList decodeDetermination rest
      let (evidence, rest) ← readList decodeEvidence rest
      let (conflicts, rest) ← readList decodeConflict rest
      let (cases, rest) ← readList decodeCase rest
      let (actions, rest) ← readList decodeAction rest
      finish
        { context := context
          authority := authority
          pack := pack
          obligation := obligation
          beforeRevision := beforeRevision
          evaluatedAt := evaluatedAt
          payments := payments
          claims := claims
          determinations := determinations
          evidence := evidence
          conflicts := conflicts
          cases := cases
          actions := actions }
        rest) = some input
    rw [hDone]
    simp [finish, hWellFormed, hCanonical]
  · unfold decodeFinancialInput
    simp only [if_neg hSize']
    cases remaining with
    | nil => contradiction
    | cons head tail =>
        change (do
          let rest ← readMagic bytes
          let (context, rest) ← decodeContext rest
          let (authority, rest) ← decodeAuthority rest
          let (pack, rest) ← decodeControlPack rest
          let (obligation, rest) ← decodeObligation rest
          let (beforeRevision, rest) ← readNatBE 8 rest
          let (evaluatedAt, rest) ← readNatBE 8 rest
          let (payments, rest) ← readList decodePayment rest
          let (claims, rest) ← readList decodeClaim rest
          let (determinations, rest) ← readList decodeDetermination rest
          let (evidence, rest) ← readList decodeEvidence rest
          let (conflicts, rest) ← readList decodeConflict rest
          let (cases, rest) ← readList decodeCase rest
          let (actions, rest) ← readList decodeAction rest
          finish
            { context := context
              authority := authority
              pack := pack
              obligation := obligation
              beforeRevision := beforeRevision
              evaluatedAt := evaluatedAt
              payments := payments
              claims := claims
              determinations := determinations
              evidence := evidence
              conflicts := conflicts
              cases := cases
              actions := actions }
            rest) = none
        rw [hDone]
        simp [finish]

theorem parseFinancialInput_rawEncode_append
    (input : FinancialInput) (tail : Bytes)
    (hInput : financialInputWireAdmissible input) :
    ∀ {α : Type} (finish : FinancialInput → Bytes → Option α),
      (do
        let rest ← readMagic (rawEncodeFinancialInput input ++ tail)
        let (context, rest) ← decodeContext rest
        let (authority, rest) ← decodeAuthority rest
        let (pack, rest) ← decodeControlPack rest
        let (obligation, rest) ← decodeObligation rest
        let (beforeRevision, rest) ← readNatBE 8 rest
        let (evaluatedAt, rest) ← readNatBE 8 rest
        let (payments, rest) ← readList decodePayment rest
        let (claims, rest) ← readList decodeClaim rest
        let (determinations, rest) ← readList decodeDetermination rest
        let (evidence, rest) ← readList decodeEvidence rest
        let (conflicts, rest) ← readList decodeConflict rest
        let (cases, rest) ← readList decodeCase rest
        let (actions, rest) ← readList decodeAction rest
        finish
          { context := context
            authority := authority
            pack := pack
            obligation := obligation
            beforeRevision := beforeRevision
            evaluatedAt := evaluatedAt
            payments := payments
            claims := claims
            determinations := determinations
            evidence := evidence
            conflicts := conflicts
            cases := cases
            actions := actions }
          rest) = finish input tail := by
  rcases hInput with
    ⟨_, hContext, hAuthority, hPack, hObligation, hBeforeRevision,
      hEvaluatedAt, hPayments, hClaims, hDeterminations, hEvidence, hConflicts,
      hCases, hActions, _⟩
  rcases hPayments with ⟨hPaymentsCount, hPayment⟩
  rcases hClaims with ⟨hClaimsCount, hClaim⟩
  rcases hDeterminations with ⟨hDeterminationsCount, hDetermination⟩
  rcases hEvidence with ⟨hEvidenceCount, hEvidenceRecord⟩
  rcases hConflicts with ⟨hConflictsCount, hConflict⟩
  rcases hCases with ⟨hCasesCount, hCaseRecord⟩
  rcases hActions with ⟨hActionsCount, hAction⟩
  have hMagicRead :
      readMagic (rawEncodeFinancialInput input ++ tail) =
        some ((encodeContext input.context ++ encodeAuthority input.authority ++
          encodeControlPack input.pack ++ encodeObligation input.obligation ++
          natBE 8 input.beforeRevision ++ natBE 8 input.evaluatedAt ++
          encodeList encodePayment input.payments ++
          encodeList encodeClaim input.claims ++
          encodeList encodeDetermination input.determinations ++
          encodeList encodeEvidence input.evidence ++
          encodeList encodeConflict input.conflicts ++
          encodeList encodeCase input.cases ++
          encodeList encodeAction input.actions) ++ tail) := by
    rw [rawEncodeFinancialInput_eq_magic_append, List.append_assoc]
    exact readMagic_accepts_prefix _
  have hContextRead : ∀ next : Bytes,
      decodeContext (encodeContext input.context ++ next) =
        some (input.context, next) := by
    intro next
    exact decodeContext_encodeContext_append input.context next hContext
  have hAuthorityRead : ∀ next : Bytes,
      decodeAuthority (encodeAuthority input.authority ++ next) =
        some (input.authority, next) := by
    intro next
    exact decodeAuthority_encodeAuthority_append input.authority next hAuthority
  have hPackRead : ∀ next : Bytes,
      decodeControlPack (encodeControlPack input.pack ++ next) =
        some (input.pack, next) := by
    intro next
    exact decodeControlPack_encodeControlPack_append input.pack next hPack
  have hObligationRead : ∀ next : Bytes,
      decodeObligation (encodeObligation input.obligation ++ next) =
        some (input.obligation, next) := by
    intro next
    exact decodeObligation_encodeObligation_append input.obligation next hObligation
  have hPaymentsRead : ∀ next : Bytes,
      readList decodePayment (encodeList encodePayment input.payments ++ next) =
        some (input.payments, next) := by
    intro next
    apply readList_encodeList_append_of_mem encodePayment decodePayment
      input.payments next hPaymentsCount.1 hPaymentsCount.2
    intro value hMem rest
    exact decodePayment_encodePayment_append value rest (hPayment value hMem)
  have hClaimsRead : ∀ next : Bytes,
      readList decodeClaim (encodeList encodeClaim input.claims ++ next) =
        some (input.claims, next) := by
    intro next
    apply readList_encodeList_append_of_mem encodeClaim decodeClaim
      input.claims next hClaimsCount.1 hClaimsCount.2
    intro value hMem rest
    exact decodeClaim_encodeClaim_append value rest (hClaim value hMem)
  have hDeterminationsRead : ∀ next : Bytes,
      readList decodeDetermination
          (encodeList encodeDetermination input.determinations ++ next) =
        some (input.determinations, next) := by
    intro next
    apply readList_encodeList_append_of_mem encodeDetermination decodeDetermination
      input.determinations next hDeterminationsCount.1 hDeterminationsCount.2
    intro value hMem rest
    exact decodeDetermination_encodeDetermination_append value rest
      (hDetermination value hMem)
  have hEvidenceRead : ∀ next : Bytes,
      readList decodeEvidence (encodeList encodeEvidence input.evidence ++ next) =
        some (input.evidence, next) := by
    intro next
    apply readList_encodeList_append_of_mem encodeEvidence decodeEvidence
      input.evidence next hEvidenceCount.1 hEvidenceCount.2
    intro value hMem rest
    exact decodeEvidence_encodeEvidence_append value rest
      (hEvidenceRecord value hMem)
  have hConflictsRead : ∀ next : Bytes,
      readList decodeConflict
          (encodeList encodeConflict input.conflicts ++ next) =
        some (input.conflicts, next) := by
    intro next
    apply readList_encodeList_append_of_mem encodeConflict decodeConflict
      input.conflicts next hConflictsCount.1 hConflictsCount.2
    intro value hMem rest
    exact decodeConflict_encodeConflict_append value rest
      (hConflict value hMem)
  have hCasesRead : ∀ next : Bytes,
      readList decodeCase (encodeList encodeCase input.cases ++ next) =
        some (input.cases, next) := by
    intro next
    apply readList_encodeList_append_of_mem encodeCase decodeCase
      input.cases next hCasesCount.1 hCasesCount.2
    intro value hMem rest
    exact decodeCase_encodeCase_append value rest (hCaseRecord value hMem)
  have hActionsRead : ∀ next : Bytes,
      readList decodeAction (encodeList encodeAction input.actions ++ next) =
        some (input.actions, next) := by
    intro next
    apply readList_encodeList_append_of_mem encodeAction decodeAction
      input.actions next hActionsCount.1 hActionsCount.2
    intro value hMem rest
    exact decodeAction_encodeAction_append value rest (hAction value hMem)
  intro α finish
  simp only [hMagicRead, Option.bind_eq_bind, Option.bind_some,
    hContextRead, hAuthorityRead,
    hPackRead, hObligationRead, readNat8_natBE_append _ _ hBeforeRevision,
    readNat8_natBE_append _ _ hEvaluatedAt, hPaymentsRead, hClaimsRead,
    hDeterminationsRead, hEvidenceRead, hConflictsRead, hCasesRead,
    hActionsRead, List.append_assoc]

theorem decodeFinancialInput_rawEncode
    (input : FinancialInput)
    (hInput : financialInputWireAdmissible input) :
     decodeFinancialInput (rawEncodeFinancialInput input) = some input := by
  have hCanonical := encodeFinancialInput_rawEncode input hInput
  have hInput' := hInput
  rcases hInput with
    ⟨hWellFormed, hContext, hAuthority, hPack, hObligation, hBeforeRevision,
      hEvaluatedAt, hPayments, hClaims, hDeterminations, hEvidence, hConflicts,
      hCases, hActions, hRawSize⟩
  have hDecoded := decodeFinancialInput_of_parsed
    (rawEncodeFinancialInput input) input [] hRawSize
    (by
      intro α finish
      simpa only [List.append_nil] using
        parseFinancialInput_rawEncode_append input [] hInput' finish)
    (by intro _; exact ⟨hWellFormed, hCanonical⟩)
  simpa using hDecoded

theorem decodeFinancialInput_rawEncode_rejects_nonempty_tail
    (input : FinancialInput) (tail : Bytes)
    (hInput : financialInputWireAdmissible input)
    (hTail : tail ≠ []) :
    decodeFinancialInput (rawEncodeFinancialInput input ++ tail) = none := by
  cases tail with
  | nil => exact (hTail rfl).elim
  | cons head tail =>
      by_cases hTooLarge :
          (rawEncodeFinancialInput input ++ head :: tail).length >
            maxTotalEncodedBytes
      · simp only [decodeFinancialInput, hTooLarge, if_true]
      · have hSize :
            (rawEncodeFinancialInput input ++ head :: tail).length ≤
              maxTotalEncodedBytes := Nat.le_of_not_gt hTooLarge
        have hDecoded := decodeFinancialInput_of_parsed
          (rawEncodeFinancialInput input ++ head :: tail) input (head :: tail)
          hSize
          (by
            intro α finish
            exact parseFinancialInput_rawEncode_append input
              (head :: tail) hInput finish)
          (by
            intro hEmpty
            exact (List.cons_ne_nil head tail hEmpty).elim)
        simpa using hDecoded

theorem encodeFinancialResult_rawEncode
    (result : FinancialResult)
    (hResult : financialResultWireAdmissible result) :
    encodeFinancialResult result = some (rawEncodeFinancialResult result) := by
  rcases hResult with
    ⟨hWellFormed, hContext, hAuthorityId, hAuthorityEpoch, hAuthorityDigest,
      hPackId, hPackDigest, hBeforeRevision, hAfterRevision, hEvaluatedAt,
      hRuleVersion, hEvidenceIds, hCompletionAt, hOwedCents,
      hClaimedAdjustmentCents, hLawfulAdjustmentCents, hReceivedCashCents,
      hShortfallCents, hOverageCents, hRawSize⟩
  simp [encodeFinancialResult, hWellFormed, hRawSize]

theorem rawEncodeFinancialResult_eq_magic_append
    (result : FinancialResult) :
    rawEncodeFinancialResult result =
      financialResultCodecMagic ++ encodeContext result.context ++
        encodeString result.authorityId ++ natBE 8 result.authorityEpoch ++
        encodeDigest result.authorityDigest ++ encodeString result.packId ++
        encodeDigest result.packDigest ++ natBE 8 result.beforeRevision ++
        natBE 8 result.afterRevision ++ natBE 8 result.evaluatedAt ++
        natBE 8 result.ruleVersion ++ encodeList encodeString result.evidenceIds ++
        encodeOptionNat result.completionAt ++ natBE 8 result.owedCents ++
        natBE 8 result.claimedAdjustmentCents ++ natBE 8 result.lawfulAdjustmentCents ++
        natBE 8 result.receivedCashCents ++ natBE 8 result.shortfallCents ++
        natBE 8 result.overageCents ++ encodeBool result.cashSatisfied ++
        encodeBool result.amountSatisfied ++ encodeBool result.timely ++
        encodeBool result.reportingComplete ++
        [encodeVerificationStatus result.verificationStatus,
          encodeCaseStatus result.caseStatus, encodeDeliveryStatus result.deliveryStatus] := by
  rfl

theorem decodeFinancialResult_of_parsed
    (bytes : Bytes) (result : FinancialResult) (remaining : Bytes)
    (hSize : bytes.length ≤ maxTotalEncodedBytes)
    (hParsed : ∀ {α : Type} (finish : FinancialResult → Bytes → Option α),
      (do
        let rest ← readResultMagic bytes
        let (context, rest) ← decodeContext rest
        let (authorityId, rest) ← readString rest
        let (authorityEpoch, rest) ← readNatBE 8 rest
        let (authorityDigest, rest) ← readDigest rest
        let (packId, rest) ← readString rest
        let (packDigest, rest) ← readDigest rest
        let (beforeRevision, rest) ← readNatBE 8 rest
        let (afterRevision, rest) ← readNatBE 8 rest
        let (evaluatedAt, rest) ← readNatBE 8 rest
        let (ruleVersion, rest) ← readNatBE 8 rest
        let (evidenceIds, rest) ← readList readString rest
        let (completionAt, rest) ← readOptionNat rest
        let (owedCents, rest) ← readNatBE 8 rest
        let (claimedAdjustmentCents, rest) ← readNatBE 8 rest
        let (lawfulAdjustmentCents, rest) ← readNatBE 8 rest
        let (receivedCashCents, rest) ← readNatBE 8 rest
        let (shortfallCents, rest) ← readNatBE 8 rest
        let (overageCents, rest) ← readNatBE 8 rest
        let (cashSatisfied, rest) ← readBool rest
        let (amountSatisfied, rest) ← readBool rest
        let (timely, rest) ← readBool rest
        let (reportingComplete, rest) ← readBool rest
        let (verificationByte, rest) ← readByte rest
        let verificationStatus ← decodeVerificationStatus verificationByte
        let (caseByte, rest) ← readByte rest
        let caseStatus ← decodeCaseStatus caseByte
        let (deliveryByte, rest) ← readByte rest
        let deliveryStatus ← decodeDeliveryStatus deliveryByte
        finish
          { context := context
            authorityId := authorityId
            authorityEpoch := authorityEpoch
            authorityDigest := authorityDigest
            packId := packId
            packDigest := packDigest
            beforeRevision := beforeRevision
            afterRevision := afterRevision
            evaluatedAt := evaluatedAt
            ruleVersion := ruleVersion
            evidenceIds := evidenceIds
            completionAt := completionAt
            owedCents := owedCents
            claimedAdjustmentCents := claimedAdjustmentCents
            lawfulAdjustmentCents := lawfulAdjustmentCents
            receivedCashCents := receivedCashCents
            shortfallCents := shortfallCents
            overageCents := overageCents
            cashSatisfied := cashSatisfied
            amountSatisfied := amountSatisfied
            timely := timely
            reportingComplete := reportingComplete
            verificationStatus := verificationStatus
            caseStatus := caseStatus
            deliveryStatus := deliveryStatus }
          rest) =
         finish result remaining)
    (hFinal : remaining = [] →
      financialResultWellFormed result = true ∧
        encodeFinancialResult result = some bytes) :
    decodeFinancialResult bytes =
      if remaining = [] then some result else none := by
  have hSize' : ¬ bytes.length > maxTotalEncodedBytes := Nat.not_lt.mpr hSize
  let finish : FinancialResult → Bytes → Option FinancialResult := fun candidate rest =>
    if rest.isEmpty then
      if financialResultWellFormed candidate then
        match encodeFinancialResult candidate with
        | some canonical => if canonical = bytes then some candidate else none
        | none => none
      else none
    else none
  have hDone := hParsed (α := FinancialResult) finish
  by_cases hRemaining : remaining = []
  · subst remaining
    rcases hFinal rfl with ⟨hWellFormed, hCanonical⟩
    unfold decodeFinancialResult
    simp only [if_neg hSize']
    change (do
      let rest ← readResultMagic bytes
      let (context, rest) ← decodeContext rest
      let (authorityId, rest) ← readString rest
      let (authorityEpoch, rest) ← readNatBE 8 rest
      let (authorityDigest, rest) ← readDigest rest
      let (packId, rest) ← readString rest
      let (packDigest, rest) ← readDigest rest
      let (beforeRevision, rest) ← readNatBE 8 rest
      let (afterRevision, rest) ← readNatBE 8 rest
      let (evaluatedAt, rest) ← readNatBE 8 rest
      let (ruleVersion, rest) ← readNatBE 8 rest
      let (evidenceIds, rest) ← readList readString rest
      let (completionAt, rest) ← readOptionNat rest
      let (owedCents, rest) ← readNatBE 8 rest
      let (claimedAdjustmentCents, rest) ← readNatBE 8 rest
      let (lawfulAdjustmentCents, rest) ← readNatBE 8 rest
      let (receivedCashCents, rest) ← readNatBE 8 rest
      let (shortfallCents, rest) ← readNatBE 8 rest
      let (overageCents, rest) ← readNatBE 8 rest
      let (cashSatisfied, rest) ← readBool rest
      let (amountSatisfied, rest) ← readBool rest
      let (timely, rest) ← readBool rest
      let (reportingComplete, rest) ← readBool rest
      let (verificationByte, rest) ← readByte rest
      let verificationStatus ← decodeVerificationStatus verificationByte
      let (caseByte, rest) ← readByte rest
      let caseStatus ← decodeCaseStatus caseByte
      let (deliveryByte, rest) ← readByte rest
      let deliveryStatus ← decodeDeliveryStatus deliveryByte
      finish
        { context := context
          authorityId := authorityId
          authorityEpoch := authorityEpoch
          authorityDigest := authorityDigest
          packId := packId
          packDigest := packDigest
          beforeRevision := beforeRevision
          afterRevision := afterRevision
          evaluatedAt := evaluatedAt
          ruleVersion := ruleVersion
          evidenceIds := evidenceIds
          completionAt := completionAt
          owedCents := owedCents
          claimedAdjustmentCents := claimedAdjustmentCents
          lawfulAdjustmentCents := lawfulAdjustmentCents
          receivedCashCents := receivedCashCents
          shortfallCents := shortfallCents
          overageCents := overageCents
          cashSatisfied := cashSatisfied
          amountSatisfied := amountSatisfied
          timely := timely
          reportingComplete := reportingComplete
          verificationStatus := verificationStatus
          caseStatus := caseStatus
          deliveryStatus := deliveryStatus }
        rest) = some result
    rw [hDone]
    simp [finish, hWellFormed, hCanonical]
  · unfold decodeFinancialResult
    simp only [if_neg hSize']
    cases remaining with
    | nil => contradiction
    | cons head tail =>
        change (do
          let rest ← readResultMagic bytes
          let (context, rest) ← decodeContext rest
          let (authorityId, rest) ← readString rest
          let (authorityEpoch, rest) ← readNatBE 8 rest
          let (authorityDigest, rest) ← readDigest rest
          let (packId, rest) ← readString rest
          let (packDigest, rest) ← readDigest rest
          let (beforeRevision, rest) ← readNatBE 8 rest
          let (afterRevision, rest) ← readNatBE 8 rest
          let (evaluatedAt, rest) ← readNatBE 8 rest
          let (ruleVersion, rest) ← readNatBE 8 rest
          let (evidenceIds, rest) ← readList readString rest
          let (completionAt, rest) ← readOptionNat rest
          let (owedCents, rest) ← readNatBE 8 rest
          let (claimedAdjustmentCents, rest) ← readNatBE 8 rest
          let (lawfulAdjustmentCents, rest) ← readNatBE 8 rest
          let (receivedCashCents, rest) ← readNatBE 8 rest
          let (shortfallCents, rest) ← readNatBE 8 rest
          let (overageCents, rest) ← readNatBE 8 rest
          let (cashSatisfied, rest) ← readBool rest
          let (amountSatisfied, rest) ← readBool rest
          let (timely, rest) ← readBool rest
          let (reportingComplete, rest) ← readBool rest
          let (verificationByte, rest) ← readByte rest
          let verificationStatus ← decodeVerificationStatus verificationByte
          let (caseByte, rest) ← readByte rest
          let caseStatus ← decodeCaseStatus caseByte
          let (deliveryByte, rest) ← readByte rest
          let deliveryStatus ← decodeDeliveryStatus deliveryByte
          finish
            { context := context
              authorityId := authorityId
              authorityEpoch := authorityEpoch
              authorityDigest := authorityDigest
              packId := packId
              packDigest := packDigest
              beforeRevision := beforeRevision
              afterRevision := afterRevision
              evaluatedAt := evaluatedAt
              ruleVersion := ruleVersion
              evidenceIds := evidenceIds
              completionAt := completionAt
              owedCents := owedCents
              claimedAdjustmentCents := claimedAdjustmentCents
              lawfulAdjustmentCents := lawfulAdjustmentCents
              receivedCashCents := receivedCashCents
              shortfallCents := shortfallCents
              overageCents := overageCents
              cashSatisfied := cashSatisfied
              amountSatisfied := amountSatisfied
              timely := timely
              reportingComplete := reportingComplete
              verificationStatus := verificationStatus
              caseStatus := caseStatus
              deliveryStatus := deliveryStatus }
            rest) = none
        rw [hDone]
        simp [finish]

theorem parseFinancialResult_rawEncode_append
    (result : FinancialResult) (tail : Bytes)
    (hResult : financialResultWireAdmissible result) :
    ∀ {α : Type} (finish : FinancialResult → Bytes → Option α),
      (do
        let rest ← readResultMagic (rawEncodeFinancialResult result ++ tail)
        let (context, rest) ← decodeContext rest
        let (authorityId, rest) ← readString rest
        let (authorityEpoch, rest) ← readNatBE 8 rest
        let (authorityDigest, rest) ← readDigest rest
        let (packId, rest) ← readString rest
        let (packDigest, rest) ← readDigest rest
        let (beforeRevision, rest) ← readNatBE 8 rest
        let (afterRevision, rest) ← readNatBE 8 rest
        let (evaluatedAt, rest) ← readNatBE 8 rest
        let (ruleVersion, rest) ← readNatBE 8 rest
        let (evidenceIds, rest) ← readList readString rest
        let (completionAt, rest) ← readOptionNat rest
        let (owedCents, rest) ← readNatBE 8 rest
        let (claimedAdjustmentCents, rest) ← readNatBE 8 rest
        let (lawfulAdjustmentCents, rest) ← readNatBE 8 rest
        let (receivedCashCents, rest) ← readNatBE 8 rest
        let (shortfallCents, rest) ← readNatBE 8 rest
        let (overageCents, rest) ← readNatBE 8 rest
        let (cashSatisfied, rest) ← readBool rest
        let (amountSatisfied, rest) ← readBool rest
        let (timely, rest) ← readBool rest
        let (reportingComplete, rest) ← readBool rest
        let (verificationByte, rest) ← readByte rest
        let verificationStatus ← decodeVerificationStatus verificationByte
        let (caseByte, rest) ← readByte rest
        let caseStatus ← decodeCaseStatus caseByte
        let (deliveryByte, rest) ← readByte rest
        let deliveryStatus ← decodeDeliveryStatus deliveryByte
        finish
          { context := context
            authorityId := authorityId
            authorityEpoch := authorityEpoch
            authorityDigest := authorityDigest
            packId := packId
            packDigest := packDigest
            beforeRevision := beforeRevision
            afterRevision := afterRevision
            evaluatedAt := evaluatedAt
            ruleVersion := ruleVersion
            evidenceIds := evidenceIds
            completionAt := completionAt
            owedCents := owedCents
            claimedAdjustmentCents := claimedAdjustmentCents
            lawfulAdjustmentCents := lawfulAdjustmentCents
            receivedCashCents := receivedCashCents
            shortfallCents := shortfallCents
            overageCents := overageCents
            cashSatisfied := cashSatisfied
            amountSatisfied := amountSatisfied
            timely := timely
            reportingComplete := reportingComplete
            verificationStatus := verificationStatus
            caseStatus := caseStatus
            deliveryStatus := deliveryStatus }
          rest) = finish result tail := by
  rcases hResult with
    ⟨_, hContext, hAuthorityId, hAuthorityEpoch, hAuthorityDigest, hPackId,
      hPackDigest, hBeforeRevision, hAfterRevision, hEvaluatedAt, hRuleVersion,
      hEvidenceIds, hCompletionAt, hOwedCents, hClaimedAdjustmentCents,
      hLawfulAdjustmentCents, hReceivedCashCents, hShortfallCents, hOverageCents,
      _⟩
  rcases hEvidenceIds with ⟨hEvidenceIdsCount, hEvidenceId⟩
  have hMagicRead :
      readResultMagic (rawEncodeFinancialResult result ++ tail) =
        some ((encodeContext result.context ++ encodeString result.authorityId ++
          natBE 8 result.authorityEpoch ++ encodeDigest result.authorityDigest ++
          encodeString result.packId ++ encodeDigest result.packDigest ++
          natBE 8 result.beforeRevision ++ natBE 8 result.afterRevision ++
          natBE 8 result.evaluatedAt ++ natBE 8 result.ruleVersion ++
          encodeList encodeString result.evidenceIds ++
          encodeOptionNat result.completionAt ++ natBE 8 result.owedCents ++
          natBE 8 result.claimedAdjustmentCents ++
          natBE 8 result.lawfulAdjustmentCents ++
          natBE 8 result.receivedCashCents ++ natBE 8 result.shortfallCents ++
          natBE 8 result.overageCents ++ encodeBool result.cashSatisfied ++
          encodeBool result.amountSatisfied ++ encodeBool result.timely ++
          encodeBool result.reportingComplete ++
          [encodeVerificationStatus result.verificationStatus,
            encodeCaseStatus result.caseStatus, encodeDeliveryStatus result.deliveryStatus]) ++ tail) := by
    rw [rawEncodeFinancialResult_eq_magic_append]
    simp only [List.append_assoc, readResultMagic_accepts_prefix]
  have hContextRead : ∀ next : Bytes,
      decodeContext (encodeContext result.context ++ next) =
        some (result.context, next) := by
    intro next
    exact decodeContext_encodeContext_append result.context next hContext
  have hAuthorityIdRead : ∀ next : Bytes,
      readString (encodeString result.authorityId ++ next) =
        some (result.authorityId, next) := by
    intro next
    exact readString_encodeString_append result.authorityId next hAuthorityId
  have hAuthorityEpochRead : ∀ next : Bytes,
      readNatBE 8 (natBE 8 result.authorityEpoch ++ next) =
        some (result.authorityEpoch, next) := by
    intro next
    exact readNat8_natBE_append result.authorityEpoch next hAuthorityEpoch
  have hAuthorityDigestRead : ∀ next : Bytes,
      readDigest (encodeDigest result.authorityDigest ++ next) =
        some (result.authorityDigest, next) := by
    intro next
    exact readDigest_wire_append result.authorityDigest next hAuthorityDigest
  have hPackIdRead : ∀ next : Bytes,
      readString (encodeString result.packId ++ next) =
        some (result.packId, next) := by
    intro next
    exact readString_encodeString_append result.packId next hPackId
  have hPackDigestRead : ∀ next : Bytes,
      readDigest (encodeDigest result.packDigest ++ next) =
        some (result.packDigest, next) := by
    intro next
    exact readDigest_wire_append result.packDigest next hPackDigest
  have hBeforeRevisionRead : ∀ next : Bytes,
      readNatBE 8 (natBE 8 result.beforeRevision ++ next) =
        some (result.beforeRevision, next) := by
    intro next
    exact readNat8_natBE_append result.beforeRevision next hBeforeRevision
  have hAfterRevisionRead : ∀ next : Bytes,
      readNatBE 8 (natBE 8 result.afterRevision ++ next) =
        some (result.afterRevision, next) := by
    intro next
    exact readNat8_natBE_append result.afterRevision next hAfterRevision
  have hEvaluatedAtRead : ∀ next : Bytes,
      readNatBE 8 (natBE 8 result.evaluatedAt ++ next) =
        some (result.evaluatedAt, next) := by
    intro next
    exact readNat8_natBE_append result.evaluatedAt next hEvaluatedAt
  have hRuleVersionRead : ∀ next : Bytes,
      readNatBE 8 (natBE 8 result.ruleVersion ++ next) =
        some (result.ruleVersion, next) := by
    intro next
    exact readNat8_natBE_append result.ruleVersion next hRuleVersion
  have hEvidenceRead : ∀ next : Bytes,
      readList readString (encodeList encodeString result.evidenceIds ++ next) =
        some (result.evidenceIds, next) := by
    intro next
    exact readList_encodeString_append result.evidenceIds next
      hEvidenceIdsCount.1 hEvidenceId
  have hCompletionAtRead : ∀ next : Bytes,
      readOptionNat (encodeOptionNat result.completionAt ++ next) =
        some (result.completionAt, next) := by
    intro next
    exact readOptionNat_encodeOptionNat_append result.completionAt next hCompletionAt
  have hOwedCentsRead : ∀ next : Bytes,
      readNatBE 8 (natBE 8 result.owedCents ++ next) =
        some (result.owedCents, next) := by
    intro next
    exact readNat8_natBE_append result.owedCents next hOwedCents
  have hClaimedAdjustmentCentsRead : ∀ next : Bytes,
      readNatBE 8 (natBE 8 result.claimedAdjustmentCents ++ next) =
        some (result.claimedAdjustmentCents, next) := by
    intro next
    exact readNat8_natBE_append result.claimedAdjustmentCents next hClaimedAdjustmentCents
  have hLawfulAdjustmentCentsRead : ∀ next : Bytes,
      readNatBE 8 (natBE 8 result.lawfulAdjustmentCents ++ next) =
        some (result.lawfulAdjustmentCents, next) := by
    intro next
    exact readNat8_natBE_append result.lawfulAdjustmentCents next hLawfulAdjustmentCents
  have hReceivedCashCentsRead : ∀ next : Bytes,
      readNatBE 8 (natBE 8 result.receivedCashCents ++ next) =
        some (result.receivedCashCents, next) := by
    intro next
    exact readNat8_natBE_append result.receivedCashCents next hReceivedCashCents
  have hShortfallCentsRead : ∀ next : Bytes,
      readNatBE 8 (natBE 8 result.shortfallCents ++ next) =
        some (result.shortfallCents, next) := by
    intro next
    exact readNat8_natBE_append result.shortfallCents next hShortfallCents
  have hOverageCentsRead : ∀ next : Bytes,
      readNatBE 8 (natBE 8 result.overageCents ++ next) =
        some (result.overageCents, next) := by
    intro next
    exact readNat8_natBE_append result.overageCents next hOverageCents
  have hCashSatisfiedRead : ∀ next : Bytes,
      readBool (encodeBool result.cashSatisfied ++ next) =
        some (result.cashSatisfied, next) := by
    intro next
    exact readBool_encodeBool_append result.cashSatisfied next
  have hAmountSatisfiedRead : ∀ next : Bytes,
      readBool (encodeBool result.amountSatisfied ++ next) =
        some (result.amountSatisfied, next) := by
    intro next
    exact readBool_encodeBool_append result.amountSatisfied next
  have hTimelyRead : ∀ next : Bytes,
      readBool (encodeBool result.timely ++ next) =
        some (result.timely, next) := by
    intro next
    exact readBool_encodeBool_append result.timely next
  have hReportingCompleteRead : ∀ next : Bytes,
      readBool (encodeBool result.reportingComplete ++ next) =
        some (result.reportingComplete, next) := by
    intro next
    exact readBool_encodeBool_append result.reportingComplete next
  intro α finish
  simp only [hMagicRead, Option.bind_eq_bind, Option.bind_some,
    hContextRead, hAuthorityIdRead, hAuthorityEpochRead, hAuthorityDigestRead,
    hPackIdRead, hPackDigestRead, hBeforeRevisionRead, hAfterRevisionRead,
    hEvaluatedAtRead, hRuleVersionRead, hEvidenceRead, hCompletionAtRead,
    hOwedCentsRead, hClaimedAdjustmentCentsRead, hLawfulAdjustmentCentsRead,
    hReceivedCashCentsRead, hShortfallCentsRead, hOverageCentsRead,
    hCashSatisfiedRead, hAmountSatisfiedRead, hTimelyRead,
    hReportingCompleteRead, List.cons_append, List.nil_append, readByte,
    decodeVerificationStatus_encodeVerificationStatus,
    decodeCaseStatus_encodeCaseStatus, decodeDeliveryStatus_encodeDeliveryStatus,
    List.append_assoc]

theorem decodeFinancialResult_rawEncode
    (result : FinancialResult)
    (hResult : financialResultWireAdmissible result) :
     decodeFinancialResult (rawEncodeFinancialResult result) = some result := by
  have hCanonical := encodeFinancialResult_rawEncode result hResult
  have hResult' := hResult
  rcases hResult with
    ⟨hWellFormed, hContext, hAuthorityId, hAuthorityEpoch, hAuthorityDigest,
      hPackId, hPackDigest, hBeforeRevision, hAfterRevision, hEvaluatedAt,
      hRuleVersion, hEvidenceIds, hCompletionAt, hOwedCents,
      hClaimedAdjustmentCents, hLawfulAdjustmentCents, hReceivedCashCents,
      hShortfallCents, hOverageCents, hRawSize⟩
  have hDecoded := decodeFinancialResult_of_parsed
    (rawEncodeFinancialResult result) result [] hRawSize
    (by
      intro α finish
      simpa only [List.append_nil] using
        parseFinancialResult_rawEncode_append result [] hResult' finish)
    (by intro _; exact ⟨hWellFormed, hCanonical⟩)
  simpa using hDecoded

theorem decodeFinancialResult_rawEncode_rejects_nonempty_tail
    (result : FinancialResult) (tail : Bytes)
    (hResult : financialResultWireAdmissible result)
    (hTail : tail ≠ []) :
    decodeFinancialResult (rawEncodeFinancialResult result ++ tail) = none := by
  cases tail with
  | nil => exact (hTail rfl).elim
  | cons head tail =>
      by_cases hTooLarge :
          (rawEncodeFinancialResult result ++ head :: tail).length >
            maxTotalEncodedBytes
      · simp only [decodeFinancialResult, hTooLarge, if_true]
      · have hSize :
            (rawEncodeFinancialResult result ++ head :: tail).length ≤
              maxTotalEncodedBytes := Nat.le_of_not_gt hTooLarge
        have hDecoded := decodeFinancialResult_of_parsed
          (rawEncodeFinancialResult result ++ head :: tail) result (head :: tail)
          hSize
          (by
            intro α finish
            exact parseFinancialResult_rawEncode_append result
              (head :: tail) hResult finish)
          (by
            intro hEmpty
            exact (List.cons_ne_nil head tail hEmpty).elim)
        simpa using hDecoded

theorem decodeFinancialInput_of_encodeFinancialInput
    (input : FinancialInput)
    (hInput : financialInputWireAdmissible input)
    (wire : Bytes)
    (hWire : encodeFinancialInput input = some wire) :
    decodeFinancialInput wire = some input := by
  have hCanonical := encodeFinancialInput_rawEncode input hInput
  have hRawEq : rawEncodeFinancialInput input = wire :=
    Option.some.inj (hCanonical.symm.trans hWire)
  rw [← hRawEq]
  exact decodeFinancialInput_rawEncode input hInput

theorem decodeFinancialResult_of_encodeFinancialResult
    (result : FinancialResult)
    (hResult : financialResultWireAdmissible result)
    (wire : Bytes)
    (hWire : encodeFinancialResult result = some wire) :
    decodeFinancialResult wire = some result := by
  have hCanonical := encodeFinancialResult_rawEncode result hResult
  have hRawEq : rawEncodeFinancialResult result = wire :=
    Option.some.inj (hCanonical.symm.trans hWire)
  rw [← hRawEq]
  exact decodeFinancialResult_rawEncode result hResult

theorem rawEncodeFinancialInput_injective_of_admissible
    (left right : FinancialInput)
    (hLeft : financialInputWireAdmissible left)
    (hRight : financialInputWireAdmissible right)
    (hWire : rawEncodeFinancialInput left = rawEncodeFinancialInput right) :
    left = right := by
  have hDecoded :
      decodeFinancialInput (rawEncodeFinancialInput left) =
        decodeFinancialInput (rawEncodeFinancialInput right) :=
    congrArg decodeFinancialInput hWire
  rw [decodeFinancialInput_rawEncode left hLeft,
    decodeFinancialInput_rawEncode right hRight] at hDecoded
  exact Option.some.inj hDecoded

theorem rawEncodeFinancialResult_injective_of_admissible
    (left right : FinancialResult)
    (hLeft : financialResultWireAdmissible left)
    (hRight : financialResultWireAdmissible right)
    (hWire : rawEncodeFinancialResult left = rawEncodeFinancialResult right) :
    left = right := by
  have hDecoded :
      decodeFinancialResult (rawEncodeFinancialResult left) =
        decodeFinancialResult (rawEncodeFinancialResult right) :=
    congrArg decodeFinancialResult hWire
  rw [decodeFinancialResult_rawEncode left hLeft,
    decodeFinancialResult_rawEncode right hRight] at hDecoded
  exact Option.some.inj hDecoded

theorem encodeFinancialInput_injective_of_admissible
    (left right : FinancialInput)
    (hLeft : financialInputWireAdmissible left)
    (hRight : financialInputWireAdmissible right)
    (hWire : encodeFinancialInput left = encodeFinancialInput right) :
    left = right := by
  rw [encodeFinancialInput_rawEncode left hLeft,
    encodeFinancialInput_rawEncode right hRight] at hWire
  exact rawEncodeFinancialInput_injective_of_admissible left right hLeft hRight
    (Option.some.inj hWire)

theorem encodeFinancialResult_injective_of_admissible
    (left right : FinancialResult)
    (hLeft : financialResultWireAdmissible left)
    (hRight : financialResultWireAdmissible right)
    (hWire : encodeFinancialResult left = encodeFinancialResult right) :
    left = right := by
  rw [encodeFinancialResult_rawEncode left hLeft,
    encodeFinancialResult_rawEncode right hRight] at hWire
  exact rawEncodeFinancialResult_injective_of_admissible left right hLeft hRight
    (Option.some.inj hWire)

end BlindLedger.Financial
