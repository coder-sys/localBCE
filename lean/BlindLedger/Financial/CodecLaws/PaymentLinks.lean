import BlindLedger.Financial.CodecLaws.Records
import BlindLedger.Financial.CorrectionTransition.PaidSum

/-! Codec laws for the `BLFCMD03` payment-link list.  The request-level laws
    (`decodeCorrectionTransitionRequest_of_encode`, `_of_decode`,
    `_rejects_trailing`) keep their text; once `commandWireAdmissible` swaps its
    `correctionPaid` clause for `paymentLinkWireAdmissible`, their proofs use
    `readPaymentLinks_append` where they used `readCorrectionPaids_append`. -/

namespace BlindLedger.Financial.CorrectionTransition

open BlindLedger.Financial

def paymentLinkWireAdmissible (link : PaymentLink) : Prop :=
  stringWireAdmissible link.paymentId ∧ stringWireAdmissible link.actionId

theorem readPaymentLink_append (link : PaymentLink) (rest : Bytes)
    (h : paymentLinkWireAdmissible link) :
    readPaymentLink (encodePaymentLink link ++ rest) = some (link, rest) := by
  simp [readPaymentLink, encodePaymentLink, List.append_assoc,
    readString_encodeString_append _ _ h.1, readString_encodeString_append _ _ h.2]

theorem readPaymentLinks_append (links : List PaymentLink) (rest : Bytes)
    (h : wireListAdmissible links paymentLinkWireAdmissible) :
    readList readPaymentLink (encodeList encodePaymentLink links ++ rest) =
      some (links, rest) :=
  readList_encodeList_append_of_mem _ _ links rest h.1.1 h.1.2
    (fun link hMember tail => readPaymentLink_append link tail (h.2 link hMember))

end BlindLedger.Financial.CorrectionTransition
