import BlindLedger.Financial.Payment.Codec
import BlindLedger.Financial.Theorems.Vectors

namespace BlindLedger.Financial.Payment

open BlindLedger.Financial

/-! Form-A known answers (design 7.5), checked when this file builds: a record and a reverse
    request round-trip byte for byte, and any change to the bytes is refused. -/

private def katRequest (command : Command) : PaymentRequest :=
  { input := katBase, inputBytes := (rawEncodeFinancialInput katBase).length, receipts := [],
    foreign := ⟨false, true⟩, expectedRevision := some 0, command }

private def katRecord : Command := .record
  { paymentId := "payment:kat:1", evidenceId := "evidence:kat:1", commonOriginId := "origin:kat:1",
    sourceId := "source:kat", sourceVersion := "v1", localRef := none, amountCents := 700_000,
    eventAt := 1_774_900_000_000, paysActionId := some "action:kat" }

private def katReverse : Command := .reverse
  { paymentId := "payment:kat:1", evidenceId := "evidence:kat:2", commonOriginId := none,
    eventAt := some 1_774_910_000_000 }

private def roundTrips (c : Command) : Bool :=
  let w := encodePaymentRequest (katRequest c)
  requestWellFormed (katRequest c) && (decodePaymentRequest w).map encodePaymentRequest == some w

#guard roundTrips katRecord
#guard roundTrips katReverse
#guard (encodePaymentRequest (katRequest katRecord)).take 9 == paymentMagic ++ [UInt8.ofNat 1]
#guard (decodePaymentRequest (encodePaymentRequest (katRequest katRecord) ++ [UInt8.ofNat 0])).isNone
#guard (decodePaymentRequest ((encodePaymentRequest (katRequest katReverse)).dropLast)).isNone

end BlindLedger.Financial.Payment
