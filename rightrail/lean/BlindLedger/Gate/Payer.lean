import BlindLedger.Gate.Spec

/-! The payer adapter's reads (gate-producer-v1 §2): the rows of state one token's decision needs, and the
    reason a release is held.  Theorems: `ProducerTheorems`. -/
namespace BlindLedger.Gate

/-- The rows of payer state one token's decision reads: the adapter loads only these. -/
def slice (s : PayerState) (t : Token) : PayerState :=
  { fence := s.fence, now := s.now,
    certs := s.certs.filter (·.tenantId == t.leaf.tenantId),
    checkpoints := (batchOf s t).toList,
    grants := s.grants.filter (·.grantId == t.leaf.grantId),
    released := s.released.filter (· == payKey t),
    forked := s.forked.filter fun f =>
      f.1.checkpoint.tenantId == t.leaf.tenantId && f.1.checkpoint.epoch == t.leaf.epoch,
    equivocations := s.equivocations.filter fun q => q.1.tenantId == t.leaf.tenantId && q.1.epoch == t.leaf.epoch,
    pins := s.pins.filter (·.1 == payKey t) }

/-- The first of the twelve checks a token fails, in `verifyToken`'s order: the HOLD reason. -/
inductive Failure
  | parse | batch | path | fence | expiry | payment | route | outcome | grant | released | forked | pin
  deriving DecidableEq, Repr

def firstFailure (c : Crypto) (s : PayerState) (p : Payment) (bytes : Bytes) : Option Failure :=
  match decodeToken bytes with
  | none => some .parse
  | some t =>
    match batchOf s t with
    | none => some .batch
    | some st =>
      ([(inBatch c st.checkpoint t, Failure.path), (aboveFence s t, .fence), (unexpired s t, .expiry),
        (paymentMatches c p t, .payment), (routed c s p t, .route), (allows t, .outcome), (granted s t, .grant),
        (unreleased s t, .released), (unforked s t, .forked), (keyPinned s t, .pin)].find? (!·.1)).map (·.2)

end BlindLedger.Gate
