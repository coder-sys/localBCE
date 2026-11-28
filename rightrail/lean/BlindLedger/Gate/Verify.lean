import BlindLedger.Gate.Payer

/-! `accepts` is the decision of the `gate_verify` executable (`VerifyCli`) on one certificate and one checkpoint:
    on a state that holds only the given authority link, install the certificate, then store the checkpoint.  The
    certificate is judged as the payer judges it (`Cosign.installCert`): canonical, of the link's tenant and
    generation, naming the link, its keys apart from the link's keys and commitments, and signed by the link's root
    and witness keys.  So no checkpoint verifies under a root or witness key. -/
namespace BlindLedger.Gate

def emptyState : PayerState :=
  { Cosign.Auth.empty with now := 0, checkpoints := [], grants := [], released := [], forked := [], pins := [] }

/-- The state that holds the one authority link, as its tenant's whole chain; no chain at all when the link has one
    key in both roles. -/
def linkState (link : Cosign.Link) : PayerState :=
  { emptyState with chainOf := fun t => if t = link.tenantId then Cosign.Chain.start link else none }

def accepts (link : Cosign.Link) (cert checkpoint : Bytes) : Bool :=
  match installCert realCrypto (linkState link) cert with
  | (s, .installed) => match storeCheckpoint realCrypto s checkpoint with
    | some s' => s'.forked.isEmpty
    | none => false
  | _ => false

end BlindLedger.Gate
