import BlindLedger.Gate.Spec
import BlindLedger.Gate.MlDsa87

/-! The real `Crypto` of the gate: SHA3-512, ML-DSA-87 (pure, empty context, so M' = `00 00 ‖ message`) and a
    KEY-CERT that decodes and carries a valid signature from the tenant's root key.  `accepts` is the whole
    decision of the `gate_verify` executable (`VerifyCli`): under a root key, install the certificate, then
    store the checkpoint, on an empty payer state. -/
namespace BlindLedger.Gate

def sha3 (x : Bytes) : Bytes := (Semantic.sha3_512 x.toByteArray).toList

def mlDsaOk (pk msg sig : Bytes) : Bool :=
  MlDsa87.verify pk.toByteArray (([0, 0] ++ msg).toByteArray) sig.toByteArray

/-- `roots`: (tenant, root public key). -/
def realCrypto (roots : List (Bytes × Bytes)) : Crypto where
  hash := sha3
  certChainOk e := decodeKeyCert e.signed == some e && roots.any fun r => r.1 == e.tenantId &&
    mlDsaOk r.2 (e.signed.take (e.signed.length - 2 - mlDsa87Signature)) (e.signed.drop (e.signed.length - mlDsa87Signature))
  sigOk := mlDsaOk

def emptyState : PayerState :=
  { fence := fun _ => 0, now := 0, certs := [], checkpoints := [], grants := [], released := [],
    forked := [], equivocations := [], pins := [] }

def accepts (rootPk cert checkpoint : Bytes) : Bool :=
  match decodeCheckpoint checkpoint, decodeKeyCert cert with
  | some x, some e =>
    let c := realCrypto [(x.checkpoint.tenantId, rootPk)]
    match installCert c emptyState e with
    | (s, true) => match storeCheckpoint c s checkpoint with
      | some s' => s'.forked.isEmpty
      | none => false
    | _ => false
  | _, _ => false

end BlindLedger.Gate
