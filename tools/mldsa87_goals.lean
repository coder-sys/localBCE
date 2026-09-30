import BlindLedger.Gate.Verify
import BlindLedger.Gate.Theorems

/-! ML-DSA-87 non-bypass and totality: the fixed theorem STATEMENTS of lean-expansion-plan item 11
    (design: C:\Users\neers\rrb\designs\mldsa-theorems-v1.md).  Every proof is `sorry` on purpose.
    This file is outside `lean/`, so no executable, library target, TCB report or pin manifest sees it.
    Check: from `lean/`, `lake build BlindLedger.Gate.Theorems BlindLedger.Gate.Verify`, then
    `lake env lean ../tools/mldsa87_goals.lean`.  A prover moves each statement, unchanged, into
    `lean/BlindLedger/Gate/` with its proof and an axiom pin, and deletes it here. -/

namespace BlindLedger.Gate

/-- A decoded signed checkpoint is exactly its signed header, the length 4627 as u16 BE, and the signature. -/
theorem decodeCheckpoint_bytes {b : Bytes} {x : SignedCheckpoint} (h : decodeCheckpoint b = some x) :
    b = x.header ++ natBE 2 mlDsa87Signature ++ x.signature ∧ x.signature.length = mlDsa87Signature := by
  sorry

/-- A decoded KEY-CERT is the whole input: a root-signed body ending in the epoch key, then the root signature. -/
theorem decodeKeyCert_bytes {b : Bytes} {e : EpochCert} (h : decodeKeyCert b = some e) :
    e.signed = b ∧ e.publicKey.length = mlDsa87Key ∧ ∃ body sig,
      b = body ++ natBE 2 mlDsa87Signature ++ sig ∧ sig.length = mlDsa87Signature ∧ e.publicKey <:+ body := by
  sorry

/-- gate_verify's whole decision: ACCEPT exactly when both inputs decode, the certificate names the checkpoint's
    tenant and epoch, the root key signed the certificate body and the certified key signed the header. -/
theorem accepts_iff (rootPk cert checkpoint : Bytes) :
    accepts rootPk cert checkpoint = true ↔ ∃ x e, decodeCheckpoint checkpoint = some x ∧
      decodeKeyCert cert = some e ∧ e.tenantId = x.checkpoint.tenantId ∧ e.epoch = x.checkpoint.epoch ∧
      mlDsaOk rootPk (cert.take (cert.length - 2 - mlDsa87Signature)) (cert.drop (cert.length - mlDsa87Signature)) = true ∧
      mlDsaOk e.publicKey x.header x.signature = true := by
  sorry

/-- Non-bypass on the raw input bytes: gate_verify accepts only if ML-DSA-87 `verify` returned true for the root key
    on `00 00 ‖ body` and for a key inside that body on `00 00 ‖ header`, where `body` and `header` are the exact
    bytes of the two inputs before their signatures. -/
theorem accepts_nonbypass {rootPk cert checkpoint : Bytes} (h : accepts rootPk cert checkpoint = true) :
    ∃ body certSig pk header sig : Bytes,
      cert = body ++ natBE 2 mlDsa87Signature ++ certSig ∧ checkpoint = header ++ natBE 2 mlDsa87Signature ++ sig ∧
      pk <:+ body ∧ pk.length = mlDsa87Key ∧
      MlDsa87.verify rootPk.toByteArray ([0, 0] ++ body).toByteArray certSig.toByteArray = true ∧
      MlDsa87.verify pk.toByteArray ([0, 0] ++ header).toByteArray sig.toByteArray = true := by
  sorry

/-- Every installed certificate passed its chain check; every stored checkpoint is the decoding of its own bytes,
    filed under the hash of its signed header, and signed by an installed key of its tenant and epoch. -/
def Verified (c : Crypto) (s : PayerState) : Prop :=
  (∀ e ∈ s.certs, c.certChainOk e = true) ∧
    ∀ st ∈ s.checkpoints, ∃ x, decodeCheckpoint st.bytes = some x ∧ st.checkpoint = x.checkpoint ∧
      st.digest = c.hash x.header ∧ ∃ e ∈ s.certs, e.tenantId = x.checkpoint.tenantId ∧
        e.epoch = x.checkpoint.epoch ∧ c.sigOk e.publicKey x.header x.signature = true

theorem Steps.verified {c : Crypto} {s s' : PayerState} (h : Steps c s s') (hs : Verified c s) : Verified c s' := by
  sorry

/-- Payer non-bypass for every `Crypto`: a released payment's token names, by the hash of its signed header, a stored
    checkpoint whose signature verified under a chain-checked key of the token's tenant and epoch. -/
theorem release_signed {c : Crypto} {s s' : PayerState} {p : Payment} {bytes : Bytes} (hs : Verified c s)
    (h : release c s p bytes = some s') :
    ∃ t st x e, decodeToken bytes = some t ∧ st ∈ s.checkpoints ∧ decodeCheckpoint st.bytes = some x ∧
      t.checkpointDigest = c.hash x.header ∧ e ∈ s.certs ∧ c.certChainOk e = true ∧
      e.tenantId = t.leaf.tenantId ∧ e.epoch = t.leaf.epoch ∧ c.sigOk e.publicKey x.header x.signature = true := by
  sorry

end BlindLedger.Gate

namespace BlindLedger.Keccak

/-- A shorter squeeze is a prefix of a longer one (FIPS 202's SHAKE is an extendable-output function). -/
theorem sponge_prefix (rate : Nat) (suffix : UInt8) (data : ByteArray) {m n : Nat} (h : m ≤ n) :
    (sponge rate suffix data n).extract 0 m = sponge rate suffix data m := by
  sorry

end BlindLedger.Keccak

namespace BlindLedger.Gate.MlDsa87

open BlindLedger.Keccak

/-- ACCEPT implies every check of FIPS 204 Algorithm 8 before the final hash comparison passed: key and signature
    sizes, a well-formed hint, `‖z‖∞ < γ1 - β`, and both samplers finished within Table 3's XOF bytes. -/
theorem verify_true_checks {pk msg sig : ByteArray} (h : verify pk msg sig = true) :
    pk.size = 2592 ∧ sig.size = 4627 ∧ (hintUnpack (sig.extract (64 + 7 * 640) 4627)).isSome ∧
      (∀ s < l, ∀ j < 256, Int.natAbs ((gamma1 : Int) - ((unpack sig (64 + 640 * s) 20)[j]! : Nat)) < gamma1 - beta) ∧
      (sampleInBall (sig.extract 0 64)).isSome ∧ (expandA (pk.extract 0 32)).isSome := by
  sorry

/-- Within Table 3's bound the bounded RejNTTPoly is the standard's unbounded one: every longer SHAKE128 stream
    gives the same polynomial. -/
theorem rejNtt_stable {seed : ByteArray} {a : Poly} (h : rejNtt seed = some a) {n : Nat} (hn : rejNttBytes ≤ n) :
    rejNttFrom (shake128 seed n) = some a := by
  sorry

/-- The same for SampleInBall over SHAKE256. -/
theorem sampleInBall_stable {seed : ByteArray} {c : Poly} (h : sampleInBall seed = some c) {n : Nat}
    (hn : sampleInBallBytes ≤ n) : sampleInBallFrom (shake256 seed n) = some c := by
  sorry

/-- The signature encoding is canonical (FIPS 204 Algorithms 27 and 21): two 4627-byte signatures with the same c~,
    the same z and the same decoded hint are the same bytes, so no signature byte can change without changing what
    `verify` checks (the non-malleability half of strong unforgeability). -/
theorem sig_canonical {sig sig' : ByteArray} {hint : Array Poly} (hs : sig.size = 4627) (hs' : sig'.size = 4627)
    (hc : sig.extract 0 64 = sig'.extract 0 64)
    (hz : ∀ s < l, unpack sig (64 + 640 * s) 20 = unpack sig' (64 + 640 * s) 20)
    (hh : hintUnpack (sig.extract (64 + 7 * 640) 4627) = some hint)
    (hh' : hintUnpack (sig'.extract (64 + 7 * 640) 4627) = some hint) : sig = sig' := by
  sorry

/-- UseHint (Algorithm 40) gives a 4-bit value on reduced input, so verify's `p[2i] + 16 p[2i+1]` byte packing is
    FIPS 204's w1Encode (Algorithm 28, SimpleBitPack with b = 15) and never wraps. -/
theorem useHint_lt (h : Nat) {r : Nat} (hr : r < q) : useHint h r < 16 := by
  sorry

/-- NTT round trip (Algorithms 41 and 42) on reduced polynomials. -/
theorem invNtt_ntt {p : Poly} (hs : p.size = 256) (hq : ∀ x ∈ p, x < q) : invNtt (ntt p) = p := by
  sorry

/-- Schoolbook product in Z_q[X]/(X^256 + 1): the reference that the NTT-domain product must equal. -/
def negacyclic (a b : Poly) : Poly :=
  (Array.range 256).map fun i => (List.range 256).foldl (fun acc j =>
    if j ≤ i then (acc + a[j]! * b[i - j]!) % q else (acc + (q - a[j]! * b[i + 256 - j]! % q)) % q) 0

/-- The pointwise NTT product is the negacyclic product, so verify's `A z - c t1 2^d` is the standard's. -/
theorem invNtt_pointwise {a b : Poly} (ha : a.size = 256) (hb : b.size = 256) :
    invNtt ((Array.range 256).map fun j => (ntt a)[j]! * (ntt b)[j]! % q) = negacyclic a b := by
  sorry

end BlindLedger.Gate.MlDsa87
