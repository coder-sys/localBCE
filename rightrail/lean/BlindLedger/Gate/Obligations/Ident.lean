import BlindLedger.Gate.Obligations.Records
import BlindLedger.Sha3Quick
import BlindLedger.Financial.Types

namespace BlindLedger.Gate.Obligations

open BlindLedger.Gate.FactCodec

/-! Identities of the program-obligations shard (design `one-store` §2.2), the lookup `ident`, and the new bounds
    (§9.1).

    Cost: `H` (SHA3-512) takes one permutation per 72 input bytes, rounded down, plus one; `H256` (SHA3-256) one
    per 136, plus one.  So `ob`, `cid`, `ak`, `ck` and `actor` are one `H256` permutation for identifiers of up to
    55 bytes, and a `sid` of two 32-byte fields is one. -/

/-- A domain tag: `RR/GATE/<name>/v1` and a zero byte, as the base design's §2.1. -/
def dom (name : String) : Bytes := ("RR/GATE/" ++ name ++ "/v1").toUTF8.toList ++ [0]

def H (b : Bytes) : Bytes := (BlindLedger.Semantic.sha3_512Quick ⟨b.toArray⟩).toList
def H256 (b : Bytes) : Bytes := (BlindLedger.Semantic.sha3_256Quick ⟨b.toArray⟩).toList

/-- A field with its two-byte little-endian length. -/
def lp16 (x : Bytes) : Bytes := leBytes 2 x.length ++ x

def lpCat : List Bytes → Bytes
  | [] => []
  | x :: xs => lp16 x ++ lpCat xs

def scopeOf (state deployment program period currency : Bytes) : Bytes :=
  H (dom "SCOPE" ++ lpCat [state, deployment, program, period, currency])

def obOf (scope item : Bytes) : Bytes := H256 (dom "OBL" ++ scope ++ lp16 item)
def cidOf (scope commandId : Bytes) : Bytes := H256 (dom "CMD" ++ scope ++ lp16 commandId)
def rqdOf (canonical : Bytes) : Bytes := H (dom "CMDREQ" ++ canonical)
def idemOf (ob claimSid : Bytes) (akind : Nat) : Bytes := H (dom "ACTIONKEY" ++ ob ++ claimSid ++ leBytes 1 akind)
def erefOf (result : Bytes) : Bytes := H (dom "EVALRES" ++ result)
def akOf (scope actionId : Bytes) : Bytes := H256 (dom "ACTION" ++ scope ++ lp16 actionId)
def ckOf (scope caseId : Bytes) : Bytes := H256 (dom "CASE" ++ scope ++ lp16 caseId)
def actorOf (actorId : Bytes) : Bytes := H256 (dom "ACTOR" ++ lp16 actorId)

/-- What the `sid` of a fact row of kinds 14, 15 and 22-26 hashes: the base's rule with the source field 0. -/
def sidInput (k : Nat) (fs : List Bytes) : Bytes := dom "SID" ++ leBytes 2 0 ++ leBytes 1 k ++ lpCat fs

def sidOf (k : Nat) (fs : List Bytes) : Bytes := H256 (sidInput k fs)

/-- `pop` in an OBLIG fact (§2.4): the population's lookup key, scoped as `cid`, `ak` and `ck` are. -/
def popOf (scope population : Bytes) : Bytes := H256 (dom "POP" ++ scope ++ lp16 population)

/-- The subject of a FUND fact (§2.4), `H256(dom OBL ‖ scope)`.  Its input is shorter than any `ob`'s, so the two
    never share an input. -/
def fundSubjectOf (scope : Bytes) : Bytes := H256 (dom "OBL" ++ scope)

/-- The `sid` of an OBLIG fact: the scope first, then the population id and the item id.  Every other kind starts
    with `ob`, which holds the scope; these two have no `ob`, so the scope itself comes first, and two period stores on
    one shard that reuse an identifier never share a statement. -/
def obligSidOf (scope population item : Bytes) : Bytes := sidOf 14 [scope, population, item]

/-- The `sid` of a FUND fact: the scope first, then the funding source reference. -/
def fundSidOf (scope sourceRef : Bytes) : Bytes := sidOf 25 [scope, sourceRef]

/-! Vectors, computed independently with Python's `hashlib.sha3_256` over the same bytes: scope `pat 64 1`,
    population `pop-1`, item `item-1`, funding source `fund-1`.  A change to a domain, a field order or a length
    prefix changes them. -/
#guard popOf (pat 64 1) "pop-1".toUTF8.toList ==
  hexBytes "ed5f4f668e09e80d56495c2d6558617c77fdd876779cf4af759b95af1e86c182"
#guard fundSubjectOf (pat 64 1) == hexBytes "08e33d61bfb15b68e4671f2d50854614d1bf23ec89980a77610cbb981e3dfe97"
#guard obligSidOf (pat 64 1) "pop-1".toUTF8.toList "item-1".toUTF8.toList ==
  hexBytes "ab7b3e6622e26ebbd778bccea3f8b5407e06cba277b48e94c1ddf6fe2efccdbb"
#guard fundSidOf (pat 64 1) "fund-1".toUTF8.toList ==
  hexBytes "c8d329eb2572c6b920a8b7d87cc8b34af3f898f7c56457c03df5e19532e44d7a"
#guard obOf (pat 64 1) "item-1".toUTF8.toList ==
  hexBytes "f401d2cbfd9eccb33754e85c39dfadfc8e44102d4f64e7bbede14727c0597f5e"

theorem lpCat_inj : ∀ (fs gs : List Bytes), (∀ f ∈ fs, f.length < 256 ^ 2) → (∀ g ∈ gs, g.length < 256 ^ 2) →
    lpCat fs = lpCat gs → fs = gs
  | [], [], _, _, _ => rfl
  | [], _ :: _, _, _, h => by simp [lpCat, lp16, leBytes] at h
  | _ :: _, [], _, _, h => by simp [lpCat, lp16, leBytes] at h
  | f :: fs, g :: gs, hf, hg, h => by
    simp only [lpCat, lp16, List.append_assoc] at h
    have h1 := List.append_inj h (by simp [leBytes_length])
    have hl : f.length = g.length := by
      have := congrArg fromLE h1.1
      rwa [fromLE_leBytes _ _ (hf f (by simp)), fromLE_leBytes _ _ (hg g (by simp))] at this
    have h2 := List.append_inj h1.2 hl
    rw [h2.1, lpCat_inj fs gs (fun x hx => hf x (by simp [hx])) (fun x hx => hg x (by simp [hx])) h2.2]

/-- `source_free_identity` (§9.2): a `sid` of kinds 14, 15 and 22-26 is a function of the kind and the identity
    fields alone (`sidOf` takes no source; the source field is 0), and its input determines both, so two rows
    with one `sid` input are one fact.  The one in force is the later in commit order: `in_force_latest`. -/
theorem source_free_identity {k k' : Nat} {fs gs : List Bytes} (hk : k < 256) (hk' : k' < 256)
    (hf : ∀ f ∈ fs, f.length < 256 ^ 2) (hg : ∀ g ∈ gs, g.length < 256 ^ 2) :
    sidInput k fs = sidInput k' gs ↔ k = k' ∧ fs = gs := by
  constructor
  · intro h
    simp only [sidInput, List.append_assoc] at h
    have h0 := List.append_cancel_left (List.append_cancel_left h)
    have h1 := List.append_inj h0 (by simp [leBytes_length])
    refine ⟨?_, lpCat_inj fs gs hf hg h1.2⟩
    have := congrArg fromLE h1.1
    rwa [fromLE_leBytes 1 _ (by simpa using hk), fromLE_leBytes 1 _ (by simpa using hk')] at this
  · rintro ⟨rfl, rfl⟩
    rfl

/-- The row in force for a `sid`: the latest row of it in commit order. -/
def inForce {β : Type} (rows : List (Bytes × β)) (s : Bytes) : Option β :=
  ((rows.filter fun p => p.1 == s).getLast?).map (·.2)

theorem in_force_latest {β : Type} (rows : List (Bytes × β)) (s : Bytes) (v : β) :
    inForce (rows ++ [(s, v)]) s = some v := by
  simp [inForce]

theorem in_force_other {β : Type} (rows : List (Bytes × β)) {s s' : Bytes} (v : β) (h : s' ≠ s) :
    inForce (rows ++ [(s', v)]) s = inForce rows s := by
  simp [inForce, h]

/-! ## `ident`: the newest record of each key

    Case, action and command records hold their key (`ck`, `ak`, `cid`) at offset 2.  `ident` maps a tag and key to
    the number of the newest record that holds it; appending a record updates one entry. -/

def identKey : Bytes → Option (Nat × Bytes)
  | t :: _ :: rest =>
    if t.toNat = 0x72 ∨ t.toNat = 0xF3 ∨ t.toNat = 0x74 then some (t.toNat, rest.take 32) else none
  | _ => none

def identStep (m : Nat × Bytes → Option Nat) (i : Nat) (r : Bytes) : Nat × Bytes → Option Nat :=
  fun k => if identKey r = some k then some i else m k

def identGo (m : Nat × Bytes → Option Nat) (i : Nat) : List Bytes → Nat × Bytes → Option Nat
  | [] => m
  | r :: rs => identGo (identStep m i r) (i + 1) rs

def ident (log : List Bytes) : Nat × Bytes → Option Nat := identGo (fun _ => none) 0 log

theorem identGo_append (m : Nat × Bytes → Option Nat) (i : Nat) (l : List Bytes) (r : Bytes) :
    identGo m i (l ++ [r]) = identStep (identGo m i l) (i + l.length) r := by
  induction l generalizing m i with
  | nil => rfl
  | cons a l ih =>
    show identGo (identStep m i a) (i + 1) (l ++ [r]) = _
    rw [ih]
    simp only [identGo, List.length_cons]
    congr 1
    omega

/-- Appending a record changes only the entry of its own key. -/
theorem ident_append (log : List Bytes) (r : Bytes) (k : Nat × Bytes) :
    ident (log ++ [r]) k = if identKey r = some k then some log.length else ident log k := by
  simp [ident, identGo_append, identStep]

theorem getElem?_snoc (l : List Bytes) (r : Bytes) (j : Nat) :
    (l ++ [r])[j]? = if j < l.length then l[j]? else if j = l.length then some r else none := by
  by_cases h1 : j < l.length
  · rw [if_pos h1, List.getElem?_append_left h1]
  · rw [if_neg h1, List.getElem?_append_right (by omega)]
    by_cases h2 : j = l.length
    · subst h2; simp
    · rw [if_neg h2]
      obtain ⟨m, hm⟩ : ∃ m, j - l.length = m + 1 := ⟨j - l.length - 1, by omega⟩
      rw [hm]
      simp

/-- `ident` names the newest record of a key, and names none when no record holds it. -/
theorem ident_spec (log : List Bytes) (k : Nat × Bytes) :
    (∀ i, ident log k = some i →
      (∃ r, log[i]? = some r ∧ identKey r = some k) ∧ ∀ j r, i < j → log[j]? = some r → identKey r ≠ some k) ∧
    (ident log k = none → ∀ r ∈ log, identKey r ≠ some k) := by
  obtain ⟨rv, rfl⟩ : ∃ rv, log = rv.reverse := ⟨log.reverse, (List.reverse_reverse log).symm⟩
  induction rv with
  | nil => exact ⟨fun i h => by simp [ident, identGo] at h, fun _ r hr => by simp at hr⟩
  | cons r rs ih =>
    rw [List.reverse_cons]
    generalize rs.reverse = l at ih ⊢
    rw [ident_append]
    by_cases hr : identKey r = some k
    · rw [if_pos hr]
      refine ⟨fun i hi => ?_, fun h => by cases h⟩
      simp only [Option.some.injEq] at hi
      subst hi
      refine ⟨⟨r, by simp, hr⟩, fun j r' hj hr' => ?_⟩
      rw [getElem?_snoc, if_neg (by omega), if_neg (by omega)] at hr'
      cases hr'
    · rw [if_neg hr]
      refine ⟨fun i hi => ?_, fun h r' hr' => ?_⟩
      · obtain ⟨⟨r0, h0, hk0⟩, hn⟩ := ih.1 i hi
        have hil : i < l.length := by
          rcases Nat.lt_or_ge i l.length with hil | hge
          · exact hil
          · rw [List.getElem?_eq_none_iff.2 hge] at h0
            cases h0
        refine ⟨⟨r0, by rw [List.getElem?_append_left hil]; exact h0, hk0⟩, fun j r' hj hr' => ?_⟩
        rw [getElem?_snoc] at hr'
        split at hr'
        · exact hn j r' hj hr'
        · split at hr'
          · simp only [Option.some.injEq] at hr'
            subst hr'
            exact hr
          · cases hr'
      · simp only [List.mem_append, List.mem_singleton] at hr'
        rcases hr' with hr' | rfl
        · exact ih.2 h r' hr'
        · exact hr

/-- The key a decoded case, action or command record holds is the key `ident` reads from its bytes. -/
theorem identKey_rec {t : Nat} (ht : t = 0x72 ∨ t = 0xF3 ∨ t = 0x74) (a : Nat) (k r : Bytes) (hk : k.length = 32) :
    identKey (leBytes 1 t ++ (leBytes 1 a ++ (k ++ r))) = some (t, k) := by
  rcases ht with rfl | rfl | rfl <;> simp [leBytes, identKey, List.take_left' hk]

theorem case_key {x : CaseRec} (h : caseC.WF x) : identKey (caseC.enc x) = some (0x72, x.ck) := by
  obtain ⟨hf, -⟩ := h
  simp only [caseC, fit] at hf
  exact identKey_rec (by decide) x.op x.ck _ hf.2.2.1

theorem action_key {x : ActionRec} (h : actionC.WF x) : identKey (actionC.enc x) = some (0xF3, x.ak) := by
  obtain ⟨hf, -⟩ := h
  simp only [actionC, fit] at hf
  exact identKey_rec (by decide) x.op x.ak _ hf.2.2.1

theorem cmd_key {x : CmdRec} (h : cmdC.WF x) : identKey (cmdC.enc x) = some (0x74, x.cid) := by
  obtain ⟨hf, -⟩ := h
  simp only [cmdC, fit] at hf
  exact identKey_rec (by decide) x.ckind x.cid _ hf.2.2.1

/-! ## Bounds (§9.1)

    The record widths the financial bounds must fit.  `revisionCap` is the largest revision, and `recordCap` the
    largest record number, whose "+1" form (an expected revision, a link to a record) still fits a 5-byte field;
    `attemptCap` is the width of `attempt`.  The financial worker's own `maxRevision` (10,000) and its capacity
    conditions stay as they are until the worker's pin retires (§12 step 3); here they are proved to fit the new
    widths. -/

def revisionCap : Nat := 2 ^ 40 - 2
def recordCap : Nat := 2 ^ 40 - 2
def attemptCap : Nat := 2 ^ 32 - 1

open BlindLedger.Financial in
theorem bounds_fit :
    revisionCap < 256 ^ 5 ∧ revisionCap + 1 < 256 ^ 5 ∧ recordCap + 1 < 256 ^ 5 ∧ revisionCap < 10 ^ 13 ∧
    maxRevision ≤ revisionCap ∧ attemptCap < 256 ^ 4 ∧
    maxRows ≤ attemptCap ∧ maxCents < 256 ^ 8 ∧ maxTime < 256 ^ 8 ∧ maxAuthorityEpoch < 256 ^ 8 ∧
    maxIdBytes < 256 ^ 2 ∧ 4 * (2 + maxIdBytes) + 2 * (2 + maxTextBytes) ≤ 255 * textBytes := by
  decide

end BlindLedger.Gate.Obligations
