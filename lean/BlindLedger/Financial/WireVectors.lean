import BlindLedger.Financial.Theorems.Vectors

/-! `wire_vectors` (test-only, not pinned): prints `<name> <hex>` of the Lean-encoded request bytes for fixed inputs.
    `tests/test_wire_vectors.py` encodes the same logical inputs with the live Python encoders and requires equal bytes. -/
namespace BlindLedger.Financial

def wvHex (b : Bytes) : String :=
  String.join (b.map fun x => let d := "0123456789abcdef".toList; s!"{d.getD (x.toNat / 16) '0'}{d.getD (x.toNat % 16) '0'}")

def wvHexVal (c : Char) : Nat := if c.toNat ≥ 65 then c.toNat - 55 else c.toNat - 48

def wvUnhex : List Char → Bytes
  | a :: b :: r => UInt8.ofNat (wvHexVal a * 16 + wvHexVal b) :: wvUnhex r
  | _ => []

/-- The control-pack digest the Python owner computes for `katPack`'s fields (sha3-512 over the canonical JSON). -/
def wvPackDigest : Bytes := wvUnhex "686AAFAB8E362CC65FC25722DADFFAA119BE819001179B7073A2BFA20E1B979C2ECB3D01EB9D62EFC5D0A7171B5BD3F2154C3DB36F9CFF2DE6EADCFEA23747EA".toList

def wvLongId : String := "a" ++ String.ofList (List.replicate 127 'b')
/-- 114 bytes: `"determination:" ++ wvActId` is then exactly `maxIdBytes` (128). -/
def wvActId : String := "a" ++ String.ofList (List.replicate 113 'b')
def wvDetId : String := "determination:" ++ wvActId

def wvFix (i : FinancialInput) : FinancialInput := { i with pack := { i.pack with digest := wvPackDigest } }

def wvInputs : List (String × FinancialInput) := [
  ("blfin02_base", wvFix katBase),
  ("blfin02_authorized", wvFix katAuthorized),
  ("blfin02_live_authorized", wvFix { katAuthorized with context := { katContext with mode := .LIVE } }),
  ("blfin02_reversed_conflict_shadow_restore", wvFix
    { katReversedInput with
      context := { katContext with mode := .SHADOW, provenance := .CONTINUITY_RESTORE }
      evidence := [katCashEvidence, katConflictEvidence, katOffsetEvidence, katReversalEvidence]
      conflicts := [katConflict] }),
  ("blfin02_max_length", wvFix
    { katAuthorized with
      evidence := [{ katCashEvidence with sourceId := wvLongId, sourceVersion := wvLongId, localRef := wvLongId },
                   katOffsetEvidence]
      determinations := [{ katDetermination with determinationId := wvDetId }]
      cases := [{ caseId := wvLongId, obligationId := katContext.obligationId, reason := wvLongId,
                  nextActionOwner := "CASE_OWNER", dueAt := katObligation.dueAt, status := .AUTHORIZED,
                  updatedAt := 1_774_864_800_000 }]
      actions := [{ katAuthorizedAction with actionId := wvActId, determinationId := some wvDetId }] })]

end BlindLedger.Financial

open BlindLedger.Financial in
def main : IO UInt32 := do
  let mut bad : UInt32 := 0
  for (name, input) in wvInputs do
    match encodeFinancialInput input with
    | some w => IO.println s!"{name} {wvHex w}"
    | none => IO.println s!"{name} NONE"; bad := 1
  return bad
