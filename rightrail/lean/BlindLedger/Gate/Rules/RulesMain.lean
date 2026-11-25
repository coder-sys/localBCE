import BlindLedger.Gate.Rules.Run

namespace BlindLedger.Gate.Rules.RulesMain
open BlindLedger.Gate.Rules

/-- SHA3-512 of the sources this runner was built from, CRLF read as LF; the unit test recomputes
    it from the files, so a stale runner fails that test whatever its file times. -/
def source : String := Run.hexOf (BlindLedger.Semantic.sha3_512Fast (String.join [include_str "Spec.lean",
  include_str "Fast.lean", include_str "Run.lean",
  include_str "RulesMain.lean", include_str "RulesShip.lean", include_str "../Engine/OneProc.lean",
  include_str "../OnepIndex.lean", include_str "../Anchor.lean", include_str "../Spec.lean",
  include_str "../../Sha3.lean", include_str "../../Sha3Fast.lean", include_str "../../Sha3Quick.lean",
  include_str "../../Sha3Lanes.lean", include_str "../Engine3/Sha3Fused.lean",
  include_str "../MlDsa87.lean", include_str "../Payer.lean", include_str "../Producer.lean", include_str "../Verify.lean", include_str "../Batch.lean",
  include_str "../PublishSpec.lean", include_str "../Cosign/Codec.lean", include_str "../Cosign/Chain.lean", include_str "../Cosign/Verify.lean",
  include_str "../Cosign/Link.lean", include_str "../Cosign/Install.lean",
  include_str "../Flat/Model.lean",
  include_str "../Flat/Io.lean", include_str "../Flat/Bin.lean", include_str "../Flat/Chunk.lean",
  include_str "../Flat/Store.lean", include_str "../Flat/ChunkIo.lean", include_str "../Flat/Worker.lean",
  include_str "../Authority.lean", include_str "../Flat/StoreLog.lean", include_str "../Flat/StoreTombs.lean", include_str "../Frame/Fast.lean",
  include_str "../Frame/Spec.lean", include_str "../Keyset.lean", include_str "Request.lean", include_str "../SnapshotV2.lean",
  include_str "../CauseRelease.lean", include_str "../AuthorityLaws.lean", include_str "../ParseLaws.lean",
  include_str "../CheckpointTheorems.lean", include_str "Bypass.lean", include_str "DecideLayer.lean", include_str "ExactDuplicate.lean",
  include_str "../../../lakefile.toml",
  include_str "../../../lean-toolchain"]).crlfToLf.toUTF8)

/-- The one-shot `gate_rules <vectors>`: the vector text through `Run.runText`, its lines printed. -/
def run (args : List String) : IO UInt32 := do
  IO.println s!"RULES_SOURCE {source}"
  let [path] := args | do IO.eprintln "RULES_VECTORS=USAGE gate_rules <path>"; return 2
  let (out, pass) := Run.runText (← IO.FS.readFile path)
  out.forM IO.println
  return (if pass then 0 else 1)

end BlindLedger.Gate.Rules.RulesMain