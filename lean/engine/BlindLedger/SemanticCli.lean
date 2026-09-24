import BlindLedger.SemanticExecutable

def main : IO Unit := do
  let stdin ← IO.getStdin
  let data ← BlindLedger.Semantic.readBounded stdin 1_000_001 ByteArray.empty
  IO.println (BlindLedger.Semantic.runBytes data)
