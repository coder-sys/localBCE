import BlindLedger.Gate.Obligations.Format.Records

/-! `obligations_constants`: prints every width, offset and tag of the obligations records as JSON, from the layouts
    of `Format.Records` and nothing else.  `app/right_rail_obligations_constants.json` is its output, committed;
    `tests/test_obligations_format.py` requires the two to be equal, and the host reads that file and holds no number
    of its own.  `domains` gives the digest domains of the fold record by name.

    A field is `{name, offset, width, kind}`: `num` (a little-endian number), `blk` (a block of bytes) or `lit`
    (bytes that must hold the little-endian `value`: the tag, a fixed code, or zeros). -/

namespace BlindLedger.Gate.Obligations.Format.Constants

open BlindLedger.Gate.FactCodec

def q (s : String) : String := "\"" ++ s ++ "\""

def field (name kind : String) (o w : Nat) (extra : String := "") : String :=
  "{\"name\": " ++ q name ++ ", \"offset\": " ++ toString o ++ ", \"width\": " ++ toString w ++ ", \"kind\": " ++
    q kind ++ extra ++ "}"

/-- The fields of a layout from offset `o`; cells take their names in order, literals are named by what they hold. -/
def fields : List Fld → List String → Nat → List String
  | [], _, _ => []
  | .lit w v :: fs, ns, o =>
    field (if o = 0 then "tag" else if v = 0 then "zero" else "fixed") "lit" o w (", \"value\": " ++ toString v) ::
      fields fs ns (o + w)
  | .num w :: fs, n :: ns, o => field n "num" o w :: fields fs ns (o + w)
  | .blk w :: fs, n :: ns, o => field n "blk" o w :: fields fs ns (o + w)
  | _ :: _, [], _ => ["\"a cell without a name\""]

def list (ind : String) (xs : List String) : String :=
  "[\n" ++ ",\n".intercalate (xs.map (ind ++ "  " ++ ·)) ++ "\n" ++ ind ++ "]"

def json : String :=
  let recs := catalog.map fun r =>
    "{\"name\": " ++ q r.name ++ ", \"tag\": " ++ toString (tagOfL r.L) ++ ", \"fields\": " ++
      list "    " (fields r.L r.cells 0) ++ "}"
  "{\n  \"body_bytes\": " ++ toString bodyBytes ++ ",\n  \"record_bytes\": " ++ toString recBytes ++
    ",\n  \"domains\": {\"EVALFIX\": " ++ q domEvalFix ++ ", \"EVIDACC\": " ++ q domEvidAcc ++ "}" ++
    ",\n  \"link\": " ++ list "  " (fields linkL ["prev", "count"] bodyBytes) ++
    ",\n  \"records\": " ++ list "  " recs ++ "\n}\n"

end BlindLedger.Gate.Obligations.Format.Constants

def main : IO Unit := IO.print BlindLedger.Gate.Obligations.Format.Constants.json
