import Lean

open Lean

private structure ModuleNode where
  name : Name
  path : String
  imports : Array Name

private partial def collectModules
    (pending : List Name) (seen : List Name) (nodes : Array ModuleNode) : IO (Array ModuleNode) := do
  match pending with
  | [] => pure nodes
  | module :: rest =>
    if module ∈ seen then
      collectModules rest seen nodes
    else
      let path ← findOLean module
      let path ← IO.FS.realPath path
      let (data, _) ← readModuleData path
      let imports := data.imports.map (·.module)
      collectModules (imports.toList ++ rest) (module :: seen)
        (nodes.push { name := module, path := path.toString, imports := imports })

private def moduleNodeJson (node : ModuleNode) : Json :=
  Json.mkObj [
    ("name", Json.str node.name.toString),
    ("path", Json.str node.path),
    ("imports", Json.arr (node.imports.map fun module => Json.str module.toString))
  ]

unsafe def main : IO Unit := do
  let nodes ← collectModules
    [`BlindLedger.Theorems, `BlindLedger.SecurityExecutable, `Lean] [] #[]
  let nodes := nodes.qsort fun left right => left.name.toString < right.name.toString
  let output := Json.mkObj [
    ("format", Json.str "lean-olean-import-graph/v1"),
    ("roots", Json.arr #[
      Json.str "BlindLedger.Theorems",
      Json.str "BlindLedger.SecurityExecutable",
      Json.str "Lean"
    ]),
    ("modules", Json.arr (nodes.map moduleNodeJson))
  ]
  IO.println output.compress
