import Lean.Environment
import Lean.Util.Path
import Std.Data.HashMap
import Std.Data.HashSet
import BlindLedger.Sha3Fast
open Lean

/-! Statement pin.  Run (tests/test_statement_pin.py does):
    `lean --run tools/stmt_hash.lean ROOT STATEMENTS TCBLIST Module...`  with LEAN_PATH at the built lib.
    MEMORY: the tool does not import an environment.  It reads the .olean of each named module and of every module they
    import (walking imports, never entering a STOP-RULE root), so the toolchain's own files are never loaded: an
    environment import of the Lean library alone costs about 2 GB.  implemented_by and extern marks are read from the
    attribute entries of the declaring module, which is where the compiler looks them up.
    For each theorem named in STATEMENTS it hashes the type, and for every non-theorem constant reachable from those types
    (through types and values; an inductive through its constructor types) it hashes type and value.  Hashed form: a
    pretty-printer-free node list of the kernel Expr (binder names and mdata dropped, sharing numbered in visit order).
    STOP RULE: a constant declared in a module whose root is Init, Std, Lean, Mathlib, Batteries or Lake is not entered
    (the toolchain pin covers it); a theorem reached below a root is not entered either (proofs are never hashed, so a
    statement or definition edit moves the hash and a proof edit does not, except a proof term inlined in a definition body).
    Hashed per constant: the type and value nodes (binder INFO kept: default/implicit/strict/inst; binder names and mdata
    dropped), definition safety (safe/unsafe/partial), reducibility hints, and for an inductive numParams, numIndices,
    isRec, isUnsafe and the constructor list with constructor types.  A reached opaque, partial, implemented_by or extern
    constant makes the tool FAIL (non-zero exit, constant named): its kernel value is a stub, so hashing it would be a hole.
    The one exception is the compiler's own `I.ctorIdx`, implemented by `I.ctorIdx._impl`, when `ctorIdxPair` confirms the pair.
    Digest is SHA3-512 (BlindLedger.Semantic.Fast).  Output, sorted: `name K hash16` (first 16 hex of that constant's
    hash), `path F hash16` per TCB file, then `tcb full`, `root full`.  tcb and root are authoritative; root is over the
    FULL per-name hashes and the tcb line. -/

namespace StmtHash

/-- Cache key: strict equality (binder names and info count), so a binder-info-only difference is never merged. -/
structure K where
  e : Expr

instance : BEq K := ⟨fun a b => a.e.equal b.e⟩
instance : Hashable K := ⟨fun a => a.e.hash⟩

structure S where
  ids : Std.HashMap K Nat := {}
  nodes : Std.HashMap String Nat := {}
  out : String := ""

def bi : BinderInfo → String
  | .default => "d"
  | .implicit => "i"
  | .strictImplicit => "s"
  | .instImplicit => "c"

def lvl : Level → String
  | .zero => "0"
  | .succ l => "(S " ++ lvl l ++ ")"
  | .max a b => "(M " ++ lvl a ++ " " ++ lvl b ++ ")"
  | .imax a b => "(I " ++ lvl a ++ " " ++ lvl b ++ ")"
  | .param n => "P" ++ n.toString
  | .mvar _ => "?"

partial def ser (e : Expr) : StateM S Nat := do
  match e with
  | .mdata _ x => ser x
  | _ =>
    if let some i := (← get).ids[K.mk e]? then return i
    let line ← match e with
      | .bvar i => pure s!"b {i}"
      | .fvar _ | .mvar _ => pure "?"
      | .sort l => pure s!"s {lvl l}"
      | .const n ls => pure s!"c {n} {" ".intercalate (ls.map lvl)}"
      | .app f a => do let f ← ser f; let a ← ser a; pure s!"a {f} {a}"
      | .lam _ t b i => do let t ← ser t; let b ← ser b; pure s!"l {bi i} {t} {b}"
      | .forallE _ t b i => do let t ← ser t; let b ← ser b; pure s!"p {bi i} {t} {b}"
      | .letE _ t v b _ => do let t ← ser t; let v ← ser v; let b ← ser b; pure s!"t {t} {v} {b}"
      | .lit (.natVal n) => pure s!"n {n}"
      | .lit (.strVal s) => pure s!"z {s.quote}"
      | .proj s i x => do let x ← ser x; pure s!"j {s} {i} {x}"
      | .mdata _ x => pure s!"{(← ser x)}"
    let st ← get
    if let some id := st.nodes[line]? then
      set { st with ids := st.ids.insert (K.mk e) id }
      return id
    let id := st.nodes.size
    set { ids := st.ids.insert (K.mk e) id, nodes := st.nodes.insert line id, out := st.out ++ line ++ "\n" : S }
    return id

/-- Canonical text of a list of exprs (each as its root node id after the shared node list). -/
def canon (es : List Expr) : String :=
  let (roots, st) := (es.mapM ser).run {}
  st.out ++ "r " ++ " ".intercalate (roots.map toString)

def hex (b : ByteArray) : String :=
  b.foldl (init := "") fun s x =>
    let d := Nat.toDigits 16 x.toNat
    s ++ (if d.length < 2 then "0" else "") ++ String.ofList d

def sha (s : String) : String := hex (BlindLedger.Semantic.sha3_512Fast s.toUTF8)

def stopRoots : List Name := [`Init, `Std, `Lean, `Mathlib, `Batteries, `Lake]

/-- Every constant of the non-toolchain modules, with their implemented_by and extern marks.  A constant below a stop
    root is absent, which is the same as stopped. -/
structure Db where
  consts : Std.HashMap Name ConstantInfo := {}
  owner : Std.HashMap Name Name := {}
  implBy : Std.HashMap Name Name := {}
  extern : Std.HashSet Name := {}

unsafe def load (mods : List String) : IO Db := do
  let mut db : Db := {}
  let mut seen : Std.HashSet Name := {}
  let mut todo : Array Name := (mods.map String.toName).toArray
  while h : todo.size > 0 do
    let m := todo.back
    todo := todo.pop
    if seen.contains m || stopRoots.contains m.getRoot then continue
    seen := seen.insert m
    let (data, _) ← readModuleData (← findOLean m)
    for n in data.constNames, ci in data.constants do
      if let some prev := db.owner[n]? then
        -- importModules admits one repeat: the same theorem statement realized in two modules (equation lemmas)
        let same := match db.consts[n]?, ci with
          | some (.thmInfo a), .thmInfo b => a.type == b.type && a.levelParams == b.levelParams && a.all == b.all
          | _, _ => false
        unless same do
          throw <| IO.userError s!"environment already contains {n}: declared in both {prev} and {m}"
      else
        db := { db with consts := db.consts.insert n ci, owner := db.owner.insert n m }
    for (ext, es) in data.entries do
      if ext == `Lean.Compiler.implementedByAttr then
        for (n, ib) in (unsafeCast es : Array (Name × Name)) do db := { db with implBy := db.implBy.insert n ib }
      else if ext == `Lean.externAttr then
        for (n, _) in (unsafeCast es : Array (Name × Name)) do db := { db with extern := db.extern.insert n }
    todo := todo ++ data.imports.map (·.module)
  return db

def safety : DefinitionSafety → String
  | .safe => "safe"
  | .unsafe => "unsafe"
  | .partial => "partial"

def hint : ReducibilityHints → String
  | .opaque => "o"
  | .abbrev => "a"
  | .regular n => s!"r{n}"

-- CTORIDX-PAIR-BEGIN (tools/stmt_hash.lean carries the same text; tests/test_tcb_gate.py compares them)
/-! Lean 4.36 (Lean/Meta/Constructions/CtorIdx.lean, `mkCtorIdx` and `mkCtorIdxImpl`) gives every inductive type `I` with more than
    one constructor a function `I.ctorIdx : I → Nat`, defined by `I.casesOn`, and makes the compiler run the unsafe
    `I.ctorIdx._impl`, which reads the constructor tag with `getObjTagNat`.  The pair is accepted by its structure and never by its
    name: any code can define a `Foo.ctorIdx._impl` with another body. -/

/-- Strips `k` lambdas, leaving loose variables; `none` if there are fewer. -/
def stripLams : Expr → Nat → Option Expr
  | e, 0 => some e
  | .lam _ _ b _, k + 1 => stripLams b k
  | _, _ => none

/-- `fun xs x => getObjTagNat.{l} (I xs) x`, built from the binders of `ctorIdx`'s type (`k` of them, the last is `x`). -/
def tagReader (l : Level) : Expr → Nat → Expr
  | .forallE n t b bi, k + 1 =>
    .lam n t (if k == 0 then mkApp2 (mkConst ``getObjTagNat [l]) (t.liftLooseBVars 0 1) (.bvar 0) else tagReader l b k) bi
  | e, _ => e

/-- The value `mkCtorIdx` gives `I.ctorIdx` for `I` with several constructors: `fun params indices x => I.casesOn params
    (fun indices x => Nat) indices x (fun fields => 0) (fun fields => 1) ...`, with the fields' binder types left free. -/
def casesOnShape (find? : Name → Option ConstantInfo) (info : InductiveVal) (v : Expr) : Bool :=
  let n := info.numParams + info.numIndices
  match stripLams v (n + 1) with
  | none => false
  | some b =>
    let args := b.getAppArgs
    let us := info.levelParams.map mkLevelParam
    b.getAppFn == mkConst (Name.mkStr info.name "casesOn") (Level.one :: us)
      && args.size == info.numParams + 1 + info.numIndices + 1 + info.ctors.length
      && (List.range info.numParams).all (fun i => args[i]! == .bvar (n - i))
      && (stripLams args[info.numParams]! (info.numIndices + 1)) == some (mkConst ``Nat)
      && (List.range info.numIndices).all (fun j => args[info.numParams + 1 + j]! == .bvar (n - info.numParams - j))
      && args[info.numParams + 1 + info.numIndices]! == .bvar 0
      && (info.ctors.zipIdx).all fun (c, k) =>
        match find? c with
        | some (.ctorInfo ci) => (stripLams args[info.numParams + 2 + info.numIndices + k]! ci.numFields) == some (.lit (.natVal ci.cidx))
        | _ => false

/-- `I.ctorIdx` and `I.ctorIdx._impl` are exactly what the compiler builds for the inductive type `I` with several constructors:
    `I.ctorIdx` is a safe definition by `I.casesOn`, implemented by `I.ctorIdx._impl` and by nothing else, and the unsafe
    `I.ctorIdx._impl` has the same type and levels and is the tag read of `ctorIdx`'s own binders. -/
def ctorIdxPair (find? : Name → Option ConstantInfo) (implBy? : Name → Option Name) (indName : Name) : Bool :=
  match find? indName, find? (Name.mkStr indName "ctorIdx"), find? (Name.mkStr (Name.mkStr indName "ctorIdx") "_impl") with
  | some (.inductInfo info), some (.defnInfo d), some (.defnInfo i) =>
    let n := info.numParams + info.numIndices + 1
    let rec sortOf : Expr → Nat → Option Level
      | .sort l, 0 => some l
      | .forallE _ _ b _, k + 1 => sortOf b k
      | _, _ => none
    info.ctors.length > 1 && d.safety == .safe && i.safety == .unsafe
      && implBy? d.name == some i.name
      && d.levelParams == info.levelParams && i.levelParams == info.levelParams
      && i.type.eqv d.type
      && casesOnShape find? info d.value
      && (match sortOf info.type (n - 1) with
          | some l => i.value.eqv (tagReader l d.type n)
          | none => false)
  | _, _, _ => false

/-- A constant `c` carrying escape hatch `k` that is half of a compiler-built `ctorIdx` pair (see `ctorIdxPair`). -/
def isCtorIdxPair (find? : Name → Option ConstantInfo) (implBy? : Name → Option Name) (c : Name) (k : String) : Bool :=
  match c with
  | .str ind "ctorIdx" => k == "implemented_by" && ctorIdxPair find? implBy? ind
  | .str (.str ind "ctorIdx") "_impl" => k == "unsafe" && ctorIdxPair find? implBy? ind
  | _ => false
-- CTORIDX-PAIR-END

/-- One reached constant: (line prefix, full hash, constants it points at), or an error naming a stub constant.
    Theorems below a root are skipped. -/
def entry (db : Db) (c : Name) (isRoot : Bool) : Except String (Option (String × String × Array Name)) :=
  if let some ib := db.implBy[c]? then
    if isCtorIdxPair (db.consts[·]?) (db.implBy[·]?) c "implemented_by" then
      -- the compiler's tag read: `ctorIdx`'s kernel value is its `casesOn` definition, which the check above confirms
      match db.consts[c]? with
      | some (.defnInfo v) => pure (some (s!"{c} D {safety v.safety} {hint v.hints}", sha (canon [v.type, v.value]), v.type.getUsedConstants ++ v.value.getUsedConstants))
      | _ => throw s!"reached constant {c} is implemented_by {ib}: its kernel value is not the compiled code"
    else throw s!"reached constant {c} is implemented_by {ib}: its kernel value is not the compiled code"
  else if db.extern.contains c then
    throw s!"reached constant {c} is extern: its C text is not in the pinned Expr"
  else match db.consts[c]? with
  | some (.thmInfo v) => pure (if isRoot then some (s!"{c} T", sha (canon [v.type]), v.type.getUsedConstants) else none)
  | some (.defnInfo v) =>
    if v.safety == .partial then throw s!"reached constant {c} is partial: its kernel value is a default inhabitant"
    else pure (some (s!"{c} D {safety v.safety} {hint v.hints}", sha (canon [v.type, v.value]),
      v.type.getUsedConstants ++ v.value.getUsedConstants))
  | some (.opaqueInfo _) => throw s!"reached constant {c} is opaque: its kernel value is a stub"
  | some (.axiomInfo v) => pure (some (s!"{c} A", sha (canon [v.type]), v.type.getUsedConstants))
  | some (.quotInfo v) => pure (some (s!"{c} Q", sha (canon [v.type]), #[]))
  | some (.inductInfo v) =>
    let tys := v.type :: v.ctors.filterMap fun k => (db.consts[k]?).map (·.type)
    pure (some (s!"{c} I {v.numParams} {v.numIndices} {v.isRec} {v.isUnsafe} {v.ctors}", sha (canon tys),
      (tys.foldl (fun a t => a ++ t.getUsedConstants) #[])))
  | some (.ctorInfo v) => pure (some ("", "", #[v.induct]))
  | some (.recInfo _) => pure (some ("", "", #[c.getPrefix]))
  | none => pure none

def lf (b : ByteArray) : ByteArray := ⟨b.data.filter (· != 13)⟩

end StmtHash
open StmtHash

unsafe def main (args : List String) : IO UInt32 := do
  let root :: stmts :: tcb :: mods := args | throw <| IO.userError "usage: ROOT STATEMENTS TCBLIST Module..."
  initSearchPath (← findSysroot)
  let db ← load mods
  let names := ((← IO.FS.readFile stmts).replace "\r" "").splitOn "\n" |>.filter (· ≠ "")
  let mut seen : Std.HashSet Name := {}
  let mut todo : Array Name := #[]
  let mut lines : Array (String × String) := #[]
  for n in names do
    let c := n.toName
    let some ci := db.consts[c]? | throw <| IO.userError s!"unknown name: {n}"
    -- an axiom-checked definition is pinned like any definition a theorem reaches
    unless ci.isTheorem do
      todo := todo.push c
      continue
    seen := seen.insert c
    match entry db c true with
    | .error m => throw <| IO.userError m
    | .ok none => throw <| IO.userError s!"unreachable {n}"
    | .ok (some (p, h, us)) => lines := lines.push (p, h); todo := todo ++ us
  while h : todo.size > 0 do
    let c := todo.back
    todo := todo.pop
    if seen.contains c then continue
    seen := seen.insert c
    match entry db c false with
    | .error m => throw <| IO.userError m
    | .ok none => continue
    | .ok (some (p, h, us)) =>
      unless p == "" do lines := lines.push (p, h)
      todo := todo ++ us
  lines := lines.qsort (fun a b => a.1 ++ " " ++ a.2 < b.1 ++ " " ++ b.2)
  let files := (((← IO.FS.readFile (root ++ "/" ++ tcb)).replace "\r" "").splitOn "\n" |>.filter (· ≠ "")).toArray.qsort (· < ·)
  let mut tl : Array (String × String) := #[]
  for f in files do tl := tl.push (f, sha (String.fromUTF8! (lf (← IO.FS.readBinFile (root ++ "/" ++ f)))))
  let tcbLine := s!"tcb {sha ("\n".intercalate (tl.toList.map fun (f, h) => s!"{f} {h}"))}"
  for (p, h) in lines do IO.println s!"{p} {h.take 16}"
  for (f, h) in tl do IO.println s!"{f} F {h.take 16}"
  IO.println tcbLine
  IO.println s!"root {sha ("\n".intercalate ((lines.map fun (p, h) => s!"{p} {h}").push tcbLine).toList)}"
  return 0
