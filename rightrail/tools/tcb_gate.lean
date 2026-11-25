import Lean
open Lean

/-! The TCB gate (Constitution V.3, XI.2; lean-expansion-plan item 6).  Run from `lean/`:
    `lake env lean --run ../tools/tcb_gate.lean exe=Root.Module ...`  (tests/test_tcb_gate.py does); `--list` also names every allowlisted constant.
    For each pinned exe it walks every constant reachable from `main`, through types and values (the kernel view
    that `#print axioms` takes) and through the compiled code (the IR call graph plus `implemented_by` targets,
    the view of what actually runs; a `partial` def is walked through its `_unsafe_rec` body), and from every startup
    initializer and `@[csimp]` theorem.  It exits 1 on any axiom outside `standardAxioms` and `axiomsAllowed`
    (so `sorryAx` and `Lean.ofReduceBool`, the axiom behind `native_decide`, fail), on any partial,
    implemented_by, extern, opaque, unsafe, fixpoint (`partial_fixpoint`) or loop (`while`/`repeat`, `IO.iterate`, `for` over a `Stream`) constant that `allowed` does not name, on `main` without compiled code, and
    on an `Init` or `Std` module that resolves outside the toolchain.  The one thing accepted by structure rather than by name is the
    compiler's own `I.ctorIdx` with its unsafe `I.ctorIdx._impl` (`ctorIdxPair`). -/

/-- Lean's own logic. -/
def standardAxioms : List Name := [`propext, `Classical.choice, `Quot.sound]

/-- Non-standard axioms a pinned closure may reach, each with its reason, and only from a constant declared in `Init`/`Std`. -/
def axiomsAllowed : List (Name × String) :=
  [(`lcProof, "core placeholder proof inside `unsafeCast`, reached through `List.attachWith`'s implementation")]

/-- One allowlist entry: `name` is a whole module family (`module := true`: every constant declared in a module
    under that prefix) or one exact constant, and `kinds` are the escape hatches it may carry. -/
structure Allow where
  name : Name
  module : Bool
  kinds : List String
  reason : String
  deriving Inhabited

def core (m : Name) : Allow :=
  { name := m, module := true, kinds := ["extern", "implemented_by", "opaque", "unsafe", "partial", "loop"],
    reason := s!"toolchain `{m}`: compiler and C runtime primitives, trusted as the pinned toolchain (tools/tcb_toolchain.txt)" }

/-- THE ALLOWLIST.  Anything else is a violation.  A `VIOLATION-TODO` reason marks a real hole in a pinned closure:
    it passes the gate only so a reviewer can decide, and the report names it. -/
def allowed : List Allow := [
  core `Init, core `Std,
  { name := `BlindLedger.Gate.Obligations.openExclusive, module := false, kinds := ["extern", "opaque"],
    reason := "obligations_shard log open with no sharing: CRT _wsopen (_SH_DENYRW) on a path converted by kernel32 MultiByteToWideChar, asm-labelled C, no decision logic" },
  { name := `BlindLedger.Gate.Flat.Io.pgOpen, module := false, kinds := ["extern", "opaque"],
    reason := "gate_engine flat history file open: CRT _wopen on a path converted by kernel32 MultiByteToWideChar, asm-labelled C, no decision logic" },
  { name := `BlindLedger.Gate.Flat.Io.pgRead, module := false, kinds := ["extern", "opaque"],
    reason := "gate_engine flat history file positioned page read: CRT _lseeki64 + _read, asm-labelled C, no decision logic" },
  { name := `BlindLedger.Gate.Flat.Io.pgWrite, module := false, kinds := ["extern", "opaque"],
    reason := "gate_engine flat history file positioned page write: CRT _lseeki64 + _write, asm-labelled C, no decision logic" },
  { name := `BlindLedger.Gate.Flat.Io.pgSync, module := false, kinds := ["extern", "opaque"],
    reason := "gate_engine flat history file CRT _commit(fd), asm-labelled C, no decision logic" },
  { name := `BlindLedger.Gate.Flat.Io.pgTrunc, module := false, kinds := ["extern", "opaque"],
    reason := "gate_engine flat history file CRT _chsize_s(fd, len), asm-labelled C, no decision logic" },
  { name := `BlindLedger.Gate.Flat.Io.pgClose, module := false, kinds := ["extern", "opaque"],
    reason := "gate_engine flat history file CRT _close(fd), asm-labelled C, no decision logic" },
  { name := `BlindLedger.Gate.Flat.Io.pgReadAt, module := false, kinds := ["extern", "opaque"],
    reason := "obligations_shard log record read at an offset: kernel32 ReadFile with an OVERLAPPED offset, asm-labelled C, no decision logic" },
  { name := `BlindLedger.Financial.serveWorker, module := false, kinds := ["fixpoint"],
    reason := "the worker's frame loop, unbounded by design (answers until end of input); kernel-visible body, serveWorker_run and serveWorker_stateless" }]

def moduleOf (env : Environment) (c : Name) : Name :=
  match env.getModuleIdxFor? c with
  | some i => env.header.moduleNames[i.toNat]!
  | none => .anonymous

def trusted (m : Name) : Bool := (`Init).isPrefixOf m || (`Std).isPrefixOf m

/-- Init/Std `partial` helpers that loop on a caller's continuation: project code that names one is an unbounded loop (`IO.iterate`;
    `for x in stream`, whose `Std.Stream.forIn.visit` runs while `next?` answers `some`).  Init and Std themselves may use them. -/
def loopHelpers : List Name := [`IO.iterate, `Std.instForInOfMonadOfStream, `Std.Stream.forIn]

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

/-- `c._unsafe_rec` is the body of partial def `c`: walked for what it reaches, but `c`'s own `partial` entry covers it. -/
def kindsOf (env : Environment) (c : Name) (ci : ConstantInfo) : Array String := Id.run do
  let mut ks := #[]
  if (Compiler.isUnsafeRecName? c).isSome then return ks
  if ci.isPartial || (ci matches .opaqueInfo _ && env.contains (Compiler.mkUnsafeRecName c)) then ks := ks.push "partial"
  else if ci matches .opaqueInfo _ then ks := ks.push "opaque"
  if ci.isUnsafe then ks := ks.push "unsafe"
  if let some v := ci.value? then
    let used := v.getUsedConstants
    if used.contains ``Lean.Order.fix then ks := ks.push "fixpoint"  -- partial_fixpoint; WF recursion uses `WellFounded.fix`
    if used.contains ``Lean.Loop.mk || used.contains ``repeatM || (!trusted (moduleOf env c) && loopHelpers.any used.contains) then
      ks := ks.push "loop"  -- `while`/`repeat`/`IO.iterate`/`for` over a stream: an unbounded loop hidden behind Init's `partial`
  if (Compiler.getImplementedBy? env c).isSome then ks := ks.push "implemented_by"
  if isExtern env c || (match IR.findEnvDecl env c with | some (.extern ..) => true | _ => false) then ks := ks.push "extern"
  return ks

partial def irCallees (b : IR.FnBody) (acc : Array Name) : Array Name :=
  match b with
  | .vdecl _ _ e k => irCallees k (match e with | .fap c _ | .pap c _ => acc.push c | _ => acc)
  | .jdecl _ _ v k => irCallees k (irCallees v acc)
  | .case _ _ _ alts => alts.foldl (fun a alt => irCallees alt.body a) acc
  | .set _ _ _ k | .setTag _ _ k | .uset _ _ _ k | .sset _ _ _ _ _ k | .inc _ _ _ _ k | .dec _ _ _ _ k | .del _ k =>
    irCallees k acc
  | .ret .. | .jmp .. | .unreachable => acc

/-- Kernel edges (types and values), `implemented_by` targets, and the compiled code's callees, kept apart. -/
def edges (env : Environment) (c : Name) : Array Name × Array Name := Id.run do
  let mut out : Array Name := #[]
  match env.find? c with
  | some (.defnInfo v) | some (.thmInfo v) | some (.opaqueInfo v) => out := v.type.getUsedConstants ++ v.value.getUsedConstants
  | some (.axiomInfo v) | some (.ctorInfo v) | some (.recInfo v) => out := v.type.getUsedConstants
  | some (.inductInfo v) => out := v.type.getUsedConstants ++ v.ctors.toArray
  | _ => pure ()
  if let some t := Compiler.getImplementedBy? env c then out := out.push t
  if env.contains (Compiler.mkUnsafeRecName c) then out := out.push (Compiler.mkUnsafeRecName c)
  let calls := match IR.findEnvDecl env c with | some (.fdecl (body := b) ..) => irCallees b #[] | _ => #[]
  return (out, calls)

/-- Every constant reachable from `roots`, and the set the compiled code calls. -/
partial def walk (env : Environment) (roots : Array Name) : Array Name × NameSet := Id.run do
  let mut seen : NameSet := {}
  let mut called : NameSet := {}
  let mut order := #[]
  let mut todo := roots
  while !todo.isEmpty do
    let c := todo.back!
    todo := todo.pop
    if seen.contains c then continue
    seen := seen.insert c
    order := order.push c
    let (kernel, calls) := edges env c
    called := calls.foldl (·.insert ·) called
    todo := todo ++ kernel ++ calls
  return (order, called)

/-- Every `Init.*`/`Std.*` module the environment imported must come from the toolchain's `lib/lean`. -/
def strayModules (env : Environment) (sysroot : System.FilePath) : IO (Array String) := do
  let norm (p : System.FilePath) : IO String := return (← IO.FS.realPath p).toString.replace "\\" "/" |>.toLower
  let lib ← norm (sysroot / "lib" / "lean")
  let mut out := #[]
  for m in env.header.moduleNames.filter trusted do
    let f ← norm (← findOLean m)
    unless f.startsWith (lib ++ "/") do out := out.push s!"module {m} resolves outside the toolchain: {f}"
  return out

def matches? (env : Environment) (c : Name) (k : String) (e : Allow) : Bool :=
  k ∈ e.kinds && (if e.module then e.name.isPrefixOf (moduleOf env c) else e.name == c)

def checkExe (list : Bool) (sysroot : System.FilePath) (csimps : Array Compiler.CSimp.Entry) (exe root : String) : IO Bool := do
  let env ← importModules #[{ module := root.toName }] {}
  -- Roots: `main`; everything that runs at startup (`[init]` and `[builtin_init]` declarations and their init
  -- functions, bare `initialize do ...` included); every `@[csimp]` theorem, whose proof licenses the compiler's replacement of one constant by another.
  let inits := (env.constants.fold (init := #[]) fun acc c _ => if hasInitAttr env c || isIOUnitInitFn env c then acc.push c else acc).qsort Name.lt
  let initFns := inits.filterMap (getInitFnNameFor? env)
  -- The `@[csimp]` entries each imported module outside Init/Std stored in its .olean: `importModules` without `loadExts`
  -- still records every module's extension entries, read here as data, so no project initializer runs.
  let mut own : Array Compiler.CSimp.Entry := #[]
  for i in [:env.header.moduleNames.size] do
    unless trusted env.header.moduleNames[i]! do
      for e in Compiler.CSimp.ext.ext.getModuleEntries env i do
        own := own.push (match e with | .global e | .scoped _ e => e)
  let csimps := csimps ++ own
  -- A `local csimp` entry is never stored, yet it changes how the rest of its module compiles, and `csimp` accepts any constant (theorem,
  -- axiom or definition) whose type is an equality of two constants (`@c1 = @c2`). So every such constant a non-Init/Std module declares
  -- is a root too, whatever its attributes.
  let mut eqConsts : Array Name := #[]
  for i in [:env.header.moduleNames.size] do
    unless trusted env.header.moduleNames[i]! do
      for ci in env.header.moduleData[i]!.constants do
        if let some (_, l, r) := ci.type.eq? then
          if l.isConst && r.isConst then eqConsts := eqConsts.push ci.name
  let (order, called) := walk env (#[`main] ++ inits ++ initFns ++ csimps.map (·.thmName) ++ eqConsts)
  let cs := order.qsort Name.lt
  let mut axs : Array Name := #[]
  let mut counts : Array Nat := allowed.toArray.map fun _ => 0
  let mut bad : Array String := ← strayModules env sysroot
  if (IR.findEnvDecl env `main).isNone then bad := bad.push "no compiled code for main"
  let mut todos : Array String := #[]
  let mut pairs := 0
  for c in cs do
    let some ci := env.find? c | continue
    if ci matches .axiomInfo _ then
      axs := axs.push c
      if c ∈ standardAxioms then pure ()
      else if axiomsAllowed.any (·.1 == c) then
        for r in cs do
          if (edges env r).1.contains c && !trusted (moduleOf env r) then bad := bad.push s!"axiom {c} [used by {r} in {moduleOf env r}]"
      else bad := bad.push s!"axiom {c}"
    for k in kindsOf env c ci do
      -- A toolchain (`Init`/`Std`) pair is accepted here too, by the same structure; the `core` entry would also cover it.
      if isCtorIdxPair env.find? (Compiler.getImplementedBy? env) c k then
        if k == "unsafe" then pairs := pairs + 1  -- one per pair: its `_impl` half
        if list then IO.println s!"    {k} {c}"
        continue
      match allowed.findIdx? (matches? env c k) with
      | some i =>
        if allowed[i]!.reason.startsWith "VIOLATION-TODO" then todos := todos.push s!"{k} {c}"
        else counts := counts.set! i (counts[i]! + 1)
        if list then IO.println s!"    {k} {c}"
      | none => bad := bad.push s!"{k} {c} [{moduleOf env c}]"
  let project := inits.filter fun c => (`BlindLedger).isPrefixOf (moduleOf env c)
  IO.println s!"{exe}: {cs.size} constants walked; axioms {axs.toList}"
  IO.println s!"  startup initializers: {inits.size}, {project.size} in BlindLedger {project.toList}"
  let stale := (csimps.filter (called.contains ·.fromDeclName)).map (·.fromDeclName)
  IO.println s!"  csimp: {csimps.size} theorems walked, {own.size} from project modules {(own.map (·.thmName)).qsort Name.lt |>.toList}; {eqConsts.size} constant-equality constants also rooted; replaced constants still called by compiled code: {stale.toList}"
  for (e, n) in allowed.zip counts.toList do
    if n > 0 then IO.println s!"  allowlist {e.name}{if e.module then ".*" else ""} x{n}: {e.reason}"
  if pairs > 0 then
    IO.println s!"  compiler-built ctorIdx pairs x{pairs}: `I.ctorIdx` by `I.casesOn` and its unsafe `I.ctorIdx._impl` tag read, each pair accepted by structure (Lean/Meta/Constructions/CtorIdx.lean)"
  for t in todos do IO.println s!"  VIOLATION-TODO {t}"
  for b in bad do IO.println s!"  VIOLATION {b}"
  IO.println s!"  {bad.size} violations"
  return bad.isEmpty

/-- Extension state is loaded only with `loadExts`, which would run a module's initializers, so the core `@[csimp]` table is
    read from the toolchain's own `Init` and `Std`; `checkExe` adds the project's entries from its modules' stored data. -/
unsafe def main (args : List String) : IO UInt32 := do
  let sysroot ← findSysroot
  initSearchPath sysroot
  enableInitializersExecution
  let core ← importModules #[{ module := `Init }, { module := `Std }] {} (loadExts := true)
  let stray ← strayModules core sysroot
  for s in stray do IO.eprintln s
  let csimps : Array Compiler.CSimp.Entry := (Compiler.CSimp.ext.getState core).map.fold (init := #[]) fun acc _ e => acc.push e
  let mut ok := stray.isEmpty
  for a in args.filter (· != "--list") do
    match a.splitOn "=" with
    | [exe, root] => ok := (← checkExe (args.contains "--list") sysroot csimps exe root) && ok
    | _ => throw <| IO.userError s!"expected exe=Module, got {a}"
  return if ok then 0 else 1
