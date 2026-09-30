import Lean
open Lean

/-! The TCB gate (Constitution V.3, XI.2; lean-expansion-plan item 6).  Run from `lean/`:
    `lake env lean --run ../tools/tcb_gate.lean exe=Root.Module ...`  (tests/test_tcb_gate.py does); `--list` also names every allowlisted constant.
    For each pinned exe it walks every constant reachable from `main`, through types and values (the kernel view
    that `#print axioms` takes) and through the compiled code (the IR call graph plus `implemented_by` targets,
    the view of what actually runs), and from every startup initializer and `@[csimp]` theorem.  It exits 1 on any axiom outside `standardAxioms` and `axiomsAllowed`
    (so `sorryAx` and `Lean.ofReduceBool`, the axiom behind `native_decide`, fail), and on any partial,
    implemented_by, extern, opaque or unsafe constant that `allowed` does not name. -/

/-- Lean's own logic. -/
def standardAxioms : List Name := [`propext, `Classical.choice, `Quot.sound]

/-- Non-standard axioms a pinned closure may reach, each with its reason. -/
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
  { name := m, module := true, kinds := ["extern", "implemented_by", "opaque", "unsafe", "partial"],
    reason := s!"toolchain `{m}`: compiler and C runtime primitives, trusted as the pinned toolchain (tools/tcb_toolchain.txt)" }

/-- THE ALLOWLIST.  Anything else is a violation.  A `VIOLATION-TODO` reason marks a real hole in a pinned closure:
    it passes the gate only so the lead can decide, and the report names it. -/
def allowed : List Allow := [
  core `Init, core `Std,
  { name := `BlindLedger.Financial.WorkerCli.reserveArena, module := false, kinds := ["extern", "opaque"],
    reason := "the worker's mimalloc arena reservation, one C call, no decision logic" },
  { name := `BlindLedger.Financial.WorkerCli.serve, module := false, kinds := ["partial"],
    reason := "VIOLATION-TODO: the worker's stdin loop is partial; M1.5 makes it total (lean-expansion-plan item 5)" },
  { name := `BlindLedger.Financial.WorkerCli.readExact, module := false, kinds := ["partial"],
    reason := "VIOLATION-TODO: the frame reader loop is partial; M1.5 makes it total (lean-expansion-plan item 5)" },
  { name := `BlindLedger.Financial.CorrectionTransition.Runtime.readFinancialBounded, module := false, kinds := ["partial"],
    reason := "VIOLATION-TODO: the correction exe's request reader loop is partial; needs a fuel bound or a total loop" },
  { name := `BlindLedger.Gate.MlDsa87.rejNtt, module := false, kinds := ["partial"],
    reason := "VIOLATION-TODO: ML-DSA rejection sampling in gate_verify's closure is partial; needs a fuel bound" },
  { name := `BlindLedger.Gate.MlDsa87.sampleInBall, module := false, kinds := ["partial"],
    reason := "VIOLATION-TODO: ML-DSA challenge sampling in gate_verify's closure is partial; needs a fuel bound" }]

def kindsOf (env : Environment) (c : Name) (ci : ConstantInfo) : Array String := Id.run do
  let mut ks := #[]
  if ci.isPartial || (ci matches .opaqueInfo _ && env.contains (Compiler.mkUnsafeRecName c)) then ks := ks.push "partial"
  else if ci matches .opaqueInfo _ then ks := ks.push "opaque"
  if ci.isUnsafe then ks := ks.push "unsafe"
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
  | _ => acc

/-- Kernel edges (types and values), `implemented_by` targets, and the compiled code's callees, kept apart. -/
def edges (env : Environment) (c : Name) : Array Name × Array Name := Id.run do
  let mut out : Array Name := #[]
  match env.find? c with
  | some (.defnInfo v) | some (.thmInfo v) | some (.opaqueInfo v) => out := v.type.getUsedConstants ++ v.value.getUsedConstants
  | some (.axiomInfo v) | some (.ctorInfo v) | some (.recInfo v) => out := v.type.getUsedConstants
  | some (.inductInfo v) => out := v.type.getUsedConstants ++ v.ctors.toArray
  | _ => pure ()
  if let some t := Compiler.getImplementedBy? env c then out := out.push t
  let calls := match IR.findEnvDecl env c with | some (.fdecl (body := b) ..) => irCallees b #[] | _ => #[]
  return (out, calls)

def moduleOf (env : Environment) (c : Name) : Name :=
  match env.getModuleIdxFor? c with
  | some i => env.header.moduleNames[i.toNat]!
  | none => .anonymous

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

def matches? (env : Environment) (c : Name) (k : String) (e : Allow) : Bool :=
  k ∈ e.kinds && (if e.module then e.name.isPrefixOf (moduleOf env c) else e.name == c)

def checkExe (list : Bool) (csimps : Array Compiler.CSimp.Entry) (exe root : String) : IO Bool := do
  let env ← importModules #[{ module := root.toName }] {}
  -- Roots: `main`; everything that runs at startup (`[init]` and `[builtin_init]` declarations and their init
  -- functions); every `@[csimp]` theorem, whose proof licenses the compiler's replacement of one constant by another.
  let inits := (env.constants.fold (init := #[]) fun acc c _ => if hasInitAttr env c then acc.push c else acc).qsort Name.lt
  let initFns := inits.filterMap (getInitFnNameFor? env)
  let (order, called) := walk env (#[`main] ++ inits ++ initFns ++ csimps.map (·.thmName))
  let cs := order.qsort Name.lt
  let mut axs : Array Name := #[]
  let mut counts : Array Nat := allowed.toArray.map fun _ => 0
  let mut bad : Array String := #[]
  let mut todos : Array String := #[]
  for c in cs do
    let some ci := env.find? c | continue
    if ci matches .axiomInfo _ then
      axs := axs.push c
      unless c ∈ standardAxioms || axiomsAllowed.any (·.1 == c) do bad := bad.push s!"axiom {c}"
    for k in kindsOf env c ci do
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
  IO.println s!"  csimp: {csimps.size} theorems walked; replaced constants still called by compiled code: {stale.toList}"
  for (e, n) in allowed.zip counts.toList do
    if n > 0 then IO.println s!"  allowlist {e.name}{if e.module then ".*" else ""} x{n}: {e.reason}"
  for t in todos do IO.println s!"  VIOLATION-TODO {t}"
  for b in bad do IO.println s!"  VIOLATION {b}"
  IO.println s!"  {bad.size} violations"
  return bad.isEmpty

/-- Extension state is loaded only with `loadExts`, which would run a module's initializers, so the `@[csimp]` table is
    read from the toolchain's own `Init` and `Std` (no project code runs); a project `@[csimp]` fails the Python test. -/
unsafe def main (args : List String) : IO UInt32 := do
  initSearchPath (← findSysroot)
  enableInitializersExecution
  let core ← importModules #[{ module := `Init }, { module := `Std }] {} (loadExts := true)
  let csimps : Array Compiler.CSimp.Entry := (Compiler.CSimp.ext.getState core).map.fold (init := #[]) fun acc _ e => acc.push e
  let mut ok := true
  for a in args.filter (· != "--list") do
    match a.splitOn "=" with
    | [exe, root] => ok := (← checkExe (args.contains "--list") csimps exe root) && ok
    | _ => throw <| IO.userError s!"expected exe=Module, got {a}"
  return if ok then 0 else 1
