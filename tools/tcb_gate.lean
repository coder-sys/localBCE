import Lean
open Lean

/-! The TCB gate (Constitution V.3, XI.2; lean-expansion-plan item 6).  Run from `lean/`:
    `lake env lean --run ../tools/tcb_gate.lean exe=Root.Module ...`  (tests/test_tcb_gate.py does); `--list` also names every allowlisted constant.
    For each pinned exe it walks every constant reachable from `main`, through types and values (the kernel view
    that `#print axioms` takes) and through the compiled code (the IR call graph plus `implemented_by` targets,
    the view of what actually runs; a `partial` def is walked through its `_unsafe_rec` body), and from every startup
    initializer and `@[csimp]` theorem.  It exits 1 on any axiom outside `standardAxioms` and `axiomsAllowed`
    (so `sorryAx` and `Lean.ofReduceBool`, the axiom behind `native_decide`, fail), on any partial,
    implemented_by, extern, opaque, unsafe, fixpoint (`partial_fixpoint`) or loop (`while`/`repeat`) constant that `allowed` does not name, on `main` without compiled code, and
    on an `Init` or `Std` module that resolves outside the toolchain. -/

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
    it passes the gate only so the lead can decide, and the report names it. -/
def allowed : List Allow := [
  core `Init, core `Std,
  { name := `BlindLedger.Financial.WorkerCli.reserveArena, module := false, kinds := ["extern", "opaque"],
    reason := "the worker's mimalloc arena reservation, one C call, no decision logic" },
  { name := `BlindLedger.Financial.serveWorker, module := false, kinds := ["fixpoint"],
    reason := "the worker's frame loop, unbounded by design (answers until end of input); kernel-visible body, serveWorker_run and serveWorker_stateless" }]

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
    if used.contains ``Lean.Loop.mk || used.contains ``repeatM then ks := ks.push "loop"  -- `while`/`repeat`: an unbounded loop hidden behind Init's `partial`
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

def trusted (m : Name) : Bool := (`Init).isPrefixOf m || (`Std).isPrefixOf m

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
  let (order, called) := walk env (#[`main] ++ inits ++ initFns ++ csimps.map (·.thmName))
  let cs := order.qsort Name.lt
  let mut axs : Array Name := #[]
  let mut counts : Array Nat := allowed.toArray.map fun _ => 0
  let mut bad : Array String := ← strayModules env sysroot
  if (IR.findEnvDecl env `main).isNone then bad := bad.push "no compiled code for main"
  let mut todos : Array String := #[]
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
