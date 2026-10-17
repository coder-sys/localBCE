import BlindLedger.Financial.Payment.Ledger

/-! Cash-file fold: the theorem STATEMENTS of design
    C:\Users\neers\rrb\designs\cash-batch-speed-v1.md §3.C (S2).  Every proof is `sorry`.
    This file is outside `lean/`, so no executable, library target, TCB report or pin manifest sees it.
    Check: from `lean/`, `lake env lean ../tools/cash_file_fold_goals.lean` over a build of
    `BlindLedger.Financial.Payment.Ledger`.
    `Ledger` models one obligation, so a file's lines over several items step a family of ledgers,
    each line its own item's.  Today's owner is the per-line path (`lineRun`, `lineTrace`); S2's one
    Lean call per file folds each item's lines alone (`itemCalls`) and puts the outcomes back in
    file order (`fileOutcomes`).  U3 proves its wire response decodes to `fileOutcomes`
    (`respondFile_eq_trace`), moves these statements beside `run` and `trace` with proofs and axiom
    pins, and deletes this file.  U3's bridge premise, outside this model: the owner's input for an
    item's line reads nothing that another item's line in the same file writes. -/

namespace BlindLedger.Financial.Payment.CashFile

/-- One cash-file line: the item it pays and its call. -/
abbrev Line := String × Call

/-- Today's path: a line steps its own item's ledger and leaves every other item's unchanged. -/
def lineStep (Ls : String → Ledger) (l : Line) : String → Ledger :=
  fun i => if i = l.1 then step (Ls i) l.2 else Ls i

def lineRun (Ls : String → Ledger) (ls : List Line) : String → Ledger := ls.foldl lineStep Ls

/-- Today's per-line outcomes, in file order. -/
def lineTrace : (String → Ledger) → List Line → List PaymentOutcome
  | _, [] => []
  | Ls, l :: ls => (Ls l.1).outcome l.2 :: lineTrace (lineStep Ls l) ls

/-- An item's own lines, in file order. -/
def itemCalls (ls : List Line) (i : String) : List Call := (ls.filter (·.1 == i)).map (·.2)

/-- S2's batched path: each item's lines folded alone; line `k` takes its item's next outcome. -/
def fileOutcomes (Ls : String → Ledger) (ls : List Line) : List (Option PaymentOutcome) :=
  ls.mapIdx fun k l => (trace (Ls l.1) (itemCalls ls l.1))[(itemCalls (ls.take k) l.1).length]?

/-! ### 1. The per-file evaluation equals the per-line fold, at every step -/

/-- Every line's outcome: the batched path gives exactly the per-line path's. -/
theorem fileOutcomes_eq_lineTrace (Ls : String → Ledger) (ls : List Line) :
    fileOutcomes Ls ls = (lineTrace Ls ls).map some := by
  sorry

/-- The outcomes of a file's first `k` lines are those of the first `k` lines alone, so the
    equality above holds at every step, not only for the whole file. -/
theorem lineTrace_take (Ls : String → Ledger) (ls : List Line) (k : Nat) :
    (lineTrace Ls ls).take k = lineTrace Ls (ls.take k) := by
  sorry

/-! ### 2. Items fold independently -/

/-- Each item's ledger after any lines (after every prefix, with `ls.take k`) is its own lines'
    fold from its own start. -/
theorem run_item_independent (Ls : String → Ledger) (ls : List Line) (i : String) :
    lineRun Ls ls i = run (Ls i) (itemCalls ls i) := by
  sorry

/-- Each item's outcomes are its own lines' trace, whatever other items' lines lie between. -/
theorem lineTrace_item (Ls : String → Ledger) (ls : List Line) (i : String) :
    ((ls.zip (lineTrace Ls ls)).filter (·.1.1 == i)).map (·.2) = trace (Ls i) (itemCalls ls i) := by
  sorry

/-- Reordering lines of different items, each item's own order kept, changes no item's state. -/
theorem lineRun_reorder (Ls : String → Ledger) (ls ls' : List Line)
    (h : ∀ i, itemCalls ls' i = itemCalls ls i) : lineRun Ls ls' = lineRun Ls ls := by
  sorry

/-- ... and no item's outcomes. -/
theorem lineTrace_reorder (Ls : String → Ledger) (ls ls' : List Line)
    (h : ∀ i, itemCalls ls' i = itemCalls ls i) (i : String) :
    ((ls'.zip (lineTrace Ls ls')).filter (·.1.1 == i)).map (·.2) =
      ((ls.zip (lineTrace Ls ls)).filter (·.1.1 == i)).map (·.2) := by
  sorry

end BlindLedger.Financial.Payment.CashFile
