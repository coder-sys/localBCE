/-! Partition laws (OWNER-SCALE OS0; rrb/state/owner-scale-design-20261007.md (d), decisions D-OS1..6).

    A keyed model of the owner store.  Every row lives at a `Key`; every key has one `Anchor` (its obligation,
    sender, feed, or a named partition); the pack routes anchors to partitions.  A file is one transaction.  The
    single-store spec holds every line with an anchor outside its file's partition (D-OS1:
    `obligation_other_partition`, `act_other_partition`); the partitioned store runs the same file step on the
    file's own database.  The file semantics is abstract and must be local to the file's header and its kept
    lines' anchors (`Sem.isLocal`); the event chain and `financial_meta` are not keyed rows and are covered by
    `merge_chain`.  Not imported by any pinned executable. -/

namespace BlindLedger.Financial.Partition

abbrev PartId := Nat

structure PayerProgram where
  payer : String
  program : String
deriving DecidableEq, Repr

inductive Anchor where
  | obligation (obligationId : String)
  | sender (senderId : String)
  | feed (feedId : String)
  | partition (p : PartId)
deriving DecidableEq, Repr

inductive Key where
  | obligation (obligationId : String)
  | payment (obligationId commonOriginId : String)
  | cell (tenant senderId cellKey : String)
  | pool (senderId trn03 trn02 : String)
  | feed (feedId : String)
  | deposit (feedId entryId : String)
  | command (header : Anchor) (digest : String)
deriving DecidableEq, Repr

def Key.anchor : Key → Anchor
  | .obligation o => .obligation o
  | .payment o _ => .obligation o
  | .cell _ s _ => .sender s
  | .pool s _ _ => .sender s
  | .feed f => .feed f
  | .deposit f _ => .feed f
  | .command h _ => h

structure Pack where
  senders : List (String × PayerProgram)   -- SENDER_CHANNELS: sender -> (payer, program)
  feeds : List (String × List String)       -- DEPOSIT_FEEDS: feed -> covered 835 senders
  items : List (String × PayerProgram)      -- population: obligation -> its item's (payer, program)
  parts : List (PayerProgram × PartId)      -- (payer, program) component -> writer database
deriving Repr

def senderRoute (pk : Pack) (s : String) : Option PartId :=
  (List.lookup s pk.senders).bind fun pp => List.lookup pp pk.parts

/-- The routing function: an anchor's partition under the pack; `none` is unknown (file refused, line held). -/
def route (pk : Pack) : Anchor → Option PartId
  | .obligation o => (List.lookup o pk.items).bind fun pp => List.lookup pp pk.parts
  | .sender s => senderRoute pk s
  | .feed f => ((List.lookup f pk.feeds).bind List.head?).bind (senderRoute pk)
  | .partition p => some p

def routeKey (pk : Pack) (k : Key) : Option PartId := route pk k.anchor

/-- S0 pack checks: each feed covers a sender and all its senders share the feed's partition (feeds stay
    inside one component); `item_partition`: each item's (payer, program) is a SENDER_CHANNELS payer with a
    partition. -/
def packOk (pk : Pack) : Bool :=
  pk.feeds.all (fun x => !x.2.isEmpty &&
    x.2.all fun s => (senderRoute pk s).isSome && senderRoute pk s == route pk (.feed x.1)) &&
  pk.items.all fun x => pk.senders.any (·.2 == x.2) && (List.lookup x.2 pk.parts).isSome

/-- S0 refusal `route_stable` as a check: the new pack is well formed and routes every anchor with history as
    the old pack does. -/
def packUpdateOk (pk pk' : Pack) (hist : List Anchor) : Bool :=
  packOk pk' && hist.all fun a => route pk' a == route pk a

/-! ## Stores and locality (generic over keys; SHARD-L reuses these) -/

abbrev Store (K V : Type) := K → Option V

/-- `t` is local to `foot`: it changes no key outside `foot`, and its outcome and its result on `foot` read
    only `foot`. -/
structure Local {K V R : Type} (foot : K → Bool) (t : Store K V → Store K V × R) : Prop where
  frame : ∀ s k, foot k = false → (t s).1 k = s k
  reads : ∀ s s', (∀ k, foot k = true → s k = s' k) →
    (t s).2 = (t s').2 ∧ ∀ k, foot k = true → (t s).1 k = (t s').1 k

/-- Steps on disjoint keys commute: either order gives the same store, and each step's outcome is the one it
    has alone. -/
theorem step_commute {K V R₁ R₂ : Type} {fa fb : K → Bool}
    {a : Store K V → Store K V × R₁} {b : Store K V → Store K V × R₂}
    (ha : Local fa a) (hb : Local fb b) (hd : ∀ k, fa k = true → fb k = false) (s : Store K V) :
    (b (a s).1).1 = (a (b s).1).1 ∧ (a (b s).1).2 = (a s).2 ∧ (b (a s).1).2 = (b s).2 := by
  sorry

/-! ## Files, the single-store spec and the partitioned store -/

variable {V B R : Type}

structure Line (B : Type) where
  anchors : List Anchor   -- what the line touches: its obligation; an approval line's act key
  body : B

structure File (B : Type) where
  header : Anchor         -- 835: ISA/GS sender; cash: channel; deposit: feed; approval: named partition
  lines : List (Line B)

/-- Keys a file transaction may touch: those anchored at its header or at an anchor of a line it keeps. -/
def foot (h : Anchor) (ls : List (Line B)) (k : Key) : Bool :=
  k.anchor == h || ls.any fun l => l.anchors.contains k.anchor

/-- Owner file semantics on the kept lines: one transaction, local to `foot`. -/
structure Sem (V B R : Type) where
  apply : Anchor → List (Line B) → Store Key V → Store Key V × R
  isLocal : ∀ h ls, Local (foot h ls) (apply h ls)

def homeOk (pk : Pack) (p : PartId) (l : Line B) : Bool := l.anchors.all fun a => route pk a == some p

inductive FileReceipt (R : Type) where
  | unrouted                         -- unknown channel: the existing refusal, nothing written
  | done (r : R) (held : List Bool)  -- held[i]: line i HELD as data, no money effect

/-- One file in the single-store spec: refused if unrouted, else lines outside the file's partition are held
    and the rest apply in one transaction. -/
def stepFile (pk : Pack) (sem : Sem V B R) (s : Store Key V) (f : File B) : Store Key V × FileReceipt R :=
  match route pk f.header with
  | none => (s, .unrouted)
  | some p =>
    let r := sem.apply f.header (f.lines.filter (homeOk pk p)) s
    (r.1, .done r.2 (f.lines.map fun l => !homeOk pk p l))

def runSingle (pk : Pack) (sem : Sem V B R) :
    Store Key V → List (File B) → Store Key V × List (File B × FileReceipt R)
  | s, [] => (s, [])
  | s, f :: fs =>
    let a := stepFile pk sem s f
    let b := runSingle pk sem a.1 fs
    (b.1, (f, a.2) :: b.2)

def routesTo (pk : Pack) (p : PartId) (f : File B) : Bool := route pk f.header == some p

/-- Partition `p`'s database: the rows of `s` whose key routes to `p`. -/
def restrict (pk : Pack) (p : PartId) (s : Store Key V) : Store Key V :=
  fun k => if routeKey pk k = some p then s k else none

/-- The merged view: each routed key read from its partition's database, an unrouted key from `base`. -/
def merge (pk : Pack) (base : Store Key V) (ss : PartId → Store Key V) : Store Key V :=
  fun k => match routeKey pk k with
    | some p => ss p k
    | none => base k

/-- A pack update never changes the route of a key with history, nor of a header with history. -/
theorem route_stable (pk pk' : Pack) (hist : List Anchor) (s : Store Key V)
    (hu : packUpdateOk pk pk' hist = true) (hh : ∀ k, s k ≠ none → k.anchor ∈ hist) :
    (∀ k, s k ≠ none → routeKey pk' k = routeKey pk k) ∧ ∀ a ∈ hist, route pk' a = route pk a := by
  sorry

/-- Reachable states of distinct partitions share no key (obligation, payment, cell, pool, feed, deposit,
    command). -/
theorem disjoint_keys (pk : Pack) (sem : Sem V B R) (s0 : Store Key V) (fs gs : List (File B))
    {p q : PartId} (hfs : ∀ f ∈ fs, route pk f.header = some p) (hgs : ∀ g ∈ gs, route pk g.header = some q)
    (hpq : p ≠ q) (k : Key) :
    (runSingle pk sem (restrict pk p s0) fs).1 k = none ∨
      (runSingle pk sem (restrict pk q s0) gs).1 k = none := by
  sorry

/-- For any interleaving `ms` of the per-partition file lists, merging the independent partition runs gives
    the single-store run's store, and each partition's receipts are the single run's receipts for its files. -/
theorem partition_run_eq (pk : Pack) (sem : Sem V B R) (s0 : Store Key V)
    (fsOf : PartId → List (File B)) (ms : List (File B)) (hms : ∀ p, ms.filter (routesTo pk p) = fsOf p) :
    merge pk s0 (fun p => (runSingle pk sem (restrict pk p s0) (fsOf p)).1) = (runSingle pk sem s0 ms).1 ∧
    ∀ p, (runSingle pk sem s0 ms).2.filter (fun x => routesTo pk p x.1) =
      (runSingle pk sem (restrict pk p s0) (fsOf p)).2 := by
  sorry

def total (val : Option V → Int) (ks : List Key) (s : Store Key V) : Int := (ks.map fun k => val (s k)).sum

/-- Global conservation is the sum over partitions: any per-row quantity totalled over the single-store run
    equals the partitions' totals plus the untouched unrouted rows. -/
theorem conservation_merge (pk : Pack) (sem : Sem V B R) (s0 : Store Key V) (ms : List (File B))
    (val : Option V → Int) (hval : val none = 0) (ks : List Key) (ps : List PartId) (hps : ps.Nodup)
    (hcov : ∀ k ∈ ks, ∀ p, routeKey pk k = some p → p ∈ ps) :
    total val ks (runSingle pk sem s0 ms).1 =
      total val (ks.filter fun k => (routeKey pk k).isNone) s0 +
      (ps.map fun p => total val ks (runSingle pk sem (restrict pk p s0) (ms.filter (routesTo pk p))).1).sum := by
  sorry

/-- A held line has no money effect: the file writes what it writes without that line, and touches no key of
    another partition.  Both specs run `stepFile` (the partitioned store on the file's own database). -/
theorem other_partition_held (pk : Pack) (sem : Sem V B R) (s : Store Key V) (f : File B) {p : PartId}
    (hr : route pk f.header = some p) {xs ys : List (Line B)} {l : Line B} (hsplit : f.lines = xs ++ l :: ys)
    (hh : homeOk pk p l = false) :
    (stepFile pk sem s f).1 = (stepFile pk sem s { f with lines := xs ++ ys }).1 ∧
    ∀ k, routeKey pk k ≠ some p → (stepFile pk sem s f).1 k = s k := by
  sorry

/-! ## Per-partition chains and the merged root -/

structure Event (D P : Type) where
  part : PartId
  seq : Nat
  prev : D
  body : P
  head : D

variable {D P : Type} [DecidableEq D]

/-- One partition's chain from `(head, seq)`: sequence numbers count up by one, each `prev` is the previous head,
    each head is `H prev body`. -/
def chainOk (H : D → P → D) : D × Nat → List (Event D P) → Bool
  | _, [] => true
  | t, e :: es => e.seq == t.2 + 1 && e.prev == t.1 && e.head == H e.prev e.body && chainOk H (e.head, e.seq) es

def chainTip : D × Nat → List (Event D P) → D × Nat
  | t, [] => t
  | _, e :: es => chainTip (e.head, e.seq) es

def setTip (st : PartId → D × Nat) (p : PartId) (t : D × Nat) : PartId → D × Nat :=
  fun q => if q = p then t else st q

/-- The streaming verifier over the merged event stream: each event extends its own partition's chain. -/
def mergedOk (H : D → P → D) : (PartId → D × Nat) → List (Event D P) → Bool
  | _, [] => true
  | st, e :: es => e.seq == (st e.part).2 + 1 && e.prev == (st e.part).1 && e.head == H e.prev e.body &&
      mergedOk H (setTip st e.part (e.head, e.seq)) es

def mergedTip : (PartId → D × Nat) → List (Event D P) → PartId → D × Nat
  | st, [] => st
  | st, e :: es => mergedTip (setTip st e.part (e.head, e.seq)) es

/-- The merged root over partitions `parts` (ascending): `Hr` of each partition's (id, seq, head). -/
def rootOf (Hr : List (PartId × Nat × D) → D) (parts : List PartId) (tip : PartId → D × Nat) : D :=
  Hr (parts.map fun p => (p, (tip p).2, (tip p).1))

def rootValid (H : D → P → D) (Hr : List (PartId × Nat × D) → D) (parts : List PartId)
    (g : PartId → D × Nat) (evs : List (Event D P)) (r : D) : Bool :=
  mergedOk H g evs && evs.all (fun e => parts.contains e.part) && r == rootOf Hr parts (mergedTip g evs)

/-- The merged root is valid iff every event names a listed partition, every partition chain is valid, and the
    root is `Hr` of the partition chains' own tips. -/
theorem merge_chain (H : D → P → D) (Hr : List (PartId × Nat × D) → D) (parts : List PartId)
    (g : PartId → D × Nat) (evs : List (Event D P)) (r : D) :
    rootValid H Hr parts g evs r = true ↔
      (∀ e ∈ evs, e.part ∈ parts) ∧
      (∀ p ∈ parts, chainOk H (g p) (evs.filter (·.part == p)) = true) ∧
      r = rootOf Hr parts (fun p => chainTip (g p) (evs.filter (·.part == p))) := by
  sorry

end BlindLedger.Financial.Partition
