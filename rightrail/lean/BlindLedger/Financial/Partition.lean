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
  have hd' : ∀ k, fb k = true → fa k = false := fun k hk => by
    cases h : fa k
    · rfl
    · rw [hd k h] at hk; cases hk
  obtain ⟨ra, va⟩ := ha.reads (b s).1 s fun k hk => hb.frame s k (hd k hk)
  obtain ⟨rb, vb⟩ := hb.reads (a s).1 s fun k hk => ha.frame s k (hd' k hk)
  refine ⟨funext fun k => ?_, ra, rb⟩
  cases hfa : fa k
  · cases hfb : fb k
    · rw [hb.frame _ k hfb, ha.frame _ k hfa, ha.frame _ k hfa, hb.frame _ k hfb]
    · rw [vb k hfb, ha.frame _ k hfa]
  · rw [hb.frame _ k (hd k hfa), va k hfa]

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

theorem foot_route {pk : Pack} {p : PartId} {h : Anchor} {ls : List (Line B)} {k : Key}
    (hh : route pk h = some p) (hls : ∀ l ∈ ls, homeOk pk p l = true) (hk : foot h ls k = true) :
    routeKey pk k = some p := by
  simp only [foot, Bool.or_eq_true, beq_iff_eq, List.any_eq_true] at hk
  rcases hk with hk | ⟨l, hl, hm⟩
  · rw [routeKey, hk, hh]
  · have := hls l hl
    simp only [homeOk, List.all_eq_true, beq_iff_eq] at this
    exact this _ (by simpa using hm)

theorem stepFile_frame (pk : Pack) (sem : Sem V B R) (s : Store Key V) (f : File B) {k : Key}
    (hk : ∀ p, route pk f.header = some p → routeKey pk k ≠ some p) : (stepFile pk sem s f).1 k = s k := by
  cases hr : route pk f.header with
  | none => simp [stepFile, hr]
  | some p =>
    simp only [stepFile, hr]
    apply (sem.isLocal _ _).frame
    cases hf : foot f.header (f.lines.filter (homeOk pk p)) k
    · rfl
    · exact absurd (foot_route hr (fun l hl => (List.mem_filter.mp hl).2) hf) (hk p hr)

theorem stepFile_restrict (pk : Pack) (sem : Sem V B R) (s : Store Key V) (f : File B) {q : PartId}
    (hr : route pk f.header = some q) :
    (stepFile pk sem (restrict pk q s) f).2 = (stepFile pk sem s f).2 ∧
    (stepFile pk sem (restrict pk q s) f).1 = restrict pk q (stepFile pk sem s f).1 := by
  simp only [stepFile, hr]
  have hloc := sem.isLocal f.header (f.lines.filter (homeOk pk q))
  have hkept : ∀ l ∈ f.lines.filter (homeOk pk q), homeOk pk q l = true :=
    fun l hl => (List.mem_filter.mp hl).2
  obtain ⟨ho, hv⟩ := hloc.reads (restrict pk q s) s fun k hk => by
    simp [restrict, foot_route hr hkept hk]
  refine ⟨by rw [ho], funext fun k => ?_⟩
  cases hf : foot f.header (f.lines.filter (homeOk pk q)) k
  · rw [hloc.frame _ k hf]; unfold restrict; rw [hloc.frame _ k hf]
  · rw [hv k hf]; simp [restrict, foot_route hr hkept hf]

theorem restrict_step_other (pk : Pack) (sem : Sem V B R) (s : Store Key V) (f : File B) {p : PartId}
    (hp : routesTo pk p f = false) : restrict pk p (stepFile pk sem s f).1 = restrict pk p s := by
  funext k
  unfold restrict
  split
  · next hk =>
    refine stepFile_frame pk sem s f fun p' hp' hk' => ?_
    rw [hk] at hk'
    cases hk'
    simp [routesTo, hp'] at hp
  · rfl

theorem merge_step (pk : Pack) (sem : Sem V B R) (s : Store Key V) (f : File B) (T : PartId → Store Key V) :
    merge pk (stepFile pk sem s f).1 T = merge pk s T := by
  funext k
  unfold merge
  split
  · rfl
  · next hk => exact stepFile_frame pk sem s f fun p' _ h => by rw [hk] at h; cases h

theorem run_support (pk : Pack) (sem : Sem V B R) {p : PartId} :
    ∀ (s : Store Key V) (fs : List (File B)), (∀ f ∈ fs, route pk f.header = some p) →
    (∀ k, routeKey pk k ≠ some p → s k = none) →
    ∀ k, routeKey pk k ≠ some p → (runSingle pk sem s fs).1 k = none
  | s, [], _, hs, k, hk => hs k hk
  | s, f :: fs, hfs, hs, k, hk => by
    simp only [runSingle]
    refine run_support pk sem _ fs (fun g hg => hfs g (List.mem_cons_of_mem _ hg)) (fun k' hk' => ?_) k hk
    rw [stepFile_frame pk sem s f fun p' hp' => by
      obtain rfl : p' = p := Option.some.inj (hp'.symm.trans (hfs f (by simp)))
      exact hk']
    exact hs k' hk'

theorem run_merge (pk : Pack) (sem : Sem V B R) : ∀ (s0 : Store Key V) (ms : List (File B)),
    merge pk s0 (fun p => (runSingle pk sem (restrict pk p s0) (ms.filter (routesTo pk p))).1) =
      (runSingle pk sem s0 ms).1 ∧
    ∀ p, (runSingle pk sem s0 ms).2.filter (fun x => routesTo pk p x.1) =
      (runSingle pk sem (restrict pk p s0) (ms.filter (routesTo pk p))).2
  | s0, [] => by
    refine ⟨funext fun k => ?_, fun p => rfl⟩
    simp only [List.filter_nil, runSingle, merge, restrict]
    split <;> simp_all
  | s0, f :: ms => by
    obtain ⟨ih1, ih2⟩ := run_merge pk sem (stepFile pk sem s0 f).1 ms
    have hpart : ∀ p, runSingle pk sem (restrict pk p s0) ((f :: ms).filter (routesTo pk p)) =
        if routesTo pk p f then
          ((runSingle pk sem (restrict pk p (stepFile pk sem s0 f).1) (ms.filter (routesTo pk p))).1,
            (f, (stepFile pk sem s0 f).2) ::
              (runSingle pk sem (restrict pk p (stepFile pk sem s0 f).1) (ms.filter (routesTo pk p))).2)
        else runSingle pk sem (restrict pk p (stepFile pk sem s0 f).1) (ms.filter (routesTo pk p)) := by
      intro p
      cases hp : routesTo pk p f
      · simp only [List.filter_cons, hp, restrict_step_other pk sem s0 f hp]
        rfl
      · have hq : route pk f.header = some p := by simpa [routesTo] using hp
        obtain ⟨h2, h1⟩ := stepFile_restrict pk sem s0 f hq
        simp only [List.filter_cons, hp, if_true, runSingle, h1, h2]
    refine ⟨?_, fun p => ?_⟩
    · have hT : (fun p => (runSingle pk sem (restrict pk p s0) ((f :: ms).filter (routesTo pk p))).1) =
          fun p => (runSingle pk sem (restrict pk p (stepFile pk sem s0 f).1) (ms.filter (routesTo pk p))).1 :=
        funext fun p => by rw [hpart p]; split <;> rfl
      rw [hT, ← merge_step pk sem s0 f, ih1]
      rfl
    · rw [hpart p]
      show ((f, (stepFile pk sem s0 f).2) :: (runSingle pk sem (stepFile pk sem s0 f).1 ms).2).filter _ = _
      cases hp : routesTo pk p f
      · simp only [List.filter_cons, hp, ih2 p]
        rfl
      · simp only [List.filter_cons, hp, ih2 p]
        rfl

/-- A pack update never changes the route of a key with history, nor of a header with history. -/
theorem route_stable (pk pk' : Pack) (hist : List Anchor) (s : Store Key V)
    (hu : packUpdateOk pk pk' hist = true) (hh : ∀ k, s k ≠ none → k.anchor ∈ hist) :
    (∀ k, s k ≠ none → routeKey pk' k = routeKey pk k) ∧ ∀ a ∈ hist, route pk' a = route pk a := by
  simp only [packUpdateOk, Bool.and_eq_true, List.all_eq_true, beq_iff_eq] at hu
  exact ⟨fun k hk => hu.2 _ (hh k hk), hu.2⟩

/-- Reachable states of distinct partitions share no key (obligation, payment, cell, pool, feed, deposit,
    command). -/
theorem disjoint_keys (pk : Pack) (sem : Sem V B R) (s0 : Store Key V) (fs gs : List (File B))
    {p q : PartId} (hfs : ∀ f ∈ fs, route pk f.header = some p) (hgs : ∀ g ∈ gs, route pk g.header = some q)
    (hpq : p ≠ q) (k : Key) :
    (runSingle pk sem (restrict pk p s0) fs).1 k = none ∨
      (runSingle pk sem (restrict pk q s0) gs).1 k = none := by
  by_cases hk : routeKey pk k = some p
  · exact .inr <| run_support pk sem _ gs hgs (fun k' hk' => by simp [restrict, hk']) k
      (by rw [hk]; exact fun h => hpq (Option.some.inj h))
  · exact .inl <| run_support pk sem _ fs hfs (fun k' hk' => by simp [restrict, hk']) k hk

/-- For any interleaving `ms` of the per-partition file lists, merging the independent partition runs gives
    the single-store run's store, and each partition's receipts are the single run's receipts for its files. -/
theorem partition_run_eq (pk : Pack) (sem : Sem V B R) (s0 : Store Key V)
    (fsOf : PartId → List (File B)) (ms : List (File B)) (hms : ∀ p, ms.filter (routesTo pk p) = fsOf p) :
    merge pk s0 (fun p => (runSingle pk sem (restrict pk p s0) (fsOf p)).1) = (runSingle pk sem s0 ms).1 ∧
    ∀ p, (runSingle pk sem s0 ms).2.filter (fun x => routesTo pk p x.1) =
      (runSingle pk sem (restrict pk p s0) (fsOf p)).2 := by
  obtain rfl : fsOf = fun p => ms.filter (routesTo pk p) := funext fun p => (hms p).symm
  exact run_merge pk sem s0 ms

def total (val : Option V → Int) (ks : List Key) (s : Store Key V) : Int := (ks.map fun k => val (s k)).sum

theorem total_cons (val : Option V → Int) (k : Key) (ks : List Key) (s : Store Key V) :
    total val (k :: ks) s = val (s k) + total val ks s := by
  simp only [total, List.map_cons, List.sum_cons]

theorem sum_map_add {α : Type} (f g : α → Int) :
    ∀ l : List α, (l.map fun x => f x + g x).sum = (l.map f).sum + (l.map g).sum
  | [] => by simp
  | x :: l => by simp only [List.map_cons, List.sum_cons, sum_map_add f g l]; omega

theorem sum_zero {α : Type} (f : α → Int) : ∀ l : List α, (∀ x ∈ l, f x = 0) → (l.map f).sum = 0
  | [], _ => by simp
  | x :: l, h => by
    simp only [List.map_cons, List.sum_cons, h x (by simp), sum_zero f l fun y hy => h y (by simp [hy])]
    rfl

theorem sum_single {α : Type} (f : α → Int) (p : α) (hf : ∀ q, q ≠ p → f q = 0) :
    ∀ l : List α, l.Nodup → p ∈ l → (l.map f).sum = f p
  | [], _, h => by simp at h
  | q :: l, hn, hm => by
    rw [List.nodup_cons] at hn
    simp only [List.map_cons, List.sum_cons]
    by_cases hq : q = p
    · subst hq
      rw [sum_zero f l fun x hx => hf x fun h => by subst h; exact hn.1 hx]
      omega
    · rw [hf q hq, sum_single f p hf l hn.2 (by simpa [Ne.symm hq] using hm)]
      omega

theorem total_merge (pk : Pack) (s0 : Store Key V) (T : PartId → Store Key V) (val : Option V → Int)
    (hval : val none = 0) (ps : List PartId) (hps : ps.Nodup)
    (hsup : ∀ p k, routeKey pk k ≠ some p → T p k = none) :
    ∀ ks : List Key, (∀ k ∈ ks, ∀ p, routeKey pk k = some p → p ∈ ps) →
    total val ks (merge pk s0 T) =
      total val (ks.filter fun k => (routeKey pk k).isNone) s0 + (ps.map fun p => total val ks (T p)).sum
  | [], _ => by
    have := sum_zero (fun _ : PartId => (0 : Int)) ps fun _ _ => rfl
    simp only [total, List.filter_nil, List.map_nil, List.sum_nil] at this ⊢
    omega
  | k :: ks, hcov => by
    have ih := total_merge pk s0 T val hval ps hps hsup ks fun k' hk' => hcov k' (List.mem_cons_of_mem _ hk')
    have hsplit : (ps.map fun p => total val (k :: ks) (T p)).sum =
        (ps.map fun p => val (T p k)).sum + (ps.map fun p => total val ks (T p)).sum := by
      rw [← sum_map_add]; simp only [total_cons]
    rw [total_cons, hsplit]
    cases hr : routeKey pk k with
    | none =>
      have h0 : (ps.map fun p => val (T p k)).sum = 0 := sum_zero _ _ fun q _ => by
        show val (T q k) = 0
        rw [hsup q k (by rw [hr]; exact fun h => nomatch h), hval]
      have hm : merge pk s0 T k = s0 k := by simp [merge, hr]
      simp only [List.filter_cons, hr, Option.isNone_none, ↓reduceIte, total_cons, h0, hm]
      omega
    | some p =>
      have h1 : (ps.map fun p => val (T p k)).sum = val (T p k) := sum_single _ p (fun q hq => by
          show val (T q k) = 0
          rw [hsup q k (by rw [hr]; exact fun h => hq (Option.some.inj h).symm), hval])
        ps hps (hcov k (by simp) p hr)
      have hm : merge pk s0 T k = T p k := by simp [merge, hr]
      simp only [List.filter_cons, hr, Option.isNone_some, Bool.false_eq_true, ↓reduceIte, h1, hm]
      omega

/-- Global conservation is the sum over partitions: any per-row quantity totalled over the single-store run
    equals the partitions' totals plus the untouched unrouted rows. -/
theorem conservation_merge (pk : Pack) (sem : Sem V B R) (s0 : Store Key V) (ms : List (File B))
    (val : Option V → Int) (hval : val none = 0) (ks : List Key) (ps : List PartId) (hps : ps.Nodup)
    (hcov : ∀ k ∈ ks, ∀ p, routeKey pk k = some p → p ∈ ps) :
    total val ks (runSingle pk sem s0 ms).1 =
      total val (ks.filter fun k => (routeKey pk k).isNone) s0 +
      (ps.map fun p => total val ks (runSingle pk sem (restrict pk p s0) (ms.filter (routesTo pk p))).1).sum := by
  rw [← (run_merge pk sem s0 ms).1]
  exact total_merge pk s0 _ val hval ps hps (fun p k hk => run_support pk sem (restrict pk p s0)
    (ms.filter (routesTo pk p)) (fun f hf => by simpa [routesTo] using (List.mem_filter.mp hf).2)
    (fun k' hk' => by simp [restrict, hk']) k hk) ks hcov

/-- A held line has no money effect: the file writes what it writes without that line, and touches no key of
    another partition.  Both specs run `stepFile` (the partitioned store on the file's own database). -/
theorem other_partition_held (pk : Pack) (sem : Sem V B R) (s : Store Key V) (f : File B) {p : PartId}
    (hr : route pk f.header = some p) {xs ys : List (Line B)} {l : Line B} (hsplit : f.lines = xs ++ l :: ys)
    (hh : homeOk pk p l = false) :
    (stepFile pk sem s f).1 = (stepFile pk sem s { f with lines := xs ++ ys }).1 ∧
    ∀ k, routeKey pk k ≠ some p → (stepFile pk sem s f).1 k = s k := by
  refine ⟨?_, fun k hk => stepFile_frame pk sem s f fun p' hp' h =>
    hk (by rw [Option.some.inj (hr.symm.trans hp')]; exact h)⟩
  simp only [stepFile, hr, hsplit, List.filter_append, List.filter_cons, hh, Bool.false_eq_true, ↓reduceIte]

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

omit [DecidableEq D] in
theorem setTip_self (st : PartId → D × Nat) (p : PartId) (t : D × Nat) : setTip st p t p = t := by
  simp [setTip]

omit [DecidableEq D] in
theorem setTip_other (st : PartId → D × Nat) {p q : PartId} (t : D × Nat) (h : q ≠ p) :
    setTip st p t q = st q := by
  simp [setTip, h]

theorem mergedOk_iff (H : D → P → D) : ∀ (st : PartId → D × Nat) (evs : List (Event D P)),
    mergedOk H st evs = true ↔ ∀ p, chainOk H (st p) (evs.filter (·.part == p)) = true
  | st, [] => by simp [mergedOk, chainOk]
  | st, e :: es => by
    have ih := mergedOk_iff H (setTip st e.part (e.head, e.seq)) es
    simp only [mergedOk, Bool.and_eq_true, ih]
    constructor
    · rintro ⟨hc, hall⟩ p
      by_cases hp : e.part = p
      · subst hp
        have := hall e.part
        rw [setTip_self] at this
        simp only [List.filter_cons, beq_self_eq_true, ↓reduceIte, chainOk, Bool.and_eq_true]
        exact ⟨hc, this⟩
      · have := hall p
        rw [setTip_other _ _ (Ne.symm hp)] at this
        simpa [List.filter_cons, hp] using this
    · intro h
      have he := h e.part
      simp only [List.filter_cons, beq_self_eq_true, ↓reduceIte, chainOk, Bool.and_eq_true]
        at he
      refine ⟨he.1, fun p => ?_⟩
      by_cases hp : e.part = p
      · subst hp; rw [setTip_self]; exact he.2
      · rw [setTip_other _ _ (Ne.symm hp)]
        simpa [List.filter_cons, hp] using h p

omit [DecidableEq D] in
theorem mergedTip_eq : ∀ (st : PartId → D × Nat) (evs : List (Event D P)) (p : PartId),
    mergedTip st evs p = chainTip (st p) (evs.filter (·.part == p))
  | st, [], p => rfl
  | st, e :: es, p => by
    show mergedTip (setTip st e.part (e.head, e.seq)) es p = _
    rw [mergedTip_eq _ es p]
    by_cases hp : e.part = p
    · subst hp; simp [setTip, chainTip]
    · simp [setTip, hp, Ne.symm hp]

/-- The merged root is valid iff every event names a listed partition, every partition chain is valid, and the
    root is `Hr` of the partition chains' own tips. -/
theorem merge_chain (H : D → P → D) (Hr : List (PartId × Nat × D) → D) (parts : List PartId)
    (g : PartId → D × Nat) (evs : List (Event D P)) (r : D) :
    rootValid H Hr parts g evs r = true ↔
      (∀ e ∈ evs, e.part ∈ parts) ∧
      (∀ p ∈ parts, chainOk H (g p) (evs.filter (·.part == p)) = true) ∧
      r = rootOf Hr parts (fun p => chainTip (g p) (evs.filter (·.part == p))) := by
  have htip : mergedTip g evs = fun p => chainTip (g p) (evs.filter (·.part == p)) := funext (mergedTip_eq g evs)
  have hmem : ∀ x : Event D P, parts.contains x.part = true ↔ x.part ∈ parts := fun x => by simp
  unfold rootValid
  rw [htip]
  simp only [Bool.and_eq_true, mergedOk_iff, List.all_eq_true, beq_iff_eq, hmem]
  constructor
  · rintro ⟨⟨hc, hm⟩, hr⟩
    exact ⟨hm, fun p _ => hc p, hr⟩
  · rintro ⟨hm, hc, hr⟩
    refine ⟨⟨fun p => ?_, hm⟩, hr⟩
    by_cases hp : p ∈ parts
    · exact hc p hp
    · have : evs.filter (·.part == p) = [] := List.filter_eq_nil_iff.mpr fun e he h => by
        simp only [beq_iff_eq] at h
        exact hp (by rw [← h]; exact hm e he)
      rw [this]; rfl

end BlindLedger.Financial.Partition
