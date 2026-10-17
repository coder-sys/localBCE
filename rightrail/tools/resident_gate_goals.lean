import BlindLedger.Financial.WorkerLaws

/-! Resident gate workers: goals (rr-core, 2026-10-01). Design: `resident-gate-v1.md`.

    One frame loop for every resident Lean exe, generic in its per-frame answer. Definitions are final
    text. Theorem bodies are `sorry` for the builder: each is the existing `WorkerLaws` proof with
    `workerRespond` replaced by `spec` and `maxWorkerFrameBytes` by `cap`. The two `example`s at the
    end are proved here: the evaluator and the gate are instances. -/

namespace BlindLedger.ResidentGoals

open BlindLedger.Financial

attribute [local partial_fixpoint_monotone] Lean.Order.MonadTail.monotone_bind_right

/-- The one frame loop: answer each `u32 BE length || frame` with `u32 BE length || respond frame` until end
    of input (exit 0), or stop on a bad or oversize frame (exit 65). It replaces `serveWorker`. -/
@[specialize] def serveFrames {m : Type → Type} [Monad m] [Lean.Order.MonadTail m]
    (respond : ByteArray → Bytes) (cap : Nat)
    (read : USize → m ByteArray) (write : ByteArray → m Unit) : m UInt32 := do
  let header ← readUpTo read 4 .empty
  if header.size = 0 then return 0
  let some (length, _) := readNatBE 4 header.toList | return workerExitFrame
  if length > cap then return workerExitFrame
  let body ← readUpTo read length .empty
  if body.size < length then return workerExitFrame
  let response := respond body
  write (natBE 4 response.length ++ response).toByteArray
  serveFrames respond cap read write
partial_fixpoint

/-- The loop as a total function of its whole input (exit code, output, unread input). It replaces
    `workerRun`. -/
def framesRun (spec : Bytes → Bytes) (cap : Nat) (input : Bytes) : UInt32 × Bytes × Bytes :=
  if input = [] then (0, [], []) else
  match _h : readNatBE 4 input with
  | none => (workerExitFrame, [], [])
  | some (length, rest) =>
    if length > cap then (workerExitFrame, [], rest)
    else if rest.length < length then (workerExitFrame, [], [])
    else
      let (code, out, left) := framesRun spec cap (rest.drop length)
      (code, frame (spec (rest.take length)) ++ out, left)
termination_by input.length
decreasing_by
  have := readNatBE_length _h
  simp only [List.length_drop]; omega

private theorem framesRun_nil (spec : Bytes → Bytes) (cap : Nat) : framesRun spec cap [] = (0, [], []) := by
  rw [framesRun, if_pos rfl]

private theorem framesRun_read {spec : Bytes → Bytes} {cap : Nat} {input rest : Bytes} {v : Nat}
    (hne : input ≠ []) (h : readNatBE 4 input = some (v, rest)) :
    framesRun spec cap input =
      if cap < v then (workerExitFrame, [], rest)
      else if rest.length < v then (workerExitFrame, [], [])
      else ((framesRun spec cap (rest.drop v)).1,
        frame (spec (rest.take v)) ++ (framesRun spec cap (rest.drop v)).2.1,
        (framesRun spec cap (rest.drop v)).2.2) := by
  rw [framesRun, if_neg hne]
  split
  · rename_i hh; rw [h] at hh; cases hh
  · rename_i length rest' hh
    rw [h] at hh
    simp only [Option.some.injEq, Prod.mk.injEq] at hh
    obtain ⟨rfl, rfl⟩ := hh
    rfl

private theorem framesRun_short {spec : Bytes → Bytes} {cap : Nat} {t : Bytes} (hne : t ≠ [])
    (h : t.length < 4) : framesRun spec cap t = (workerExitFrame, [], []) := by
  rw [framesRun, if_neg hne]
  split
  · rfl
  · rename_i hh; rw [readNatBE_none h] at hh; cases hh

private theorem framesRun_frame {spec : Bytes → Bytes} {cap : Nat} (hcap : cap < 256 ^ 4) {f X : Bytes}
    (hf : f.length ≤ cap) :
    framesRun spec cap (frame f ++ X) =
      ((framesRun spec cap X).1, frame (spec f) ++ (framesRun spec cap X).2.1, (framesRun spec cap X).2.2) := by
  have hr : readNatBE 4 (frame f ++ X) = some (f.length, f ++ X) :=
    (List.append_assoc _ _ _) ▸ readNatBE_natBE (by omega) (f ++ X)
  have hne : frame f ++ X ≠ [] := by
    intro hh; have := congrArg List.length hh; simp [frame, natBE_length] at this
  rw [framesRun_read hne hr, if_neg (by omega), if_neg (by simp), List.drop_left' rfl, List.take_left' rfl]

private theorem framesRun_frames (spec : Bytes → Bytes) (cap : Nat) (hcap : cap < 256 ^ 4) (frames : List Bytes)
    (h : ∀ f ∈ frames, f.length ≤ cap) :
    framesRun spec cap (frames.flatMap frame) = (0, (frames.map spec).flatMap frame, []) := by
  induction frames with
  | nil => simpa using framesRun_nil spec cap
  | cons f fs ih =>
    have hf := h f (by simp)
    have := ih (fun g hg => h g (by simp [hg]))
    simp only [List.flatMap_cons, List.map_cons]
    rw [framesRun_frame hcap hf, this]

private theorem framesRun_head {spec : Bytes → Bytes} {cap n : Nat} {t : Bytes} (hFit : n < 256 ^ 4)
    (hne : natBE 4 n ++ t ≠ []) :
    framesRun spec cap (natBE 4 n ++ t) =
      if cap < n then (workerExitFrame, [], t)
      else if t.length < n then (workerExitFrame, [], [])
      else ((framesRun spec cap (t.drop n)).1,
        frame (spec (t.take n)) ++ (framesRun spec cap (t.drop n)).2.1, (framesRun spec cap (t.drop n)).2.2) :=
  framesRun_read hne (readNatBE_natBE hFit t)

private theorem framesRun_cut {spec : Bytes → Bytes} {cap : Nat} (hcap : cap < 256 ^ 4) {n : Nat} {t : Bytes}
    (hn : n ≤ cap) (ht : t.length < n) :
    framesRun spec cap (natBE 4 n ++ t) = (workerExitFrame, [], []) := by
  have hFit : n < 256 ^ 4 := Nat.lt_of_le_of_lt hn hcap
  have hne : natBE 4 n ++ t ≠ [] := by
    intro hh; have := congrArg List.length hh; simp [natBE_length] at this
  rw [framesRun_head hFit hne, if_neg (by omega), if_pos ht]

/-- The `ByteArray` answer agrees with a list-level specification on every frame. -/
def RespondsAs (respond : ByteArray → Bytes) (spec : Bytes → Bytes) : Prop :=
  ∀ w : ByteArray, respond w = spec w.toList

/-- On every pipe and every chunking, the loop is `framesRun` (replaces `serveWorker_run`). -/
theorem serveFrames_run (respond : ByteArray → Bytes) (spec : Bytes → Bytes) (hr : RespondsAs respond spec)
    (cap : Nat) (p : Pipe) :
    let r := (serveFrames respond cap Pipe.read Pipe.write).run p
    r.1 = (framesRun spec cap p.input).1 ∧
    r.2.output = p.output ++ (framesRun spec cap p.input).2.1 ∧
    r.2.input = (framesRun spec cap p.input).2.2 := by
  induction hk : p.input.length using Nat.strongRecOn generalizing p with
  | _ k ih =>
  simp only []
  rw [serveFrames, run_bind']
  obtain ⟨hA, hB, hC, hD⟩ := readUpTo_pipe 4 ByteArray.empty p
  generalize (readUpTo Pipe.read 4 ByteArray.empty).run p = r1 at hA hB hC hD ⊢
  simp only [ByteArray.size_empty, ByteArray.toList_empty, List.nil_append, Nat.sub_zero] at hA hB
  dsimp only
  have hsz : r1.1.size = (p.input.take 4).length := by rw [← Fast.length_toList, hA]
  by_cases hE : r1.1.size = 0
  · have hin : p.input = [] := by
      have : (p.input.take 4).length = 0 := by omega
      simpa using this
    rw [if_pos hE, StateT.run_pure, hin, framesRun_nil]
    exact ⟨rfl, by show r1.2.output = _; simp [hC], by show r1.2.input = _; simp [hB, hin]⟩
  · rw [if_neg hE]
    have hne : p.input ≠ [] := fun h0 => hE (by rw [hsz, h0]; rfl)
    rw [hA]
    by_cases h4 : p.input.length < 4
    · have hnone : readNatBE 4 (p.input.take 4) = none := readNatBE_none (by simp; omega)
      rw [hnone, framesRun_short hne h4]
      refine ⟨rfl, ?_, ?_⟩
      · show r1.2.output = _; simp [hC]
      · show r1.2.input = _; simp [hB, List.drop_of_length_le (by omega : p.input.length ≤ 4)]
    · obtain ⟨v, hv1, hv2⟩ := readNatBE_take (w := 4) (l := p.input) (by omega)
      rw [hv1]
      dsimp only
      rw [framesRun_read hne hv2]
      by_cases hBig : cap < v
      · rw [if_pos (show v > cap from hBig), if_pos hBig, StateT.run_pure]
        refine ⟨rfl, ?_, ?_⟩
        · show r1.2.output = _; simp [hC]
        · show r1.2.input = _; simp [hB]
      · rw [if_neg (show ¬ v > cap from hBig), if_neg hBig]
        obtain ⟨hA2, hB2, hC2, hD2⟩ := readUpTo_pipe v ByteArray.empty r1.2
        rw [run_bind']
        generalize (readUpTo Pipe.read v ByteArray.empty).run r1.2 = r2 at hA2 hB2 hC2 hD2 ⊢
        simp only [ByteArray.size_empty, ByteArray.toList_empty, List.nil_append, Nat.sub_zero, hB] at hA2 hB2
        have hsz2 : r2.1.size = (List.take v (p.input.drop 4)).length := by rw [← Fast.length_toList, hA2]
        by_cases hS : r2.1.size < v
        · have hl : (p.input.drop 4).length < v := by rw [hsz2, List.length_take] at hS; omega
          rw [if_pos hS, StateT.run_pure, if_pos hl]
          refine ⟨rfl, ?_, ?_⟩
          · show r2.2.output = _; simp [hC2, hC]
          · show r2.2.input = _; simp [hB2, List.drop_of_length_le (by omega : (p.input.drop 4).length ≤ v)]
        · have hl : ¬ (p.input.drop 4).length < v := by rw [hsz2, List.length_take] at hS; omega
          rw [if_neg hS, run_bind', if_neg hl]
          simp only [Pipe.write, StateT.run]
          have hlt : (List.drop v (List.drop 4 p.input)).length < k := by
            simp only [List.length_drop]; omega
          obtain ⟨i1, i2, i3⟩ := ih _ hlt
            { input := r2.2.input,
              output := r2.2.output ++
                (List.toByteArray (natBE 4 (List.length (respond r2.1)) ++ respond r2.1)).toList,
              reads := r2.2.reads, cut := r2.2.cut }
            (by show r2.2.input.length = _; rw [hB2])
          have hresp : respond r2.1 = spec (List.take v (List.drop 4 p.input)) := by
            rw [hr, hA2]
          refine ⟨i1.trans (by show (framesRun spec cap r2.2.input).1 = _; rw [hB2]), i2.trans ?_,
            i3.trans (by show (framesRun spec cap r2.2.input).2.2 = _; rw [hB2])⟩
          dsimp only
          rw [hB2, hC2, hC, toList_toByteArray, hresp]
          simp [frame]

/-- Statelessness (replaces `serveWorker_stateless`): the output stream is `spec` mapped over the frames, so
    the answer to a frame depends on that frame alone, never on an earlier call. -/
theorem serveFrames_stateless (respond : ByteArray → Bytes) (spec : Bytes → Bytes) (hr : RespondsAs respond spec)
    (cap : Nat) (hcap : cap < 256 ^ 4) (frames : List Bytes) (h : ∀ f ∈ frames, f.length ≤ cap)
    (out : Bytes) (reads : Nat) (cut : Nat → Nat) :
    let r := (serveFrames respond cap Pipe.read Pipe.write).run ⟨frames.flatMap frame, out, reads, cut⟩
    r.1 = 0 ∧ r.2.output = out ++ (frames.map spec).flatMap frame ∧ r.2.input = [] := by
  obtain ⟨h1, h2, h3⟩ := serveFrames_run respond spec hr cap ⟨frames.flatMap frame, out, reads, cut⟩
  dsimp only at h1 h2 h3 ⊢
  rw [framesRun_frames spec cap hcap frames h] at h1 h2 h3
  exact ⟨h1, h2, h3⟩

/-- Resident equals fresh: one long-lived process answers a sequence of frames with exactly the bytes that
    one fresh process per frame (one frame, then end of input) would print, under any chunking of either. -/
theorem serveFrames_resident_eq_fresh (respond : ByteArray → Bytes) (spec : Bytes → Bytes)
    (hr : RespondsAs respond spec) (cap : Nat) (hcap : cap < 256 ^ 4) (frames : List Bytes)
    (h : ∀ f ∈ frames, f.length ≤ cap) (cut cut' : Nat → Nat) :
    ((serveFrames respond cap Pipe.read Pipe.write).run ⟨frames.flatMap frame, [], 0, cut⟩).2.output =
      frames.flatMap fun f =>
        ((serveFrames respond cap Pipe.read Pipe.write).run ⟨frame f, [], 0, cut'⟩).2.output := by
  have key : ∀ f : Bytes, f.length ≤ cap →
      ((serveFrames respond cap Pipe.read Pipe.write).run ⟨frame f, [], 0, cut'⟩).2.output = frame (spec f) := by
    intro f hf
    obtain ⟨_, h2, _⟩ := serveFrames_stateless respond spec hr cap hcap [f] (by simpa using hf) [] 0 cut'
    simpa using h2
  obtain ⟨-, h2, -⟩ := serveFrames_stateless respond spec hr cap hcap frames h [] 0 cut
  rw [h2, List.nil_append]
  clear h2
  induction frames with
  | nil => rfl
  | cons f fs ih =>
    simp only [List.map_cons, List.flatMap_cons]
    rw [key f (h f (by simp)), ih (fun g hg => h g (by simp [hg]))]

/-- An oversize length ends the stream after the earlier answers; its body is never read
    (replaces `workerRun_oversize`). -/
theorem framesRun_oversize (spec : Bytes → Bytes) (cap : Nat) (hcap : cap < 256 ^ 4) (frames : List Bytes)
    (h : ∀ f ∈ frames, f.length ≤ cap) (length : Nat) (hBig : cap < length) (hFit : length < 256 ^ 4)
    (rest : Bytes) :
    framesRun spec cap (frames.flatMap frame ++ natBE 4 length ++ rest) =
      (workerExitFrame, (frames.map spec).flatMap frame, rest) := by
  induction frames with
  | nil =>
    have hne : natBE 4 length ++ rest ≠ [] := by
      intro hh; have := congrArg List.length hh; simp [natBE_length] at this
    simp only [List.flatMap_nil, List.nil_append, List.map_nil]
    rw [framesRun_head hFit hne, if_pos hBig]
  | cons f fs ih =>
    have hf := h f (by simp)
    have e : (frame f ++ fs.flatMap frame) ++ natBE 4 length ++ rest
        = frame f ++ (fs.flatMap frame ++ natBE 4 length ++ rest) := by simp
    simp only [List.flatMap_cons, List.map_cons]
    rw [e, framesRun_frame hcap hf, ih (fun g hg => h g (by simp [hg]))]

/-- A cut-off last frame ends the stream with no answer for it (replaces `workerRun_truncated`). -/
theorem framesRun_truncated (spec : Bytes → Bytes) (cap : Nat) (hcap : cap < 256 ^ 4) (frames : List Bytes)
    (h : ∀ f ∈ frames, f.length ≤ cap) (f t : Bytes) (hf : f.length ≤ cap) (ht : t <+: frame f)
    (hne : t ≠ []) (hshort : t.length < (frame f).length) :
    framesRun spec cap (frames.flatMap frame ++ t) = (workerExitFrame, (frames.map spec).flatMap frame, []) := by
  have hbase : framesRun spec cap t = (workerExitFrame, [], []) := by
    by_cases h4 : t.length < 4
    · exact framesRun_short hne h4
    · have ht' := List.prefix_iff_eq_take.1 ht
      have hA : (natBE 4 f.length).length = 4 := natBE_length 4 f.length
      have hlen : (frame f).length = 4 + f.length := by simp [frame, hA]
      generalize hk : t.length = k at ht' h4 hshort
      have e : t = natBE 4 f.length ++ f.take (k - 4) := by
        rw [ht', frame, List.take_append, List.take_of_length_le (by omega), hA]
      have hlt : (f.take (k - 4)).length < f.length := by rw [List.length_take]; omega
      have hcut := framesRun_cut (spec := spec) hcap hf hlt
      rwa [← e] at hcut
  induction frames with
  | nil => simpa using hbase
  | cons g gs ih =>
    have hg := h g (by simp)
    simp only [List.flatMap_cons, List.map_cons, List.append_assoc]
    rw [framesRun_frame hcap hg, ih (fun x hx => h x (by simp [hx]))]

/-- The gate's answer: the old exit code as one byte (0 ACCEPT/INDEX/STORED/FORK/BATCH, 1 REJECT/HOLD,
    2 FRAME), then the old stdout text. `decide` is `VerifyCli`'s `fun w => parse frame w.length w`. -/
def gateAnswer (decide : Bytes → Option (String × UInt32)) (wire : Bytes) : Bytes :=
  match decide wire with
  | some (line, code) => code.toUInt8 :: line.toUTF8.toList
  | none => 2 :: "GATE_VERIFY=FRAME".toUTF8.toList

def gateRespond (decide : Bytes → Option (String × UInt32)) (wire : ByteArray) : Bytes :=
  gateAnswer decide wire.toList

/-- The gate is an instance, so `serveFrames_stateless` and `_resident_eq_fresh` hold for `gate_verify`. -/
example (decide : Bytes → Option (String × UInt32)) : RespondsAs (gateRespond decide) (gateAnswer decide) :=
  fun _ => rfl

/-- The evaluator is an instance through its existing theorem: no new proof for it. -/
example : RespondsAs workerRespondBA workerRespond := workerRespondBA_eq

/-- `maxWorkerFrameBytes` meets `hcap` through its existing theorem. -/
example : maxWorkerFrameBytes < 256 ^ 4 := maxWorkerFrameBytes_fits_u32

end BlindLedger.ResidentGoals
