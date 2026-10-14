import BlindLedger.Gate.Engine.Log

/-! ENGINE-0 S3 (design `engine0-design-20261013` sections 1.1 and 7): the ENGINE-FRAME/v1 pipe
    codec and the ByteArray hash path.  Synthetic, nonpayment; moves no money.  Frames are
    transport and never hashed.

    `be4 len || u8 ver=1 || u8 op || body`, `len` counts from `ver`, `2 <= len <= frameMax`.
    Py -> engine ops 0x01 OPEN .. 0x06 SIGNED; engine -> Py 0x81 PROPOSAL, 0x82 OK, 0xE0 REFUSED.
    An unknown ver or op or a length out of range refuses; a short read never decodes; trailing
    bytes are returned untouched (E8), so the caller refuses them. -/

namespace BlindLedger.Gate.Engine

open BlindLedger.Gate

def frameMax : Nat := 64 * 1024 * 1024

def opKnown (op : Nat) : Bool := [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x81, 0x82, 0xE0].contains op

structure Frame where
  op : Nat
  body : Bytes

def frameIn (f : Frame) : Bytes := natBE 4 (f.body.length + 2) ++ natBE 1 1 ++ natBE 1 f.op ++ f.body
def encodeFrame (f : Frame) : ByteArray := (frameIn f).toByteArray
def Frame.wf (f : Frame) : Prop := opKnown f.op ∧ f.op < 256 ^ 1 ∧ f.body.length + 2 ≤ frameMax

def pFrame : P Frame := do
  let n ← rd 4
  need (decide (2 ≤ n ∧ n ≤ frameMax))
  let v ← rd 1
  need (v == 1)
  let op ← rd 1
  need (opKnown op)
  let body ← take (n - 2)
  pure ⟨op, body⟩

/-- One frame off the front of `b`, and the bytes after it. -/
def decodeFrame (b : ByteArray) : Option (Frame × ByteArray) :=
  (pFrame.run b.data.toList).map fun p => (p.1, p.2.toByteArray)

theorem toByteArray_toList (a : ByteArray) : a.data.toList.toByteArray = a :=
  ByteArray.ext (Array.toList_inj.1 (by rw [List.toList_data_toByteArray]))

theorem pFrame_run {b r : Bytes} {f : Frame} (h : pFrame.run b = some (f, r)) : frameIn f ++ r = b ∧ f.wf := by
  obtain ⟨n, r1, h1, g1⟩ := Approval.bind_run h
  obtain ⟨u1, r2, h2, g2⟩ := Approval.bind_run g1
  obtain ⟨hn, rfl⟩ := Approval.need_run h2
  obtain ⟨v, r3, h3, g3⟩ := Approval.bind_run g2
  obtain ⟨u2, r4, h4, g4⟩ := Approval.bind_run g3
  obtain ⟨hv, rfl⟩ := Approval.need_run h4
  obtain ⟨op, r5, h5, g5⟩ := Approval.bind_run g4
  obtain ⟨u3, r6, h6, g6⟩ := Approval.bind_run g5
  obtain ⟨ho, rfl⟩ := Approval.need_run h6
  obtain ⟨bd, r7, h7, g7⟩ := Approval.bind_run g6
  obtain ⟨rfl, rfl⟩ := Approval.pure_run g7
  obtain ⟨e1, -⟩ := rd_run h1
  obtain ⟨e3, -⟩ := rd_run h3
  obtain ⟨e5, w5⟩ := rd_run h5
  obtain ⟨e7, hl⟩ := Approval.take_run h7
  simp only [decide_eq_true_eq] at hn
  simp only [beq_iff_eq] at hv
  have hb : bd.length + 2 = n := by omega
  have hw : bd.length + 2 ≤ frameMax := hb ▸ hn.2
  subst e7 e5 e3 e1 hv
  exact ⟨by simp [frameIn, hb], ho, w5, hw⟩

theorem pFrame_app (f : Frame) (h : f.wf) (r : Bytes) : pFrame.run (frameIn f ++ r) = some (f, r) := by
  obtain ⟨ho, h8, hl⟩ := h
  have hn : f.body.length + 2 < 256 ^ 4 := by unfold frameMax at hl; omega
  have hc : decide (2 ≤ f.body.length + 2 ∧ f.body.length + 2 ≤ frameMax) = true := by simp [hl]
  simp only [pFrame, frameIn, List.append_assoc, seq_app (rd_app hn), hc, need_seq,
    seq_app (rd_app (w := 1) (v := 1) (by decide)), beq_self_eq_true, seq_app (rd_app h8), ho,
    Nat.add_sub_cancel, seq_app (fun r => take_app (a := f.body) (r := r) rfl)] <;> rfl

/-- E8: a decoded frame is well formed and re-encodes to exactly the bytes it was read from; the
    rest is returned untouched.  `Option` makes the decoder total: every input decodes or refuses. -/
theorem E8_frame_total {b rest : ByteArray} {f : Frame} (h : decodeFrame b = some (f, rest)) :
    encodeFrame f ++ rest = b ∧ f.wf := by
  cases hr : pFrame.run b.data.toList with
  | none => simp [decodeFrame, hr] at h
  | some q =>
    obtain ⟨f', r⟩ := q
    simp only [decodeFrame, hr, Option.map_some, Option.some.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    obtain ⟨he, hw⟩ := pFrame_run hr
    refine ⟨?_, hw⟩
    rw [encodeFrame, ← List.toByteArray_append, he, toByteArray_toList]

/-- The decoder never reads past `len`: whatever follows a well-formed frame comes back as the rest. -/
theorem decodeFrame_app (f : Frame) (h : f.wf) (r : ByteArray) : decodeFrame (encodeFrame f ++ r) = some (f, r) := by
  have he : (encodeFrame f ++ r).data.toList = frameIn f ++ r.data.toList := by
    rw [encodeFrame, ByteArray.data_append, Array.toList_append, List.toList_data_toByteArray]
  simp only [decodeFrame, he, pFrame_app f h, Option.map_some, toByteArray_toList]

/-- The engine hashes ByteArrays; the spec hashes byte lists. -/
def sha3B (a : ByteArray) : ByteArray := Semantic.sha3_512Fast a

/-- C5: the engine's ByteArray hash is the spec hash. -/
theorem C5_bytes_refine (a : ByteArray) : (sha3B a).toList = sha3 a.data.toList := by
  rw [sha3, toByteArray_toList, sha3B]

end BlindLedger.Gate.Engine
