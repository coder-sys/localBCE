/-! The history engine's pipe: a request frame is read into one buffer that the loop owns and reuses (no chunk per read, no
    append), and an answer is written from its parts (no copy to put the head and root in place).  Standard input and output of
    the process, read and written straight through the system calls; nothing else in the process reads standard input or
    writes standard output.
    Synthetic, nonpayment, non-PHI, activation=false. -/

namespace BlindLedger.Gate.Engine3.Run

/-- Reads up to `n` bytes of standard input into `b` from position `off` on and returns `b`, whose size is `off` plus the bytes read
    (`off` itself at the end of input).  `b` is written in place when it is not shared and has room; else a copy with room
    (rounded up to a whole MiB) is.  `off` is at most the size of `b`. -/
@[extern c inline "({ extern void* rr_gsh_r(int) __asm__(\"GetStdHandle\"); extern int rr_rf(void*, void*, unsigned, unsigned*, void*) __asm__(\"ReadFile\"); lean_object* b_ = #1; size_t off_ = #2, n_ = #3; if (!(b_->m_rc == 1 || b_->m_rc == -1) || lean_sarray_capacity(b_) < off_ + n_) { size_t cap_ = (off_ + n_ + 1048575) & ~(size_t)1048575; lean_object* c_ = lean_alloc_sarray(1, off_, cap_); __builtin_memcpy(lean_sarray_cptr(c_), lean_sarray_cptr(b_), off_); lean_dec(b_); b_ = c_; } unsigned got_ = 0; if (!rr_rf(rr_gsh_r(-10), lean_sarray_cptr(b_) + off_, (unsigned)(n_ > 1073741824 ? 1073741824 : n_), &got_, 0)) got_ = 0; lean_to_sarray(b_)->m_size = off_ + got_; lean_io_result_mk_ok(b_); })"]
opaque readInto (b : ByteArray) (off n : USize) : IO ByteArray

/-- `n` bytes at the start of `b` (fewer only at the end of input): the buffer, whose size is the number read. -/
partial def readFull (b : ByteArray) (n : Nat) : IO ByteArray := do
  let rec go (b : ByteArray) (off : Nat) : IO ByteArray := do
    if n ≤ off then return b
    let b ← readInto b off.toUSize (n - off).toUSize
    if b.size ≤ off then return b else go b b.size
  go b 0

/-- Writes `b[off, off + len)` to standard output; 0 when all of it was written. -/
@[extern c inline "({ extern void* rr_gsh_w(int) __asm__(\"GetStdHandle\"); extern int rr_wf(void*, const void*, unsigned, unsigned*, void*) __asm__(\"WriteFile\"); size_t n_ = #3; const uint8_t* p_ = lean_sarray_cptr(#1) + #2; int ok_ = 1; while (n_ > 0) { unsigned w_ = 0; if (!rr_wf(rr_gsh_w(-11), p_, (unsigned)(n_ > 1073741824 ? 1073741824 : n_), &w_, 0) || w_ == 0) { ok_ = 0; break; } p_ += w_; n_ -= w_; } lean_io_result_mk_ok(lean_box_uint32(ok_ ? 0 : 1)); })"]
opaque writeRange (b : @& ByteArray) (off len : USize) : IO UInt32

/-- Runs the allocator's process start-up, which the Windows loader callback would run but this build does not link: until it
    has run the allocator treats the process as still loading and frees memory with a reset, which keeps it charged. -/
@[extern c inline "(mi_process_init(), lean_io_result_mk_ok(lean_box(0)))"]
opaque allocLoad : IO Unit

end BlindLedger.Gate.Engine3.Run
