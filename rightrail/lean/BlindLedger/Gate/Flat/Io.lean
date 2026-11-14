/-! Page file I/O for the history index (conformance/FLAT_V1.md §6): the only code in the index that touches the OS.

    TCB (gate_engine, gate_rules), the class of `ResidentP.fsyncH`: the C runtime's `_wopen`, `_lseeki64`, `_read`, `_write`,
    `_commit`, `_chsize_s` and `_close`, and kernel32's `MultiByteToWideChar`, asm-labelled so no header declaration is needed.  Trusted for bytes only, as `Flat.Op.run` states: `pgRead` at offset `o` is a pread of `len` bytes (fewer at the
    end of the file; a failed seek or read is an IO error, never a short read), `pgWrite` a pwrite, `pgSync` an fsync, `pgTrunc` a truncation to a length.  Every status is 0 on success.
    `pgReadAt` is `ReadFile` with an `OVERLAPPED` offset (kernel32, asm-labelled like the others).  A file descriptor is the small number `pgOpen` returns (`0xFFFFFFFF`: failed).  No decision logic lives here. -/

namespace BlindLedger.Gate.Flat.Io

/-- Opens (creating if absent) the file at the UTF-8 `path` for reading and writing, in binary mode. -/
@[extern c inline "({ extern int rr_mb(unsigned, unsigned, const char*, int, unsigned short*, int) __asm__(\"MultiByteToWideChar\"); extern int rr_wopen(const unsigned short*, int, int) __asm__(\"_wopen\"); unsigned short w[32768]; int fd = rr_mb(65001, 0, lean_string_cstr(#1), -1, w, 32768) ? rr_wopen(w, 0x8102, 0x180) : -1; lean_io_result_mk_ok(lean_box_uint32((uint32_t)fd)); })"]
opaque pgOpen (path : @& String) : IO UInt32

/-- Up to `len` bytes at byte offset `off`; an IO error when the seek or read fails (a short or empty result is the end of the file only). -/
@[extern c inline "({ extern long long rr_seek(int, long long, int) __asm__(\"_lseeki64\"); extern int rr_read(int, void*, unsigned) __asm__(\"_read\"); size_t n = #3; lean_object* a = lean_alloc_sarray(1, 0, n); int got = rr_seek((int)#1, (long long)#2, 0) < 0 ? -1 : rr_read((int)#1, lean_sarray_cptr(a), (unsigned)n); got < 0 ? (lean_dec(a), lean_io_result_mk_error(lean_mk_io_user_error(lean_mk_string(\"pgRead\")))) : (lean_sarray_set_size(a, (size_t)got), lean_io_result_mk_ok(a)); })"]
opaque pgRead (fd : UInt32) (off : UInt64) (len : USize) : IO ByteArray

/-- Like `pgRead`, in one system call: kernel32's `ReadFile` with the offset in an `OVERLAPPED`, so there is no seek.  The same
    results: up to `len` bytes, fewer or none at the end of the file (`ERROR_HANDLE_EOF`), an IO error on any other failure.
    The file pointer is not meant to be used after it. -/
@[extern c inline "({ extern void* rr_osh(int) __asm__(\"_get_osfhandle\"); extern int rr_rf(void*, void*, unsigned, unsigned*, void*) __asm__(\"ReadFile\"); extern unsigned rr_gle(void) __asm__(\"GetLastError\"); size_t n = #3; lean_object* a = lean_alloc_sarray(1, 0, n); unsigned long long ov[4] = {0, 0, #2, 0}; unsigned got = 0; int ok = rr_rf(rr_osh((int)#1), lean_sarray_cptr(a), (unsigned)n, &got, ov); int bad = !ok && rr_gle() != 38; bad ? (lean_dec(a), lean_io_result_mk_error(lean_mk_io_user_error(lean_mk_string(\"pgReadAt\")))) : (lean_sarray_set_size(a, (size_t)(ok ? got : 0)), lean_io_result_mk_ok(a)); })"]
opaque pgReadAt (fd : UInt32) (off : UInt64) (len : USize) : IO ByteArray

/-- All of `b` at byte offset `off`. -/
@[extern c inline "({ extern long long rr_seek(int, long long, int) __asm__(\"_lseeki64\"); extern int rr_write(int, const void*, unsigned) __asm__(\"_write\"); size_t n = lean_sarray_size(#3); int ok = rr_seek((int)#1, (long long)#2, 0) >= 0 && rr_write((int)#1, lean_sarray_cptr(#3), (unsigned)n) == (int)n; lean_io_result_mk_ok(lean_box_uint32(ok ? 0 : 1)); })"]
opaque pgWrite (fd : UInt32) (off : UInt64) (b : @& ByteArray) : IO UInt32

/-- `_commit`: the file's written bytes are on disk when this returns 0. -/
@[extern c inline "({ extern int rr_commit(int) __asm__(\"_commit\"); lean_io_result_mk_ok(lean_box_uint32((uint32_t)rr_commit((int)#1))); })"]
opaque pgSync (fd : UInt32) : IO UInt32

/-- `_chsize_s(fd, len)`: the file is cut to `len` bytes (0: empty). -/
@[extern c inline "({ extern int rr_chsize(int, long long) __asm__(\"_chsize_s\"); lean_io_result_mk_ok(lean_box_uint32((uint32_t)rr_chsize((int)#1, (long long)#2))); })"]
opaque pgTrunc (fd : UInt32) (len : UInt64) : IO UInt32

@[extern c inline "({ extern int rr_close(int) __asm__(\"_close\"); lean_io_result_mk_ok(lean_box_uint32((uint32_t)rr_close((int)#1))); })"]
opaque pgClose (fd : UInt32) : IO UInt32

end BlindLedger.Gate.Flat.Io
