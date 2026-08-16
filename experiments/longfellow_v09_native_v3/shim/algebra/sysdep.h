// Task-local portable arithmetic adapter for MSVC.
// It preserves the pinned Longfellow sysdep interface without GNU asm.
#ifndef BLIND_LEDGER_LONGFELLOW_SYSDEP_H_
#define BLIND_LEDGER_LONGFELLOW_SYSDEP_H_

#include <cstddef>
#include <cstdint>
#include <intrin.h>

namespace proofs {

static inline uint64_t adc(uint64_t* a, uint64_t b, uint64_t c) {
  const uint64_t old = *a;
  const uint64_t result = old + b;
  const uint64_t carry1 = result < old;
  const uint64_t result2 = result + c;
  const uint64_t carry2 = result2 < result;
  *a = result2;
  return carry1 | carry2;
}

static inline uint32_t adc(uint32_t* a, uint32_t b, uint32_t c) {
  const uint32_t old = *a;
  const uint32_t result = old + b;
  const uint32_t carry1 = result < old;
  const uint32_t result2 = result + c;
  const uint32_t carry2 = result2 < result;
  *a = result2;
  return carry1 | carry2;
}

static inline uint64_t sbb(uint64_t* a, uint64_t b, uint64_t c) {
  const uint64_t old = *a;
  const uint64_t result = old - b;
  const uint64_t borrow1 = old < b;
  const uint64_t result2 = result - c;
  const uint64_t borrow2 = result < c;
  *a = result2;
  return borrow1 | borrow2;
}

static inline uint32_t sbb(uint32_t* a, uint32_t b, uint32_t c) {
  const uint32_t old = *a;
  const uint32_t result = old - b;
  const uint32_t borrow1 = old < b;
  const uint32_t result2 = result - c;
  const uint32_t borrow2 = result < c;
  *a = result2;
  return borrow1 | borrow2;
}

static inline void mulq(uint64_t* l, uint64_t* h, uint64_t a, uint64_t b) {
  *l = _umul128(a, b, h);
}

static inline void mulq(uint32_t* l, uint32_t* h, uint32_t a, uint32_t b) {
  const uint64_t product = static_cast<uint64_t>(a) * b;
  *l = static_cast<uint32_t>(product);
  *h = static_cast<uint32_t>(product >> 32);
}

template <class limb_t>
static inline limb_t identity_limb(limb_t v) { return v; }

template <class limb_t>
static inline limb_t zero_limb() { return identity_limb<limb_t>(0); }

template <class limb_t>
static inline void accum(size_t wa, limb_t a[], size_t wb,
                         const limb_t b[]) {
  limb_t carry = 0;
  for (size_t i = 0; i < wb; ++i) carry = adc(&a[i], b[i], carry);
  for (size_t i = wb; i < wa; ++i) carry = adc(&a[i], 0, carry);
}

template <class limb_t>
static inline void negaccum(size_t wa, limb_t a[], size_t wb,
                            const limb_t b[]) {
  limb_t borrow = 0;
  for (size_t i = 0; i < wb; ++i) borrow = sbb(&a[i], b[i], borrow);
  for (size_t i = wb; i < wa; ++i) borrow = sbb(&a[i], 0, borrow);
}

template <class limb_t>
static inline limb_t add_limb(size_t width, limb_t a[], const limb_t b[]) {
  limb_t carry = 0;
  for (size_t i = 0; i < width; ++i) carry = adc(&a[i], b[i], carry);
  limb_t high = zero_limb<limb_t>();
  (void)adc(&high, 0, carry);
  return high;
}

template <class limb_t>
static inline limb_t addh(size_t width, limb_t a[], const limb_t b[]) {
  limb_t carry = 0;
  for (size_t i = 1; i < width; ++i) carry = adc(&a[i], b[i - 1], carry);
  limb_t high = zero_limb<limb_t>();
  (void)adc(&high, b[width - 1], carry);
  return high;
}

template <class limb_t>
static inline limb_t sub_limb(size_t width, limb_t a[], const limb_t b[]) {
  limb_t borrow = 0;
  for (size_t i = 0; i < width; ++i) borrow = sbb(&a[i], b[i], borrow);
  limb_t high = zero_limb<limb_t>();
  (void)sbb(&high, 0, borrow);
  return high;
}

template <class limb_t>
static inline void mulhl(size_t width, limb_t l[], limb_t h[], limb_t a,
                         const limb_t b[]) {
  for (size_t i = 0; i < width; ++i) mulq(&l[i], &h[i], a, b[i]);
}

template <class limb_t>
static inline void mov(size_t width, limb_t a[], const limb_t b[]) {
  for (size_t i = 0; i < width; ++i) a[i] = b[i];
}

template <class limb_t>
static inline void cmovne(size_t width, limb_t a[], limb_t x, limb_t y,
                          const limb_t b[]) {
  for (size_t i = 0; i < width; ++i) a[i] = (x != y) ? b[i] : a[i];
}

template <class limb_t>
static inline void cmovnz(size_t width, limb_t a[], limb_t nz,
                          const limb_t b[]) {
  cmovne(width, a, nz, static_cast<limb_t>(0), b);
}

template <class limb_t>
static inline limb_t addcmovc(limb_t a, limb_t b, limb_t c) {
  const limb_t t = a + b;
  return (a > t) ? t : c;
}

template <class limb_t>
static inline limb_t sub_sysdep(limb_t a, limb_t y, limb_t m) {
  const limb_t t = a - y;
  return (y > a) ? (t + m) : t;
}

static inline uint32_t addcmovc_32(uint32_t a, uint32_t b, uint32_t c) {
  return addcmovc(a, b, c);
}

static inline uint32_t sub_sysdep_32(uint32_t a, uint32_t y, uint32_t m) {
  return sub_sysdep(a, y, m);
}

}  // namespace proofs

#endif  // BLIND_LEDGER_LONGFELLOW_SYSDEP_H_
