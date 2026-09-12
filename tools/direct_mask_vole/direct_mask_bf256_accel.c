/*
 * Child-local GF(2^256) multiplication backend.
 *
 * The representation is the pinned FAEST representation: values[0] is the
 * least-significant 64-bit polynomial limb and the modulus is
 * x^256 + x^10 + x^5 + x^2 + 1.  The accelerated path uses four-by-four
 * carry-less 64-bit products followed by fixed-word reduction.  Dispatch is
 * based only on public CPU capability and never on field inputs.
 */

#include "direct_mask_bf256_accel.h"

#include <stdint.h>

#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
#include <intrin.h>
#include <windows.h>
#include <wmmintrin.h>
#elif defined(__x86_64__) || defined(__i386__)
#include <cpuid.h>
#include <wmmintrin.h>
#endif

typedef void (*direct_mask_bf256_mul_fn)(bf256_t* dst, const bf256_t* lhs,
                                         const bf256_t* rhs);

#if defined(DIRECT_MASK_BF256_FORCE_PORTABLE) && \
    !defined(DIRECT_MASK_BF256_TEST_SEAM)
#error "DIRECT_MASK_BF256_FORCE_PORTABLE is test-only"
#endif

static int direct_mask_bf256_cpu_has_pclmul(void) {
#if defined(DIRECT_MASK_BF256_FORCE_PORTABLE)
  return 0;
#elif defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
  int regs[4] = {0, 0, 0, 0};
  __cpuid(regs, 0);
  if (regs[0] < 1) {
    return 0;
  }
  __cpuid(regs, 1);
  return (regs[2] & (1 << 1)) != 0;
#elif (defined(__x86_64__) || defined(__i386__)) && (defined(__GNUC__) || defined(__clang__))
  unsigned int eax = 0;
  unsigned int ebx = 0;
  unsigned int ecx = 0;
  unsigned int edx = 0;
  if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
    return 0;
  }
  return (ecx & (1u << 1)) != 0;
#else
  return 0;
#endif
}

int direct_mask_bf256_pclmul_available(void) {
  return direct_mask_bf256_cpu_has_pclmul();
}

#if (defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))) || \
    defined(__x86_64__) || defined(__i386__)
#if (defined(__GNUC__) || defined(__clang__)) && !defined(_MSC_VER)
__attribute__((target("pclmul")))
#endif
static void direct_mask_bf256_mul_pclmul(bf256_t* dst, const bf256_t* lhs,
                                         const bf256_t* rhs) {
  uint64_t product[8] = {0, 0, 0, 0, 0, 0, 0, 0};

  for (unsigned int i = 0; i != 4; ++i) {
    for (unsigned int j = 0; j != 4; ++j) {
      const __m128i left = _mm_cvtsi64_si128((long long)BF_VALUE(*lhs, i));
      const __m128i right = _mm_cvtsi64_si128((long long)BF_VALUE(*rhs, j));
      const __m128i product_pair = _mm_clmulepi64_si128(left, right, 0x00);
      uint64_t pair[2];

      _mm_storeu_si128((__m128i*)pair, product_pair);
      product[i + j] ^= pair[0];
      product[i + j + 1] ^= pair[1];
    }
  }

  /* Reduce x^256 through x^256 = x^10 + x^5 + x^2 + 1. */
  for (int i = 7; i >= 4; --i) {
    const uint64_t high = product[i];
    product[i] = 0;

    product[i - 4] ^= high;
    product[i - 4] ^= high << 2;
    product[i - 3] ^= high >> 62;
    product[i - 4] ^= high << 5;
    product[i - 3] ^= high >> 59;
    product[i - 4] ^= high << 10;
    product[i - 3] ^= high >> 54;
  }

  for (unsigned int i = 0; i != 4; ++i) {
    BF_VALUE(*dst, i) = product[i];
  }
}
#endif

/* The pinned portable implementation permits a destination aliasing lhs but
 * overwrites rhs before all rhs bits have been consumed.  Copy both public
 * inputs at this dispatch boundary so the supported public alias contract is
 * identical for the portable and accelerated backends. */
static void direct_mask_bf256_mul_portable_alias_safe(
    bf256_t* dst, const bf256_t* lhs, const bf256_t* rhs) {
  bf256_t lhs_copy = *lhs;
  bf256_t rhs_copy = *rhs;
  direct_mask_bf256_mul_portable(dst, &lhs_copy, &rhs_copy);
}

#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
static volatile PVOID direct_mask_bf256_mul_impl;

static direct_mask_bf256_mul_fn direct_mask_bf256_select_impl(void) {
  PVOID current = InterlockedCompareExchangePointer(
      &direct_mask_bf256_mul_impl, NULL, NULL);
  if (current != NULL) {
    return (direct_mask_bf256_mul_fn)current;
  }

  direct_mask_bf256_mul_fn selected = direct_mask_bf256_cpu_has_pclmul()
                                          ? direct_mask_bf256_mul_pclmul
                                          : direct_mask_bf256_mul_portable_alias_safe;
  current = InterlockedCompareExchangePointer(
      &direct_mask_bf256_mul_impl, (PVOID)selected, NULL);
  return current == NULL ? selected : (direct_mask_bf256_mul_fn)current;
}
#elif defined(__GNUC__) || defined(__clang__)
static direct_mask_bf256_mul_fn direct_mask_bf256_mul_impl;

static direct_mask_bf256_mul_fn direct_mask_bf256_select_impl(void) {
  direct_mask_bf256_mul_fn current =
      __atomic_load_n(&direct_mask_bf256_mul_impl, __ATOMIC_ACQUIRE);
  if (current != NULL) {
    return current;
  }

  direct_mask_bf256_mul_fn selected =
#if defined(__x86_64__) || defined(__i386__)
      direct_mask_bf256_cpu_has_pclmul() ? direct_mask_bf256_mul_pclmul
                                         : direct_mask_bf256_mul_portable_alias_safe;
#else
      direct_mask_bf256_mul_portable_alias_safe;
#endif
  if (__atomic_compare_exchange_n(&direct_mask_bf256_mul_impl, &current, selected, 0,
                                  __ATOMIC_RELEASE, __ATOMIC_ACQUIRE)) {
    return selected;
  }
  return current;
}
#else
static direct_mask_bf256_mul_fn direct_mask_bf256_select_impl(void) {
  return direct_mask_bf256_mul_portable_alias_safe;
}
#endif

void bf256_mul(bf256_t* dst, const bf256_t* lhs, const bf256_t* rhs) {
  direct_mask_bf256_select_impl()(dst, lhs, rhs);
}

void bf256_mul_inplace(bf256_t* lhs, const bf256_t* rhs) {
  bf256_t lhs_copy = *lhs;
  bf256_t result;
  direct_mask_bf256_select_impl()(&result, &lhs_copy, rhs);
  *lhs = result;
}

const char* direct_mask_bf256_backend_name(void) {
#if (defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))) || \
    defined(__GNUC__) || defined(__clang__)
  return direct_mask_bf256_select_impl() == direct_mask_bf256_mul_portable_alias_safe
             ? "portable"
             : "pclmul";
#else
  return "portable";
#endif
}
