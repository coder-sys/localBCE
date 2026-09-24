// Task-local CPU adapter for the pinned Longfellow generic interface.
// Windows CNG supplies AES/RNG; SHA-256 is kept explicit for transcript
// CopyState compatibility. This is an experiment build adapter, not a
// production cryptographic qualification.
#ifndef BLIND_LEDGER_LONGFELLOW_TASK_UTIL_CRYPTO_H_
#define BLIND_LEDGER_LONGFELLOW_TASK_UTIL_CRYPTO_H_

#include <cstddef>
#include <cstdint>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <bcrypt.h>

#ifdef ERROR
#undef ERROR
#endif
#ifdef WARNING
#undef WARNING
#endif
#ifdef INFO
#undef INFO
#endif

#include "util/panic.h"

namespace proofs {

constexpr size_t kSHA256DigestSize = 32;
constexpr size_t kPRFKeySize = 32;
constexpr size_t kPRFInputSize = 16;
constexpr size_t kPRFOutputSize = 16;

class SHA256 {
 public:
  SHA256();
  SHA256(const SHA256&) = default;
  SHA256& operator=(const SHA256&) = default;

  void Update(const uint8_t bytes[], size_t n);
  void DigestData(uint8_t digest[kSHA256DigestSize]);
  void CopyState(const SHA256& src) { *this = src; }

  void Update8(uint64_t x) {
    uint8_t buf[8];
    for (size_t i = 0; i < 8; ++i) {
      buf[i] = static_cast<uint8_t>(x);
      x >>= 8;
    }
    Update(buf, sizeof(buf));
  }

 private:
  void Transform(const uint8_t block[64]);

  uint32_t h_[8];
  uint64_t bitlen_;
  size_t datalen_;
  uint8_t data_[64];
};

class PRF {
 public:
  explicit PRF(const uint8_t key[kPRFKeySize]);
  ~PRF();
  PRF(const PRF&) = delete;
  PRF& operator=(const PRF&) = delete;

  void Eval(uint8_t out[kPRFOutputSize], uint8_t in[kPRFInputSize]);

 private:
  BCRYPT_ALG_HANDLE alg_ = nullptr;
  BCRYPT_KEY_HANDLE key_ = nullptr;
  std::vector<uint8_t> object_;
};

void rand_bytes(uint8_t out[], size_t n);
void hex_to_str(char out[], const uint8_t in[], size_t n);

}  // namespace proofs

#endif  // BLIND_LEDGER_LONGFELLOW_TASK_UTIL_CRYPTO_H_
