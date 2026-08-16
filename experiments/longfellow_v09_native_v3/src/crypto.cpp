#include "util/crypto.h"

#include <cstdint>

namespace proofs {
namespace {

constexpr uint32_t kRound[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed0,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

constexpr uint32_t RotR(uint32_t x, unsigned n) {
  return (x >> n) | (x << (32 - n));
}
constexpr uint32_t Ch(uint32_t x, uint32_t y, uint32_t z) {
  return (x & y) ^ (~x & z);
}
constexpr uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) {
  return (x & y) ^ (x & z) ^ (y & z);
}
constexpr uint32_t Big0(uint32_t x) {
  return RotR(x, 2) ^ RotR(x, 13) ^ RotR(x, 22);
}
constexpr uint32_t Big1(uint32_t x) {
  return RotR(x, 6) ^ RotR(x, 11) ^ RotR(x, 25);
}
constexpr uint32_t Small0(uint32_t x) {
  return RotR(x, 7) ^ RotR(x, 18) ^ (x >> 3);
}
constexpr uint32_t Small1(uint32_t x) {
  return RotR(x, 17) ^ RotR(x, 19) ^ (x >> 10);
}

void Require(NTSTATUS status, const char* message) {
  check(status == 0, message);
}

}  // namespace

SHA256::SHA256()
    : h_{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
         0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19},
      bitlen_(0), datalen_(0), data_{} {}

void SHA256::Transform(const uint8_t block[64]) {
  uint32_t w[64];
  for (size_t i = 0; i < 16; ++i) {
    w[i] = (static_cast<uint32_t>(block[4 * i]) << 24) |
           (static_cast<uint32_t>(block[4 * i + 1]) << 16) |
           (static_cast<uint32_t>(block[4 * i + 2]) << 8) |
           static_cast<uint32_t>(block[4 * i + 3]);
  }
  for (size_t i = 16; i < 64; ++i) {
    w[i] = Small1(w[i - 2]) + w[i - 7] + Small0(w[i - 15]) + w[i - 16];
  }
  uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3];
  uint32_t e = h_[4], f = h_[5], g = h_[6], h = h_[7];
  for (size_t i = 0; i < 64; ++i) {
    const uint32_t t1 = h + Big1(e) + Ch(e, f, g) + kRound[i] + w[i];
    const uint32_t t2 = Big0(a) + Maj(a, b, c);
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }
  h_[0] += a;
  h_[1] += b;
  h_[2] += c;
  h_[3] += d;
  h_[4] += e;
  h_[5] += f;
  h_[6] += g;
  h_[7] += h;
}

void SHA256::Update(const uint8_t bytes[], size_t n) {
  for (size_t i = 0; i < n; ++i) {
    data_[datalen_++] = bytes[i];
    if (datalen_ == sizeof(data_)) {
      Transform(data_);
      bitlen_ += 512;
      datalen_ = 0;
    }
  }
}

void SHA256::DigestData(uint8_t digest[kSHA256DigestSize]) {
  const uint64_t total_bits = bitlen_ + static_cast<uint64_t>(datalen_) * 8;
  size_t i = datalen_;
  data_[i++] = 0x80;
  if (i > 56) {
    while (i < 64) data_[i++] = 0;
    Transform(data_);
    i = 0;
  }
  while (i < 56) data_[i++] = 0;
  for (size_t j = 0; j < 8; ++j) data_[63 - j] = total_bits >> (8 * j);
  Transform(data_);
  for (size_t j = 0; j < 8; ++j) {
    digest[4 * j] = static_cast<uint8_t>(h_[j] >> 24);
    digest[4 * j + 1] = static_cast<uint8_t>(h_[j] >> 16);
    digest[4 * j + 2] = static_cast<uint8_t>(h_[j] >> 8);
    digest[4 * j + 3] = static_cast<uint8_t>(h_[j]);
  }
}

PRF::PRF(const uint8_t key[kPRFKeySize]) {
  Require(BCryptOpenAlgorithmProvider(&alg_, BCRYPT_AES_ALGORITHM, nullptr, 0),
          "BCryptOpenAlgorithmProvider(AES) failed");
  Require(BCryptSetProperty(alg_, BCRYPT_CHAINING_MODE,
                            reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_ECB)),
                            sizeof(BCRYPT_CHAIN_MODE_ECB), 0),
          "BCryptSetProperty(AES ECB) failed");
  DWORD object_len = 0;
  DWORD result_len = 0;
  Require(BCryptGetProperty(alg_, BCRYPT_OBJECT_LENGTH,
                            reinterpret_cast<PUCHAR>(&object_len),
                            sizeof(object_len), &result_len, 0),
          "BCryptGetProperty(AES object length) failed");
  object_.resize(object_len);
  Require(BCryptGenerateSymmetricKey(
              alg_, &key_, object_.data(), static_cast<ULONG>(object_.size()),
              const_cast<PUCHAR>(key), kPRFKeySize, 0),
          "BCryptGenerateSymmetricKey failed");
}

PRF::~PRF() {
  if (key_ != nullptr) BCryptDestroyKey(key_);
  if (alg_ != nullptr) BCryptCloseAlgorithmProvider(alg_, 0);
}

void PRF::Eval(uint8_t out[kPRFOutputSize], uint8_t in[kPRFInputSize]) {
  ULONG out_len = 0;
  Require(BCryptEncrypt(key_, in, kPRFInputSize, nullptr, nullptr, 0, out,
                        kPRFOutputSize, &out_len, 0),
          "BCryptEncrypt failed");
  check(out_len == kPRFOutputSize, "BCryptEncrypt returned wrong length");
}

void rand_bytes(uint8_t out[], size_t n) {
  Require(BCryptGenRandom(nullptr, out, static_cast<ULONG>(n),
                          BCRYPT_USE_SYSTEM_PREFERRED_RNG),
          "BCryptGenRandom failed");
}

void hex_to_str(char out[], const uint8_t in[], size_t n) {
  constexpr char hex[] = "0123456789abcdef";
  for (size_t i = 0; i < n; ++i) {
    out[2 * i] = hex[in[i] >> 4];
    out[2 * i + 1] = hex[in[i] & 0x0f];
  }
  out[2 * n] = '\0';
}

}  // namespace proofs
