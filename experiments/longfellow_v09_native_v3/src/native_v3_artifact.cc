#include "native_v3_artifact.h"

#include <algorithm>
#include <array>
#include <fstream>
#include <limits>

namespace blind_ledger_longfellow {
namespace {

constexpr std::array<uint8_t, 8> kMagic = {
    'B', 'L', 'V', '3', 'L', 'F', '0', '1'};
constexpr uint32_t kVersion = 1;
constexpr size_t kHeaderBytes = 8 + 4 + 32 + 4 + 8;

void PutU32(std::vector<uint8_t>& out, uint32_t value) {
  out.push_back(static_cast<uint8_t>(value >> 24));
  out.push_back(static_cast<uint8_t>(value >> 16));
  out.push_back(static_cast<uint8_t>(value >> 8));
  out.push_back(static_cast<uint8_t>(value));
}

void PutU64(std::vector<uint8_t>& out, uint64_t value) {
  for (size_t i = 0; i < 8; ++i) {
    out.push_back(static_cast<uint8_t>(value >> (56 - 8 * i)));
  }
}

uint32_t GetU32(const uint8_t* p) {
  return (static_cast<uint32_t>(p[0]) << 24) |
         (static_cast<uint32_t>(p[1]) << 16) |
         (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

uint64_t GetU64(const uint8_t* p) {
  uint64_t value = 0;
  for (size_t i = 0; i < 8; ++i) value = (value << 8) | p[i];
  return value;
}

bool ReadFile(const std::string& path, std::vector<uint8_t>& bytes,
              std::string& error) {
  std::ifstream input(path, std::ios::binary | std::ios::ate);
  if (!input) {
    error = "open";
    return false;
  }
  const std::streamoff size = input.tellg();
  if (size < 0 || static_cast<uint64_t>(size) >
                      static_cast<uint64_t>(kHeaderBytes) +
                          kNativeV3PublicBytes + kNativeV3MaxProofBytes) {
    error = "size";
    return false;
  }
  bytes.resize(static_cast<size_t>(size));
  input.seekg(0, std::ios::beg);
  if (!bytes.empty() &&
      !input.read(reinterpret_cast<char*>(bytes.data()), bytes.size())) {
    error = "read";
    return false;
  }
  return true;
}

}  // namespace

bool write_native_v3_artifact(const std::string& path,
                              const std::array<uint8_t, 32>& circuit_id,
                              const std::vector<uint8_t>& public_bytes,
                              const std::vector<uint8_t>& proof_bytes,
                              std::string& error) {
  if (public_bytes.size() != kNativeV3PublicBytes) {
    error = "public-length";
    return false;
  }
  if (proof_bytes.size() > kNativeV3MaxProofBytes ||
      proof_bytes.size() > std::numeric_limits<uint64_t>::max()) {
    error = "proof-length";
    return false;
  }
  std::vector<uint8_t> bytes;
  bytes.reserve(kHeaderBytes + public_bytes.size() + proof_bytes.size());
  bytes.insert(bytes.end(), kMagic.begin(), kMagic.end());
  PutU32(bytes, kVersion);
  bytes.insert(bytes.end(), circuit_id.begin(), circuit_id.end());
  PutU32(bytes, static_cast<uint32_t>(public_bytes.size()));
  PutU64(bytes, static_cast<uint64_t>(proof_bytes.size()));
  bytes.insert(bytes.end(), public_bytes.begin(), public_bytes.end());
  bytes.insert(bytes.end(), proof_bytes.begin(), proof_bytes.end());

  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  if (!output) {
    error = "create";
    return false;
  }
  output.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
  if (!output) {
    error = "write";
    return false;
  }
  return true;
}

bool read_native_v3_artifact(const std::string& path, NativeV3Artifact& artifact,
                             std::string& error) {
  std::vector<uint8_t> bytes;
  if (!ReadFile(path, bytes, error)) return false;
  if (bytes.size() < kHeaderBytes ||
      !std::equal(kMagic.begin(), kMagic.end(), bytes.begin())) {
    error = "header";
    return false;
  }
  if (GetU32(bytes.data() + 8) != kVersion) {
    error = "version";
    return false;
  }
  const uint32_t public_size = GetU32(bytes.data() + 44);
  const uint64_t proof_size = GetU64(bytes.data() + 48);
  if (public_size != kNativeV3PublicBytes ||
      proof_size > kNativeV3MaxProofBytes ||
      proof_size > std::numeric_limits<size_t>::max()) {
    error = "length";
    return false;
  }
  const size_t expected = kHeaderBytes + static_cast<size_t>(public_size) +
                          static_cast<size_t>(proof_size);
  if (expected != bytes.size()) {
    error = "trailing-or-truncated";
    return false;
  }
  std::copy(bytes.begin() + 12, bytes.begin() + 44, artifact.circuit_id.begin());
  artifact.public_bytes.assign(bytes.begin() + kHeaderBytes,
                               bytes.begin() + kHeaderBytes + public_size);
  artifact.proof_bytes.assign(bytes.begin() + kHeaderBytes + public_size,
                              bytes.end());
  return true;
}

const uint8_t* native_v3_transcript_label(size_t& length) {
  static constexpr uint8_t kLabel[] =
      "BL/NATIVE-V3/LONGFELLOW/TRANSCRIPT/v1";
  length = sizeof(kLabel) - 1;
  return kLabel;
}

}  // namespace blind_ledger_longfellow
