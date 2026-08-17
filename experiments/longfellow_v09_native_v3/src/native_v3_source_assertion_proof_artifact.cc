#include "native_v3_source_assertion_proof_artifact.h"

#include <algorithm>
#include <fstream>
#include <limits>

namespace blind_ledger_longfellow::source_assertion_proof {
namespace {

constexpr char kMagic[] = "BLASV3P1";

uint32_t read_u32(const std::vector<uint8_t>& bytes, size_t offset) {
  return (static_cast<uint32_t>(bytes[offset]) << 24) |
         (static_cast<uint32_t>(bytes[offset + 1]) << 16) |
         (static_cast<uint32_t>(bytes[offset + 2]) << 8) |
         static_cast<uint32_t>(bytes[offset + 3]);
}

uint64_t read_u64(const std::vector<uint8_t>& bytes, size_t offset) {
  uint64_t result = 0;
  for (size_t index = 0; index < 8; ++index) {
    result = (result << 8) | bytes[offset + index];
  }
  return result;
}

void append_u32(std::vector<uint8_t>& bytes, uint32_t value) {
  for (size_t index = 0; index < 4; ++index) {
    bytes.push_back(static_cast<uint8_t>(value >> (24 - index * 8)));
  }
}

void append_u64(std::vector<uint8_t>& bytes, uint64_t value) {
  for (size_t index = 0; index < 8; ++index) {
    bytes.push_back(static_cast<uint8_t>(value >> (56 - index * 8)));
  }
}

bool checked_total(size_t proof_size, size_t& total) {
  if (proof_size > kMaxProofBytes ||
      proof_size > std::numeric_limits<size_t>::max() - kHeaderBytes -
                        kPublicStatementBytes) {
    return false;
  }
  total = kHeaderBytes + kPublicStatementBytes + proof_size;
  return true;
}

}  // namespace

bool parse_artifact_bytes(const std::vector<uint8_t>& bytes, Artifact& artifact,
                          std::string& error) {
  if (bytes.size() < kHeaderBytes) {
    error = "header-truncated";
    return false;
  }
  if (!std::equal(bytes.begin(), bytes.begin() + sizeof(kMagic) - 1,
                  reinterpret_cast<const uint8_t*>(kMagic))) {
    error = "magic";
    return false;
  }
  if (read_u32(bytes, 8) != kFormatVersion) {
    error = "version";
    return false;
  }
  const uint32_t public_size = read_u32(bytes, 56);
  const uint64_t proof_size64 = read_u64(bytes, 60);
  if (public_size != kPublicStatementBytes) {
    error = "public-length";
    return false;
  }
  if (proof_size64 > kMaxProofBytes || proof_size64 > std::numeric_limits<size_t>::max()) {
    error = "proof-length";
    return false;
  }
  size_t expected_size = 0;
  if (!checked_total(static_cast<size_t>(proof_size64), expected_size)) {
    error = "size-cap";
    return false;
  }
  if (bytes.size() != expected_size) {
    error = bytes.size() < expected_size ? "truncated" : "trailing";
    return false;
  }
  artifact.circuit_id = {};
  std::copy_n(bytes.begin() + 12, kCircuitIdBytes, artifact.circuit_id.begin());
  artifact.rate = read_u32(bytes, 44);
  artifact.queries = read_u32(bytes, 48);
  artifact.transcript_version = read_u32(bytes, 52);
  artifact.public_statement.assign(bytes.begin() + kHeaderBytes,
                                   bytes.begin() + kHeaderBytes +
                                       kPublicStatementBytes);
  artifact.proof.assign(bytes.begin() + kHeaderBytes + kPublicStatementBytes,
                        bytes.end());
  return true;
}

bool read_artifact_bytes(const std::string& path, std::vector<uint8_t>& bytes,
                         std::string& error) {
  std::ifstream input(path, std::ios::binary | std::ios::ate);
  if (!input) {
    error = "open";
    return false;
  }
  const std::streamoff size = input.tellg();
  if (size < 0 || static_cast<uint64_t>(size) >
                      kHeaderBytes + kPublicStatementBytes + kMaxProofBytes) {
    error = "file-size-cap";
    return false;
  }
  bytes.resize(static_cast<size_t>(size));
  input.seekg(0, std::ios::beg);
  if (!bytes.empty()) {
    input.read(reinterpret_cast<char*>(bytes.data()),
               static_cast<std::streamsize>(bytes.size()));
  }
  if (!input) {
    error = "read";
    return false;
  }
  return true;
}

bool read_artifact(const std::string& path, Artifact& artifact,
                   std::string& error) {
  std::vector<uint8_t> bytes;
  return read_artifact_bytes(path, bytes, error) &&
         parse_artifact_bytes(bytes, artifact, error);
}

bool serialize_artifact(const Artifact& artifact, std::vector<uint8_t>& bytes,
                        std::string& error) {
  if (artifact.public_statement.size() != kPublicStatementBytes) {
    error = "public-length";
    return false;
  }
  if (artifact.proof.size() > kMaxProofBytes) {
    error = "proof-length";
    return false;
  }
  bytes.clear();
  bytes.insert(bytes.end(), reinterpret_cast<const uint8_t*>(kMagic),
               reinterpret_cast<const uint8_t*>(kMagic) + sizeof(kMagic) - 1);
  append_u32(bytes, kFormatVersion);
  bytes.insert(bytes.end(), artifact.circuit_id.begin(), artifact.circuit_id.end());
  append_u32(bytes, artifact.rate);
  append_u32(bytes, artifact.queries);
  append_u32(bytes, artifact.transcript_version);
  append_u32(bytes, static_cast<uint32_t>(artifact.public_statement.size()));
  append_u64(bytes, static_cast<uint64_t>(artifact.proof.size()));
  bytes.insert(bytes.end(), artifact.public_statement.begin(),
               artifact.public_statement.end());
  bytes.insert(bytes.end(), artifact.proof.begin(), artifact.proof.end());
  return true;
}

bool write_artifact(const std::string& path,
                    const std::array<uint8_t, kCircuitIdBytes>& circuit_id,
                    uint32_t rate, uint32_t queries, uint32_t transcript_version,
                    const std::vector<uint8_t>& public_statement,
                    const std::vector<uint8_t>& proof, std::string& error) {
  Artifact artifact;
  artifact.circuit_id = circuit_id;
  artifact.rate = rate;
  artifact.queries = queries;
  artifact.transcript_version = transcript_version;
  artifact.public_statement = public_statement;
  artifact.proof = proof;
  std::vector<uint8_t> bytes;
  if (!serialize_artifact(artifact, bytes, error)) return false;
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  if (!output) {
    error = "open-output";
    return false;
  }
  output.write(reinterpret_cast<const char*>(bytes.data()),
               static_cast<std::streamsize>(bytes.size()));
  if (!output) {
    error = "write-output";
    return false;
  }
  return true;
}

}  // namespace blind_ledger_longfellow::source_assertion_proof
