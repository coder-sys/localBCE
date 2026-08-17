#include "native_v3_source_assertion_public_parity.h"

#include <algorithm>
#include <fstream>

namespace blind_ledger_longfellow::source_assertion_public_parity {
namespace {

void PutU32(std::vector<uint8_t>& bytes, uint32_t value) {
  bytes.push_back(static_cast<uint8_t>(value >> 24));
  bytes.push_back(static_cast<uint8_t>(value >> 16));
  bytes.push_back(static_cast<uint8_t>(value >> 8));
  bytes.push_back(static_cast<uint8_t>(value));
}

bool GetU32(const std::vector<uint8_t>& bytes, size_t& offset,
           uint32_t& value) {
  if (bytes.size() - offset < 4) return false;
  value = (static_cast<uint32_t>(bytes[offset]) << 24) |
          (static_cast<uint32_t>(bytes[offset + 1]) << 16) |
          (static_cast<uint32_t>(bytes[offset + 2]) << 8) |
          static_cast<uint32_t>(bytes[offset + 3]);
  offset += 4;
  return true;
}

bool ReadBytes(const std::string& path, std::vector<uint8_t>& bytes,
               std::string& error) {
  std::ifstream input(path, std::ios::binary | std::ios::ate);
  if (!input) {
    error = "open";
    return false;
  }
  const std::streampos end = input.tellg();
  if (end < 0 || static_cast<uint64_t>(end) != kFileBytes) {
    error = "length";
    return false;
  }
  bytes.resize(kFileBytes);
  input.seekg(0, std::ios::beg);
  input.read(reinterpret_cast<char*>(bytes.data()),
             static_cast<std::streamsize>(bytes.size()));
  if (!input) {
    error = "read";
    return false;
  }
  return true;
}

}  // namespace

bool serialize(const Artifact& artifact, std::vector<uint8_t>& bytes,
               std::string& error) {
  if (artifact.statement_bytes.size() != kStatementBytes) {
    error = "statement-length";
    return false;
  }
  if (artifact.field_bytes.size() != kFieldCount * kFieldBytes) {
    error = "field-vector-length";
    return false;
  }
  bytes.clear();
  bytes.reserve(kFileBytes);
  bytes.insert(bytes.end(), kMagic, kMagic + kMagicBytes);
  PutU32(bytes, kVersion);
  PutU32(bytes, static_cast<uint32_t>(kStatementBytes));
  PutU32(bytes, static_cast<uint32_t>(kFieldCount));
  bytes.insert(bytes.end(), artifact.statement_bytes.begin(),
               artifact.statement_bytes.end());
  bytes.insert(bytes.end(), artifact.field_bytes.begin(),
               artifact.field_bytes.end());
  return bytes.size() == kFileBytes;
}

bool write(const std::string& path, const Artifact& artifact,
           std::string& error) {
  std::vector<uint8_t> bytes;
  if (!serialize(artifact, bytes, error)) return false;
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  if (!output) {
    error = "open-output";
    return false;
  }
  output.write(reinterpret_cast<const char*>(bytes.data()),
               static_cast<std::streamsize>(bytes.size()));
  if (!output) {
    error = "write";
    return false;
  }
  return true;
}

bool read(const std::string& path, Artifact& artifact, std::string& error) {
  std::vector<uint8_t> bytes;
  if (!ReadBytes(path, bytes, error)) return false;
  if (!std::equal(bytes.begin(), bytes.begin() + kMagicBytes, kMagic)) {
    error = "magic";
    return false;
  }
  size_t offset = kMagicBytes;
  uint32_t version = 0;
  uint32_t statement_bytes = 0;
  uint32_t field_count = 0;
  if (!GetU32(bytes, offset, version) ||
      !GetU32(bytes, offset, statement_bytes) ||
      !GetU32(bytes, offset, field_count)) {
    error = "header";
    return false;
  }
  if (version != kVersion || statement_bytes != kStatementBytes ||
      field_count != kFieldCount) {
    error = "header-values";
    return false;
  }
  if (bytes.size() - offset != kStatementBytes + kFieldCount * kFieldBytes) {
    error = "trailing";
    return false;
  }
  artifact.statement_bytes.assign(bytes.begin() + offset,
                                 bytes.begin() + offset + kStatementBytes);
  offset += kStatementBytes;
  artifact.field_bytes.assign(bytes.begin() + offset, bytes.end());
  return true;
}

}  // namespace blind_ledger_longfellow::source_assertion_public_parity
