#ifndef BLIND_LEDGER_LONGFELLOW_V09_SOURCE_ASSERTION_PUBLIC_PARITY_H_
#define BLIND_LEDGER_LONGFELLOW_V09_SOURCE_ASSERTION_PUBLIC_PARITY_H_

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace blind_ledger_longfellow::source_assertion_public_parity {

constexpr char kMagic[] = "BLPVKAT1";
constexpr size_t kMagicBytes = sizeof(kMagic) - 1;
constexpr uint32_t kVersion = 1;
constexpr size_t kFieldBytes = 16;
constexpr size_t kStatementBytes = 1018;
constexpr size_t kFieldCount = 1 + kStatementBytes * 8;
constexpr size_t kHeaderBytes = kMagicBytes + 4 + 4 + 4;
constexpr size_t kFileBytes = kHeaderBytes + kStatementBytes +
                               kFieldCount * kFieldBytes;

struct Artifact {
  std::vector<uint8_t> statement_bytes;
  std::vector<uint8_t> field_bytes;
};

bool serialize(const Artifact& artifact, std::vector<uint8_t>& bytes,
               std::string& error);
bool write(const std::string& path, const Artifact& artifact,
           std::string& error);
bool read(const std::string& path, Artifact& artifact, std::string& error);

}  // namespace blind_ledger_longfellow::source_assertion_public_parity

#endif  // BLIND_LEDGER_LONGFELLOW_V09_SOURCE_ASSERTION_PUBLIC_PARITY_H_
