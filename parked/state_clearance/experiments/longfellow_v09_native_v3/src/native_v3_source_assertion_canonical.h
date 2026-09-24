#ifndef BLIND_LEDGER_LONGFELLOW_V09_SOURCE_ASSERTION_CANONICAL_H_
#define BLIND_LEDGER_LONGFELLOW_V09_SOURCE_ASSERTION_CANONICAL_H_

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "arrays/dense.h"
#include "native_v3_source_assertion_relation.h"

namespace blind_ledger_longfellow::source_assertion_verifier {

// The artifact remains a big-endian canonical wire record.  This typed
// decoder is the verifier-owned boundary between that record and the
// circuit's native bit wires; it deliberately does not call producer
// statement or witness helpers.
class CanonicalStatementDecoder {
 public:
  static constexpr size_t kStatementBytes = 1018;
  static constexpr size_t kPublicFieldCount = 1 + kStatementBytes * 8;

  static bool Decode(
      const std::vector<uint8_t>& bytes,
      blind_ledger_longfellow::source_assertion::Statement& statement,
      std::string& reason);

  static bool PackPublicInput(
      const blind_ledger_longfellow::source_assertion::Statement& statement,
      const blind_ledger_longfellow::source_assertion::RelationField& field,
      proofs::Dense<blind_ledger_longfellow::source_assertion::RelationField>&
          public_input,
      std::string& reason);
};

}  // namespace blind_ledger_longfellow::source_assertion_verifier

#endif  // BLIND_LEDGER_LONGFELLOW_V09_SOURCE_ASSERTION_CANONICAL_H_
