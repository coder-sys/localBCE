#include <array>
#include <cstdio>
#include <string>
#include <vector>

#include "arrays/dense.h"
#include "circuits/tests/sha3/sha3_reference.h"
#include "native_v3_source_assertion_public_parity.h"
#include "native_v3_source_assertion_relation.h"

namespace {

using blind_ledger_longfellow::source_assertion::RelationField;
using blind_ledger_longfellow::source_assertion::SourceAssertionFixture;
using blind_ledger_longfellow::source_assertion_public_parity::Artifact;

std::string Hex(const std::array<uint8_t, 64>& bytes) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string output;
  output.reserve(bytes.size() * 2);
  for (uint8_t byte : bytes) {
    output.push_back(kHex[byte >> 4]);
    output.push_back(kHex[byte & 0xf]);
  }
  return output;
}

std::string DigestFields(const std::vector<uint8_t>& field_bytes,
                         size_t field_count) {
  static constexpr char kDomain[] =
      "BL/NATIVE-V3/PUBLIC-FIELD-VECTOR/v1";
  proofs::Sha3Reference reference(64);
  reference.update(kDomain, sizeof(kDomain) - 1);
  const uint64_t count = field_count;
  uint8_t encoded_count[8] = {};
  for (size_t index = 0; index < sizeof(encoded_count); ++index) {
    encoded_count[index] = static_cast<uint8_t>(
        count >> (56 - static_cast<unsigned>(index * 8)));
  }
  reference.update(reinterpret_cast<const char*>(encoded_count),
                   sizeof(encoded_count));
  reference.update(reinterpret_cast<const char*>(field_bytes.data()),
                   field_bytes.size());
  std::array<uint8_t, 64> digest{};
  reference.final(digest.data());
  return Hex(digest);
}

}  // namespace

int main(int argc, char** argv) {
  if (argc != 3 || std::string(argv[1]) != "--output") {
    std::fprintf(stderr,
                 "usage: longfellow_source_assertion_public_parity "
                 "--output PATH\n");
    return 2;
  }

  using namespace blind_ledger_longfellow::source_assertion;
  const SourceAssertionFixture fixture = make_source_assertion_fixture();
  SourceAssertionCase parity_case = fixture.cases[0];
  // Both values are deliberately nonzero.  The producer helper packs these
  // typed numeric fields as native LSB-first wires; the verifier KAT must
  // recover the same typed values from the big-endian statement bytes.
  parity_case.statement.epoch = 9;
  parity_case.statement.sequence_before = 11;

  const RelationField field;
  proofs::Dense<RelationField> public_input(
      1, blind_ledger_longfellow::source_assertion_public_parity::kFieldCount);
  fill_source_assertion_public(parity_case, public_input);
  if (public_input.n1_ !=
      blind_ledger_longfellow::source_assertion_public_parity::kFieldCount ||
      public_input.v_[0] != field.one()) {
    std::printf("SOURCE_ASSERTION_PUBLIC_PARITY_PRODUCER_REJECT "
                "reason=field-count-or-leading-one\n");
    return 1;
  }

  Artifact artifact;
  artifact.statement_bytes = source_assertion_statement_bytes(
      parity_case.statement);
  artifact.field_bytes.resize(public_input.n1_ * RelationField::kBytes);
  for (size_t index = 0; index < public_input.n1_; ++index) {
    field.to_bytes_field(artifact.field_bytes.data() +
                             index * RelationField::kBytes,
                         public_input.v_[index]);
  }
  std::string error;
  if (!blind_ledger_longfellow::source_assertion_public_parity::write(
          argv[2], artifact, error)) {
    std::printf("SOURCE_ASSERTION_PUBLIC_PARITY_PRODUCER_REJECT reason=%s\n",
                error.c_str());
    return 1;
  }
  std::printf("SOURCE_ASSERTION_PUBLIC_PARITY_PRODUCER_PASS epoch=%llu "
              "sequence_before=%llu fields=%zu statement_bytes=%zu "
              "field_vector_bytes=%zu digest=%s\n",
              static_cast<unsigned long long>(parity_case.statement.epoch),
              static_cast<unsigned long long>(parity_case.statement.sequence_before),
              public_input.n1_, artifact.statement_bytes.size(),
              artifact.field_bytes.size(),
              DigestFields(artifact.field_bytes, public_input.n1_).c_str());
  return 0;
}
