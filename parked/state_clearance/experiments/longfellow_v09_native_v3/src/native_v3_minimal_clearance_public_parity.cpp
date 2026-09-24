#include <array>
#include <cstdio>
#include <fstream>
#include <string>
#include <vector>

#include "arrays/dense.h"
#include "circuits/tests/sha3/sha3_reference.h"
#include "native_v3_minimal_clearance_relation.h"

namespace {

using namespace blind_ledger_longfellow::minimal_clearance;

constexpr char kMagic[] = "BLMCPAR1";
constexpr uint64_t kParityEpoch = 0x0102030405060708ULL;
constexpr uint64_t kParitySequence = 0x1112131415161718ULL;

void AppendU32(std::vector<uint8_t>& output, uint32_t value) {
  for (size_t index = 0; index < 4; ++index) {
    output.push_back(static_cast<uint8_t>(value >> (24 - index * 8)));
  }
}

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
  uint8_t encoded_count[8]{};
  for (size_t index = 0; index < sizeof(encoded_count); ++index) {
    encoded_count[index] = static_cast<uint8_t>(
        field_count >> (56 - static_cast<unsigned>(index * 8)));
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
                 "usage: longfellow_minimal_clearance_public_parity "
                 "--output PATH\n");
    return 2;
  }
  const Fixture fixture = make_fixture();
  Case parity_case = fixture.cases[0];
  parity_case.statement.epoch = kParityEpoch;
  parity_case.statement.sequence_before = kParitySequence;
  auto circuit = build_circuit();
  const RelationField field;
  proofs::Dense<RelationField> public_input(1, circuit->npub_in);
  fill_public(parity_case, public_input);
  if (public_input.n1_ != circuit->npub_in ||
      public_input.v_[0] != field.one()) {
    std::printf("MINIMAL_CLEARANCE_PUBLIC_PARITY_PRODUCER_REJECT "
                "reason=field-count-or-leading-one\n");
    return 1;
  }
  const std::vector<uint8_t> statement_bytes =
      public_statement_bytes(parity_case);
  std::vector<uint8_t> field_bytes(public_input.n1_ * RelationField::kBytes);
  for (size_t index = 0; index < public_input.n1_; ++index) {
    field.to_bytes_field(field_bytes.data() + index * RelationField::kBytes,
                         public_input.v_[index]);
  }
  std::vector<uint8_t> bytes;
  bytes.insert(bytes.end(), reinterpret_cast<const uint8_t*>(kMagic),
               reinterpret_cast<const uint8_t*>(kMagic) + sizeof(kMagic) - 1);
  AppendU32(bytes, static_cast<uint32_t>(statement_bytes.size()));
  AppendU32(bytes, static_cast<uint32_t>(public_input.n1_));
  bytes.insert(bytes.end(), statement_bytes.begin(), statement_bytes.end());
  bytes.insert(bytes.end(), field_bytes.begin(), field_bytes.end());
  std::ofstream output(argv[2], std::ios::binary | std::ios::trunc);
  if (!output) return 2;
  output.write(reinterpret_cast<const char*>(bytes.data()),
               static_cast<std::streamsize>(bytes.size()));
  if (!output) return 2;
  std::printf("MINIMAL_CLEARANCE_PUBLIC_PARITY_PRODUCER_PASS epoch=%llu "
              "sequence_before=%llu fields=%zu statement_bytes=%zu "
              "field_vector_bytes=%zu digest=%s\n",
              static_cast<unsigned long long>(kParityEpoch),
              static_cast<unsigned long long>(kParitySequence),
              public_input.n1_, statement_bytes.size(), field_bytes.size(),
              DigestFields(field_bytes, public_input.n1_).c_str());
  return 0;
}
