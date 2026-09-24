#include "sha3_512_witness.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/tests/sha3/sha3_circuit.h"
#include "gf2k/gf2_128.h"
#include "util/panic.h"

namespace {

struct KatVector {
  const char* id;
  const char* message_hex;
  const char* digest_hex;
};

const KatVector kVectors[] = {
    {"empty", "",
     "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"},
    {"abc", "616263",
     "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"},
    {"binary_non_ascii", "e5",
     "150240baf95fb36f8ccb87a19a41767e7aed95125075a2b2dbba6e565e1ce8575f2b042b62e29a04e9440314a821c6224182964d8b557b16a492b3806f4c39c1"},
    {"exact_rate_72_bytes",
     "0ce9f8c3a990c268f34efd9befdb0f7c4ef8466cfdb01171f8de70dc5fefa92acbe93d29e2ac1a5c2979129f1ab08c0e77de7924ddf68a209cdfa0adc62f85c18637d9c6b33f4ff8",
     "b018a20fcf831dde290e4fb18c56342efe138472cbe142da6b77eea4fce52588c04c808eb32912faa345245a850346faec46c3a16d39bd2e1ddb1816bc57d2da"},
    {"multi_block_145_bytes",
     "664ef2e3a7059daf1c58caf52008c5227e85cdcb83b4c59457f02c508d4f4f69f826bd82c0cffc5cb6a97af6e561c6f96970005285e58f21ef6511d26e709889a7e513c434c90a3cf7448f0caeec7114c747b2a0758a3b4503a7cf0c69873ed31d94dbef2b7b2f168830ef7da3322c3d3e10cafb7c2c33c83bbf4c46a31da90cff3bfd4ccc6ed4b310758491eeba603a76",
     "e5825ff1a3c070d5a52fbbe711854a440554295ffb7a7969a17908d10163bfbe8f1d52a676e8a0137b56a11cdf0ffbb456bc899fc727d14bd8882232549d914e"},
    {"native_v3_sized_556_bytes", nullptr,
     "25d37bedc439a5ee47a0e7a702b34304adb6285ad9f29f863cf8aeb43b24a8b6105a9173b192f7ad1e50a42cf743cc0e50f334946d70b1b4257514698cc40dad"},
};

uint8_t HexNibble(char value) {
  if (value >= '0' && value <= '9') return static_cast<uint8_t>(value - '0');
  if (value >= 'a' && value <= 'f') {
    return static_cast<uint8_t>(value - 'a' + 10);
  }
  if (value >= 'A' && value <= 'F') {
    return static_cast<uint8_t>(value - 'A' + 10);
  }
  proofs::check(false, "invalid hex digit");
  return 0;
}

std::vector<uint8_t> ParseHex(const char* text) {
  const size_t length = std::strlen(text);
  proofs::check((length & 1) == 0, "odd hex length");
  std::vector<uint8_t> result(length / 2);
  for (size_t index = 0; index < result.size(); ++index) {
    result[index] = static_cast<uint8_t>(
        (HexNibble(text[2 * index]) << 4) | HexNibble(text[2 * index + 1]));
  }
  return result;
}

std::vector<uint8_t> Message(const KatVector& vector) {
  if (vector.message_hex != nullptr) return ParseHex(vector.message_hex);
  std::vector<uint8_t> result(556);
  for (size_t index = 0; index < result.size(); ++index) {
    result[index] = static_cast<uint8_t>((index * 37 + 11) & 0xff);
  }
  return result;
}

template <class Field>
uint8_t EvalByte(
    const typename proofs::Logic<
        Field, proofs::EvaluationBackend<Field>>::template bitvec<8>& value,
    const proofs::Logic<Field, proofs::EvaluationBackend<Field>>& logic,
    const Field& field) {
  uint8_t result = 0;
  for (size_t bit = 0; bit < 8; ++bit) {
    if (logic.eval(value[bit]).elt() == field.one()) {
      result |= static_cast<uint8_t>(1u << bit);
    }
  }
  return result;
}

bool DirectNoWitness(const KatVector& vector, bool mutate_digest,
                     bool mutate_message) {
  using Field = proofs::GF2_128<>;
  using Backend = proofs::EvaluationBackend<Field>;
  using Logic = proofs::Logic<Field, Backend>;
  const Field field;
  Backend backend(field, false);
  Logic logic(&backend, field);
  std::vector<uint8_t> message = Message(vector);
  std::vector<uint8_t> expected = ParseHex(vector.digest_hex);
  if (mutate_digest) expected[0] ^= 0x01;
  if (mutate_message) {
    if (message.empty()) message.push_back(0x01);
    else message[0] ^= 0x01;
  }
  std::vector<Logic::v8> seed;
  for (uint8_t byte : message) seed.push_back(logic.vbit8(byte));
  proofs::Sha3Circuit<Logic> circuit(logic);
  std::vector<Logic::v8> output;
  circuit.assert_sha3_512_no_witness(seed, output);
  for (size_t index = 0; index < expected.size(); ++index) {
    logic.vassert_eq(output[index], expected[index]);
  }
  const bool failed = backend.assertion_failed();
  if (!mutate_digest && !mutate_message) {
    proofs::check(!failed, "source assertion SHA3-512 KAT failed");
    for (size_t index = 0; index < expected.size(); ++index) {
      proofs::check(EvalByte(output[index], logic, field) == expected[index],
                    "source assertion SHA3-512 output mismatch");
    }
  }
  return (!mutate_digest && !mutate_message) ? !failed : failed;
}

bool DirectWitness(const KatVector& vector, size_t witness_rate,
                   uint8_t witness_domain, bool reorder) {
  using Field = proofs::GF2_128<>;
  using Backend = proofs::EvaluationBackend<Field>;
  using Logic = proofs::Logic<Field, Backend>;
  const Field field;
  Backend backend(field, false);
  Logic logic(&backend, field);
  const std::vector<uint8_t> message = Message(vector);
  const std::vector<uint8_t> expected = ParseHex(vector.digest_hex);
  std::vector<blind_ledger_longfellow::Sha3BlockWitness> witnesses;
  blind_ledger_longfellow::compute_sha3_512_witness(
      message, witnesses, witness_rate, witness_domain);
  if (reorder) {
    if (witnesses.size() < 2) return false;
    std::swap(witnesses[0], witnesses[1]);
  }
  std::vector<Logic::v8> seed;
  for (uint8_t byte : message) seed.push_back(logic.vbit8(byte));
  std::vector<proofs::Sha3Circuit<Logic>::BlockWitness> circuit_witnesses(
      witnesses.size());
  for (size_t block = 0; block < witnesses.size(); ++block) {
    for (size_t round = 0; round < 24; ++round) {
      if (!proofs::sha3_slice_at(round)) continue;
      for (size_t x = 0; x < 5; ++x) {
        for (size_t y = 0; y < 5; ++y) {
          for (size_t bit = 0; bit < 64; ++bit) {
            circuit_witnesses[block].a_intermediate[round][x][y][bit] =
                logic.bit((witnesses[block].a_intermediate[round][x][y] >>
                           bit) &
                          1);
          }
        }
      }
    }
  }
  proofs::Sha3Circuit<Logic> circuit(logic);
  std::vector<Logic::v8> output;
  circuit.assert_sha3_512(seed, output, circuit_witnesses);
  for (size_t index = 0; index < expected.size(); ++index) {
    logic.vassert_eq(output[index], expected[index]);
  }
  return backend.assertion_failed();
}

}  // namespace

int main() {
  size_t positives = 0;
  for (const KatVector& vector : kVectors) {
    proofs::check(DirectNoWitness(vector, false, false),
                  "source assertion SHA3 positive failed");
    ++positives;
  }
  proofs::check(DirectNoWitness(kVectors[0], true, false),
                "digest mutation escaped");
  proofs::check(DirectNoWitness(kVectors[1], false, true),
                "message mutation escaped");
  proofs::check(DirectWitness(kVectors[1], 72, 0x1f, false),
                "padding mutation escaped");
  proofs::check(DirectWitness(kVectors[1], 136, 0x06, false),
                "rate mutation escaped");
  proofs::check(DirectWitness(kVectors[3], 72, 0x06, true),
                "block-order mutation escaped");
  std::printf(
      "SOURCE_ASSERTION_SHA3_KAT_PASS vectors=%zu mutations=5 hidden_message=1 "
      "prover=0 rate=72 capacity_bits=1024 domain=06 digest_bytes=64\n",
      positives);
  return 0;
}
