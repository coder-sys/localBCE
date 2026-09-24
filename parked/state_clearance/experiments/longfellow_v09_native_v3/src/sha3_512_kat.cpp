#include "sha3_512_witness.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "arrays/dense.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/tests/sha3/sha3_circuit.h"
#include "gf2k/gf2_128.h"
#include "gf2k/lch14_reed_solomon.h"
#include "random/secure_random_engine.h"
#include "random/transcript.h"
#include "util/crypto.h"
#include "util/panic.h"
#include "zk/zk_proof.h"
#include "zk/zk_prover.h"
#include "zk/zk_verifier.h"

namespace {

struct KatVector {
  const char* id;
  size_t bit_length;
  const char* message_hex;
  const char* digest_hex;
};

const KatVector kVectors[] = {
    {"empty", 0, "",
     "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"},
    {"binary_non_ascii", 8, "e5",
     "150240baf95fb36f8ccb87a19a41767e7aed95125075a2b2dbba6e565e1ce8575f2b042b62e29a04e9440314a821c6224182964d8b557b16a492b3806f4c39c1"},
    {"short_abc_length", 24, "37d518",
     "4aa96b1547e6402c0eee781acaa660797efe26ec00b4f2e0aec4a6d10688dd64cbd7f12b3b6c7f802e2096c041208b9289aec380d1a748fdfcd4128553d781e3"},
    {"exact_rate_72_bytes", 576,
     "0ce9f8c3a990c268f34efd9befdb0f7c4ef8466cfdb01171f8de70dc5fefa92acbe93d29e2ac1a5c2979129f1ab08c0e77de7924ddf68a209cdfa0adc62f85c18637d9c6b33f4ff8",
     "b018a20fcf831dde290e4fb18c56342efe138472cbe142da6b77eea4fce52588c04c808eb32912faa345245a850346faec46c3a16d39bd2e1ddb1816bc57d2da"},
    {"multi_block_145_bytes", 1160,
     "664ef2e3a7059daf1c58caf52008c5227e85cdcb83b4c59457f02c508d4f4f69f826bd82c0cffc5cb6a97af6e561c6f96970005285e58f21ef6511d26e709889a7e513c434c90a3cf7448f0caeec7114c747b2a0758a3b4503a7cf0c69873ed31d94dbef2b7b2f168830ef7da3322c3d3e10cafb7c2c33c83bbf4c46a31da90cff3bfd4ccc6ed4b310758491eeba603a76",
     "e5825ff1a3c070d5a52fbbe711854a440554295ffb7a7969a17908d10163bfbe8f1d52a676e8a0137b56a11cdf0ffbb456bc899fc727d14bd8882232549d914e"},
    {"abc", 24, "616263",
     "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"},
  };

uint8_t HexNibble(char c) {
  if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
  if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
  if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
  proofs::check(false, "invalid hex digit");
  return 0;
}

std::vector<uint8_t> ParseHex(const char* text) {
  const size_t n = std::strlen(text);
  proofs::check((n & 1) == 0, "odd hex length");
  std::vector<uint8_t> result(n / 2);
  for (size_t i = 0; i < result.size(); ++i) {
    result[i] = static_cast<uint8_t>((HexNibble(text[2 * i]) << 4) |
                                     HexNibble(text[2 * i + 1]));
  }
  return result;
}

std::string BytesToHex(const std::vector<uint8_t>& bytes) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string result;
  result.reserve(bytes.size() * 2);
  for (uint8_t byte : bytes) {
    result.push_back(kHex[byte >> 4]);
    result.push_back(kHex[byte & 0x0f]);
  }
  return result;
}

std::vector<uint8_t> NativeV3SizedMessage() {
  std::vector<uint8_t> result(556);
  for (size_t i = 0; i < result.size(); ++i) {
    result[i] = static_cast<uint8_t>((i * 37 + 11) & 0xff);
  }
  return result;
}

std::vector<blind_ledger_longfellow::Sha3BlockWitness> WitnessFor(
    const std::vector<uint8_t>& message, size_t rate = 72,
    uint8_t domain = 0x06) {
  std::vector<blind_ledger_longfellow::Sha3BlockWitness> result;
  blind_ledger_longfellow::compute_sha3_512_witness(message, result, rate,
                                                    domain);
  return result;
}

template <class Field>
uint8_t EvalByte(const typename proofs::Logic<
                     Field, proofs::EvaluationBackend<Field>>::template bitvec<8>&
                     value,
                 const proofs::Logic<Field,
                                     proofs::EvaluationBackend<Field>>& logic,
                 const Field& field) {
  uint8_t result = 0;
  for (size_t bit = 0; bit < 8; ++bit) {
    if (logic.eval(value[bit]).elt() == field.one()) {
      result |= static_cast<uint8_t>(1u << bit);
    }
  }
  return result;
}

bool DirectCheck(const KatVector& vector, int mutation) {
  using Field = proofs::GF2_128<>;
  using EvalBackend = proofs::EvaluationBackend<Field>;
  using Logic = proofs::Logic<Field, EvalBackend>;
  const Field field;
  EvalBackend eval_backend(field, false);
  Logic logic(&eval_backend, field);

  std::vector<uint8_t> message = ParseHex(vector.message_hex);
  std::vector<uint8_t> expected = ParseHex(vector.digest_hex);
  std::vector<uint8_t> witness_message = message;
  size_t witness_rate = 72;
  uint8_t witness_domain = 0x06;

  switch (mutation) {
    case 1:  // digest mutation
      expected[0] ^= 0x01;
      break;
    case 2:  // message mutation with a freshly recomputed wrong witness
      if (witness_message.empty()) witness_message.push_back(0x01);
      else witness_message[0] ^= 0x01;
      message = witness_message;
      break;
    case 3:  // SHAKE domain mutation
      witness_domain = 0x1f;
      break;
    case 4:  // SHAKE rate mutation; short input keeps witness count equal
      witness_rate = 136;
      break;
    case 5:  // reorder the two exact-rate block witnesses
      break;
    default:
      break;
  }

  auto witnesses = WitnessFor(witness_message, witness_rate, witness_domain);
  if (mutation == 5) {
    if (witnesses.size() < 2) return false;
    std::swap(witnesses[0], witnesses[1]);
  }

  std::vector<Logic::v8> seed;
  seed.reserve(message.size());
  for (uint8_t byte : message) seed.push_back(logic.vbit8(byte));
  std::vector<proofs::Sha3Circuit<Logic>::BlockWitness> circuit_witnesses(
      witnesses.size());
  for (size_t k = 0; k < witnesses.size(); ++k) {
    for (size_t round = 0; round < 24; ++round) {
      if (!proofs::sha3_slice_at(round)) continue;
      for (size_t x = 0; x < 5; ++x) {
        for (size_t y = 0; y < 5; ++y) {
          for (size_t bit = 0; bit < 64; ++bit) {
            circuit_witnesses[k].a_intermediate[round][x][y][bit] =
                logic.bit((witnesses[k].a_intermediate[round][x][y] >> bit) &
                          1);
          }
        }
      }
    }
  }

  proofs::Sha3Circuit<Logic> circuit(logic);
  std::vector<Logic::v8> output;
  circuit.assert_sha3_512(seed, output, circuit_witnesses);
  for (size_t i = 0; i < expected.size(); ++i) {
    logic.vassert_eq(output[i], expected[i]);
  }
  const bool failed = eval_backend.assertion_failed();
  if (mutation == 0) {
    proofs::check(!failed, "valid SHA3-512 direct KAT failed");
    for (size_t i = 0; i < expected.size(); ++i) {
      proofs::check(EvalByte(output[i], logic, field) == expected[i],
                    "SHA3-512 output mismatch");
    }
  }
  return mutation == 0 ? !failed : failed;
}

bool DirectCheckNoWitness(const KatVector& vector, int mutation) {
  using Field = proofs::GF2_128<>;
  using EvalBackend = proofs::EvaluationBackend<Field>;
  using Logic = proofs::Logic<Field, EvalBackend>;
  const Field field;
  EvalBackend eval_backend(field, false);
  Logic logic(&eval_backend, field);

  std::vector<uint8_t> message = ParseHex(vector.message_hex);
  std::vector<uint8_t> expected = ParseHex(vector.digest_hex);
  if (mutation == 1) {
    expected[0] ^= 0x01;
  } else if (mutation == 2) {
    if (message.empty()) message.push_back(0x01);
    else message[0] ^= 0x01;
  }

  std::vector<Logic::v8> seed;
  seed.reserve(message.size());
  for (uint8_t byte : message) seed.push_back(logic.vbit8(byte));

  proofs::Sha3Circuit<Logic> circuit(logic);
  std::vector<Logic::v8> output;
  circuit.assert_sha3_512_no_witness(seed, output);
  for (size_t i = 0; i < expected.size(); ++i) {
    logic.vassert_eq(output[i], expected[i]);
  }
  const bool failed = eval_backend.assertion_failed();
  if (mutation == 0) {
    proofs::check(!failed, "valid SHA3-512 no-witness KAT failed");
    for (size_t i = 0; i < expected.size(); ++i) {
      proofs::check(EvalByte(output[i], logic, field) == expected[i],
                    "SHA3-512 no-witness output mismatch");
    }
  }
  return mutation == 0 ? !failed : failed;
}

template <class Field>
std::unique_ptr<proofs::Circuit<Field>> MakeCircuit(size_t message_size,
                                                    const Field& field) {
  using Backend = proofs::CompilerBackend<Field>;
  using Logic = proofs::Logic<Field, Backend>;
  using V8 = typename Logic::template bitvec<8>;
  proofs::QuadCircuit<Field> builder(field);
  const Backend backend(&builder);
  const Logic logic(&backend, field);
  proofs::Sha3Circuit<Logic> circuit(logic);

  std::vector<V8> expected(64);
  for (auto& byte : expected) byte = logic.template vinput<8>();
  builder.private_input();
  std::vector<V8> seed(message_size);
  for (auto& byte : seed) byte = logic.template vinput<8>();
  const size_t blocks = (message_size + 72) / 72;
  std::vector<typename proofs::Sha3Circuit<Logic>::BlockWitness> witnesses(
      blocks);
  for (auto& witness : witnesses) witness.input(logic);
  std::vector<V8> output;
  circuit.assert_sha3_512(seed, output, witnesses);
  for (size_t i = 0; i < expected.size(); ++i) {
    logic.vassert_eq(expected[i], output[i]);
  }
  return builder.mkcircuit(1);
}

bool ProveAndVerify(const KatVector& vector) {
  using Field = proofs::GF2_128<>;
  using RSFactory = proofs::LCH14ReedSolomonFactory<Field>;
  const Field field;
  auto circuit = MakeCircuit(vector.bit_length / 8, field);
  const auto message = ParseHex(vector.message_hex);
  const auto expected = ParseHex(vector.digest_hex);
  const auto witnesses = WitnessFor(message);

  proofs::Dense<Field> witness(1, circuit->ninputs);
  proofs::DenseFiller<Field> filler(witness);
  filler.push_back(field.one());
  for (uint8_t byte : expected) filler.push_back(byte, 8, field);
  for (uint8_t byte : message) filler.push_back(byte, 8, field);
  proofs::Sha3Witness::fill_witness(filler, witnesses, field);
  proofs::check(filler.size() == circuit->ninputs, "witness size mismatch");

  proofs::Dense<Field> pub(1, circuit->npub_in);
  for (size_t i = 0; i < pub.v_.size(); ++i) pub.v_[i] = witness.v_[i];
  const RSFactory rsf(field);
  proofs::ZkProof<Field> proof(*circuit, 4, 8);
  proofs::ZkProver<Field, RSFactory> prover(*circuit, field, rsf);
  proofs::SecureRandomEngine rng;
  const uint8_t label[] = "longfellow-v09-sha3-512";
  proofs::Transcript tp(label, sizeof(label) - 1);
  prover.commit(proof, witness, tp, rng);
  if (!prover.prove(proof, witness, tp)) return false;

  proofs::ZkVerifier<Field, RSFactory> verifier(*circuit, rsf, 4, 8, field);
  proofs::Transcript tv(label, sizeof(label) - 1);
  verifier.recv_commitment(proof, tv);
  return verifier.verify(proof, pub, tv);
}

}  // namespace

int main() {
  size_t positives = 0;
  for (const KatVector& vector : kVectors) {
    if (!DirectCheck(vector, 0)) return 2;
    ++positives;
  }
  const std::vector<uint8_t> native_message = NativeV3SizedMessage();
  const std::string native_message_hex = BytesToHex(native_message);
  const KatVector native_v3_vector = {
      "native_v3_sized_556_bytes", native_message.size() * 8,
      native_message_hex.c_str(),
      "25d37bedc439a5ee47a0e7a702b34304adb6285ad9f29f863cf8aeb43b24a8b6105a9173b192f7ad1e50a42cf743cc0e50f334946d70b1b4257514698cc40dad"};
  proofs::check(DirectCheck(native_v3_vector, 0),
                "native-v3-sized SHA3-512 KAT failed");
  ++positives;
  size_t no_witness_positives = 0;
  for (const KatVector& vector : kVectors) {
    proofs::check(DirectCheckNoWitness(vector, 0),
                  "no-witness SHA3-512 KAT failed");
    ++no_witness_positives;
  }
  proofs::check(DirectCheckNoWitness(native_v3_vector, 0),
                "native-v3-sized no-witness SHA3-512 KAT failed");
  ++no_witness_positives;
  const KatVector& short_vector = kVectors[2];
  const KatVector& exact_rate_vector = kVectors[3];
  proofs::check(DirectCheck(kVectors[0], 1), "digest mutation escaped");
  proofs::check(DirectCheck(short_vector, 2), "message mutation escaped");
  proofs::check(DirectCheck(short_vector, 3), "padding mutation escaped");
  proofs::check(DirectCheck(short_vector, 4), "rate mutation escaped");
  proofs::check(DirectCheck(exact_rate_vector, 5), "block-order mutation escaped");
  proofs::check(DirectCheckNoWitness(kVectors[0], 1),
                "no-witness digest mutation escaped");
  proofs::check(DirectCheckNoWitness(short_vector, 2),
                "no-witness message mutation escaped");
  if (!ProveAndVerify(kVectors[0])) return 3;

  std::printf(
      "SHA3_512_KAT_PASS vectors=%zu mutations=5 hidden_proof=1 rate=72 "
      "capacity_bits=1024 domain=06 digest_bytes=64 no_witness_vectors=%zu "
      "no_witness_mutations=2\n",
      positives, no_witness_positives);
  return 0;
}
