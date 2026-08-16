#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <string>
#include <vector>

#include "gf2k/lch14_reed_solomon.h"
#include "native_v3_artifact.h"
#include "native_v3_relation.h"
#include "random/secure_random_engine.h"
#include "random/transcript.h"
#include "zk/zk_prover.h"
#include "zk/zk_proof.h"

namespace {

bool parse_case(const char* text, size_t& value) {
  char* end = nullptr;
  const unsigned long parsed = std::strtoul(text, &end, 10);
  if (end == text || *end != '\0' || parsed >= 5) return false;
  value = static_cast<size_t>(parsed);
  return true;
}

}  // namespace

int main(int argc, char** argv) {
  using namespace blind_ledger_longfellow;
  if (argc != 3) {
    std::fprintf(stderr, "usage: longfellow_native_v3_prover OUTPUT CASE[0..4]\n");
    return 2;
  }
  size_t case_index = 0;
  if (!parse_case(argv[2], case_index)) {
    std::fprintf(stderr, "PROVER_REJECT reason=case\n");
    return 2;
  }

  auto circuit = build_native_v3_circuit();
  const auto fixture = make_native_v3_fixture();
  const RelationCase& relation_case = fixture.cases[case_index];
  const RelationField field;

  proofs::Dense<RelationField> witness(1, circuit->ninputs);
  fill_native_v3_witness(relation_case, witness);
  if (witness.n1_ != circuit->ninputs) {
    std::fprintf(stderr, "PROVER_REJECT reason=witness-length\n");
    return 1;
  }

  const std::vector<uint8_t> public_bytes = native_v3_public_bytes(relation_case);
  if (public_bytes.size() != kNativeV3PublicBytes) {
    std::fprintf(stderr, "PROVER_REJECT reason=public-length\n");
    return 1;
  }

  using RSFactory = proofs::LCH14ReedSolomonFactory<RelationField>;
  const RSFactory rs_factory(field);
  proofs::ZkProof<RelationField> proof(*circuit, kNativeV3LigeroRate,
                                       kNativeV3LigeroQueries);
  size_t label_length = 0;
  const uint8_t* label = native_v3_transcript_label(label_length);
  proofs::Transcript transcript(label, label_length,
                                kNativeV3TranscriptVersion);
  proofs::SecureRandomEngine rng;
  proofs::ZkProver<RelationField, RSFactory> prover(*circuit, field, rs_factory);
  prover.commit(proof, witness, transcript, rng);
  if (!prover.prove(proof, witness, transcript)) {
    std::fprintf(stderr, "PROVER_REJECT reason=circuit\n");
    return 1;
  }

  std::vector<uint8_t> proof_bytes;
  proof.write(proof_bytes, field);
  std::array<uint8_t, 32> circuit_id{};
  std::copy(std::begin(circuit->id), std::end(circuit->id), circuit_id.begin());
  std::string error;
  if (!write_native_v3_artifact(argv[1], circuit_id, public_bytes, proof_bytes,
                                error)) {
    std::fprintf(stderr, "PROVER_REJECT reason=artifact:%s\n", error.c_str());
    return 1;
  }
  std::printf(
      "PROVER_ACCEPT case=%zu inputs=%zu public_inputs=%zu layers=%zu terms=%zu "
      "public_bytes=%zu proof_bytes=%zu rate=%zu queries=%zu circuit_id=%s\n",
      case_index, circuit->ninputs, circuit->npub_in, circuit->nl,
      circuit->nterms(), public_bytes.size(), proof_bytes.size(),
      kNativeV3LigeroRate, kNativeV3LigeroQueries,
      native_v3_hex(circuit->id, sizeof(circuit->id)).c_str());
  return 0;
}
