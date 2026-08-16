#include <algorithm>
#include <cstdio>
#include <memory>
#include <string>

#include "arrays/dense.h"
#include "gf2k/lch14_reed_solomon.h"
#include "native_v3_artifact.h"
#include "native_v3_relation.h"
#include "random/transcript.h"
#include "util/readbuffer.h"
#include "zk/zk_proof.h"
#include "zk/zk_verifier.h"

namespace {

bool fill_public_input(
    const std::vector<uint8_t>& bytes,
    const blind_ledger_longfellow::RelationField& field,
    const proofs::Circuit<blind_ledger_longfellow::RelationField>& circuit,
    proofs::Dense<blind_ledger_longfellow::RelationField>& public_input) {
  if (bytes.size() != blind_ledger_longfellow::kNativeV3PublicBytes ||
      circuit.npub_in != 1 + bytes.size() * 8) {
    return false;
  }
  proofs::DenseFiller<blind_ledger_longfellow::RelationField> filler(public_input);
  filler.push_back(field.one());
  for (uint8_t byte : bytes) filler.push_back(byte, 8, field);
  return filler.size() == public_input.n1_;
}

}  // namespace

int main(int argc, char** argv) {
  using namespace blind_ledger_longfellow;
  if (argc != 2) {
    std::fprintf(stderr, "usage: longfellow_native_v3_verifier ARTIFACT\n");
    return 2;
  }
  NativeV3Artifact artifact;
  std::string error;
  if (!read_native_v3_artifact(argv[1], artifact, error)) {
    std::printf("VERIFIER_REJECT reason=artifact:%s\n", error.c_str());
    return 1;
  }

  auto circuit = build_native_v3_circuit();
  std::array<uint8_t, 32> circuit_id{};
  std::copy(std::begin(circuit->id), std::end(circuit->id), circuit_id.begin());
  if (artifact.circuit_id != circuit_id) {
    std::printf("VERIFIER_REJECT reason=circuit-id\n");
    return 1;
  }

  const RelationField field;
  proofs::Dense<RelationField> public_input(1, circuit->npub_in);
  if (!fill_public_input(artifact.public_bytes, field, *circuit, public_input)) {
    std::printf("VERIFIER_REJECT reason=public-input\n");
    return 1;
  }

  proofs::ZkProof<RelationField> proof(*circuit, kNativeV3LigeroRate,
                                       kNativeV3LigeroQueries);
  proofs::ReadBuffer buffer(artifact.proof_bytes);
  if (!proof.read(buffer, field) || buffer.remaining() != 0) {
    std::printf("VERIFIER_REJECT reason=proof-serialization\n");
    return 1;
  }

  using RSFactory = proofs::LCH14ReedSolomonFactory<RelationField>;
  const RSFactory rs_factory(field);
  size_t label_length = 0;
  const uint8_t* label = native_v3_transcript_label(label_length);
  proofs::Transcript transcript(label, label_length,
                                kNativeV3TranscriptVersion);
  proofs::ZkVerifier<RelationField, RSFactory> verifier(
      *circuit, rs_factory, kNativeV3LigeroRate, kNativeV3LigeroQueries, field);
  verifier.recv_commitment(proof, transcript);
  if (!verifier.verify(proof, public_input, transcript)) {
    std::printf("VERIFIER_REJECT reason=semantic-proof\n");
    return 1;
  }
  std::printf(
      "VERIFIER_ACCEPT inputs=%zu public_inputs=%zu layers=%zu terms=%zu "
      "public_bytes=%zu proof_bytes=%zu rate=%zu queries=%zu circuit_id=%s\n",
      circuit->ninputs, circuit->npub_in, circuit->nl, circuit->nterms(),
      artifact.public_bytes.size(), artifact.proof_bytes.size(),
      kNativeV3LigeroRate, kNativeV3LigeroQueries,
      native_v3_hex(circuit->id, sizeof(circuit->id)).c_str());
  return 0;
}
