#include <algorithm>
#include <cstdio>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

#include "gf2k/lch14_reed_solomon.h"
#include "native_v3_source_assertion_proof_artifact.h"
#include "native_v3_source_assertion_relation.h"
#include "random/secure_random_engine.h"
#include "random/transcript.h"
#include "zk/zk_prover.h"
#include "zk/zk_proof.h"

namespace {

constexpr char kTranscriptLabel[] = "BL/NATIVE-V3/LONGFELLOW/TRANSCRIPT/v1";

std::string CircuitId(const std::unique_ptr<proofs::Circuit<
    blind_ledger_longfellow::source_assertion::RelationField>>& circuit) {
  return blind_ledger_longfellow::source_assertion::source_assertion_hex(
      circuit->id, sizeof(circuit->id));
}

bool Exists(const char* path) {
  std::ifstream input(path, std::ios::binary);
  return static_cast<bool>(input);
}

}  // namespace

int main(int argc, char** argv) {
  using namespace blind_ledger_longfellow::source_assertion;
  using namespace blind_ledger_longfellow::source_assertion_proof;

  if (argc == 3 && std::string(argv[1]) == "--public-statement-file") {
    const SourceAssertionFixture fixture = make_source_assertion_fixture();
    const std::vector<uint8_t> bytes =
        source_assertion_statement_bytes(fixture.cases[0].statement);
    std::ofstream output(argv[2], std::ios::binary | std::ios::trunc);
    if (!output) return 2;
    output.write(reinterpret_cast<const char*>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
    if (!output) return 2;
    std::printf("SOURCE_ASSERTION_PRODUCER_PUBLIC_STATEMENT bytes=%zu path=%s\n",
                bytes.size(), argv[2]);
    return 0;
  }
  if (argc == 2 && std::string(argv[1]) == "--circuit-id") {
    auto circuit = build_source_assertion_circuit();
    std::printf("SOURCE_ASSERTION_CIRCUIT circuit_id=%s inputs=%zu "
                "public_inputs=%zu layers=%zu terms=%zu endpoints=%zu\n",
                CircuitId(circuit).c_str(), circuit->ninputs, circuit->npub_in,
                circuit->nl, circuit->nterms(), source_assertion_endpoint_count());
    return 0;
  }
  if (argc != 2) {
    std::fprintf(stderr,
                 "usage: longfellow_source_assertion_prover ARTIFACT | "
                 "--circuit-id\n");
    return 2;
  }
  if (Exists(argv[1])) {
    std::fprintf(stderr, "SOURCE_ASSERTION_PROVER_REJECT reason=artifact-exists\n");
    return 2;
  }

  std::fprintf(stderr, "SOURCE_ASSERTION_PROVER_ATTEMPT case=clear attempt=1\n");
  try {
    auto circuit = build_source_assertion_circuit();
    const SourceAssertionFixture fixture = make_source_assertion_fixture();
    const SourceAssertionCase& source_case = fixture.cases[0];
    const RelationField field;

    proofs::Dense<RelationField> witness(1, circuit->ninputs);
    fill_source_assertion_witness(source_case, witness);
    if (witness.n1_ != circuit->ninputs) {
      std::fprintf(stderr,
                   "SOURCE_ASSERTION_PROVER_REJECT reason=witness-length\n");
      return 1;
    }
    const std::vector<uint8_t> public_bytes =
        source_assertion_statement_bytes(source_case.statement);
    if (public_bytes.size() != kPublicStatementBytes ||
        circuit->npub_in != 1 + public_bytes.size() * 8) {
      std::fprintf(stderr,
                   "SOURCE_ASSERTION_PROVER_REJECT reason=public-length\n");
      return 1;
    }

    using RSFactory = proofs::LCH14ReedSolomonFactory<RelationField>;
    const RSFactory rs_factory(field);
    proofs::ZkProof<RelationField> proof(*circuit, kLigeroRate, kLigeroQueries);
    proofs::Transcript transcript(
        reinterpret_cast<const uint8_t*>(kTranscriptLabel),
        sizeof(kTranscriptLabel) - 1, kTranscriptVersion);
    proofs::SecureRandomEngine rng;
    proofs::ZkProver<RelationField, RSFactory> prover(*circuit, field, rs_factory);
    prover.commit(proof, witness, transcript, rng);
    // This is the only proof-generation call in this executable and in this
    // task. There is deliberately no retry or alternate-parameter path.
    if (!prover.prove(proof, witness, transcript)) {
      std::fprintf(stderr,
                   "SOURCE_ASSERTION_PROVER_REJECT reason=circuit\n");
      return 1;
    }

    std::vector<uint8_t> proof_bytes;
    proof.write(proof_bytes, field);
    std::array<uint8_t, kCircuitIdBytes> circuit_id{};
    std::copy(std::begin(circuit->id), std::end(circuit->id), circuit_id.begin());
    std::string error;
    if (!write_artifact(argv[1], circuit_id, kLigeroRate, kLigeroQueries,
                        kTranscriptVersion, public_bytes, proof_bytes, error)) {
      std::fprintf(stderr, "SOURCE_ASSERTION_PROVER_REJECT reason=artifact:%s\n",
                   error.c_str());
      return 1;
    }
    std::printf("SOURCE_ASSERTION_PROVER_ACCEPT attempt=1 case=clear "
                "inputs=%zu public_inputs=%zu layers=%zu terms=%zu "
                "public_bytes=%zu proof_bytes=%zu rate=%u queries=%u "
                "transcript_version=%u circuit_id=%s\n",
                circuit->ninputs, circuit->npub_in, circuit->nl,
                circuit->nterms(), public_bytes.size(), proof_bytes.size(),
                kLigeroRate, kLigeroQueries, kTranscriptVersion,
                CircuitId(circuit).c_str());
    return 0;
  } catch (const std::exception& exception) {
    std::fprintf(stderr, "SOURCE_ASSERTION_PROVER_REJECT reason=exception:%s\n",
                 exception.what());
    return 1;
  }
}
