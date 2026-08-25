#include <algorithm>
#include <cstdio>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

#include "gf2k/lch14_reed_solomon.h"
#include "native_v3_minimal_clearance_proof_artifact.h"
#include "native_v3_minimal_clearance_relation.h"
#include "random/secure_random_engine.h"
#include "random/transcript.h"
#include "zk/zk_prover.h"
#include "zk/zk_proof.h"

namespace {

using RelationField =
    blind_ledger_longfellow::minimal_clearance::RelationField;
using namespace blind_ledger_longfellow::minimal_clearance;
using namespace blind_ledger_longfellow::minimal_clearance_proof;

std::string CircuitId(
    const std::unique_ptr<proofs::Circuit<RelationField>>& circuit) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string result;
  result.reserve(sizeof(circuit->id) * 2);
  for (uint8_t byte : circuit->id) {
    result.push_back(kHex[byte >> 4]);
    result.push_back(kHex[byte & 0xf]);
  }
  return result;
}

bool Exists(const char* path) {
  std::ifstream input(path, std::ios::binary);
  return static_cast<bool>(input);
}

int WriteProducerStatement(const char* path) {
  const Fixture fixture = make_fixture();
  const std::vector<uint8_t> bytes = public_statement_bytes(fixture.cases[0]);
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  if (!output) return 2;
  output.write(reinterpret_cast<const char*>(bytes.data()),
               static_cast<std::streamsize>(bytes.size()));
  if (!output) return 2;
  std::printf("MINIMAL_CLEARANCE_PRODUCER_PUBLIC_STATEMENT bytes=%zu "
              "epoch=%llu sequence_before=%llu\n",
              bytes.size(),
              static_cast<unsigned long long>(fixture.cases[0].statement.epoch),
              static_cast<unsigned long long>(
                  fixture.cases[0].statement.sequence_before));
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc == 3 && std::string(argv[1]) == "--public-statement-file") {
    return WriteProducerStatement(argv[2]);
  }
  if (argc == 2 && std::string(argv[1]) == "--circuit-id") {
    auto circuit = build_circuit();
    std::printf("MINIMAL_CLEARANCE_PRODUCER_CIRCUIT circuit_id=%s inputs=%zu "
                "public_inputs=%zu layers=%zu terms=%zu endpoint_count=%zu\n",
                CircuitId(circuit).c_str(), circuit->ninputs, circuit->npub_in,
                circuit->nl, circuit->nterms(), kSha3EndpointCount);
    return 0;
  }
  size_t case_index = 0;
  if (argc == 4 && std::string(argv[2]) == "--case") {
    if (std::string(argv[3]) == "A" || std::string(argv[3]) == "clear") {
      case_index = 0;
    } else if (std::string(argv[3]) == "B" || std::string(argv[3]) == "hold") {
      case_index = 1;
    } else {
      std::fprintf(stderr,
                   "MINIMAL_CLEARANCE_PROVER_REJECT reason=case-selector\n");
      return 2;
    }
  } else if (argc != 2) {
    std::fprintf(stderr,
                 "usage: longfellow_minimal_clearance_prover ARTIFACT | "
                 "--public-statement-file PATH | --circuit-id | "
                 "ARTIFACT --case A|B\n");
    return 2;
  }
  if (Exists(argv[1])) {
    std::fprintf(stderr,
                 "MINIMAL_CLEARANCE_PROVER_REJECT reason=artifact-exists\n");
    return 2;
  }

  const char* case_label = case_index == 0 ? "A" : "B";
  std::fprintf(stderr, "MINIMAL_CLEARANCE_PROVER_ATTEMPT case=%s attempt=%zu "
               "proof_invocations_before=0\n", case_label, case_index + 1);
  try {
    auto circuit = build_circuit();
    const Fixture fixture = make_fixture();
    const Case& source_case = fixture.cases[case_index];
    const RelationField field;

    proofs::Dense<RelationField> witness(1, circuit->ninputs);
    fill_witness(source_case, witness);
    if (witness.n1_ != circuit->ninputs) {
      std::fprintf(stderr,
                   "MINIMAL_CLEARANCE_PROVER_REJECT reason=witness-length\n");
      return 1;
    }
    const std::vector<uint8_t> public_bytes =
        public_statement_bytes(source_case);
    if (public_bytes.size() !=
            blind_ledger_longfellow::minimal_clearance::kPublicStatementBytes ||
        circuit->npub_in != 1 + public_bytes.size() * 8) {
      std::fprintf(stderr,
                   "MINIMAL_CLEARANCE_PROVER_REJECT reason=public-length "
                   "bytes=%zu expected=%zu npub_in=%zu expected_npub=%zu\n",
                   public_bytes.size(),
                   blind_ledger_longfellow::minimal_clearance::kPublicStatementBytes,
                   circuit->npub_in,
                   1 + public_bytes.size() * 8);
      return 1;
    }

    using RSFactory = proofs::LCH14ReedSolomonFactory<RelationField>;
    const RSFactory rs_factory(field);
    proofs::ZkProof<RelationField> proof(*circuit, kLigeroRate, kLigeroQueries);
    proofs::Transcript transcript(
        reinterpret_cast<const uint8_t*>(kTranscriptLabel),
        sizeof(kTranscriptLabel) - 1, kTranscriptVersion);
    proofs::SecureRandomEngine rng;
    proofs::ZkProver<RelationField, RSFactory> prover(*circuit, field,
                                                       rs_factory);
    prover.commit(proof, witness, transcript, rng);
    // Exactly one proof generation call is authorized for this run.
    if (!prover.prove(proof, witness, transcript)) {
      std::fprintf(stderr,
                   "MINIMAL_CLEARANCE_PROVER_REJECT reason=circuit "
                   "proof_invocations=1\n");
      return 1;
    }

    std::vector<uint8_t> proof_bytes;
    proof.write(proof_bytes, field);
    std::array<uint8_t, kCircuitIdBytes> circuit_id{};
    std::copy(std::begin(circuit->id), std::end(circuit->id), circuit_id.begin());
    std::string error;
    if (!write_artifact(argv[1], circuit_id, kLigeroRate, kLigeroQueries,
                        kTranscriptVersion, public_bytes, proof_bytes, error)) {
      std::fprintf(stderr,
                   "MINIMAL_CLEARANCE_PROVER_REJECT reason=artifact-write\n");
      return 1;
    }
    std::printf("MINIMAL_CLEARANCE_PROVER_ACCEPT attempt=%zu case=%s "
                "proof_invocations=1 inputs=%zu public_inputs=%zu layers=%zu "
                "terms=%zu public_bytes=%zu proof_bytes=%zu rate=%u "
                "queries=%u transcript_version=%u circuit_id=%s\n",
                case_index + 1, case_label, circuit->ninputs, circuit->npub_in, circuit->nl,
                circuit->nterms(), public_bytes.size(), proof_bytes.size(),
                kLigeroRate, kLigeroQueries, kTranscriptVersion,
                CircuitId(circuit).c_str());
    return 0;
  } catch (const std::exception&) {
    std::fprintf(stderr,
                 "MINIMAL_CLEARANCE_PROVER_REJECT reason=exception\n");
    return 1;
  }
}
