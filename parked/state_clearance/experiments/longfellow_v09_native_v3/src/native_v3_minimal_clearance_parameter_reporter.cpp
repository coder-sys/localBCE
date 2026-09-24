#include <cstdio>
#include <string>
#include <type_traits>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

#include "native_v3_build_provenance.h"
#include "native_v3_minimal_clearance_proof_artifact.h"
#include "native_v3_minimal_clearance_relation.h"

namespace {

using blind_ledger_longfellow::minimal_clearance::RelationField;
using namespace blind_ledger_longfellow::minimal_clearance;
using namespace blind_ledger_longfellow::minimal_clearance_proof;

static_assert(std::is_same_v<RelationField, proofs::GF2_128<>>,
              "unsupported compiled field mapping");

std::string Hex(const uint8_t* bytes, size_t length) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string output;
  output.reserve(length * 2);
  for (size_t index = 0; index < length; ++index) {
    output.push_back(kHex[bytes[index] >> 4]);
    output.push_back(kHex[bytes[index] & 0x0f]);
  }
  return output;
}

}  // namespace

int main() {
#ifdef _WIN32
  _setmode(_fileno(stdout), _O_BINARY);
#endif
  const auto circuit = build_circuit();
  if (!circuit) return 1;
  const std::string artifact_magic =
      Hex(kArtifactMagic.data(), kArtifactMagic.size());
  const std::string circuit_id = Hex(circuit->id, sizeof(circuit->id));
  const int result = std::printf(
      "{\"activation\":false,\"artifact_header_bytes\":%zu,"
      "\"artifact_magic_hex\":\"%s\",\"artifact_public_statement_bytes\":%zu,"
      "\"artifact_version\":%u,\"circuit_id\":\"%s\","
      "\"circuit_inputs\":%llu,\"circuit_layers\":%llu,"
      "\"circuit_public_inputs\":%llu,\"circuit_terms\":%llu,"
      "\"field_degree\":%u,\"field_family\":\"GF2_128\","
      "\"field_serialized_bytes\":%u,"
      "\"patched_source_identity_sha256\":\"%s\","
      "\"production_usable\":false,"
      "\"proof_queries\":%u,\"proof_rate\":%u,"
      "\"proof_role\":\"%s\",\"proof_suite_id\":null,"
      "\"public_statement_grammar\":\"%s\","
      "\"quad_patch_sha256\":\"%s\","
      "\"schema\":\"BL/NATIVE-V3/LONGFELLOW/COMPILED-PARAMETER-REPORT/v1\","
      "\"sha3_patch_sha256\":\"%s\",\"transcript_label\":\"%s\","
      "\"transcript_version\":%u,\"upstream_commit\":\"%s\","
      "\"upstream_remote\":\"%s\",\"upstream_tree\":\"%s\"}\n",
      kHeaderBytes, artifact_magic.c_str(), kPublicStatementBytes,
      kFormatVersion, circuit_id.c_str(),
      static_cast<unsigned long long>(circuit->ninputs),
      static_cast<unsigned long long>(circuit->nl),
      static_cast<unsigned long long>(circuit->npub_in),
      static_cast<unsigned long long>(circuit->nterms()),
      static_cast<unsigned int>(RelationField::kBits),
      static_cast<unsigned int>(RelationField::kBytes),
      BLIND_LEDGER_PATCHED_SOURCE_IDENTITY_SHA256, kLigeroQueries,
      kLigeroRate, kProofRole, kPublicStatementGrammar,
      BLIND_LEDGER_QUAD_PATCH_SHA256, BLIND_LEDGER_SHA3_PATCH_SHA256,
      kTranscriptLabel, kTranscriptVersion, BLIND_LEDGER_UPSTREAM_COMMIT,
      BLIND_LEDGER_UPSTREAM_REMOTE, BLIND_LEDGER_UPSTREAM_TREE);
  return result < 0 ? 1 : 0;
}
