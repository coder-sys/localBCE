#include "native_v3_parameter_attestation.h"

#include <algorithm>
#include <cstdio>
#include <fstream>
#include <limits>
#include <stdexcept>
#include <string_view>
#include <type_traits>
#include <vector>

#include "circuits/tests/sha3/sha3_reference.h"
#include "native_v3_minimal_clearance_proof_artifact.h"
#include "native_v3_minimal_clearance_relation.h"
#include "native_v3_parameter_attestation_build_config.h"

namespace {

using blind_ledger_longfellow::minimal_clearance::RelationField;
using blind_ledger_longfellow::parameter_attestation::Facts;
using blind_ledger_longfellow::parameter_attestation::FieldId;
using blind_ledger_longfellow::parameter_attestation::FieldType;

static_assert(std::is_same_v<RelationField, proofs::GF2_128<>>,
              "unsupported relation field mapping");

void PutU16(std::vector<uint8_t>& output, uint16_t value) {
  output.push_back(static_cast<uint8_t>(value >> 8));
  output.push_back(static_cast<uint8_t>(value));
}

void PutU32(std::vector<uint8_t>& output, uint32_t value) {
  for (size_t index = 0; index < 4; ++index) {
    output.push_back(static_cast<uint8_t>(value >> (24 - index * 8)));
  }
}

void PutU64(std::vector<uint8_t>& output, uint64_t value) {
  for (size_t index = 0; index < 8; ++index) {
    output.push_back(static_cast<uint8_t>(value >> (56 - index * 8)));
  }
}

void PutField(std::vector<uint8_t>& output, FieldId id, FieldType type,
              const std::vector<uint8_t>& payload) {
  if (payload.size() > std::numeric_limits<uint32_t>::max()) {
    throw std::runtime_error("attestation field too large");
  }
  PutU16(output, static_cast<uint16_t>(id));
  output.push_back(static_cast<uint8_t>(type));
  PutU32(output, static_cast<uint32_t>(payload.size()));
  output.insert(output.end(), payload.begin(), payload.end());
}

std::vector<uint8_t> Bytes(std::string_view value) {
  return std::vector<uint8_t>(value.begin(), value.end());
}

std::vector<uint8_t> Bytes(const std::array<uint8_t, 8>& value) {
  return std::vector<uint8_t>(value.begin(), value.end());
}

std::vector<uint8_t> Bytes(const std::array<uint8_t, 32>& value) {
  return std::vector<uint8_t>(value.begin(), value.end());
}

std::vector<uint8_t> U32(uint32_t value) {
  std::vector<uint8_t> output;
  output.reserve(4);
  PutU32(output, value);
  return output;
}

std::vector<uint8_t> U64(uint64_t value) {
  std::vector<uint8_t> output;
  output.reserve(8);
  PutU64(output, value);
  return output;
}

std::vector<uint8_t> SerializeBody(const Facts& facts) {
  using namespace blind_ledger_longfellow::parameter_attestation;
  std::vector<uint8_t> body;
  body.reserve(2048);
  body.insert(body.end(), kRecordMagic.begin(), kRecordMagic.end());
  PutU32(body, kRecordVersion);
  PutU32(body, kRecordFieldCount);
  PutField(body, FieldId::kFieldFamily, FieldType::kBytes,
           Bytes(facts.field_family));
  PutField(body, FieldId::kFieldDegree, FieldType::kU32, U32(facts.field_degree));
  PutField(body, FieldId::kFieldSerializedBytes, FieldType::kU32,
           U32(facts.field_serialized_bytes));
  PutField(body, FieldId::kProofRate, FieldType::kU32, U32(facts.proof_rate));
  PutField(body, FieldId::kProofQueries, FieldType::kU32,
           U32(facts.proof_queries));
  PutField(body, FieldId::kTranscriptLabel, FieldType::kBytes,
           Bytes(facts.transcript_label));
  PutField(body, FieldId::kTranscriptVersion, FieldType::kU32,
           U32(facts.transcript_version));
  PutField(body, FieldId::kArtifactMagic, FieldType::kBytes,
           Bytes(facts.artifact_magic));
  PutField(body, FieldId::kArtifactVersion, FieldType::kU32,
           U32(facts.artifact_version));
  PutField(body, FieldId::kArtifactHeaderBytes, FieldType::kU64,
           U64(facts.artifact_header_bytes));
  PutField(body, FieldId::kArtifactPublicStatementBytes, FieldType::kU64,
           U64(facts.artifact_public_statement_bytes));
  PutField(body, FieldId::kProofRole, FieldType::kBytes,
           Bytes(facts.proof_role));
  PutField(body, FieldId::kPublicStatementGrammar, FieldType::kBytes,
           Bytes(facts.public_statement_grammar));
  PutField(body, FieldId::kCircuitId, FieldType::kBytes,
           Bytes(facts.circuit_id));
  PutField(body, FieldId::kCircuitInputs, FieldType::kU64,
           U64(facts.circuit_inputs));
  PutField(body, FieldId::kCircuitPublicInputs, FieldType::kU64,
           U64(facts.circuit_public_inputs));
  PutField(body, FieldId::kCircuitLayers, FieldType::kU64,
           U64(facts.circuit_layers));
  PutField(body, FieldId::kCircuitTerms, FieldType::kU64,
           U64(facts.circuit_terms));
  PutField(body, FieldId::kUpstreamRemote, FieldType::kBytes,
           Bytes(facts.upstream_remote));
  PutField(body, FieldId::kUpstreamCommit, FieldType::kBytes,
           Bytes(facts.upstream_commit));
  PutField(body, FieldId::kUpstreamTree, FieldType::kBytes,
           Bytes(facts.upstream_tree));
  PutField(body, FieldId::kSha3PatchSha256, FieldType::kBytes,
           Bytes(facts.sha3_patch_sha256));
  PutField(body, FieldId::kQuadPatchSha256, FieldType::kBytes,
           Bytes(facts.quad_patch_sha256));
  PutField(body, FieldId::kPatchedSourceIdentitySha256, FieldType::kBytes,
           Bytes(facts.patched_source_identity_sha256));
  return body;
}

std::array<uint8_t, 64> Identity(const std::vector<uint8_t>& body) {
  using namespace blind_ledger_longfellow::parameter_attestation;
  proofs::Sha3Reference reference(64);
  reference.update(kIdentityDomain, sizeof(kIdentityDomain) - 1);
  reference.update(reinterpret_cast<const char*>(body.data()), body.size());
  std::array<uint8_t, 64> output{};
  reference.final(output.data());
  return output;
}

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

Facts BuildFacts(
    const std::unique_ptr<proofs::Circuit<RelationField>>& circuit) {
  using namespace blind_ledger_longfellow;
  using namespace blind_ledger_longfellow::minimal_clearance;
  using namespace blind_ledger_longfellow::minimal_clearance_proof;
  Facts facts;
  facts.field_family = "GF2_128";
  facts.field_degree = static_cast<uint32_t>(RelationField::kBits);
  facts.field_serialized_bytes = static_cast<uint32_t>(RelationField::kBytes);
  facts.proof_rate = kLigeroRate;
  facts.proof_queries = kLigeroQueries;
  facts.transcript_label.assign(kTranscriptLabel);
  facts.transcript_version = kTranscriptVersion;
  facts.artifact_magic = kArtifactMagic;
  facts.artifact_version = kFormatVersion;
  facts.artifact_header_bytes = kHeaderBytes;
  facts.artifact_public_statement_bytes = kPublicStatementBytes;
  facts.proof_role.assign(kProofRole);
  facts.public_statement_grammar.assign(kPublicStatementGrammar);
  std::copy(std::begin(circuit->id), std::end(circuit->id),
            facts.circuit_id.begin());
  facts.circuit_inputs = circuit->ninputs;
  facts.circuit_public_inputs = circuit->npub_in;
  facts.circuit_layers = circuit->nl;
  facts.circuit_terms = circuit->nterms();
  facts.upstream_remote = BLIND_LEDGER_UPSTREAM_REMOTE;
  facts.upstream_commit = BLIND_LEDGER_UPSTREAM_COMMIT;
  facts.upstream_tree = BLIND_LEDGER_UPSTREAM_TREE;
  facts.sha3_patch_sha256 = BLIND_LEDGER_SHA3_PATCH_SHA256;
  facts.quad_patch_sha256 = BLIND_LEDGER_QUAD_PATCH_SHA256;
  facts.patched_source_identity_sha256 =
      BLIND_LEDGER_PATCHED_SOURCE_IDENTITY_SHA256;
  return facts;
}

bool WriteBytes(const char* path, const std::vector<uint8_t>& bytes) {
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  if (!output) return false;
  output.write(reinterpret_cast<const char*>(bytes.data()),
               static_cast<std::streamsize>(bytes.size()));
  return static_cast<bool>(output);
}

}  // namespace

int main(int argc, char** argv) {
  if (argc != 2) {
    std::fprintf(stderr,
                 "usage: longfellow_native_v3_parameter_attestation_producer "
                 "OUTPUT_RECORD\n");
    return 2;
  }
  auto circuit =
      blind_ledger_longfellow::minimal_clearance::build_circuit();
  const Facts facts = BuildFacts(circuit);
  const std::vector<uint8_t> body = SerializeBody(facts);
  const auto identity = Identity(body);
  std::vector<uint8_t> record = body;
  record.insert(record.end(), identity.begin(), identity.end());
  if (record.size() >
      blind_ledger_longfellow::parameter_attestation::kMaxRecordBytes ||
      !WriteBytes(argv[1], record)) {
    std::fprintf(stderr, "PARAMETER_ATTESTATION_PRODUCER_REJECT reason=write\n");
    return 1;
  }
  std::printf(
      "PARAMETER_ATTESTATION_PRODUCER_ACCEPT record_bytes=%zu "
      "record_sha3_512=%s circuit_id=%s field_family=%s field_degree=%u "
      "field_bytes=%u rate=%u queries=%u transcript_version=%u "
      "artifact_version=%u artifact_header_bytes=%llu "
      "public_statement_bytes=%llu inputs=%llu public_inputs=%llu "
      "layers=%llu terms=%llu upstream_commit=%s upstream_tree=%s "
      "patched_source_identity_sha256=%s\n",
      record.size(), Hex(identity.data(), identity.size()).c_str(),
      Hex(facts.circuit_id.data(), facts.circuit_id.size()).c_str(),
      facts.field_family.c_str(), facts.field_degree, facts.field_serialized_bytes,
      facts.proof_rate, facts.proof_queries, facts.transcript_version,
      facts.artifact_version,
      static_cast<unsigned long long>(facts.artifact_header_bytes),
      static_cast<unsigned long long>(facts.artifact_public_statement_bytes),
      static_cast<unsigned long long>(facts.circuit_inputs),
      static_cast<unsigned long long>(facts.circuit_public_inputs),
      static_cast<unsigned long long>(facts.circuit_layers),
      static_cast<unsigned long long>(facts.circuit_terms),
      facts.upstream_commit.c_str(), facts.upstream_tree.c_str(),
      facts.patched_source_identity_sha256.c_str());
  return 0;
}
