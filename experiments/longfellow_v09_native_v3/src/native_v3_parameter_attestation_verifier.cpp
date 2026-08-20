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
              "unsupported verifier field mapping");

void PutU16(std::vector<uint8_t>& output, uint16_t value) {
  output.push_back(static_cast<uint8_t>(value >> 8));
  output.push_back(static_cast<uint8_t>(value));
}

void PutU32(std::vector<uint8_t>& output, uint32_t value) {
  output.push_back(static_cast<uint8_t>(value >> 24));
  output.push_back(static_cast<uint8_t>(value >> 16));
  output.push_back(static_cast<uint8_t>(value >> 8));
  output.push_back(static_cast<uint8_t>(value));
}

void PutU64(std::vector<uint8_t>& output, uint64_t value) {
  for (size_t index = 0; index != 8; ++index) {
    output.push_back(static_cast<uint8_t>(value >> (56 - index * 8)));
  }
}

void PutField(std::vector<uint8_t>& output, FieldId id, FieldType type,
              const std::vector<uint8_t>& payload) {
  if (payload.size() > std::numeric_limits<uint32_t>::max()) {
    throw std::runtime_error("verifier field too large");
  }
  PutU16(output, static_cast<uint16_t>(id));
  output.push_back(static_cast<uint8_t>(type));
  PutU32(output, static_cast<uint32_t>(payload.size()));
  output.insert(output.end(), payload.begin(), payload.end());
}

std::vector<uint8_t> Text(const std::string& value) {
  return std::vector<uint8_t>(value.begin(), value.end());
}

std::vector<uint8_t> Bytes(const std::array<uint8_t, 8>& value) {
  return std::vector<uint8_t>(value.begin(), value.end());
}

std::vector<uint8_t> Bytes(const std::array<uint8_t, 32>& value) {
  return std::vector<uint8_t>(value.begin(), value.end());
}

std::vector<uint8_t> Number32(uint32_t value) {
  std::vector<uint8_t> output;
  PutU32(output, value);
  return output;
}

std::vector<uint8_t> Number64(uint64_t value) {
  std::vector<uint8_t> output;
  PutU64(output, value);
  return output;
}

// This is deliberately a separately written encoder from the producer.
std::vector<uint8_t> ExpectedBody(const Facts& facts) {
  using namespace blind_ledger_longfellow::parameter_attestation;
  std::vector<uint8_t> body;
  body.insert(body.end(), kRecordMagic.begin(), kRecordMagic.end());
  PutU32(body, kRecordVersion);
  PutU32(body, kRecordFieldCount);
  PutField(body, FieldId::kFieldFamily, FieldType::kBytes,
           Text(facts.field_family));
  PutField(body, FieldId::kFieldDegree, FieldType::kU32,
           Number32(facts.field_degree));
  PutField(body, FieldId::kFieldSerializedBytes, FieldType::kU32,
           Number32(facts.field_serialized_bytes));
  PutField(body, FieldId::kProofRate, FieldType::kU32,
           Number32(facts.proof_rate));
  PutField(body, FieldId::kProofQueries, FieldType::kU32,
           Number32(facts.proof_queries));
  PutField(body, FieldId::kTranscriptLabel, FieldType::kBytes,
           Text(facts.transcript_label));
  PutField(body, FieldId::kTranscriptVersion, FieldType::kU32,
           Number32(facts.transcript_version));
  PutField(body, FieldId::kArtifactMagic, FieldType::kBytes,
           Bytes(facts.artifact_magic));
  PutField(body, FieldId::kArtifactVersion, FieldType::kU32,
           Number32(facts.artifact_version));
  PutField(body, FieldId::kArtifactHeaderBytes, FieldType::kU64,
           Number64(facts.artifact_header_bytes));
  PutField(body, FieldId::kArtifactPublicStatementBytes, FieldType::kU64,
           Number64(facts.artifact_public_statement_bytes));
  PutField(body, FieldId::kProofRole, FieldType::kBytes,
           Text(facts.proof_role));
  PutField(body, FieldId::kPublicStatementGrammar, FieldType::kBytes,
           Text(facts.public_statement_grammar));
  PutField(body, FieldId::kCircuitId, FieldType::kBytes,
           Bytes(facts.circuit_id));
  PutField(body, FieldId::kCircuitInputs, FieldType::kU64,
           Number64(facts.circuit_inputs));
  PutField(body, FieldId::kCircuitPublicInputs, FieldType::kU64,
           Number64(facts.circuit_public_inputs));
  PutField(body, FieldId::kCircuitLayers, FieldType::kU64,
           Number64(facts.circuit_layers));
  PutField(body, FieldId::kCircuitTerms, FieldType::kU64,
           Number64(facts.circuit_terms));
  PutField(body, FieldId::kUpstreamRemote, FieldType::kBytes,
           Text(facts.upstream_remote));
  PutField(body, FieldId::kUpstreamCommit, FieldType::kBytes,
           Text(facts.upstream_commit));
  PutField(body, FieldId::kUpstreamTree, FieldType::kBytes,
           Text(facts.upstream_tree));
  PutField(body, FieldId::kSha3PatchSha256, FieldType::kBytes,
           Text(facts.sha3_patch_sha256));
  PutField(body, FieldId::kQuadPatchSha256, FieldType::kBytes,
           Text(facts.quad_patch_sha256));
  PutField(body, FieldId::kPatchedSourceIdentitySha256, FieldType::kBytes,
           Text(facts.patched_source_identity_sha256));
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

bool ReadU16(const std::vector<uint8_t>& bytes, size_t& offset,
             uint16_t& value, size_t end) {
  if (end - offset < 2) return false;
  value = (static_cast<uint16_t>(bytes[offset]) << 8) |
          static_cast<uint16_t>(bytes[offset + 1]);
  offset += 2;
  return true;
}

bool ReadU32(const std::vector<uint8_t>& bytes, size_t& offset,
             uint32_t& value, size_t end) {
  if (end - offset < 4) return false;
  value = (static_cast<uint32_t>(bytes[offset]) << 24) |
          (static_cast<uint32_t>(bytes[offset + 1]) << 16) |
          (static_cast<uint32_t>(bytes[offset + 2]) << 8) |
          static_cast<uint32_t>(bytes[offset + 3]);
  offset += 4;
  return true;
}

bool ParseRecord(const std::vector<uint8_t>& bytes, std::string& reason) {
  using namespace blind_ledger_longfellow::parameter_attestation;
  if (bytes.size() < kRecordMagic.size() + 8 + kIdentityBytes) {
    reason = "record.truncated";
    return false;
  }
  if (bytes.size() > kMaxRecordBytes) {
    reason = "record.size-cap";
    return false;
  }
  const size_t body_end = bytes.size() - kIdentityBytes;
  if (!std::equal(kRecordMagic.begin(), kRecordMagic.end(), bytes.begin())) {
    reason = "record.magic";
    return false;
  }
  size_t offset = kRecordMagic.size();
  uint32_t version = 0;
  uint32_t field_count = 0;
  if (!ReadU32(bytes, offset, version, body_end) ||
      !ReadU32(bytes, offset, field_count, body_end)) {
    reason = "record.header";
    return false;
  }
  if (version != kRecordVersion) {
    reason = "record.version";
    return false;
  }
  if (field_count != kRecordFieldCount) {
    reason = "record.field-count";
    return false;
  }
  for (uint32_t index = 0; index < field_count; ++index) {
    uint16_t id = 0;
    if (!ReadU16(bytes, offset, id, body_end) || offset >= body_end) {
      reason = "field.header";
      return false;
    }
    const auto expected_id = static_cast<uint16_t>(index + 1);
    if (id < expected_id) {
      reason = "field.duplicate-or-reordered";
      return false;
    }
    if (id != expected_id) {
      reason = id > kRecordFieldCount ? "field.unknown"
                                      : "field.missing-or-reordered";
      return false;
    }
    const uint8_t raw_type = bytes[offset++];
    uint32_t length = 0;
    if (!ReadU32(bytes, offset, length, body_end) ||
        length > body_end - offset) {
      reason = "field.length";
      return false;
    }
    const auto id_enum = static_cast<FieldId>(id);
    const bool is_numeric32 =
        id_enum == FieldId::kFieldDegree || id_enum == FieldId::kFieldSerializedBytes ||
        id_enum == FieldId::kProofRate || id_enum == FieldId::kProofQueries ||
        id_enum == FieldId::kTranscriptVersion || id_enum == FieldId::kArtifactVersion;
    const bool is_numeric64 =
        id_enum == FieldId::kArtifactHeaderBytes ||
        id_enum == FieldId::kArtifactPublicStatementBytes ||
        (id_enum >= FieldId::kCircuitInputs &&
         id_enum <= FieldId::kCircuitTerms);
    const uint8_t expected_type =
        is_numeric32 ? static_cast<uint8_t>(FieldType::kU32)
        : is_numeric64 ? static_cast<uint8_t>(FieldType::kU64)
                       : static_cast<uint8_t>(FieldType::kBytes);
    if (raw_type != expected_type) {
      reason = "field.type";
      return false;
    }
    const size_t expected_length = is_numeric32 ? 4 : is_numeric64 ? 8 : 0;
    if (expected_length != 0 && length != expected_length) {
      reason = "field.numeric-length";
      return false;
    }
    if (expected_length == 0 && (length == 0 || length > 256)) {
      reason = "field.bytes-length";
      return false;
    }
    if (id_enum == FieldId::kArtifactMagic && length != 8) {
      reason = "field.artifact-magic-length";
      return false;
    }
    if (id_enum == FieldId::kCircuitId && length != 32) {
      reason = "field.circuit-id-length";
      return false;
    }
    offset += length;
  }
  if (offset != body_end) {
    reason = "record.trailing-before-identity";
    return false;
  }
  const std::vector<uint8_t> body(bytes.begin(), bytes.begin() + body_end);
  const auto expected_identity = Identity(body);
  if (!std::equal(expected_identity.begin(), expected_identity.end(),
                  bytes.begin() + body_end)) {
    reason = "record.identity";
    return false;
  }
  return true;
}

bool ReadFile(const char* path, std::vector<uint8_t>& bytes, std::string& reason) {
  std::ifstream input(path, std::ios::binary | std::ios::ate);
  if (!input) {
    reason = "file.open";
    return false;
  }
  const std::streamoff size = input.tellg();
  if (size < 0 || static_cast<uint64_t>(size) >
                      blind_ledger_longfellow::parameter_attestation::kMaxRecordBytes) {
    reason = "file.size";
    return false;
  }
  bytes.resize(static_cast<size_t>(size));
  input.seekg(0, std::ios::beg);
  if (!bytes.empty() &&
      !input.read(reinterpret_cast<char*>(bytes.data()),
                  static_cast<std::streamsize>(bytes.size()))) {
    reason = "file.read";
    return false;
  }
  return true;
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

int Reject(const std::string& reason) {
  std::fprintf(stderr, "PARAMETER_ATTESTATION_VERIFIER_REJECT reason=%s\n",
               reason.c_str());
  return 1;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc != 2) {
    return Reject("usage");
  }
  std::vector<uint8_t> record;
  std::string reason;
  if (!ReadFile(argv[1], record, reason) || !ParseRecord(record, reason)) {
    return Reject(reason);
  }

  // The verifier-only circuit target cannot construct a producer fixture or
  // import producer acceptance state. Its dimensions and ID are reconstructed
  // from the compiled relation here.
  auto circuit =
      blind_ledger_longfellow::minimal_clearance::build_circuit();
  Facts expected;
  using namespace blind_ledger_longfellow;
  using namespace blind_ledger_longfellow::minimal_clearance;
  using namespace blind_ledger_longfellow::minimal_clearance_proof;
  expected.field_family = "GF2_128";
  expected.field_degree = static_cast<uint32_t>(RelationField::kBits);
  expected.field_serialized_bytes = static_cast<uint32_t>(RelationField::kBytes);
  expected.proof_rate = kLigeroRate;
  expected.proof_queries = kLigeroQueries;
  expected.transcript_label.assign(kTranscriptLabel);
  expected.transcript_version = kTranscriptVersion;
  expected.artifact_magic = kArtifactMagic;
  expected.artifact_version = kFormatVersion;
  expected.artifact_header_bytes = kHeaderBytes;
  expected.artifact_public_statement_bytes = kPublicStatementBytes;
  expected.proof_role.assign(kProofRole);
  expected.public_statement_grammar.assign(kPublicStatementGrammar);
  std::copy(std::begin(circuit->id), std::end(circuit->id),
            expected.circuit_id.begin());
  expected.circuit_inputs = circuit->ninputs;
  expected.circuit_public_inputs = circuit->npub_in;
  expected.circuit_layers = circuit->nl;
  expected.circuit_terms = circuit->nterms();
  expected.upstream_remote = BLIND_LEDGER_UPSTREAM_REMOTE;
  expected.upstream_commit = BLIND_LEDGER_UPSTREAM_COMMIT;
  expected.upstream_tree = BLIND_LEDGER_UPSTREAM_TREE;
  expected.sha3_patch_sha256 = BLIND_LEDGER_SHA3_PATCH_SHA256;
  expected.quad_patch_sha256 = BLIND_LEDGER_QUAD_PATCH_SHA256;
  expected.patched_source_identity_sha256 =
      BLIND_LEDGER_PATCHED_SOURCE_IDENTITY_SHA256;

  const std::vector<uint8_t> expected_body = ExpectedBody(expected);
  const std::vector<uint8_t> actual_body(record.begin(),
                                         record.end() -
                                             blind_ledger_longfellow::parameter_attestation::kIdentityBytes);
  if (actual_body != expected_body) {
    return Reject("facts.mismatch");
  }
  const auto identity = Identity(actual_body);
  std::printf(
      "PARAMETER_ATTESTATION_VERIFIER_ACCEPT record_bytes=%zu "
      "record_sha3_512=%s circuit_id=%s field_family=%s field_degree=%u "
      "field_bytes=%u rate=%u queries=%u transcript_version=%u "
      "artifact_version=%u inputs=%llu public_inputs=%llu layers=%llu "
      "terms=%llu patched_source_identity_sha256=%s\n",
      record.size(), Hex(identity.data(), identity.size()).c_str(),
      Hex(expected.circuit_id.data(), expected.circuit_id.size()).c_str(),
      expected.field_family.c_str(), expected.field_degree,
      expected.field_serialized_bytes, expected.proof_rate, expected.proof_queries,
      expected.transcript_version, expected.artifact_version,
      static_cast<unsigned long long>(expected.circuit_inputs),
      static_cast<unsigned long long>(expected.circuit_public_inputs),
      static_cast<unsigned long long>(expected.circuit_layers),
      static_cast<unsigned long long>(expected.circuit_terms),
      expected.patched_source_identity_sha256.c_str());
  return 0;
}
