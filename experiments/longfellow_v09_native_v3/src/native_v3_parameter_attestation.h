#ifndef BLIND_LEDGER_NATIVE_V3_PARAMETER_ATTESTATION_H_
#define BLIND_LEDGER_NATIVE_V3_PARAMETER_ATTESTATION_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace blind_ledger_longfellow::parameter_attestation {

inline constexpr std::array<uint8_t, 8> kRecordMagic = {
    'B', 'L', 'P', 'A', 'V', '3', '0', '1'};
inline constexpr uint32_t kRecordVersion = 1;
inline constexpr uint32_t kRecordFieldCount = 24;
inline constexpr size_t kIdentityBytes = 64;
inline constexpr size_t kMaxRecordBytes = 16u * 1024u;
inline constexpr char kIdentityDomain[] =
    "BL/NATIVE-V3/LONGFELLOW/IMPLEMENTATION-PARAMETER-ATTESTATION/v1\0";

enum class FieldType : uint8_t {
  kBytes = 1,
  kU32 = 2,
  kU64 = 3,
};

enum class FieldId : uint16_t {
  kFieldFamily = 1,
  kFieldDegree = 2,
  kFieldSerializedBytes = 3,
  kProofRate = 4,
  kProofQueries = 5,
  kTranscriptLabel = 6,
  kTranscriptVersion = 7,
  kArtifactMagic = 8,
  kArtifactVersion = 9,
  kArtifactHeaderBytes = 10,
  kArtifactPublicStatementBytes = 11,
  kProofRole = 12,
  kPublicStatementGrammar = 13,
  kCircuitId = 14,
  kCircuitInputs = 15,
  kCircuitPublicInputs = 16,
  kCircuitLayers = 17,
  kCircuitTerms = 18,
  kUpstreamRemote = 19,
  kUpstreamCommit = 20,
  kUpstreamTree = 21,
  kSha3PatchSha256 = 22,
  kQuadPatchSha256 = 23,
  kPatchedSourceIdentitySha256 = 24,
};

struct Facts {
  std::string field_family;
  uint32_t field_degree = 0;
  uint32_t field_serialized_bytes = 0;
  uint32_t proof_rate = 0;
  uint32_t proof_queries = 0;
  std::string transcript_label;
  uint32_t transcript_version = 0;
  std::array<uint8_t, 8> artifact_magic{};
  uint32_t artifact_version = 0;
  uint64_t artifact_header_bytes = 0;
  uint64_t artifact_public_statement_bytes = 0;
  std::string proof_role;
  std::string public_statement_grammar;
  std::array<uint8_t, 32> circuit_id{};
  uint64_t circuit_inputs = 0;
  uint64_t circuit_public_inputs = 0;
  uint64_t circuit_layers = 0;
  uint64_t circuit_terms = 0;
  std::string upstream_remote;
  std::string upstream_commit;
  std::string upstream_tree;
  std::string sha3_patch_sha256;
  std::string quad_patch_sha256;
  std::string patched_source_identity_sha256;
};

}  // namespace blind_ledger_longfellow::parameter_attestation

#endif  // BLIND_LEDGER_NATIVE_V3_PARAMETER_ATTESTATION_H_
