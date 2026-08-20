#ifndef BLIND_LEDGER_LONGFELLOW_MINIMAL_CLEARANCE_PROOF_ARTIFACT_H_
#define BLIND_LEDGER_LONGFELLOW_MINIMAL_CLEARANCE_PROOF_ARTIFACT_H_

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace blind_ledger_longfellow::minimal_clearance_proof {

constexpr size_t kCircuitIdBytes = 32;
constexpr size_t kPublicStatementBytes = 3340;
constexpr size_t kHeaderBytes = 68;
constexpr size_t kMaxProofBytes = 512u * 1024u * 1024u;
constexpr uint32_t kFormatVersion = 1;
constexpr uint32_t kLigeroRate = 4;
constexpr uint32_t kLigeroQueries = 189;
constexpr uint32_t kTranscriptVersion = 6;
inline constexpr char kTranscriptLabel[] =
    "BL/NATIVE-V3/MINIMAL-CLEARANCE/TRANSCRIPT/v1";
inline constexpr std::array<uint8_t, 8> kArtifactMagic = {
    'B', 'L', 'M', 'C', 'V', '3', 'P', '1'};

struct Artifact {
  std::array<uint8_t, kCircuitIdBytes> circuit_id{};
  uint32_t rate = 0;
  uint32_t queries = 0;
  uint32_t transcript_version = 0;
  std::vector<uint8_t> public_statement;
  std::vector<uint8_t> proof;
};

// Fixed-size, fail-closed envelope parser. It accepts no trailing bytes and
// contains no private witness or producer-side acceptance state.
bool parse_artifact_bytes(const std::vector<uint8_t>& bytes, Artifact& artifact,
                          std::string& error);
bool read_artifact_bytes(const std::string& path, std::vector<uint8_t>& bytes,
                         std::string& error);
bool read_artifact(const std::string& path, Artifact& artifact,
                   std::string& error);
bool serialize_artifact(const Artifact& artifact, std::vector<uint8_t>& bytes,
                        std::string& error);
bool write_artifact(const std::string& path,
                    const std::array<uint8_t, kCircuitIdBytes>& circuit_id,
                    uint32_t rate, uint32_t queries, uint32_t transcript_version,
                    const std::vector<uint8_t>& public_statement,
                    const std::vector<uint8_t>& proof, std::string& error);

}  // namespace blind_ledger_longfellow::minimal_clearance_proof

#endif  // BLIND_LEDGER_LONGFELLOW_MINIMAL_CLEARANCE_PROOF_ARTIFACT_H_
