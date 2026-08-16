#ifndef BLIND_LEDGER_LONGFELLOW_V09_NATIVE_V3_ARTIFACT_H_
#define BLIND_LEDGER_LONGFELLOW_V09_NATIVE_V3_ARTIFACT_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace blind_ledger_longfellow {

constexpr size_t kNativeV3LigeroRate = 4;
constexpr size_t kNativeV3LigeroQueries = 189;
constexpr size_t kNativeV3TranscriptVersion = 6;
constexpr size_t kNativeV3PublicBytes = 593;
constexpr size_t kNativeV3MaxProofBytes = 512u * 1024u * 1024u;

struct NativeV3Artifact {
  std::array<uint8_t, 32> circuit_id{};
  std::vector<uint8_t> public_bytes;
  std::vector<uint8_t> proof_bytes;
};

bool write_native_v3_artifact(const std::string& path,
                              const std::array<uint8_t, 32>& circuit_id,
                              const std::vector<uint8_t>& public_bytes,
                              const std::vector<uint8_t>& proof_bytes,
                              std::string& error);

bool read_native_v3_artifact(const std::string& path, NativeV3Artifact& artifact,
                             std::string& error);

const uint8_t* native_v3_transcript_label(size_t& length);

}  // namespace blind_ledger_longfellow

#endif  // BLIND_LEDGER_LONGFELLOW_V09_NATIVE_V3_ARTIFACT_H_
