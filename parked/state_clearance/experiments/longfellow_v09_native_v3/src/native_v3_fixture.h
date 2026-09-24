#ifndef BLIND_LEDGER_LONGFELLOW_V09_NATIVE_V3_FIXTURE_H_
#define BLIND_LEDGER_LONGFELLOW_V09_NATIVE_V3_FIXTURE_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace blind_ledger_longfellow {

constexpr size_t kDigestBytes = 64;
using Digest = std::array<uint8_t, kDigestBytes>;

enum class HashKind {
  kSourceRoot,
  kCompleteness,
  kChronology,
  kBeforeState,
  kRequest,
  kReplay,
  kDecision,
  kDecisionPath,
  kAfterAudit,
  kAfterRoot,
  kAfterState,
  kSourceAddress,
  kSubjectKey,
  kAuditAddress,
  kJoin,
  kReceipt,
  kPrivateBatch,
  kSettlement,
};

struct PublicStatement {
  uint8_t protocol_version = 3;
  Digest proof_suite{};
  Digest execution_context{};
  Digest settlement_domain{};
  uint64_t epoch = 7;
  uint64_t sequence_before = 0;
  Digest state_before_id{};
  Digest state_after_id{};
  Digest governance_snapshot{};
  Digest control_set{};
  Digest private_batch_commitment{};
  Digest settlement_commitment{};
};

struct RelationCase {
  PublicStatement statement;

  // Private logical decision-row material.
  Digest provider_id{};
  Digest credential_id{};
  Digest enrollment_id{};
  Digest attempt_id{};
  Digest mode_id{};
  Digest rule_id{};
  Digest phase0_receipt_binding{};
  Digest source_payload{};
  Digest source_root{};
  Digest completeness_payload{};
  Digest completeness_id{};
  Digest chronology_id{};
  Digest replay_id{};
  Digest exception_id{};
  Digest reason_id{};
  Digest request_id{};
  Digest decision_id{};
  Digest decision_path_id{};

  Digest before_audit_head{};
  Digest before_continuity_root{};
  Digest after_audit_head{};
  Digest after_continuity_root{};

  // Private ordered access rows.
  Digest read_decision_id{};
  Digest read_address{};
  Digest read_key{};
  Digest read_before{};
  Digest read_after{};
  Digest write_decision_id{};
  Digest write_address{};
  Digest write_key{};
  Digest write_before{};
  Digest write_after{};

  Digest join_id{};
  Digest receipt_id{};

  uint8_t policy_result = 0;
  uint8_t effective_directive = 0;
  uint8_t complete = 0;
  uint8_t authoritative_membership = 0;
  uint8_t authoritative_absence = 0;
  uint8_t active_status = 0;
  uint8_t exception_present = 0;
  uint8_t proof_session_accepted = 0;
  uint8_t economic_mutation = 0;

  uint64_t event_time = 0;
  uint64_t observation_time = 0;
  uint64_t rule_effective_time = 0;
  uint64_t decision_time = 0;

  uint32_t decision_index = 0;
  uint32_t decision_count = 1;
  uint32_t read_access_index = 0;
  uint32_t write_access_index = 1;
  uint32_t access_count = 2;
  uint32_t read_decision_index = 0;
  uint32_t write_decision_index = 0;
  uint8_t read_mode = 1;
  uint8_t write_mode = 2;
  uint64_t read_time = 0;
  uint64_t write_time = 0;
};

struct NativeV3Fixture {
  std::array<RelationCase, 5> cases{};
};

NativeV3Fixture make_native_v3_fixture();

// Returns the exact fixed canonical bytes absorbed by one relation endpoint.
std::vector<uint8_t> build_hash_input(const RelationCase& c,
                                      HashKind kind);

// Host-side reference only for deterministic witness/public-input generation.
// Every hidden digest is recomputed and constrained by the circuit as well.
Digest hash_sha3_512(const std::vector<uint8_t>& input);

}  // namespace blind_ledger_longfellow

#endif  // BLIND_LEDGER_LONGFELLOW_V09_NATIVE_V3_FIXTURE_H_
