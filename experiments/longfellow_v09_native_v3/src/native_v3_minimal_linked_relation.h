#ifndef BLIND_LEDGER_LONGFELLOW_V09_NATIVE_V3_MINIMAL_LINKED_RELATION_H_
#define BLIND_LEDGER_LONGFELLOW_V09_NATIVE_V3_MINIMAL_LINKED_RELATION_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "arrays/dense.h"
#include "gf2k/gf2_128.h"
#include "native_v3_fixture.h"
#include "sumcheck/circuit.h"

namespace blind_ledger_longfellow::minimal_linked {

constexpr size_t kDigestBytes = 64;
constexpr char kProofRole[] =
    "BL/NATIVE-V3/MINIMAL-LINKED-CLEARANCE/v1";
constexpr size_t kProofRoleBytes = sizeof(kProofRole) - 1;
constexpr size_t kSha3EndpointCount = 4;
constexpr size_t kStateCommitmentDigestCount = 23;
// Header/version + scalar flags + epoch/sequence-before/sequence-after + eight
// semantic u64s + seven u32s + two roles + two clearance counters + the 23
// fixed-width digests below.
constexpr size_t kStateCommitmentBytes =
    4 + 1 + 11 + (3 * 8) + (8 * 8) + (7 * 4) + 2 + (2 * 8) +
    kStateCommitmentDigestCount * kDigestBytes;

using RelationField = proofs::GF2_128<>;
using Digest = blind_ledger_longfellow::Digest;
using ProofRole = std::array<uint8_t, kProofRoleBytes>;

struct PublicStatement {
  uint8_t protocol_version = 3;
  ProofRole proof_role{};
  Digest proof_suite{};
  Digest execution_context{};
  Digest source_registry_snapshot{};
  Digest source_profile{};
  Digest governance_snapshot{};
  Digest automatic_control_set{};
  Digest settlement_domain{};
  Digest evaluator_id{};
  Digest schema_id{};
  Digest program_id{};
  Digest policy_id{};
  Digest subject_id{};
  Digest attempt_id{};
  Digest request_id{};
  Digest source_root_id{};
  Digest completeness_id{};
  Digest source_commitment{};
  Digest source_address{};
  Digest source_key{};
  Digest audit_address{};
  Digest exception_id{};
  Digest exception_scope_id{};
  Digest rule_id{};
  Digest decision_id{};
  Digest state_before_id{};
  Digest state_after_id{};
  uint64_t epoch = 0;
  uint64_t sequence_before = 0;
  uint8_t active = 0;
  uint8_t complete = 0;
  uint8_t authoritative_membership = 0;
  uint8_t authoritative_absence = 0;
  std::array<uint8_t, kStateCommitmentBytes> state_commitment_bytes{};
};

struct Case {
  PublicStatement statement{};

  // Hidden source/registry material. The verifier-selected registry IDs above
  // are public; these bytes and flags are constrained to one source digest.
  Digest provider_id{};
  Digest credential_id{};
  Digest enrollment_id{};
  Digest source_payload{};

  // Semantic decision and exact ordered access rows.
  uint8_t policy_result = 0;
  uint8_t effective_directive = 0;
  uint8_t exception_present = 0;
  uint8_t exception_authorized = 0;
  uint8_t economic_mutation = 0;
  uint64_t rule_effective_time = 0;
  uint64_t event_time = 0;
  uint64_t observation_time = 0;
  uint64_t decision_time = 0;
  uint64_t read_time = 0;
  uint64_t write_time = 0;
  uint64_t exception_valid_from = 0;
  uint64_t exception_valid_until = 0;
  uint64_t sequence_after = 0;
  uint32_t decision_index = 0;
  uint32_t decision_count = 1;
  uint32_t read_access_index = 0;
  uint32_t write_access_index = 1;
  uint32_t access_count = 2;
  uint32_t read_decision_index = 0;
  uint32_t write_decision_index = 0;
  uint8_t read_mode = 1;
  uint8_t write_mode = 2;

  uint8_t clearance_marker_before = 0;
  uint8_t clearance_marker_after = 0;
  uint64_t clearance_count_before = 0;
  uint64_t clearance_count_after = 0;

  Digest before_audit_head{};
  Digest after_audit_head{};
  Digest before_continuity_root{};
  Digest after_continuity_root{};
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
};

struct Fixture {
  std::array<Case, 5> cases{};
};

struct DerivedIdentities {
  Digest decision_id{};
  Digest join_id{};
  Digest receipt_id{};
  Digest settlement_id{};
};

Fixture make_fixture();

std::unique_ptr<proofs::Circuit<RelationField>> build_circuit();
std::unique_ptr<proofs::Circuit<RelationField>> build_circuit_stage(
    size_t endpoint_count);

void fill_public(const Case& value,
                 proofs::Dense<RelationField>& public_input);
void fill_witness(const Case& value,
                  proofs::Dense<RelationField>& witness);

std::vector<uint8_t> source_commitment_input(const Case& value);
std::vector<uint8_t> endpoint_input(const Case& value, size_t endpoint_index);
const char* endpoint_name(size_t endpoint_index);
std::vector<uint8_t> state_commitment_bytes(const Case& value);
void rebuild_state_binding(Case& value);
std::vector<uint8_t> public_statement_bytes(const Case& value);
DerivedIdentities derive_identities(const Case& value);

// Independent state-side semantic evaluator. It does not build or execute a
// Longfellow circuit and does not call the legacy 18-endpoint relation.
bool evaluate_case(const Case& value, std::string& reason);

}  // namespace blind_ledger_longfellow::minimal_linked

#endif  // BLIND_LEDGER_LONGFELLOW_V09_NATIVE_V3_MINIMAL_LINKED_RELATION_H_
