#ifndef BLIND_LEDGER_LONGFELLOW_V09_NATIVE_V3_MINIMAL_CLEARANCE_RELATION_H_
#define BLIND_LEDGER_LONGFELLOW_V09_NATIVE_V3_MINIMAL_CLEARANCE_RELATION_H_

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

namespace blind_ledger_longfellow::minimal_clearance {

constexpr size_t kDigestBytes = 64;
constexpr char kProofRole[] =
    "BL/NATIVE-V3/MINIMAL-CLEARANCE/v3";
constexpr size_t kProofRoleBytes = sizeof(kProofRole) - 1;
constexpr char kPublicStatementGrammar[] =
    "BL/NATIVE-V3/MINIMAL-CLEARANCE/STATEMENT/v3";
// This is the sole checked-in state grammar identity material.  It is ASCII,
// noncyclic, and enumerates every byte of the fixed BLST-v2 state.
constexpr char kStateLayoutLiteral[] =
    "BLST-V2|magic:u8[4]@0|version:u8@4=2|policy_result:u8@5|"
    "effective_directive:u8@6|complete:u8@7|membership:u8@8|absence:u8@9|"
    "active:u8@10|exception_present:u8@11|exception_authorized:u8@12|"
    "economic_mutation:u8@13|clearance_marker_before:u8@14|"
    "clearance_marker_after:u8@15|epoch:u64be@16|sequence_before:u64be@24|"
    "rule_effective_time:u64be@32|event_time:u64be@40|"
    "observation_time:u64be@48|decision_time:u64be@56|read_time:u64be@64|"
    "write_time:u64be@72|exception_valid_from:u64be@80|"
    "exception_valid_until:u64be@88|sequence_after:u64be@96|"
    "decision_index:u32be@104|decision_count:u32be@108|"
    "read_access_index:u32be@112|write_access_index:u32be@116|"
    "access_count:u32be@120|read_decision_index:u32be@124|"
    "write_decision_index:u32be@128|read_mode:u8@132|write_mode:u8@133|"
    "clearance_count_before:u64be@134|clearance_count_after:u64be@142|"
    "digests:23*u8[64]@150|proposed_payment_commitment:u8[64]@1622|"
    "length:1686|capacity:u32be=1|tail:final-64-bytes|no-padding";
constexpr size_t kStateLayoutLiteralBytes = sizeof(kStateLayoutLiteral) - 1;
constexpr size_t kStateCommitmentBytes = 1686;
constexpr size_t kStateHeaderAndScalars = 150;
constexpr size_t kStateDigestCount = 23;
constexpr size_t kStateProposedCommitmentOffset =
    kStateHeaderAndScalars + kStateDigestCount * kDigestBytes;
constexpr char kStateLayoutDomain[] =
    "BL/NATIVE-V3/STATE-LAYOUT/v2\0";
constexpr char kStateIdDomain[] = "BL/NATIVE-V3/STATE-ID/v1\0";
constexpr char kProposedPaymentDomain[] =
    "BL/NATIVE-V3/PROPOSED-PAYMENT-COMMITMENT/v1\0";
constexpr char kNoAuthorizedAmountDomain[] =
    "BL/NATIVE-V3/NO-AUTHORIZED-AMOUNT/v1\0";
constexpr uint32_t kStateCapacity = 1;
constexpr uint8_t kStateVersion = 2;
constexpr uint64_t kStateGenesisEpoch = 7;
constexpr size_t kPublicStatementDigestCount = 26;
constexpr size_t kPredecessorStateBytes = kStateCommitmentBytes;
constexpr size_t kPublicStatementBytes = 5090;
// Only undisclosed source material and amount material cross the ZK boundary;
// canonical state IDs are checked at the independent state-side boundary.
constexpr size_t kSha3EndpointCount = 2;
constexpr size_t kStateCommitmentDigestCount = 23;
// Header/version + scalar flags + epoch/sequence-before/sequence-after + eight
// semantic u64s + seven u32s + two roles + two clearance counters + the 23
// fixed-width digests below.
static_assert(kStateCommitmentBytes ==
              kStateHeaderAndScalars + kStateDigestCount * kDigestBytes +
                  kDigestBytes);
static_assert(kStateProposedCommitmentOffset + kDigestBytes ==
              kStateCommitmentBytes);
static_assert(kPublicStatementBytes ==
              1 + kProofRoleBytes + kPublicStatementDigestCount * kDigestBytes +
                  8 + 8 + 4 + kPredecessorStateBytes +
                  kStateCommitmentBytes);

using RelationField = proofs::GF2_128<>;
using Digest = blind_ledger_longfellow::Digest;
using ProofRole = std::array<uint8_t, kProofRoleBytes>;
struct Case;

// The semantic execution-context identity is shared by the fixture builder and
// the verifier; executable/build hashes belong only to Queue V6 metadata.
Digest ExecutionContextId();
Digest StateLayoutIdForEvidence();
Digest NoAuthorizedAmountCommitmentForEvidence();
Digest ProposedPaymentCommitmentForEvidence(const Case& value);
Digest CanonicalStateIdForEvidence(const Digest& execution_context,
                                   uint64_t sequence,
                                   const std::vector<uint8_t>& state_bytes);
std::vector<uint8_t> GenesisStateBytesForEvidence();

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
  Digest private_batch_commitment{};
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
  std::array<uint8_t, kPredecessorStateBytes> predecessor_state_bytes{};
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
  Digest source_nonce{};

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
  uint64_t amount_cents = 0;
  std::array<uint8_t, kDigestBytes> nonce{};
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
// Verifier-side public packing deliberately accepts only the typed public
// statement.  It does not require a producer fixture or private witness.
void fill_public_statement(const PublicStatement& value,
                           proofs::Dense<RelationField>& public_input);
void fill_witness(const Case& value,
                  proofs::Dense<RelationField>& witness);

std::vector<uint8_t> private_batch_commitment_input(const Case& value);
std::vector<uint8_t> endpoint_input(const Case& value, size_t endpoint_index);
const char* endpoint_name(size_t endpoint_index);
std::vector<uint8_t> state_commitment_bytes(const Case& value);
void rebuild_state_binding(Case& value);
void rebuild_transition_binding(Case& value);
std::vector<uint8_t> public_statement_bytes(const Case& value);
DerivedIdentities derive_identities(const Case& value);

// Independent state-side semantic evaluator. It does not build or execute a
// Longfellow circuit and does not call the legacy 18-endpoint relation.
bool evaluate_case(const Case& value, std::string& reason);

}  // namespace blind_ledger_longfellow::minimal_clearance

#endif  // BLIND_LEDGER_LONGFELLOW_V09_NATIVE_V3_MINIMAL_CLEARANCE_RELATION_H_
