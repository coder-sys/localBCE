#ifndef BLIND_LEDGER_LONGFELLOW_V09_NATIVE_V3_SOURCE_ASSERTION_RELATION_H_
#define BLIND_LEDGER_LONGFELLOW_V09_NATIVE_V3_SOURCE_ASSERTION_RELATION_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "arrays/dense.h"
#include "gf2k/gf2_128.h"
#include "sumcheck/circuit.h"

namespace blind_ledger_longfellow::source_assertion {

constexpr size_t kDigestBytes = 64;
using Digest = std::array<uint8_t, kDigestBytes>;

constexpr char kProofRole[] = "BL/NATIVE-V3/SOURCE-ASSERTION-ONLY/v1";
constexpr size_t kProofRoleBytes = sizeof(kProofRole) - 1;
using ProofRole = std::array<uint8_t, kProofRoleBytes>;

enum class Endpoint {
  kSourceRoot,
  kCompleteness,
  kRequest,
  kPrivateBatch,
};

struct Statement {
  uint8_t protocol_version = 3;
  Digest proof_suite{};
  ProofRole proof_role{};
  Digest execution_context{};
  Digest source_registry_snapshot{};
  Digest source_profile{};
  Digest governance_snapshot{};
  Digest automatic_control_set{};
  Digest settlement_domain{};
  Digest subject_scope{};
  uint64_t epoch = 7;
  uint64_t sequence_before = 0;
  Digest state_before_id{};
  Digest request_id{};
  Digest source_root_id{};
  Digest completeness_id{};
  Digest decision_path_id{};
  Digest exception_id{};
  uint8_t active = 0;
  uint8_t complete = 0;
  uint8_t authoritative_membership = 0;
  uint8_t authoritative_absence = 0;
  Digest private_batch_commitment{};
};

struct Witness {
  Digest provider_id{};
  Digest credential_id{};
  Digest enrollment_id{};
  Digest attempt_id{};
  Digest source_payload{};
  uint8_t active = 0;
  uint8_t complete = 0;
  uint8_t authoritative_membership = 0;
  uint8_t authoritative_absence = 0;
  uint64_t event_time = 0;
  uint64_t observation_time = 0;
  uint64_t rule_effective_time = 0;
  uint64_t decision_time = 0;
};

struct SourceAssertionCase {
  const char* label = nullptr;
  Statement statement{};
  Witness witness{};
};

struct SourceAssertionFixture {
  std::array<SourceAssertionCase, 5> cases{};
};

using RelationField = proofs::GF2_128<>;

SourceAssertionFixture make_source_assertion_fixture();

// The fixed four-endpoint source assertion relation. It proves only the
// hidden source/request commitments and assertion flags. Chronology, policy,
// exact access rows, receipt, and state mutation remain state-side concerns.
std::unique_ptr<proofs::Circuit<RelationField>>
build_source_assertion_circuit();

// Shape-only construction of the first endpoint_count endpoints in the
// canonical topological order. This never starts a prover.
std::unique_ptr<proofs::Circuit<RelationField>>
build_source_assertion_circuit_stage(size_t endpoint_count);

size_t source_assertion_endpoint_count();
Endpoint source_assertion_endpoint_at(size_t index);

// Exact retained endpoint preimages used for fixture generation and shape
// attribution. The circuit recomputes the same bytes in-circuit.
std::vector<uint8_t> build_source_assertion_hash_input(
    const SourceAssertionCase& source_case, Endpoint endpoint);

// Fixed canonical public statement encoding. The independent evaluator has a
// separate parser and does not call it while validating an input.
std::vector<uint8_t> source_assertion_statement_bytes(
    const Statement& statement);

void fill_source_assertion_witness(const SourceAssertionCase& source_case,
                                   proofs::Dense<RelationField>& witness);

void fill_source_assertion_public(const SourceAssertionCase& source_case,
                                  proofs::Dense<RelationField>& public_input);

std::string source_assertion_hex(const uint8_t* bytes, size_t length);

}  // namespace blind_ledger_longfellow::source_assertion

#endif  // BLIND_LEDGER_LONGFELLOW_V09_NATIVE_V3_SOURCE_ASSERTION_RELATION_H_
