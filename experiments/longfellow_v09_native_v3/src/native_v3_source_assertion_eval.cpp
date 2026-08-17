#include "native_v3_source_assertion_relation.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include "circuits/tests/sha3/sha3_reference.h"
#include "sumcheck/prover_layers.h"

namespace {

using SourceCase =
    blind_ledger_longfellow::source_assertion::SourceAssertionCase;
using SourceDigest = blind_ledger_longfellow::source_assertion::Digest;
using SourceEndpoint = blind_ledger_longfellow::source_assertion::Endpoint;
using SourceField =
    blind_ledger_longfellow::source_assertion::RelationField;
using SourceStatement =
    blind_ledger_longfellow::source_assertion::Statement;

constexpr size_t kRoleOffset = 65;
constexpr size_t kExecutionContextOffset = 102;
constexpr size_t kRegistryOffset = 166;
constexpr size_t kProfileOffset = 230;
constexpr size_t kGovernanceOffset = 294;
constexpr size_t kControlOffset = 358;
constexpr size_t kSettlementDomainOffset = 422;
constexpr size_t kSubjectScopeOffset = 486;
constexpr size_t kEpochOffset = 550;
constexpr size_t kSequenceOffset = 558;
constexpr size_t kStateBeforeOffset = 566;
constexpr size_t kRequestOffset = 630;
constexpr size_t kSourceRootOffset = 694;
constexpr size_t kCompletenessOffset = 758;
constexpr size_t kDecisionPathOffset = 822;
constexpr size_t kExceptionOffset = 886;
constexpr size_t kFlagsOffset = 950;
constexpr size_t kPrivateBatchOffset = 954;
constexpr size_t kStatementBytes = 1018;

std::vector<uint8_t> Domain(const char* text) {
  const size_t length = std::strlen(text);
  std::vector<uint8_t> result(text, text + length);
  result.push_back(0);
  return result;
}

void Append(std::vector<uint8_t>& output, const std::vector<uint8_t>& value) {
  output.insert(output.end(), value.begin(), value.end());
}

void Append(std::vector<uint8_t>& output, const SourceDigest& value) {
  output.insert(output.end(), value.begin(), value.end());
}

void AppendU8(std::vector<uint8_t>& output, uint8_t value) {
  output.push_back(value);
}

void AppendU32(std::vector<uint8_t>& output, uint32_t value) {
  output.push_back(static_cast<uint8_t>(value >> 24));
  output.push_back(static_cast<uint8_t>(value >> 16));
  output.push_back(static_cast<uint8_t>(value >> 8));
  output.push_back(static_cast<uint8_t>(value));
}

void AppendU64(std::vector<uint8_t>& output, uint64_t value) {
  for (size_t index = 0; index < 8; ++index) {
    output.push_back(static_cast<uint8_t>(value >> (56 - 8 * index)));
  }
}

void AppendAccess(std::vector<uint8_t>& output, const struct Access& access);

SourceDigest HashBytes(const std::vector<uint8_t>& input) {
  proofs::Sha3Reference reference(64);
  reference.update(reinterpret_cast<const char*>(input.data()), input.size());
  SourceDigest output{};
  reference.final(output.data());
  return output;
}

SourceDigest HashParts(const std::vector<uint8_t>& domain,
                       const std::vector<std::vector<uint8_t>>& parts) {
  std::vector<uint8_t> input = domain;
  for (const auto& part : parts) Append(input, part);
  return HashBytes(input);
}

SourceDigest HashText(const char* domain, const char* text) {
  const size_t length = std::strlen(text);
  return HashParts(Domain(domain),
                   {std::vector<uint8_t>(text, text + length)});
}

SourceDigest Sentinel() {
  SourceDigest output{};
  output[0] = 0xe0;
  return output;
}

std::vector<uint8_t> ToVector(const SourceDigest& value) {
  return std::vector<uint8_t>(value.begin(), value.end());
}

std::string Hex(const SourceDigest& value) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string output;
  output.reserve(value.size() * 2);
  for (uint8_t byte : value) {
    output.push_back(kHex[byte >> 4]);
    output.push_back(kHex[byte & 0x0f]);
  }
  return output;
}

struct ParsedStatement {
  uint8_t protocol_version = 0;
  SourceDigest proof_suite{};
  std::array<uint8_t, sizeof(blind_ledger_longfellow::source_assertion::kProofRole) - 1>
      proof_role{};
  SourceDigest execution_context{};
  SourceDigest source_registry_snapshot{};
  SourceDigest source_profile{};
  SourceDigest governance_snapshot{};
  SourceDigest automatic_control_set{};
  SourceDigest settlement_domain{};
  SourceDigest subject_scope{};
  uint64_t epoch = 0;
  uint64_t sequence_before = 0;
  SourceDigest state_before_id{};
  SourceDigest request_id{};
  SourceDigest source_root_id{};
  SourceDigest completeness_id{};
  SourceDigest decision_path_id{};
  SourceDigest exception_id{};
  uint8_t active = 0;
  uint8_t complete = 0;
  uint8_t authoritative_membership = 0;
  uint8_t authoritative_absence = 0;
  SourceDigest private_batch_commitment{};
};

struct Cursor {
  const std::vector<uint8_t>& bytes;
  size_t offset = 0;

  bool Byte(uint8_t& output) {
    if (offset >= bytes.size()) return false;
    output = bytes[offset++];
    return true;
  }

  bool Digest(SourceDigest& output) {
    if (bytes.size() - offset < output.size()) return false;
    std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                output.size(), output.begin());
    offset += output.size();
    return true;
  }

  template <size_t N>
  bool Role(std::array<uint8_t, N>& output) {
    if (bytes.size() - offset < output.size()) return false;
    std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                output.size(), output.begin());
    offset += output.size();
    return true;
  }

  bool U64(uint64_t& output) {
    if (bytes.size() - offset < 8) return false;
    output = 0;
    for (size_t index = 0; index < 8; ++index) {
      output = (output << 8) | bytes[offset++];
    }
    return true;
  }
};

bool IsZero(const SourceDigest& value) {
  for (uint8_t byte : value) {
    if (byte != 0) return false;
  }
  return true;
}

bool IsBinary(uint8_t value) { return value == 0 || value == 1; }

bool ParseStatement(const std::vector<uint8_t>& bytes, ParsedStatement& output,
                    std::string& reason) {
  if (bytes.size() != kStatementBytes) {
    reason = "statement.length";
    return false;
  }
  Cursor cursor{bytes};
  if (!cursor.Byte(output.protocol_version) ||
      !cursor.Digest(output.proof_suite) ||
      !cursor.Role(output.proof_role) ||
      !cursor.Digest(output.execution_context) ||
      !cursor.Digest(output.source_registry_snapshot) ||
      !cursor.Digest(output.source_profile) ||
      !cursor.Digest(output.governance_snapshot) ||
      !cursor.Digest(output.automatic_control_set) ||
      !cursor.Digest(output.settlement_domain) ||
      !cursor.Digest(output.subject_scope) || !cursor.U64(output.epoch) ||
      !cursor.U64(output.sequence_before) ||
      !cursor.Digest(output.state_before_id) ||
      !cursor.Digest(output.request_id) ||
      !cursor.Digest(output.source_root_id) ||
      !cursor.Digest(output.completeness_id) ||
      !cursor.Digest(output.decision_path_id) ||
      !cursor.Digest(output.exception_id) || !cursor.Byte(output.active) ||
      !cursor.Byte(output.complete) || !cursor.Byte(output.authoritative_membership) ||
      !cursor.Byte(output.authoritative_absence) ||
      !cursor.Digest(output.private_batch_commitment) ||
      cursor.offset != bytes.size()) {
    reason = "statement.truncated-or-trailing";
    return false;
  }
  if (output.protocol_version != 3) {
    reason = "statement.protocol";
    return false;
  }
  for (size_t index = 0; index < output.proof_role.size(); ++index) {
    if (output.proof_role[index] !=
        static_cast<uint8_t>(blind_ledger_longfellow::source_assertion::kProofRole[index])) {
      reason = "statement.proof-role";
      return false;
    }
  }
  if (!IsZero(output.proof_suite)) {
    reason = "statement.proof-suite-not-null";
    return false;
  }
  if (!IsBinary(output.active) || !IsBinary(output.complete) ||
      !IsBinary(output.authoritative_membership) ||
      !IsBinary(output.authoritative_absence)) {
    reason = "statement.flag-not-binary";
    return false;
  }
  return true;
}

std::vector<uint8_t> SerializeStatement(const ParsedStatement& statement) {
  std::vector<uint8_t> output;
  AppendU8(output, statement.protocol_version);
  Append(output, statement.proof_suite);
  output.insert(output.end(), statement.proof_role.begin(),
                statement.proof_role.end());
  Append(output, statement.execution_context);
  Append(output, statement.source_registry_snapshot);
  Append(output, statement.source_profile);
  Append(output, statement.governance_snapshot);
  Append(output, statement.automatic_control_set);
  Append(output, statement.settlement_domain);
  Append(output, statement.subject_scope);
  AppendU64(output, statement.epoch);
  AppendU64(output, statement.sequence_before);
  Append(output, statement.state_before_id);
  Append(output, statement.request_id);
  Append(output, statement.source_root_id);
  Append(output, statement.completeness_id);
  Append(output, statement.decision_path_id);
  Append(output, statement.exception_id);
  AppendU8(output, statement.active);
  AppendU8(output, statement.complete);
  AppendU8(output, statement.authoritative_membership);
  AppendU8(output, statement.authoritative_absence);
  Append(output, statement.private_batch_commitment);
  return output;
}

SourceStatement ToSourceStatement(const ParsedStatement& statement) {
  SourceStatement output;
  output.protocol_version = statement.protocol_version;
  output.proof_suite = statement.proof_suite;
  output.proof_role = statement.proof_role;
  output.execution_context = statement.execution_context;
  output.source_registry_snapshot = statement.source_registry_snapshot;
  output.source_profile = statement.source_profile;
  output.governance_snapshot = statement.governance_snapshot;
  output.automatic_control_set = statement.automatic_control_set;
  output.settlement_domain = statement.settlement_domain;
  output.subject_scope = statement.subject_scope;
  output.epoch = statement.epoch;
  output.sequence_before = statement.sequence_before;
  output.state_before_id = statement.state_before_id;
  output.request_id = statement.request_id;
  output.source_root_id = statement.source_root_id;
  output.completeness_id = statement.completeness_id;
  output.decision_path_id = statement.decision_path_id;
  output.exception_id = statement.exception_id;
  output.active = statement.active;
  output.complete = statement.complete;
  output.authoritative_membership = statement.authoritative_membership;
  output.authoritative_absence = statement.authoritative_absence;
  output.private_batch_commitment = statement.private_batch_commitment;
  return output;
}

struct RegistryRecord {
  std::string label;
  SourceDigest execution_context{};
  SourceDigest source_registry_snapshot{};
  SourceDigest source_profile{};
  SourceDigest governance_snapshot{};
  SourceDigest automatic_control_set{};
  SourceDigest settlement_domain{};
  SourceDigest subject_scope{};
  SourceDigest state_before_id{};
  SourceDigest request_id{};
  SourceDigest source_root_id{};
  SourceDigest completeness_id{};
  SourceDigest decision_path_id{};
  SourceDigest exception_id{};
  SourceDigest private_batch_commitment{};
  SourceDigest attempt_id{};
  uint8_t active = 0;
  uint8_t complete = 0;
  uint8_t authoritative_membership = 0;
  uint8_t authoritative_absence = 0;
  uint8_t policy_result = 0;
  uint8_t effective_directive = 0;
  uint64_t epoch = 7;
  uint64_t sequence_before = 0;
  uint64_t event_time = 7000;
  uint64_t observation_time = 7001;
  uint64_t rule_effective_time = 6999;
  uint64_t decision_time = 7002;
};

struct Registry {
  std::vector<RegistryRecord> records;

  const RegistryRecord* Find(const SourceDigest& subject_scope) const {
    for (const auto& record : records) {
      if (record.subject_scope == subject_scope) return &record;
    }
    return nullptr;
  }
};

Registry BuildRegistry() {
  Registry registry;
  const SourceDigest provider =
      HashText("BL/NATIVE-V3/SYNTHETIC-PROVIDER/v1", "provider-1");
  const SourceDigest credential =
      HashText("BL/NATIVE-V3/SYNTHETIC-CREDENTIAL/v1", "credential-1");
  const SourceDigest enrollment =
      HashText("BL/NATIVE-V3/SYNTHETIC-ENROLLMENT/v1", "enrollment-1");
  const SourceDigest context = HashText(
      "BL/NATIVE-V3/SOURCE-ASSERTION/EXECUTION-CONTEXT/v1", "fixed-context");
  const SourceDigest source_registry = HashText(
      "BL/NATIVE-V3/SOURCE-ASSERTION/REGISTRY-SNAPSHOT/v1", "immutable-v1");
  const SourceDigest profile = HashText(
      "BL/NATIVE-V3/SOURCE-ASSERTION/PROFILE/v1", "source-assertion-only-v1");
  const SourceDigest governance = HashText(
      "BL/NATIVE-V3/SOURCE-ASSERTION/GOVERNANCE/v1", "governance-v1");
  const SourceDigest control = HashText(
      "BL/NATIVE-V3/SOURCE-ASSERTION/CONTROL-SET/v1",
      "five-directives-v1");
  const SourceDigest settlement_domain = HashText(
      "BL/NATIVE-V3/SOURCE-ASSERTION/SETTLEMENT-DOMAIN/v1",
      "official-state-rail");
  const SourceDigest state_before = HashText(
      "BL/NATIVE-V3/SOURCE-ASSERTION/STATE-BEFORE/v1", "initial");

  struct Spec {
    const char* label;
    uint8_t active;
    uint8_t complete;
    uint8_t membership;
    uint8_t absence;
    uint8_t policy;
    uint8_t directive;
    bool exception;
  };
  const Spec specs[] = {
      {"clear", 1, 1, 1, 0, 1, 1, false},
      {"hold", 0, 1, 0, 1, 2, 2, false},
      {"human-review", 0, 0, 0, 0, 3, 3, false},
      {"block", 0, 1, 1, 0, 4, 4, false},
      {"exception-approved", 0, 1, 1, 0, 4, 5, true},
  };

  for (const Spec& spec : specs) {
    RegistryRecord record;
    record.label = spec.label;
    record.execution_context = context;
    record.source_registry_snapshot = source_registry;
    record.source_profile = profile;
    record.governance_snapshot = governance;
    record.automatic_control_set = control;
    record.settlement_domain = settlement_domain;
    record.subject_scope = HashText(
        "BL/NATIVE-V3/SOURCE-ASSERTION/SUBJECT-SCOPE/v1", spec.label);
    record.state_before_id = state_before;
    record.attempt_id = HashText(
        "BL/NATIVE-V3/SOURCE-ASSERTION/ATTEMPT/v1", spec.label);
    record.active = spec.active;
    record.complete = spec.complete;
    record.authoritative_membership = spec.membership;
    record.authoritative_absence = spec.absence;
    record.policy_result = spec.policy;
    record.effective_directive = spec.directive;
    record.exception_id = spec.exception
                             ? HashText(
                                   "BL/NATIVE-V3/EXCEPTION-AUTHORIZATION-ID/v1",
                                   spec.label)
                             : Sentinel();
    const SourceDigest source_payload = HashParts(
        Domain("BL/NATIVE-V3/SOURCE-PAYLOAD/v1"),
        {ToVector(provider), ToVector(credential), ToVector(enrollment),
         std::vector<uint8_t>{spec.active, spec.complete, spec.membership,
                              spec.absence}});
    record.decision_path_id = HashText(
        "BL/NATIVE-V3/SOURCE-ASSERTION/DECISION-PATH/v1", spec.label);
    std::vector<uint8_t> source_root =
        Domain("BL/NATIVE-V3/SOURCE-ROOT/v1");
    Append(source_root, provider);
    Append(source_root, credential);
    Append(source_root, enrollment);
    AppendU8(source_root, spec.active);
    AppendU8(source_root, spec.complete);
    AppendU8(source_root, spec.membership);
    AppendU8(source_root, spec.absence);
    record.source_root_id = HashBytes(source_root);
    std::vector<uint8_t> completeness = Domain("BL/NATIVE-V3/COMPLETENESS/v1");
    Append(completeness, provider);
    Append(completeness, credential);
    AppendU8(completeness, spec.complete);
    AppendU8(completeness, spec.absence);
    record.completeness_id = HashBytes(completeness);
    std::vector<uint8_t> request = Domain("BL/NATIVE-V3/REQUEST-ID/v1");
    Append(request, provider);
    Append(request, credential);
    Append(request, enrollment);
    Append(request, record.attempt_id);
    AppendU64(request, record.epoch);
    AppendU64(request, record.sequence_before);
    AppendU64(request, record.event_time);
    AppendU64(request, record.observation_time);
    AppendU64(request, record.rule_effective_time);
    AppendU64(request, record.decision_time);
    Append(request, state_before);
    record.request_id = HashBytes(request);
    std::vector<uint8_t> private_batch =
        Domain("BL/NATIVE-V3/PRIVATE-BATCH/v1");
    Append(private_batch, source_payload);
    Append(private_batch, record.decision_path_id);
    Append(private_batch, record.exception_id);
    Append(private_batch, record.request_id);
    record.private_batch_commitment = HashBytes(private_batch);
    registry.records.push_back(std::move(record));
  }
  return registry;
}

bool SameDigest(const SourceDigest& left, const SourceDigest& right) {
  return left == right;
}

const RegistryRecord* ValidatePublicStatement(const ParsedStatement& statement,
                                              const Registry& registry,
                                              std::string& reason) {
  const RegistryRecord* record = registry.Find(statement.subject_scope);
  if (record == nullptr) {
    reason = "registry.subject_scope_unknown";
    return nullptr;
  }
  if (statement.source_registry_snapshot !=
      record->source_registry_snapshot) {
    reason = "registry.snapshot_mismatch";
    return nullptr;
  }
  if (statement.source_profile != record->source_profile) {
    reason = "registry.profile_mismatch";
    return nullptr;
  }
  if (statement.governance_snapshot != record->governance_snapshot) {
    reason = "registry.governance_mismatch";
    return nullptr;
  }
  if (statement.automatic_control_set != record->automatic_control_set) {
    reason = "registry.control_set_mismatch";
    return nullptr;
  }
  if (statement.execution_context != record->execution_context) {
    reason = "registry.execution_context_mismatch";
    return nullptr;
  }
  if (statement.settlement_domain != record->settlement_domain) {
    reason = "registry.settlement_domain_mismatch";
    return nullptr;
  }
  if (statement.epoch != record->epoch) {
    reason = "registry.epoch_mismatch";
    return nullptr;
  }
  if (statement.sequence_before != record->sequence_before) {
    reason = "registry.sequence_mismatch";
    return nullptr;
  }
  if (statement.complete == 0 && statement.authoritative_absence != 0) {
    reason = "incomplete_authoritative_absence";
    return nullptr;
  }
  if (statement.active != record->active ||
      statement.complete != record->complete ||
      statement.authoritative_membership != record->authoritative_membership ||
      statement.authoritative_absence != record->authoritative_absence) {
    reason = "registry.assertion_flag_mismatch";
    return nullptr;
  }
  if (statement.state_before_id != record->state_before_id) {
    reason = "registry.state_before_mismatch";
    return nullptr;
  }
  if (statement.source_root_id != record->source_root_id) {
    reason = "registry.source_root_mismatch";
    return nullptr;
  }
  if (statement.completeness_id != record->completeness_id) {
    reason = "registry.completeness_mismatch";
    return nullptr;
  }
  if (statement.request_id != record->request_id) {
    reason = "request.attempt_binding_mismatch";
    return nullptr;
  }
  if (statement.decision_path_id != record->decision_path_id) {
    reason = "registry.decision_path_mismatch";
    return nullptr;
  }
  if (statement.exception_id != record->exception_id) {
    reason = "exception.identity";
    return nullptr;
  }
  if (statement.private_batch_commitment !=
      record->private_batch_commitment) {
    reason = "registry.private_batch_mismatch";
    return nullptr;
  }
  return record;
}

bool EvaluateSourceRelation(
    const proofs::Circuit<SourceField>* circuit, const SourceCase& source_case,
    std::string& reason) {
  SourceField field;
  proofs::Dense<SourceField> witness(1, circuit->ninputs);
  blind_ledger_longfellow::source_assertion::fill_source_assertion_witness(
      source_case, witness);
  proofs::ProverLayers<SourceField> evaluator(field);
  proofs::ProverLayers<SourceField>::inputs inputs;
  auto output = evaluator.eval_circuit(&inputs, circuit, witness.clone(), field);
  if (output == nullptr) {
    reason = "circuit.evaluator-null";
    return false;
  }
  for (size_t index = 0; index < output->n1_; ++index) {
    if (output->v_[index] != field.zero()) {
      reason = "circuit.assertion-failed";
      return false;
    }
  }
  return true;
}

struct Access {
  uint32_t decision_index = 0;
  uint32_t access_index = 0;
  uint32_t access_count = 2;
  uint8_t mode = 0;
  uint64_t time = 0;
  SourceDigest decision_id{};
  SourceDigest address{};
  SourceDigest key{};
  SourceDigest value_before{};
  SourceDigest value_after{};
};

void AppendAccess(std::vector<uint8_t>& output, const Access& access) {
  AppendU32(output, access.decision_index);
  AppendU32(output, access.access_index);
  AppendU32(output, access.access_count);
  AppendU8(output, access.mode);
  AppendU64(output, access.time);
  Append(output, access.decision_id);
  Append(output, access.address);
  Append(output, access.key);
  Append(output, access.value_before);
  Append(output, access.value_after);
}

struct Artifact {
  ParsedStatement statement{};
  uint8_t policy_result = 0;
  uint8_t effective_directive = 0;
  SourceDigest exception_id{};
  uint64_t event_time = 0;
  uint64_t observation_time = 0;
  uint64_t rule_effective_time = 0;
  uint64_t decision_time = 0;
  uint32_t decision_index = 0;
  uint32_t decision_count = 1;
  SourceDigest before_audit_head{};
  SourceDigest after_audit_head{};
  SourceDigest before_clearance_root{};
  SourceDigest after_clearance_root{};
  SourceDigest decision_id{};
  SourceDigest state_after_id{};
  Access read{};
  Access write{};
  SourceDigest join_id{};
  SourceDigest receipt_id{};
  SourceDigest settlement_commitment{};
  bool economic_mutation = false;
  SourceDigest fingerprint{};
};

SourceDigest ComputeFingerprint(const Artifact& artifact);

struct StoreSnapshot {
  SourceDigest state_before_id{};
  SourceDigest audit_head{};
  SourceDigest clearance_root{};
  uint64_t epoch = 7;
  uint64_t sequence = 0;
  size_t committed_count = 0;
  uint64_t generation = 0;
};

SourceDigest HashAccessAddress(const char* role,
                               const SourceDigest& subject_scope) {
  return HashParts(Domain("BL/NATIVE-V3/SOURCE-ASSERTION/STATE-ADDRESS/v1"),
                   {std::vector<uint8_t>(role, role + std::strlen(role)),
                    ToVector(subject_scope)});
}

SourceDigest HashSubjectKey(const SourceDigest& subject_scope) {
  return HashParts(Domain("BL/NATIVE-V3/SOURCE-ASSERTION/SUBJECT-KEY/v1"),
                   {ToVector(subject_scope)});
}

Artifact BuildArtifact(const ParsedStatement& statement,
                       const RegistryRecord& record,
                       const StoreSnapshot& before) {
  Artifact artifact;
  artifact.statement = statement;
  artifact.policy_result = record.policy_result;
  artifact.effective_directive = record.effective_directive;
  artifact.exception_id = record.exception_id;
  artifact.event_time = record.event_time;
  artifact.observation_time = record.observation_time;
  artifact.rule_effective_time = record.rule_effective_time;
  artifact.decision_time = record.decision_time;
  artifact.before_audit_head = before.audit_head;
  artifact.before_clearance_root = before.clearance_root;
  artifact.economic_mutation =
      artifact.effective_directive == 1 || artifact.effective_directive == 5;

  std::vector<uint8_t> decision =
      Domain("BL/NATIVE-V3/SOURCE-ASSERTION/DECISION-ID/v1");
  Append(decision, statement.request_id);
  Append(decision, statement.state_before_id);
  Append(decision, statement.source_root_id);
  Append(decision, statement.completeness_id);
  AppendU8(decision, artifact.policy_result);
  AppendU8(decision, artifact.effective_directive);
  Append(decision, artifact.exception_id);
  artifact.decision_id = HashBytes(decision);

  artifact.read.decision_index = 0;
  artifact.read.access_index = 0;
  artifact.read.access_count = 2;
  artifact.read.mode = 1;
  artifact.read.time = artifact.observation_time;
  artifact.read.decision_id = artifact.decision_id;
  artifact.read.address = HashAccessAddress("source", statement.subject_scope);
  artifact.read.key = HashSubjectKey(statement.subject_scope);
  artifact.read.value_before = statement.source_root_id;
  artifact.read.value_after = statement.source_root_id;

  artifact.after_audit_head = HashParts(
      Domain("BL/NATIVE-V3/SOURCE-ASSERTION/AUDIT-HEAD/v1"),
      {ToVector(artifact.before_audit_head), ToVector(artifact.decision_id),
       std::vector<uint8_t>{artifact.effective_directive}});
  artifact.after_clearance_root = artifact.before_clearance_root;
  if (artifact.economic_mutation) {
    artifact.after_clearance_root = HashParts(
        Domain("BL/NATIVE-V3/SOURCE-ASSERTION/CLEARANCE-ROOT/v1"),
        {ToVector(artifact.before_clearance_root),
         ToVector(artifact.decision_id)});
  }
  const uint64_t sequence_after = before.sequence + 1;
  std::vector<uint8_t> after_state =
      Domain("BL/NATIVE-V3/SOURCE-ASSERTION/STATE-ID/v1");
  Append(after_state, statement.execution_context);
  AppendU64(after_state, before.epoch);
  AppendU64(after_state, sequence_after);
  Append(after_state, artifact.after_audit_head);
  Append(after_state, artifact.after_clearance_root);
  artifact.state_after_id = HashBytes(after_state);

  artifact.write.decision_index = 0;
  artifact.write.access_index = 1;
  artifact.write.access_count = 2;
  artifact.write.mode = 2;
  artifact.write.time = artifact.decision_time;
  artifact.write.decision_id = artifact.decision_id;
  artifact.write.address = HashAccessAddress("audit", statement.subject_scope);
  artifact.write.key = artifact.decision_id;
  artifact.write.value_before = artifact.before_audit_head;
  artifact.write.value_after = artifact.after_audit_head;

  std::vector<uint8_t> join =
      Domain("BL/NATIVE-V3/SOURCE-ASSERTION/DECISION-ACCESS-JOIN/v1");
  Append(join, artifact.decision_id);
  AppendU32(join, artifact.decision_index);
  AppendU32(join, artifact.decision_count);
  AppendAccess(join, artifact.read);
  AppendAccess(join, artifact.write);
  Append(join, statement.state_before_id);
  Append(join, artifact.state_after_id);
  artifact.join_id = HashBytes(join);

  std::vector<uint8_t> receipt =
      Domain("BL/NATIVE-V3/SOURCE-ASSERTION/RECEIPT-ID/v1");
  Append(receipt, statement.execution_context);
  Append(receipt, statement.automatic_control_set);
  Append(receipt, artifact.decision_id);
  Append(receipt, artifact.join_id);
  Append(receipt, statement.state_before_id);
  Append(receipt, artifact.state_after_id);
  AppendU8(receipt, artifact.policy_result);
  AppendU8(receipt, artifact.effective_directive);
  Append(receipt, artifact.exception_id);
  artifact.receipt_id = HashBytes(receipt);

  std::vector<uint8_t> settlement =
      Domain("BL/NATIVE-V3/SOURCE-ASSERTION/SETTLEMENT-COMMITMENT/v1");
  Append(settlement, statement.settlement_domain);
  AppendU8(settlement, artifact.effective_directive);
  Append(settlement, artifact.decision_id);
  Append(settlement, artifact.state_after_id);
  artifact.settlement_commitment = HashBytes(settlement);

  artifact.fingerprint = ComputeFingerprint(artifact);
  return artifact;
}

SourceDigest ComputeFingerprint(const Artifact& artifact) {
  std::vector<uint8_t> fingerprint =
      Domain("BL/NATIVE-V3/SOURCE-ASSERTION/ARTIFACT/v1");
  Append(fingerprint, SerializeStatement(artifact.statement));
  AppendU8(fingerprint, artifact.policy_result);
  AppendU8(fingerprint, artifact.effective_directive);
  Append(fingerprint, artifact.exception_id);
  AppendU64(fingerprint, artifact.event_time);
  AppendU64(fingerprint, artifact.observation_time);
  AppendU64(fingerprint, artifact.rule_effective_time);
  AppendU64(fingerprint, artifact.decision_time);
  AppendU32(fingerprint, artifact.decision_index);
  AppendU32(fingerprint, artifact.decision_count);
  Append(fingerprint, artifact.before_audit_head);
  Append(fingerprint, artifact.after_audit_head);
  Append(fingerprint, artifact.before_clearance_root);
  Append(fingerprint, artifact.after_clearance_root);
  Append(fingerprint, artifact.decision_id);
  Append(fingerprint, artifact.state_after_id);
  AppendAccess(fingerprint, artifact.read);
  AppendAccess(fingerprint, artifact.write);
  Append(fingerprint, artifact.join_id);
  Append(fingerprint, artifact.receipt_id);
  Append(fingerprint, artifact.settlement_commitment);
  AppendU8(fingerprint, artifact.economic_mutation ? 1 : 0);
  return HashBytes(fingerprint);
}

struct Outcome {
  bool accepted = false;
  std::string reason;
  SourceDigest receipt_id{};
};

bool SameBusinessState(const StoreSnapshot& left, const StoreSnapshot& right) {
  return left.state_before_id == right.state_before_id &&
         left.audit_head == right.audit_head &&
         left.clearance_root == right.clearance_root &&
         left.epoch == right.epoch && left.sequence == right.sequence &&
         left.committed_count == right.committed_count;
}

struct Committed {
  SourceDigest fingerprint{};
  SourceDigest receipt_id{};
};

class StateStore {
 public:
  explicit StateStore(const Registry& registry) : registry_(registry) {
    state_.state_before_id = registry.records.front().state_before_id;
    state_.audit_head =
        HashText("BL/NATIVE-V3/SOURCE-ASSERTION/AUDIT-HEAD/v1", "empty");
    state_.clearance_root = HashText(
        "BL/NATIVE-V3/SOURCE-ASSERTION/CLEARANCE-ROOT/v1", "empty");
  }

  StoreSnapshot Snapshot() const { return state_; }

  Outcome Apply(const Artifact& artifact, bool inject_post_verify) {
    const std::string request_key = Hex(artifact.statement.request_id);
    const SourceDigest artifact_fingerprint = ComputeFingerprint(artifact);
    const auto committed = committed_.find(request_key);
    if (committed != committed_.end()) {
      if (committed->second.fingerprint == artifact_fingerprint) {
        return Outcome{true, "retry.exact", committed->second.receipt_id};
      }
      return Outcome{false, "retry.conflict", {}};
    }

    const RegistryRecord* record = nullptr;
    std::string reason;
    if (!ValidateArtifact(artifact, record, reason)) {
      return Outcome{false, reason, {}};
    }
    const StoreSnapshot verified = state_;
    if (inject_post_verify) {
      ++state_.generation;
    }
    if (state_.generation != verified.generation) {
      return Outcome{false, "post_verify.state_changed", {}};
    }

    state_.state_before_id = artifact.state_after_id;
    state_.audit_head = artifact.after_audit_head;
    state_.clearance_root = artifact.after_clearance_root;
    ++state_.sequence;
    committed_[request_key] = Committed{artifact_fingerprint,
                                        artifact.receipt_id};
    return Outcome{true, "committed", artifact.receipt_id};
  }

 private:
  bool ValidateArtifact(const Artifact& artifact,
                        const RegistryRecord*& record,
                        std::string& reason) const {
    record = ValidatePublicStatement(artifact.statement, registry_, reason);
    if (record == nullptr) return false;
    if (artifact.statement.epoch != state_.epoch ||
        artifact.statement.sequence_before != state_.sequence) {
      reason = "state.epoch-or-sequence-stale";
      return false;
    }
    if (artifact.statement.state_before_id != state_.state_before_id) {
      reason = "state.before-stale";
      return false;
    }
    if (!(artifact.rule_effective_time < artifact.event_time &&
          artifact.event_time < artifact.observation_time &&
          artifact.observation_time < artifact.decision_time)) {
      reason = "chronology.strict";
      return false;
    }
    if (artifact.event_time != record->event_time ||
        artifact.observation_time != record->observation_time ||
        artifact.rule_effective_time != record->rule_effective_time ||
        artifact.decision_time != record->decision_time) {
      reason = "request.attempt-binding";
      return false;
    }
    if (artifact.policy_result != record->policy_result ||
        artifact.effective_directive != record->effective_directive) {
      reason = "policy.directive-relation";
      return false;
    }
    if (artifact.exception_id != record->exception_id) {
      reason = "exception.identity";
      return false;
    }
    if (artifact.decision_index != 0) {
      reason = "decision.index";
      return false;
    }
    if (artifact.decision_count != 1) {
      reason = "decision.count";
      return false;
    }
    Artifact expected = BuildArtifact(artifact.statement, *record, state_);
    if (artifact.decision_id != expected.decision_id) {
      reason = "decision.binding";
      return false;
    }
    if (artifact.read.access_count != 2 || artifact.write.access_count != 2) {
      reason = "join.access-count";
      return false;
    }
    if (artifact.read.access_index != 0) {
      reason = "join.read-index";
      return false;
    }
    if (artifact.write.access_index != 1) {
      reason = "join.write-index";
      return false;
    }
    if (artifact.read.decision_index != 0) {
      reason = "join.read-decision-index";
      return false;
    }
    if (artifact.write.decision_index != 0) {
      reason = "join.write-decision-index";
      return false;
    }
    if (artifact.read.mode != 1) {
      reason = "join.read-role";
      return false;
    }
    if (artifact.write.mode != 2) {
      reason = "join.write-role";
      return false;
    }
    if (artifact.read.decision_id != artifact.decision_id) {
      reason = "join.read-decision-id";
      return false;
    }
    if (artifact.write.decision_id != artifact.decision_id) {
      reason = "join.write-decision-id";
      return false;
    }
    if (artifact.read.time != artifact.observation_time) {
      reason = "join.read-time";
      return false;
    }
    if (artifact.write.time != artifact.decision_time) {
      reason = "join.write-time";
      return false;
    }
    if (artifact.read.address != expected.read.address) {
      reason = "join.read-address";
      return false;
    }
    if (artifact.read.key != expected.read.key) {
      reason = "join.read-key";
      return false;
    }
    if (artifact.read.value_before != artifact.statement.source_root_id ||
        artifact.read.value_after != artifact.statement.source_root_id) {
      reason = "join.read-source-value";
      return false;
    }
    if (artifact.write.address != expected.write.address) {
      reason = "join.write-address";
      return false;
    }
    if (artifact.write.key != artifact.decision_id) {
      reason = "join.write-key";
      return false;
    }
    if (artifact.write.value_before != artifact.before_audit_head) {
      reason = "join.write-before";
      return false;
    }
    if (artifact.write.value_after != artifact.after_audit_head) {
      reason = "join.write-after";
      return false;
    }
    if (artifact.before_audit_head != state_.audit_head) {
      reason = "state.audit-before";
      return false;
    }
    if (artifact.before_clearance_root != state_.clearance_root) {
      reason = "state.clearance-before";
      return false;
    }
    if (artifact.after_audit_head != expected.after_audit_head) {
      reason = "state.audit-after";
      return false;
    }
    if (artifact.after_clearance_root != expected.after_clearance_root) {
      reason = "state.clearance-after";
      return false;
    }
    if (artifact.state_after_id != expected.state_after_id) {
      reason = "state.after-binding";
      return false;
    }
    if (artifact.join_id != expected.join_id) {
      reason = "receipt.join-binding";
      return false;
    }
    if (artifact.receipt_id != expected.receipt_id) {
      reason = "receipt.binding";
      return false;
    }
    if (artifact.settlement_commitment != expected.settlement_commitment) {
      reason = "settlement.binding";
      return false;
    }
    if (artifact.economic_mutation != expected.economic_mutation) {
      reason = "directive.economic-separation";
      return false;
    }
    return true;
  }

  const Registry& registry_;
  StoreSnapshot state_{};
  std::map<std::string, Committed> committed_;
};

struct RawMutation {
  const char* name;
  std::vector<uint8_t> bytes;
  const char* expected_reason;
};

void Flip(std::vector<uint8_t>& bytes, size_t offset) {
  bytes[offset] ^= 0x01;
}

void Flip(SourceDigest& bytes, size_t offset) {
  bytes[offset] ^= 0x01;
}

void MutateSourceRoot(SourceStatement& value) { Flip(value.source_root_id, 0); }
void MutateCompleteness(SourceStatement& value) {
  Flip(value.completeness_id, 0);
}
void MutateRequest(SourceStatement& value) { Flip(value.request_id, 0); }
void MutateDecisionPath(SourceStatement& value) {
  Flip(value.decision_path_id, 0);
}
void MutateExceptionId(SourceStatement& value) { Flip(value.exception_id, 0); }
void MutatePrivateBatch(SourceStatement& value) {
  Flip(value.private_batch_commitment, 0);
}
void MutatePublicActive(SourceStatement& value) { value.active ^= 1; }
void MutatePublicEpoch(SourceStatement& value) { ++value.epoch; }
void MutatePublicSequence(SourceStatement& value) { ++value.sequence_before; }
void MutateProofSuite(SourceStatement& value) { value.proof_suite[0] ^= 1; }
void MutateProofRole(SourceStatement& value) { value.proof_role[0] ^= 1; }

std::vector<uint8_t> ReplaceDigest(std::vector<uint8_t> bytes, size_t offset,
                                   const SourceDigest& value) {
  std::copy(value.begin(), value.end(),
            bytes.begin() + static_cast<std::ptrdiff_t>(offset));
  return bytes;
}

struct ArtifactMutation {
  const char* name;
  const char* expected_reason;
  void (*mutate)(Artifact&);
};

void MutateChronology(Artifact& value) {
  value.event_time = value.rule_effective_time;
}
void MutatePolicy(Artifact& value) { value.policy_result = 2; }
void MutateDirective(Artifact& value) { value.effective_directive = 2; }
void MutateException(Artifact& value) { Flip(value.exception_id, 0); }
void MutateDecisionIndex(Artifact& value) { value.decision_index = 1; }
void MutateDecisionCount(Artifact& value) { value.decision_count = 2; }
void MutateAccessCount(Artifact& value) { value.read.access_count = 1; }
void MutateAccessRowSwap(Artifact& value) {
  Access temporary = value.read;
  value.read = value.write;
  value.write = temporary;
}
void MutateDuplicatedAccess(Artifact& value) { value.write = value.read; }
void MutateOmittedWrite(Artifact& value) { value.write.access_count = 1; }
void MutateReadIndex(Artifact& value) { value.read.access_index = 1; }
void MutateWriteIndex(Artifact& value) { value.write.access_index = 0; }
void MutateReadDecisionIndex(Artifact& value) {
  value.read.decision_index = 1;
}
void MutateWriteDecisionIndex(Artifact& value) {
  value.write.decision_index = 1;
}
void MutateReadRole(Artifact& value) { value.read.mode = 2; }
void MutateWriteRole(Artifact& value) { value.write.mode = 1; }
void MutateReadDecisionId(Artifact& value) { Flip(value.read.decision_id, 0); }
void MutateWriteDecisionId(Artifact& value) { Flip(value.write.decision_id, 0); }
void MutateReadAddress(Artifact& value) { Flip(value.read.address, 0); }
void MutateReadKey(Artifact& value) { Flip(value.read.key, 0); }
void MutateReadBefore(Artifact& value) { Flip(value.read.value_before, 0); }
void MutateReadAfter(Artifact& value) { Flip(value.read.value_after, 0); }
void MutateWriteAddress(Artifact& value) { Flip(value.write.address, 0); }
void MutateWriteKey(Artifact& value) { Flip(value.write.key, 0); }
void MutateWriteBefore(Artifact& value) { Flip(value.write.value_before, 0); }
void MutateWriteAfter(Artifact& value) { Flip(value.write.value_after, 0); }
void MutateClearanceBefore(Artifact& value) {
  Flip(value.before_clearance_root, 0);
}
void MutateStateAfter(Artifact& value) { Flip(value.state_after_id, 0); }
void MutateReceipt(Artifact& value) { Flip(value.receipt_id, 0); }
void MutateSettlement(Artifact& value) {
  Flip(value.settlement_commitment, 0);
}

}  // namespace

int main() {
  using namespace blind_ledger_longfellow::source_assertion;
  const auto fixture = make_source_assertion_fixture();
  const Registry registry = BuildRegistry();
  const auto circuit = build_source_assertion_circuit();
  size_t valid_cases = 0;

  std::array<ParsedStatement, 5> parsed_cases{};
  std::array<const RegistryRecord*, 5> records{};
  for (size_t index = 0; index < fixture.cases.size(); ++index) {
    std::string reason;
    if (!EvaluateSourceRelation(circuit.get(), fixture.cases[index], reason)) {
      std::printf("SOURCE_ASSERTION_VALID_FAIL label=%s reason=%s\n",
                  fixture.cases[index].label, reason.c_str());
      return 1;
    }
    const auto raw = source_assertion_statement_bytes(
        fixture.cases[index].statement);
    if (!ParseStatement(raw, parsed_cases[index], reason)) {
      std::printf("SOURCE_ASSERTION_PARSE_FAIL label=%s reason=%s\n",
                  fixture.cases[index].label, reason.c_str());
      return 2;
    }
    records[index] =
        ValidatePublicStatement(parsed_cases[index], registry, reason);
    if (records[index] == nullptr) {
      std::printf("SOURCE_ASSERTION_REGISTRY_FAIL label=%s reason=%s\n",
                  fixture.cases[index].label, reason.c_str());
      return 3;
    }
    if (records[index]->label != fixture.cases[index].label) {
      std::printf("SOURCE_ASSERTION_REGISTRY_FAIL label=%s reason=label-map\n",
                  fixture.cases[index].label);
      return 4;
    }
    std::printf(
        "SOURCE_ASSERTION_VALID_PASS label=%s directive=%u complete=%u "
        "membership=%u absence=%u\n",
        fixture.cases[index].label, records[index]->effective_directive,
        records[index]->complete, records[index]->authoritative_membership,
        records[index]->authoritative_absence);
    ++valid_cases;
  }

  struct CircuitMutation {
    const char* name;
    void (*mutate)(SourceStatement&);
  };
  const std::array<CircuitMutation, 11> circuit_mutations = {{
      {"source_root_target", MutateSourceRoot},
      {"completeness_target", MutateCompleteness},
      {"request_target", MutateRequest},
      {"decision_path_target", MutateDecisionPath},
      {"exception_target", MutateExceptionId},
      {"private_batch_target", MutatePrivateBatch},
      {"public_assertion_flag", MutatePublicActive},
      {"request_epoch", MutatePublicEpoch},
      {"request_sequence", MutatePublicSequence},
      {"proof_suite", MutateProofSuite},
      {"proof_role", MutateProofRole},
  }};
  size_t circuit_mutation_passes = 0;
  for (const CircuitMutation& mutation : circuit_mutations) {
    SourceCase mutated = fixture.cases[0];
    mutation.mutate(mutated.statement);
    std::string reason;
    if (EvaluateSourceRelation(circuit.get(), mutated, reason)) {
      std::printf("SOURCE_ASSERTION_CIRCUIT_MUTATION_FAIL name=%s reason=accepted\n",
                  mutation.name);
      return 13;
    }
    std::printf("SOURCE_ASSERTION_CIRCUIT_MUTATION_PASS name=%s reason=%s\n",
                mutation.name, reason.c_str());
    ++circuit_mutation_passes;
  }

  std::vector<RawMutation> raw_mutations;
  const auto clear_raw = source_assertion_statement_bytes(
      fixture.cases[0].statement);
  const auto hold_raw = source_assertion_statement_bytes(
      fixture.cases[1].statement);
  auto add_flip = [&](const char* name, size_t offset, const char* expected) {
    auto bytes = clear_raw;
    Flip(bytes, offset);
    raw_mutations.push_back({name, std::move(bytes), expected});
  };
  add_flip("wrong_subject", kSubjectScopeOffset, "registry.subject_scope_unknown");
  add_flip("wrong_source_root", kSourceRootOffset,
           "registry.source_root_mismatch");
  add_flip("wrong_completeness", kCompletenessOffset,
           "registry.completeness_mismatch");
  add_flip("wrong_registry_snapshot", kRegistryOffset,
           "registry.snapshot_mismatch");
  add_flip("wrong_governance_snapshot", kGovernanceOffset,
           "registry.governance_mismatch");
  add_flip("wrong_source_profile", kProfileOffset,
           "registry.profile_mismatch");
  add_flip("wrong_execution_context", kExecutionContextOffset,
           "registry.execution_context_mismatch");
  add_flip("wrong_settlement_domain", kSettlementDomainOffset,
           "registry.settlement_domain_mismatch");
  add_flip("wrong_request_attempt_binding", kRequestOffset,
           "request.attempt_binding_mismatch");
  add_flip("wrong_state_before", kStateBeforeOffset,
           "registry.state_before_mismatch");
  add_flip("wrong_epoch", kEpochOffset, "registry.epoch_mismatch");
  add_flip("wrong_sequence", kSequenceOffset,
           "registry.sequence_mismatch");
  add_flip("wrong_public_assertion_flag", kFlagsOffset,
           "registry.assertion_flag_mismatch");
  add_flip("wrong_decision_path", kDecisionPathOffset,
           "registry.decision_path_mismatch");
  add_flip("wrong_exception_identity", kExceptionOffset, "exception.identity");
  add_flip("wrong_private_batch", kPrivateBatchOffset,
           "registry.private_batch_mismatch");
  auto incomplete_absence = hold_raw;
  incomplete_absence[kFlagsOffset + 1] = 0;
  raw_mutations.push_back({"incomplete_feed_absence", std::move(incomplete_absence),
                           "incomplete_authoritative_absence"});
  auto role = clear_raw;
  role[kRoleOffset] ^= 0x01;
  raw_mutations.push_back({"wrong_role_casing", std::move(role),
                           "statement.proof-role"});
  auto suite = clear_raw;
  suite[1] ^= 0x01;
  raw_mutations.push_back({"non_null_proof_suite", std::move(suite),
                           "statement.proof-suite-not-null"});
  auto truncated = clear_raw;
  truncated.pop_back();
  raw_mutations.push_back({"truncated_statement", std::move(truncated),
                           "statement.length"});
  auto reordered = clear_raw;
  std::swap(reordered[kRequestOffset], reordered[kRequestOffset + 1]);
  raw_mutations.push_back({"reordered_request_bytes", std::move(reordered),
                           "request.attempt_binding_mismatch"});
  auto cross_request = ReplaceDigest(clear_raw, kSubjectScopeOffset,
                                     parsed_cases[1].subject_scope);
  raw_mutations.push_back({"cross_request_scope_reuse", std::move(cross_request),
                           "registry.assertion_flag_mismatch"});

  size_t raw_passes = 0;
  for (const RawMutation& mutation : raw_mutations) {
    ParsedStatement parsed;
    std::string reason;
    bool accepted = ParseStatement(mutation.bytes, parsed, reason);
    if (accepted) {
      accepted = ValidatePublicStatement(parsed, registry, reason) != nullptr;
    }
    if (accepted || reason != mutation.expected_reason) {
      std::printf(
          "SOURCE_ASSERTION_RAW_MUTATION_FAIL name=%s accepted=%s reason=%s "
          "expected=%s\n",
          mutation.name, accepted ? "true" : "false", reason.c_str(),
          mutation.expected_reason);
      return 5;
    }
    std::printf("SOURCE_ASSERTION_RAW_MUTATION_PASS name=%s reason=%s\n",
                mutation.name, reason.c_str());
    ++raw_passes;
  }

  size_t state_valid_cases = 0;
  for (size_t index = 0; index < parsed_cases.size(); ++index) {
    StateStore directive_store(registry);
    const StoreSnapshot before = directive_store.Snapshot();
    Artifact directive_artifact =
        BuildArtifact(parsed_cases[index], *records[index], before);
    const Outcome outcome = directive_store.Apply(directive_artifact, false);
    const StoreSnapshot after = directive_store.Snapshot();
    const bool should_advance_clearance =
        records[index]->effective_directive == 1 ||
        records[index]->effective_directive == 5;
    const bool did_advance_clearance =
        before.clearance_root != after.clearance_root;
    if (!outcome.accepted || outcome.reason != "committed" ||
        did_advance_clearance != should_advance_clearance ||
        after.audit_head == before.audit_head || after.sequence != 1) {
      std::printf(
          "SOURCE_ASSERTION_STATE_FAIL label=%s reason=%s "
          "clearance_advanced=%s expected=%s\n",
          records[index]->label.c_str(), outcome.reason.c_str(),
          did_advance_clearance ? "true" : "false",
          should_advance_clearance ? "true" : "false");
      return 14;
    }
    std::printf(
        "SOURCE_ASSERTION_STATE_PASS label=%s directive=%u "
        "economic_mutation=%s clearance_advanced=%s payment_movement=false\n",
        records[index]->label.c_str(), records[index]->effective_directive,
        directive_artifact.economic_mutation ? "true" : "false",
        did_advance_clearance ? "true" : "false");
    ++state_valid_cases;
  }

  StateStore state(registry);
  const StoreSnapshot initial = state.Snapshot();
  Artifact clear_artifact =
      BuildArtifact(parsed_cases[0], *records[0], initial);
  Outcome clear_outcome = state.Apply(clear_artifact, false);
  if (!clear_outcome.accepted || clear_outcome.reason != "committed") {
    std::printf("SOURCE_ASSERTION_STATE_FAIL name=clear reason=%s\n",
                clear_outcome.reason.c_str());
    return 6;
  }
  std::printf("SOURCE_ASSERTION_STATE_PASS name=clear economic_mutation=%s\n",
              clear_artifact.economic_mutation ? "true" : "false");

  const std::array<ArtifactMutation, 30> artifact_mutations = {{
      {"equal_or_out_of_order_chronology", "chronology.strict",
       MutateChronology},
      {"policy_result_conflation", "policy.directive-relation", MutatePolicy},
      {"effective_directive_conflation", "policy.directive-relation",
       MutateDirective},
      {"unauthorized_exception", "exception.identity", MutateException},
      {"wrong_decision_index", "decision.index", MutateDecisionIndex},
      {"wrong_decision_count", "decision.count", MutateDecisionCount},
      {"wrong_access_count", "join.access-count", MutateAccessCount},
      {"coherent_access_row_swap", "join.read-index", MutateAccessRowSwap},
      {"duplicated_access_row", "join.write-index", MutateDuplicatedAccess},
      {"omitted_write_row", "join.access-count", MutateOmittedWrite},
      {"wrong_read_index", "join.read-index", MutateReadIndex},
      {"wrong_write_index", "join.write-index", MutateWriteIndex},
      {"wrong_read_decision_index", "join.read-decision-index",
       MutateReadDecisionIndex},
      {"wrong_write_decision_index", "join.write-decision-index",
       MutateWriteDecisionIndex},
      {"read_write_role_swap", "join.read-role", MutateReadRole},
      {"read_read_role_confusion", "join.write-role", MutateWriteRole},
      {"wrong_read_decision_id", "join.read-decision-id", MutateReadDecisionId},
      {"wrong_write_decision_id", "join.write-decision-id",
       MutateWriteDecisionId},
      {"wrong_read_address", "join.read-address", MutateReadAddress},
      {"wrong_read_key", "join.read-key", MutateReadKey},
      {"wrong_read_before", "join.read-source-value", MutateReadBefore},
      {"wrong_read_after", "join.read-source-value", MutateReadAfter},
      {"wrong_write_address", "join.write-address", MutateWriteAddress},
      {"wrong_write_key", "join.write-key", MutateWriteKey},
      {"wrong_write_before", "join.write-before", MutateWriteBefore},
      {"wrong_write_after", "join.write-after", MutateWriteAfter},
      {"wrong_clearance_before_root", "state.clearance-before",
       MutateClearanceBefore},
      {"wrong_after_state", "state.after-binding", MutateStateAfter},
      {"forged_receipt", "receipt.binding", MutateReceipt},
      {"forged_settlement", "settlement.binding", MutateSettlement},
  }};

  size_t artifact_passes = 0;
  for (const ArtifactMutation& mutation : artifact_mutations) {
    StateStore isolated(registry);
    Artifact value =
        BuildArtifact(parsed_cases[0], *records[0], isolated.Snapshot());
    mutation.mutate(value);
    const StoreSnapshot before = isolated.Snapshot();
    const Outcome outcome = isolated.Apply(value, false);
    const StoreSnapshot after = isolated.Snapshot();
    if (outcome.accepted || outcome.reason != mutation.expected_reason ||
        !SameBusinessState(before, after)) {
      std::printf(
          "SOURCE_ASSERTION_ARTIFACT_MUTATION_FAIL name=%s accepted=%s "
          "reason=%s expected=%s unchanged=%s\n",
          mutation.name, outcome.accepted ? "true" : "false",
          outcome.reason.c_str(), mutation.expected_reason,
          SameBusinessState(before, after) ? "true" : "false");
      return 7;
    }
    std::printf(
        "SOURCE_ASSERTION_ARTIFACT_MUTATION_PASS name=%s reason=%s unchanged=true\n",
        mutation.name, outcome.reason.c_str());
    ++artifact_passes;
  }

  StateStore retry_store(registry);
  Artifact retry_artifact = BuildArtifact(
      parsed_cases[0], *records[0], retry_store.Snapshot());
  const Outcome first_retry = retry_store.Apply(retry_artifact, false);
  const StoreSnapshot committed_snapshot = retry_store.Snapshot();
  const Outcome exact_retry = retry_store.Apply(retry_artifact, false);
  if (!first_retry.accepted || exact_retry.reason != "retry.exact" ||
      exact_retry.receipt_id != retry_artifact.receipt_id ||
      !SameBusinessState(committed_snapshot, retry_store.Snapshot())) {
    std::printf("SOURCE_ASSERTION_RETRY_FAIL reason=%s\n",
                exact_retry.reason.c_str());
    return 8;
  }
  std::printf("SOURCE_ASSERTION_RETRY_PASS exact=true receipt=%s\n",
              Hex(exact_retry.receipt_id).c_str());

  Artifact conflicting_retry = retry_artifact;
  Flip(conflicting_retry.receipt_id, 0);
  const StoreSnapshot conflict_before = retry_store.Snapshot();
  const Outcome conflict = retry_store.Apply(conflicting_retry, false);
  if (conflict.accepted || conflict.reason != "retry.conflict" ||
      !SameBusinessState(conflict_before, retry_store.Snapshot())) {
    std::printf("SOURCE_ASSERTION_RETRY_FAIL conflicting=true reason=%s\n",
                conflict.reason.c_str());
    return 9;
  }
  std::printf("SOURCE_ASSERTION_RETRY_PASS conflicting=true unchanged=true\n");

  StateStore competing_store(registry);
  Artifact competing_first = BuildArtifact(
      parsed_cases[0], *records[0], competing_store.Snapshot());
  if (!competing_store.Apply(competing_first, false).accepted) {
    std::printf("SOURCE_ASSERTION_CONCURRENCY_FAIL reason=first\n");
    return 10;
  }
  Artifact competing_second = BuildArtifact(
      parsed_cases[1], *records[1], initial);
  const StoreSnapshot competing_before = competing_store.Snapshot();
  const Outcome competing = competing_store.Apply(competing_second, false);
  if (competing.accepted || competing.reason != "state.epoch-or-sequence-stale" ||
      !SameBusinessState(competing_before, competing_store.Snapshot())) {
    std::printf("SOURCE_ASSERTION_CONCURRENCY_FAIL reason=%s\n",
                competing.reason.c_str());
    return 11;
  }
  std::printf("SOURCE_ASSERTION_CONCURRENCY_PASS stale_competitor=true unchanged=true\n");

  StateStore post_verify_store(registry);
  Artifact post_verify = BuildArtifact(
      parsed_cases[0], *records[0], post_verify_store.Snapshot());
  const StoreSnapshot post_before = post_verify_store.Snapshot();
  const Outcome post_outcome = post_verify_store.Apply(post_verify, true);
  const StoreSnapshot post_after = post_verify_store.Snapshot();
  if (post_outcome.accepted || post_outcome.reason != "post_verify.state_changed" ||
      !SameBusinessState(post_before, post_after)) {
    std::printf("SOURCE_ASSERTION_POST_VERIFY_FAIL reason=%s unchanged=%s\n",
                post_outcome.reason.c_str(),
                SameBusinessState(post_before, post_after) ? "true" : "false");
    return 12;
  }
  std::printf("SOURCE_ASSERTION_POST_VERIFY_PASS rejected=true unchanged=true\n");

  std::printf(
      "SOURCE_ASSERTION_EVAL_PASS valid_cases=%zu raw_mutations=%zu "
      "circuit_mutations=%zu state_valid_cases=%zu artifact_mutations=%zu "
      "directives=5 membership=1 authoritative_absence=1 "
      "exact_retry=1 conflicting_retry=1 competing_transition=1 "
      "post_verify_mutation=1 prover=0\n",
      valid_cases, raw_passes, circuit_mutation_passes, state_valid_cases,
      artifact_passes);
  return 0;
}
