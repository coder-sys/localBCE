#include "native_v3_fixture.h"

#include <cstring>
#include <string>

#include "circuits/tests/sha3/sha3_reference.h"

namespace blind_ledger_longfellow {
namespace {

constexpr uint8_t kClear = 1;
constexpr uint8_t kHold = 2;
constexpr uint8_t kHumanReview = 3;
constexpr uint8_t kBlock = 4;
constexpr uint8_t kExceptionApproved = 5;
constexpr uint8_t kPolicyPass = 1;
constexpr uint8_t kPolicyMissing = 2;
constexpr uint8_t kPolicyAmbiguous = 3;
constexpr uint8_t kPolicyFail = 4;

std::vector<uint8_t> Domain(const char* text) {
  const size_t n = std::strlen(text);
  std::vector<uint8_t> result(text, text + n);
  result.push_back(0);
  return result;
}

void Append(std::vector<uint8_t>& out, const std::vector<uint8_t>& bytes) {
  out.insert(out.end(), bytes.begin(), bytes.end());
}

void Append(std::vector<uint8_t>& out, const Digest& digest) {
  out.insert(out.end(), digest.begin(), digest.end());
}

std::vector<uint8_t> ToVector(const Digest& digest) {
  return std::vector<uint8_t>(digest.begin(), digest.end());
}

void AppendU8(std::vector<uint8_t>& out, uint8_t value) { out.push_back(value); }

void AppendU32(std::vector<uint8_t>& out, uint32_t value) {
  out.push_back(static_cast<uint8_t>(value >> 24));
  out.push_back(static_cast<uint8_t>(value >> 16));
  out.push_back(static_cast<uint8_t>(value >> 8));
  out.push_back(static_cast<uint8_t>(value));
}

void AppendU64(std::vector<uint8_t>& out, uint64_t value) {
  for (size_t i = 0; i < 8; ++i) {
    out.push_back(static_cast<uint8_t>(value >> (56 - 8 * i)));
  }
}

Digest HashParts(const std::vector<uint8_t>& domain,
                 const std::vector<std::vector<uint8_t>>& parts) {
  std::vector<uint8_t> input = domain;
  for (const auto& part : parts) Append(input, part);
  return hash_sha3_512(input);
}

Digest HashText(const char* domain, const char* text) {
  const size_t n = std::strlen(text);
  return HashParts(Domain(domain),
                   {std::vector<uint8_t>(text, text + n)});
}

Digest Sentinel() {
  Digest result{};
  result[0] = 0xe0;
  return result;
}

}  // namespace

Digest hash_sha3_512(const std::vector<uint8_t>& input) {
  proofs::Sha3Reference reference(kDigestBytes);
  reference.update(reinterpret_cast<const char*>(input.data()), input.size());
  Digest result{};
  reference.final(result.data());
  return result;
}

std::vector<uint8_t> build_hash_input(const RelationCase& c, HashKind kind) {
  std::vector<uint8_t> result;
  switch (kind) {
    case HashKind::kSourceRoot:
      Append(result, Domain("BL/NATIVE-V3/SOURCE-ROOT/v1"));
      Append(result, c.provider_id);
      Append(result, c.credential_id);
      Append(result, c.enrollment_id);
      AppendU8(result, c.active_status);
      AppendU8(result, c.complete);
      AppendU8(result, c.authoritative_membership);
      AppendU8(result, c.authoritative_absence);
      break;
    case HashKind::kCompleteness:
      Append(result, Domain("BL/NATIVE-V3/COMPLETENESS/v1"));
      Append(result, c.provider_id);
      Append(result, c.credential_id);
      AppendU8(result, c.complete);
      AppendU8(result, c.authoritative_absence);
      break;
    case HashKind::kChronology:
      Append(result, Domain("BL/NATIVE-V3/CHRONOLOGY/v1"));
      AppendU64(result, c.rule_effective_time);
      AppendU64(result, c.event_time);
      AppendU64(result, c.observation_time);
      AppendU64(result, c.decision_time);
      break;
    case HashKind::kBeforeState:
      Append(result, Domain("BL/NATIVE-V3/STATE-ID/v1"));
      Append(result, c.statement.execution_context);
      Append(result, c.mode_id);
      AppendU64(result, 0);
      AppendU32(result, 0);
      Append(result, c.before_audit_head);
      Append(result, c.before_continuity_root);
      break;
    case HashKind::kRequest:
      Append(result, Domain("BL/NATIVE-V3/REQUEST-ID/v1"));
      Append(result, c.provider_id);
      Append(result, c.credential_id);
      Append(result, c.enrollment_id);
      Append(result, c.attempt_id);
      AppendU64(result, c.statement.epoch);
      AppendU64(result, c.statement.sequence_before);
      AppendU64(result, c.event_time);
      AppendU64(result, c.observation_time);
      AppendU64(result, c.rule_effective_time);
      AppendU64(result, c.decision_time);
      Append(result, c.statement.state_before_id);
      break;
    case HashKind::kReplay:
      Append(result, Domain("BL/NATIVE-V3/REPLAY/v1"));
      Append(result, c.request_id);
      Append(result, c.statement.state_before_id);
      Append(result, c.source_root);
      Append(result, c.statement.control_set);
      break;
    case HashKind::kDecision:
      Append(result, Domain("BL/NATIVE-V3/DECISION-ID/v1"));
      Append(result, c.request_id);
      Append(result, c.statement.state_before_id);
      Append(result, c.source_root);
      Append(result, c.completeness_id);
      AppendU8(result, c.policy_result);
      AppendU8(result, c.effective_directive);
      Append(result, c.exception_id);
      break;
    case HashKind::kDecisionPath:
      Append(result, Domain("BL/NATIVE-V3/DECISION-PATH/v1"));
      Append(result, c.statement.control_set);
      Append(result, c.rule_id);
      Append(result, c.source_root);
      Append(result, c.completeness_id);
      Append(result, c.reason_id);
      AppendU8(result, c.policy_result);
      AppendU8(result, c.effective_directive);
      Append(result, c.exception_id);
      break;
    case HashKind::kAfterAudit:
      Append(result, Domain("BL/NATIVE-V3/AUDIT-HEAD/v1"));
      Append(result, c.before_audit_head);
      Append(result, c.decision_id);
      AppendU8(result, c.effective_directive);
      break;
    case HashKind::kAfterRoot:
      Append(result, Domain("BL/NATIVE-V3/ROOT/v1"));
      Append(result, c.before_continuity_root);
      Append(result, c.source_root);
      Append(result, c.decision_id);
      break;
    case HashKind::kAfterState:
      Append(result, Domain("BL/NATIVE-V3/STATE-ID/v1"));
      Append(result, c.statement.execution_context);
      Append(result, c.mode_id);
      AppendU64(result, 1);
      AppendU32(result, 1);
      Append(result, c.after_audit_head);
      Append(result, c.after_continuity_root);
      break;
    case HashKind::kSourceAddress:
      Append(result, Domain("BL/NATIVE-V3/STATE-ADDRESS/v1"));
      Append(result, std::vector<uint8_t>{'s','o','u','r','c','e'});
      Append(result, c.provider_id);
      break;
    case HashKind::kSubjectKey:
      Append(result, Domain("BL/NATIVE-V3/SUBJECT-KEY/v1"));
      Append(result, c.provider_id);
      Append(result, c.credential_id);
      Append(result, c.enrollment_id);
      break;
    case HashKind::kAuditAddress:
      Append(result, Domain("BL/NATIVE-V3/STATE-ADDRESS/v1"));
      Append(result, std::vector<uint8_t>{'a','u','d','i','t'});
      Append(result, c.provider_id);
      break;
    case HashKind::kJoin:
      Append(result, Domain("BL/NATIVE-V3/DECISION-ACCESS-JOIN/v1"));
      Append(result, c.decision_id);
      Append(result, c.read_decision_id);
      Append(result, c.read_address);
      Append(result, c.read_key);
      Append(result, c.read_before);
      Append(result, c.read_after);
      Append(result, c.write_decision_id);
      Append(result, c.write_address);
      Append(result, c.write_key);
      Append(result, c.write_before);
      Append(result, c.write_after);
      Append(result, c.statement.state_before_id);
      Append(result, c.statement.state_after_id);
      break;
    case HashKind::kReceipt:
      Append(result, Domain("BL/NATIVE-V3/RECEIPT-ID/v1"));
      Append(result, c.phase0_receipt_binding);
      Append(result, c.statement.control_set);
      Append(result, c.decision_id);
      Append(result, c.join_id);
      Append(result, c.statement.state_before_id);
      Append(result, c.statement.state_after_id);
      break;
    case HashKind::kPrivateBatch:
      Append(result, Domain("BL/NATIVE-V3/PRIVATE-BATCH/v1"));
      Append(result, c.source_payload);
      Append(result, c.decision_path_id);
      Append(result, c.exception_id);
      Append(result, c.request_id);
      break;
    case HashKind::kSettlement:
      Append(result, Domain("BL/NATIVE-V3/SETTLEMENT/v1"));
      AppendU8(result, c.effective_directive);
      Append(result, c.decision_id);
      Append(result, c.statement.state_after_id);
      break;
  }
  return result;
}

NativeV3Fixture make_native_v3_fixture() {
  NativeV3Fixture fixture;
  const Digest provider = HashText("BL/NATIVE-V3/SYNTHETIC-PROVIDER/v1", "provider-1");
  const Digest credential = HashText("BL/NATIVE-V3/SYNTHETIC-CREDENTIAL/v1", "credential-1");
  const Digest enrollment = HashText("BL/NATIVE-V3/SYNTHETIC-ENROLLMENT/v1", "enrollment-1");
  const Digest mode = HashText("BL/NATIVE-V3/EVIDENCE-MODE/v1", "DIRECT_STATE_OWNED");
  const Digest rule = HashText("BL/NATIVE-V3/RULE/v1", "synthetic-rule-v1");
  const Digest phase0 = HashText("BL/NATIVE-V3/PHASE0-RECEIPT/v1", "frozen-receipt");
  const Digest context = HashText("BL/NATIVE-V3/EXECUTION-CONTEXT/v1", "fixed-native-v3-context");
  const Digest settlement_domain = HashText("BL/NATIVE-V3/SETTLEMENT-DOMAIN/v1", "official-state-rail");
  const Digest governance = HashText("BL/NATIVE-V3/GOVERNANCE/v1", "synthetic-governance-snapshot");
  const Digest control = HashText("BL/NATIVE-V3/CONTROL-SET/v1", "CLEAR,HOLD,HUMAN_REVIEW,BLOCK,EXCEPTION_APPROVED");
  const Digest empty_audit = HashText("BL/NATIVE-V3/AUDIT-HEAD/v1", "empty");
  const Digest empty_root = HashText("BL/NATIVE-V3/ROOT/v1", "empty");

  struct Spec { uint8_t policy, directive, complete, member, absent, active, exception; const char* label; };
  const Spec specs[] = {
      {kPolicyPass, kClear, 1, 1, 0, 1, 0, "clear"},
      {kPolicyMissing, kHold, 1, 0, 1, 0, 0, "hold"},
      {kPolicyAmbiguous, kHumanReview, 0, 0, 0, 0, 0, "human-review"},
      {kPolicyFail, kBlock, 1, 1, 0, 0, 0, "block"},
      {kPolicyFail, kExceptionApproved, 1, 1, 0, 0, 1, "exception-approved"},
  };

  for (size_t i = 0; i < 5; ++i) {
    RelationCase& c = fixture.cases[i];
    const Spec& spec = specs[i];
    c.provider_id = provider;
    c.credential_id = credential;
    c.enrollment_id = enrollment;
    c.mode_id = mode;
    c.rule_id = rule;
    c.phase0_receipt_binding = phase0;
    c.policy_result = spec.policy;
    c.effective_directive = spec.directive;
    c.complete = spec.complete;
    c.authoritative_membership = spec.member;
    c.authoritative_absence = spec.absent;
    c.active_status = spec.active;
    c.exception_present = spec.exception;
    c.proof_session_accepted = 0;
    c.economic_mutation = 0;
    c.event_time = 7000;
    c.observation_time = 7001;
    c.rule_effective_time = 6999;
    c.decision_time = 7002;
    c.read_time = c.observation_time;
    c.write_time = c.decision_time;
    c.attempt_id = HashText("BL/NATIVE-V3/ATTEMPT/v1", spec.label);
    c.source_payload = HashParts(Domain("BL/NATIVE-V3/SOURCE-PAYLOAD/v1"),
                                 {ToVector(provider), ToVector(credential),
                                  ToVector(enrollment),
                                  std::vector<uint8_t>{
                                      spec.active, spec.complete, spec.member,
                                      spec.absent}});
    c.completeness_payload = HashParts(Domain("BL/NATIVE-V3/COMPLETENESS-PAYLOAD/v1"),
                                       {ToVector(provider), ToVector(credential),
                                        std::vector<uint8_t>{spec.complete,
                                                              spec.absent}});
    c.before_audit_head = empty_audit;
    c.before_continuity_root = empty_root;
    c.statement.execution_context = context;
    c.statement.settlement_domain = settlement_domain;
    c.statement.governance_snapshot = governance;
    c.statement.control_set = control;
    c.statement.epoch = 7;
    c.statement.sequence_before = 0;
    c.statement.proof_suite.fill(0);
    c.source_root = hash_sha3_512(build_hash_input(c, HashKind::kSourceRoot));
    c.completeness_id = hash_sha3_512(build_hash_input(c, HashKind::kCompleteness));
    c.chronology_id = hash_sha3_512(build_hash_input(c, HashKind::kChronology));
    c.statement.state_before_id = hash_sha3_512(build_hash_input(c, HashKind::kBeforeState));
    c.request_id = hash_sha3_512(build_hash_input(c, HashKind::kRequest));
    c.exception_id = spec.exception ? HashText("BL/NATIVE-V3/EXCEPTION-AUTHORIZATION-ID/v1", spec.label) : Sentinel();
    c.reason_id = HashText("BL/NATIVE-V3/REASON/v1", spec.label);
    c.decision_path_id = hash_sha3_512(build_hash_input(c, HashKind::kDecisionPath));
    c.decision_id = hash_sha3_512(build_hash_input(c, HashKind::kDecision));
    c.replay_id = hash_sha3_512(build_hash_input(c, HashKind::kReplay));
    c.after_audit_head = hash_sha3_512(build_hash_input(c, HashKind::kAfterAudit));
    c.after_continuity_root = hash_sha3_512(build_hash_input(c, HashKind::kAfterRoot));
    c.statement.state_after_id = hash_sha3_512(build_hash_input(c, HashKind::kAfterState));
    c.read_decision_id = c.decision_id;
    c.write_decision_id = c.decision_id;
    c.read_address = hash_sha3_512(build_hash_input(c, HashKind::kSourceAddress));
    c.read_key = hash_sha3_512(build_hash_input(c, HashKind::kSubjectKey));
    c.read_before = c.source_root;
    c.read_after = c.source_root;
    c.write_address = hash_sha3_512(build_hash_input(c, HashKind::kAuditAddress));
    c.write_key = c.decision_id;
    c.write_before = c.before_audit_head;
    c.write_after = c.after_audit_head;
    c.join_id = hash_sha3_512(build_hash_input(c, HashKind::kJoin));
    c.receipt_id = hash_sha3_512(build_hash_input(c, HashKind::kReceipt));
    c.statement.private_batch_commitment = hash_sha3_512(build_hash_input(c, HashKind::kPrivateBatch));
    c.statement.settlement_commitment = hash_sha3_512(build_hash_input(c, HashKind::kSettlement));
  }
  return fixture;
}

}  // namespace blind_ledger_longfellow
