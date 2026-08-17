#include "native_v3_minimal_linked_relation.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <string>
#include <vector>

#include "circuits/compiler/compiler.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/tests/sha3/sha3_circuit.h"
#include "circuits/tests/sha3/sha3_reference.h"
#include "util/panic.h"

namespace blind_ledger_longfellow::minimal_linked {
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
  const size_t length = std::strlen(text);
  std::vector<uint8_t> output(text, text + length);
  output.push_back(0);
  return output;
}

void Append(std::vector<uint8_t>& output, const std::vector<uint8_t>& value) {
  output.insert(output.end(), value.begin(), value.end());
}

void Append(std::vector<uint8_t>& output, const Digest& value) {
  output.insert(output.end(), value.begin(), value.end());
}

void AppendU8(std::vector<uint8_t>& output, uint8_t value) {
  output.push_back(value);
}

void AppendU32(std::vector<uint8_t>& output, uint32_t value) {
  for (size_t index = 0; index < 4; ++index) {
    output.push_back(static_cast<uint8_t>(value >> (24 - index * 8)));
  }
}

void AppendU64(std::vector<uint8_t>& output, uint64_t value) {
  for (size_t index = 0; index < 8; ++index) {
    output.push_back(static_cast<uint8_t>(value >> (56 - index * 8)));
  }
}

Digest HashBytes(const std::vector<uint8_t>& input) {
  return hash_sha3_512(input);
}

Digest HashParts(const std::vector<uint8_t>& domain,
                const std::vector<std::vector<uint8_t>>& parts) {
  std::vector<uint8_t> input = domain;
  for (const auto& part : parts) Append(input, part);
  return HashBytes(input);
}

std::vector<uint8_t> ToVector(const Digest& value) {
  return std::vector<uint8_t>(value.begin(), value.end());
}

Digest HashText(const char* domain, const char* text) {
  const size_t length = std::strlen(text);
  return HashParts(Domain(domain),
                   {std::vector<uint8_t>(text, text + length)});
}

Digest Sentinel() {
  Digest output{};
  output[0] = 0xe0;
  return output;
}

void FillRole(ProofRole& role) {
  for (size_t index = 0; index < role.size(); ++index) {
    role[index] = static_cast<uint8_t>(kProofRole[index]);
  }
}

Digest ScopeId(const Case& value) {
  if (value.exception_present == 0) return Sentinel();
  std::vector<uint8_t> interval;
  AppendU64(interval, value.exception_valid_from);
  AppendU64(interval, value.exception_valid_until);
  return HashParts(Domain("BL/NATIVE-V3/EXCEPTION-SCOPE/v1"),
                   {ToVector(value.statement.exception_id),
                    ToVector(value.statement.subject_id),
                    ToVector(value.statement.rule_id),
                    interval});
}

std::vector<uint8_t> SourceRootInput(const Case& value) {
  std::vector<uint8_t> output = Domain("BL/NATIVE-V3/SOURCE-ROOT/v1");
  Append(output, value.provider_id);
  Append(output, value.credential_id);
  Append(output, value.enrollment_id);
  AppendU8(output, value.statement.active);
  AppendU8(output, value.statement.complete);
  AppendU8(output, value.statement.authoritative_membership);
  AppendU8(output, value.statement.authoritative_absence);
  return output;
}

std::vector<uint8_t> CompletenessInput(const Case& value) {
  std::vector<uint8_t> output = Domain("BL/NATIVE-V3/COMPLETENESS/v1");
  Append(output, value.provider_id);
  Append(output, value.credential_id);
  AppendU8(output, value.statement.complete);
  AppendU8(output, value.statement.authoritative_absence);
  return output;
}

std::vector<uint8_t> RequestInput(const Case& value) {
  std::vector<uint8_t> output = Domain("BL/NATIVE-V3/REQUEST-ID/v2");
  Append(output, value.statement.subject_id);
  Append(output, value.statement.attempt_id);
  AppendU64(output, value.statement.epoch);
  AppendU64(output, value.statement.sequence_before);
  Append(output, value.statement.state_before_id);
  return output;
}

Digest BeforeStateId(const Case& value) {
  std::vector<uint8_t> epoch_sequence;
  AppendU64(epoch_sequence, value.statement.epoch);
  AppendU64(epoch_sequence, value.statement.sequence_before);
  return HashParts(
      Domain("BL/NATIVE-V3/MINIMAL-BEFORE-STATE/v1"),
      {ToVector(value.statement.execution_context), epoch_sequence,
       ToVector(value.before_audit_head),
       ToVector(value.before_continuity_root)});
}

Digest RequestId(const Case& value) {
  return HashBytes(RequestInput(value));
}

Digest DecisionId(const Case& value) {
  return HashParts(Domain("BL/NATIVE-V3/MINIMAL-DECISION/v1"),
                   {ToVector(value.statement.request_id),
                    ToVector(value.statement.source_root_id),
                    ToVector(value.statement.completeness_id),
                    std::vector<uint8_t>{value.policy_result,
                                         value.effective_directive},
                    ToVector(value.statement.exception_id)});
}

Digest AfterAudit(const Case& value) {
  return HashParts(Domain("BL/NATIVE-V3/MINIMAL-AUDIT-HEAD/v1"),
                   {ToVector(value.before_audit_head),
                    ToVector(value.statement.decision_id),
                    std::vector<uint8_t>{value.effective_directive}});
}

Digest AfterRoot(const Case& value) {
  return HashParts(Domain("BL/NATIVE-V3/MINIMAL-CONTINUITY-ROOT/v1"),
                   {ToVector(value.before_continuity_root),
                    ToVector(value.statement.source_root_id),
                    ToVector(value.statement.decision_id)});
}

void AppendStateDigests(std::vector<uint8_t>& output, const Case& value) {
  const Digest* digests[] = {
      &value.statement.source_root_id,
      &value.statement.completeness_id,
      &value.statement.subject_id,
      &value.statement.attempt_id,
      &value.statement.request_id,
      &value.statement.exception_id,
      &value.statement.exception_scope_id,
      &value.statement.rule_id,
      &value.statement.decision_id,
      &value.before_audit_head,
      &value.after_audit_head,
      &value.before_continuity_root,
      &value.after_continuity_root,
      &value.read_decision_id,
      &value.read_address,
      &value.read_key,
      &value.read_before,
      &value.read_after,
      &value.write_decision_id,
      &value.write_address,
      &value.write_key,
      &value.write_before,
      &value.write_after,
  };
  for (const Digest* digest : digests) Append(output, *digest);
}

template <class Logic>
using V8 = typename Logic::template bitvec<8>;
template <class Logic>
using V32 = typename Logic::template bitvec<32>;
template <class Logic>
using V64 = typename Logic::template bitvec<64>;
template <class Logic>
using Byte64 = std::array<V8<Logic>, kDigestBytes>;
template <class Logic>
using Role = std::array<V8<Logic>, kProofRoleBytes>;

template <class Logic>
struct PublicWires {
  V8<Logic> protocol;
  Role<Logic> proof_role;
  Byte64<Logic> proof_suite;
  Byte64<Logic> execution_context;
  Byte64<Logic> source_registry_snapshot;
  Byte64<Logic> source_profile;
  Byte64<Logic> governance_snapshot;
  Byte64<Logic> automatic_control_set;
  Byte64<Logic> settlement_domain;
  Byte64<Logic> evaluator_id;
  Byte64<Logic> schema_id;
  Byte64<Logic> program_id;
  Byte64<Logic> policy_id;
  Byte64<Logic> subject_id;
  Byte64<Logic> attempt_id;
  Byte64<Logic> request_id;
  Byte64<Logic> source_root_id;
  Byte64<Logic> completeness_id;
  Byte64<Logic> private_batch_commitment;
  Byte64<Logic> source_address;
  Byte64<Logic> source_key;
  Byte64<Logic> audit_address;
  Byte64<Logic> exception_id;
  Byte64<Logic> exception_scope_id;
  Byte64<Logic> rule_id;
  Byte64<Logic> decision_id;
  Byte64<Logic> state_before_id;
  Byte64<Logic> state_after_id;
  V64<Logic> epoch;
  V64<Logic> sequence_before;
  V8<Logic> active;
  V8<Logic> complete;
  V8<Logic> membership;
  V8<Logic> absence;
  std::array<V8<Logic>, kStateCommitmentBytes> state_commitment;
};

template <class Logic>
struct PrivateWires {
  Byte64<Logic> provider;
  Byte64<Logic> credential;
  Byte64<Logic> enrollment;
  Byte64<Logic> source_payload;
  V8<Logic> active;
  V8<Logic> complete;
  V8<Logic> membership;
  V8<Logic> absence;
  V8<Logic> policy;
  V8<Logic> directive;
  V8<Logic> exception_present;
  V8<Logic> exception_authorized;
  V8<Logic> economic_mutation;
  V64<Logic> rule_effective;
  V64<Logic> event;
  V64<Logic> observation;
  V64<Logic> decision;
  V64<Logic> read_time;
  V64<Logic> write_time;
  V64<Logic> exception_valid_from;
  V64<Logic> exception_valid_until;
  V64<Logic> sequence_after;
  V32<Logic> decision_index;
  V32<Logic> decision_count;
  V32<Logic> read_access_index;
  V32<Logic> write_access_index;
  V32<Logic> access_count;
  V32<Logic> read_decision_index;
  V32<Logic> write_decision_index;
  V8<Logic> read_mode;
  V8<Logic> write_mode;
  V8<Logic> clearance_marker_before;
  V8<Logic> clearance_marker_after;
  V64<Logic> clearance_count_before;
  V64<Logic> clearance_count_after;
  Byte64<Logic> before_audit;
  Byte64<Logic> after_audit;
  Byte64<Logic> before_root;
  Byte64<Logic> after_root;
  Byte64<Logic> read_decision_id;
  Byte64<Logic> read_address;
  Byte64<Logic> read_key;
  Byte64<Logic> read_before;
  Byte64<Logic> read_after;
  Byte64<Logic> write_decision_id;
  Byte64<Logic> write_address;
  Byte64<Logic> write_key;
  Byte64<Logic> write_before;
  Byte64<Logic> write_after;
};

template <class Logic>
void PushDigest(proofs::DenseFiller<RelationField>& filler, const Digest& value,
                const RelationField& field) {
  for (uint8_t byte : value) filler.push_back(byte, 8, field);
}

template <class Logic>
void PushPublic(proofs::DenseFiller<RelationField>& filler, const Case& value,
                const RelationField& field) {
  filler.push_back(field.one());
  filler.push_back(value.statement.protocol_version, 8, field);
  for (uint8_t byte : value.statement.proof_role) filler.push_back(byte, 8, field);
  PushDigest<Logic>(filler, value.statement.proof_suite, field);
  PushDigest<Logic>(filler, value.statement.execution_context, field);
  PushDigest<Logic>(filler, value.statement.source_registry_snapshot, field);
  PushDigest<Logic>(filler, value.statement.source_profile, field);
  PushDigest<Logic>(filler, value.statement.governance_snapshot, field);
  PushDigest<Logic>(filler, value.statement.automatic_control_set, field);
  PushDigest<Logic>(filler, value.statement.settlement_domain, field);
  PushDigest<Logic>(filler, value.statement.evaluator_id, field);
  PushDigest<Logic>(filler, value.statement.schema_id, field);
  PushDigest<Logic>(filler, value.statement.program_id, field);
  PushDigest<Logic>(filler, value.statement.policy_id, field);
  PushDigest<Logic>(filler, value.statement.subject_id, field);
  PushDigest<Logic>(filler, value.statement.attempt_id, field);
  PushDigest<Logic>(filler, value.statement.request_id, field);
  PushDigest<Logic>(filler, value.statement.source_root_id, field);
  PushDigest<Logic>(filler, value.statement.completeness_id, field);
  PushDigest<Logic>(filler, value.statement.private_batch_commitment, field);
  PushDigest<Logic>(filler, value.statement.source_address, field);
  PushDigest<Logic>(filler, value.statement.source_key, field);
  PushDigest<Logic>(filler, value.statement.audit_address, field);
  PushDigest<Logic>(filler, value.statement.exception_id, field);
  PushDigest<Logic>(filler, value.statement.exception_scope_id, field);
  PushDigest<Logic>(filler, value.statement.rule_id, field);
  PushDigest<Logic>(filler, value.statement.decision_id, field);
  PushDigest<Logic>(filler, value.statement.state_before_id, field);
  PushDigest<Logic>(filler, value.statement.state_after_id, field);
  filler.push_back(value.statement.epoch, 64, field);
  filler.push_back(value.statement.sequence_before, 64, field);
  filler.push_back(value.statement.active, 8, field);
  filler.push_back(value.statement.complete, 8, field);
  filler.push_back(value.statement.authoritative_membership, 8, field);
  filler.push_back(value.statement.authoritative_absence, 8, field);
  for (uint8_t byte : value.statement.state_commitment_bytes) {
    filler.push_back(byte, 8, field);
  }
}

template <class Logic>
void InputPublic(const Logic& logic, PublicWires<Logic>& value) {
  auto input_digest = [&]() {
    Byte64<Logic> result;
    for (auto& byte : result) byte = logic.template vinput<8>();
    return result;
  };
  value.protocol = logic.template vinput<8>();
  for (auto& byte : value.proof_role) byte = logic.template vinput<8>();
  value.proof_suite = input_digest();
  value.execution_context = input_digest();
  value.source_registry_snapshot = input_digest();
  value.source_profile = input_digest();
  value.governance_snapshot = input_digest();
  value.automatic_control_set = input_digest();
  value.settlement_domain = input_digest();
  value.evaluator_id = input_digest();
  value.schema_id = input_digest();
  value.program_id = input_digest();
  value.policy_id = input_digest();
  value.subject_id = input_digest();
  value.attempt_id = input_digest();
  value.request_id = input_digest();
  value.source_root_id = input_digest();
  value.completeness_id = input_digest();
  value.private_batch_commitment = input_digest();
  value.source_address = input_digest();
  value.source_key = input_digest();
  value.audit_address = input_digest();
  value.exception_id = input_digest();
  value.exception_scope_id = input_digest();
  value.rule_id = input_digest();
  value.decision_id = input_digest();
  value.state_before_id = input_digest();
  value.state_after_id = input_digest();
  value.epoch = logic.template vinput<64>();
  value.sequence_before = logic.template vinput<64>();
  value.active = logic.template vinput<8>();
  value.complete = logic.template vinput<8>();
  value.membership = logic.template vinput<8>();
  value.absence = logic.template vinput<8>();
  for (auto& byte : value.state_commitment) byte = logic.template vinput<8>();
}

template <class Logic>
void InputDigest(const Logic& logic, Byte64<Logic>& output) {
  for (auto& byte : output) byte = logic.template vinput<8>();
}

template <class Logic>
void InputPrivate(const Logic& logic, PrivateWires<Logic>& value) {
  InputDigest(logic, value.provider);
  InputDigest(logic, value.credential);
  InputDigest(logic, value.enrollment);
  InputDigest(logic, value.source_payload);
  value.active = logic.template vinput<8>();
  value.complete = logic.template vinput<8>();
  value.membership = logic.template vinput<8>();
  value.absence = logic.template vinput<8>();
  value.policy = logic.template vinput<8>();
  value.directive = logic.template vinput<8>();
  value.exception_present = logic.template vinput<8>();
  value.exception_authorized = logic.template vinput<8>();
  value.economic_mutation = logic.template vinput<8>();
  value.rule_effective = logic.template vinput<64>();
  value.event = logic.template vinput<64>();
  value.observation = logic.template vinput<64>();
  value.decision = logic.template vinput<64>();
  value.read_time = logic.template vinput<64>();
  value.write_time = logic.template vinput<64>();
  value.exception_valid_from = logic.template vinput<64>();
  value.exception_valid_until = logic.template vinput<64>();
  value.sequence_after = logic.template vinput<64>();
  value.decision_index = logic.template vinput<32>();
  value.decision_count = logic.template vinput<32>();
  value.read_access_index = logic.template vinput<32>();
  value.write_access_index = logic.template vinput<32>();
  value.access_count = logic.template vinput<32>();
  value.read_decision_index = logic.template vinput<32>();
  value.write_decision_index = logic.template vinput<32>();
  value.read_mode = logic.template vinput<8>();
  value.write_mode = logic.template vinput<8>();
  value.clearance_marker_before = logic.template vinput<8>();
  value.clearance_marker_after = logic.template vinput<8>();
  value.clearance_count_before = logic.template vinput<64>();
  value.clearance_count_after = logic.template vinput<64>();
  InputDigest(logic, value.before_audit);
  InputDigest(logic, value.after_audit);
  InputDigest(logic, value.before_root);
  InputDigest(logic, value.after_root);
  InputDigest(logic, value.read_decision_id);
  InputDigest(logic, value.read_address);
  InputDigest(logic, value.read_key);
  InputDigest(logic, value.read_before);
  InputDigest(logic, value.read_after);
  InputDigest(logic, value.write_decision_id);
  InputDigest(logic, value.write_address);
  InputDigest(logic, value.write_key);
  InputDigest(logic, value.write_before);
  InputDigest(logic, value.write_after);
}

template <class Logic>
typename Logic::BitW EqualBits(const Logic& logic, const V8<Logic>& left,
                               const V8<Logic>& right) {
  typename Logic::BitW result = logic.bit(1);
  for (size_t index = 0; index < 8; ++index) {
    result = logic.land(result, logic.lnot(logic.lxor(left[index], right[index])));
  }
  return result;
}

template <class Logic, size_t N>
typename Logic::BitW EqualBits(const Logic& logic,
                               const std::array<V8<Logic>, N>& left,
                               const std::array<V8<Logic>, N>& right) {
  typename Logic::BitW result = logic.bit(1);
  for (size_t byte = 0; byte < N; ++byte) {
    result = logic.land(result, EqualBits(logic, left[byte], right[byte]));
  }
  return result;
}

template <class Logic>
typename Logic::BitW EqualConstant(const Logic& logic, const V8<Logic>& value,
                                   uint8_t expected) {
  return EqualBits(logic, value, logic.vbit8(expected));
}

template <class Logic>
typename Logic::BitW EqualDigestConstant(const Logic& logic,
                                          const Byte64<Logic>& value,
                                          const Digest& expected) {
  typename Logic::BitW result = logic.bit(1);
  for (size_t index = 0; index < kDigestBytes; ++index) {
    result = logic.land(result, EqualConstant(logic, value[index],
                                              expected[index]));
  }
  return result;
}

template <class Logic>
typename Logic::BitW EqualBits(const Logic& logic, const V64<Logic>& left,
                               const V64<Logic>& right) {
  typename Logic::BitW result = logic.bit(1);
  for (size_t index = 0; index < 64; ++index) {
    result = logic.land(result, logic.lnot(logic.lxor(left[index], right[index])));
  }
  return result;
}

template <class Logic>
typename Logic::BitW EqualBits(const Logic& logic, const V32<Logic>& left,
                               const V32<Logic>& right) {
  typename Logic::BitW result = logic.bit(1);
  for (size_t index = 0; index < 32; ++index) {
    result = logic.land(result, logic.lnot(logic.lxor(left[index], right[index])));
  }
  return result;
}

template <class Logic>
typename Logic::BitW LessThan(const Logic& logic, const V64<Logic>& left,
                              const V64<Logic>& right) {
  typename Logic::BitW borrow = logic.bit(0);
  for (size_t index = 0; index < 64; ++index) {
    const auto x = logic.lxor(left[index], right[index]);
    borrow = logic.lor(logic.land(logic.lnot(left[index]), right[index]),
                       logic.land(borrow, logic.lnot(x)));
  }
  return borrow;
}

template <class Logic>
typename Logic::BitW LessOrEqual(const Logic& logic, const V64<Logic>& left,
                                  const V64<Logic>& right) {
  return logic.lor(LessThan(logic, left, right), EqualBits(logic, left, right));
}

template <class Logic>
void Implies(const Logic& logic, const typename Logic::BitW& selector,
             const typename Logic::BitW& condition) {
  (void)logic.assert_implies(selector, condition);
}

template <class Logic>
void AssertDigest(const Logic& logic, const Byte64<Logic>& left,
                  const Byte64<Logic>& right) {
  for (size_t index = 0; index < kDigestBytes; ++index) {
    logic.vassert_eq(left[index], right[index]);
  }
}

template <class Logic>
void AppendByte(std::vector<V8<Logic>>& output, const V8<Logic>& value) {
  output.push_back(value);
}

template <class Logic>
void AppendDigest(std::vector<V8<Logic>>& output, const Byte64<Logic>& value) {
  output.insert(output.end(), value.begin(), value.end());
}

template <class Logic>
void AppendU32BE(std::vector<V8<Logic>>& output, const V32<Logic>& value) {
  for (size_t byte = 0; byte < 4; ++byte) {
    V8<Logic> encoded;
    for (size_t bit = 0; bit < 8; ++bit) {
      encoded[bit] = value[(3 - byte) * 8 + bit];
    }
    output.push_back(encoded);
  }
}

template <class Logic>
void AppendU64BE(std::vector<V8<Logic>>& output, const V64<Logic>& value) {
  for (size_t byte = 0; byte < 8; ++byte) {
    V8<Logic> encoded;
    for (size_t bit = 0; bit < 8; ++bit) {
      encoded[bit] = value[(7 - byte) * 8 + bit];
    }
    output.push_back(encoded);
  }
}

template <class Logic>
void AppendLiteral(std::vector<V8<Logic>>& output, const Logic& logic,
                   const char* value, size_t length) {
  for (size_t index = 0; index < length; ++index) {
    output.push_back(logic.vbit8(static_cast<uint8_t>(value[index])));
  }
}

template <class Logic>
std::vector<V8<Logic>> StateCommitmentWires(const Logic& logic,
                                            const PublicWires<Logic>& pub,
                                            const PrivateWires<Logic>& p) {
  std::vector<V8<Logic>> output;
  output.reserve(kStateCommitmentBytes);
  AppendLiteral<Logic>(output, logic, "BLST", 4);
  AppendByte<Logic>(output, logic.vbit8(1));
  AppendByte<Logic>(output, p.policy);
  AppendByte<Logic>(output, p.directive);
  AppendByte<Logic>(output, pub.complete);
  AppendByte<Logic>(output, pub.membership);
  AppendByte<Logic>(output, pub.absence);
  AppendByte<Logic>(output, pub.active);
  AppendByte<Logic>(output, p.exception_present);
  AppendByte<Logic>(output, p.exception_authorized);
  AppendByte<Logic>(output, p.economic_mutation);
  AppendByte<Logic>(output, p.clearance_marker_before);
  AppendByte<Logic>(output, p.clearance_marker_after);
  AppendU64BE<Logic>(output, pub.epoch);
  AppendU64BE<Logic>(output, pub.sequence_before);
  AppendU64BE<Logic>(output, p.rule_effective);
  AppendU64BE<Logic>(output, p.event);
  AppendU64BE<Logic>(output, p.observation);
  AppendU64BE<Logic>(output, p.decision);
  AppendU64BE<Logic>(output, p.read_time);
  AppendU64BE<Logic>(output, p.write_time);
  AppendU64BE<Logic>(output, p.exception_valid_from);
  AppendU64BE<Logic>(output, p.exception_valid_until);
  AppendU64BE<Logic>(output, p.sequence_after);
  AppendU32BE<Logic>(output, p.decision_index);
  AppendU32BE<Logic>(output, p.decision_count);
  AppendU32BE<Logic>(output, p.read_access_index);
  AppendU32BE<Logic>(output, p.write_access_index);
  AppendU32BE<Logic>(output, p.access_count);
  AppendU32BE<Logic>(output, p.read_decision_index);
  AppendU32BE<Logic>(output, p.write_decision_index);
  AppendByte<Logic>(output, p.read_mode);
  AppendByte<Logic>(output, p.write_mode);
  AppendU64BE<Logic>(output, p.clearance_count_before);
  AppendU64BE<Logic>(output, p.clearance_count_after);
  AppendDigest<Logic>(output, pub.source_root_id);
  AppendDigest<Logic>(output, pub.completeness_id);
  AppendDigest<Logic>(output, pub.subject_id);
  AppendDigest<Logic>(output, pub.attempt_id);
  AppendDigest<Logic>(output, pub.request_id);
  AppendDigest<Logic>(output, pub.exception_id);
  AppendDigest<Logic>(output, pub.exception_scope_id);
  AppendDigest<Logic>(output, pub.rule_id);
  AppendDigest<Logic>(output, pub.decision_id);
  AppendDigest<Logic>(output, p.before_audit);
  AppendDigest<Logic>(output, p.after_audit);
  AppendDigest<Logic>(output, p.before_root);
  AppendDigest<Logic>(output, p.after_root);
  AppendDigest<Logic>(output, p.read_decision_id);
  AppendDigest<Logic>(output, p.read_address);
  AppendDigest<Logic>(output, p.read_key);
  AppendDigest<Logic>(output, p.read_before);
  AppendDigest<Logic>(output, p.read_after);
  AppendDigest<Logic>(output, p.write_decision_id);
  AppendDigest<Logic>(output, p.write_address);
  AppendDigest<Logic>(output, p.write_key);
  AppendDigest<Logic>(output, p.write_before);
  AppendDigest<Logic>(output, p.write_after);
  return output;
}

template <class Logic>
void AssertStateCommitment(const Logic& logic,
                           const PublicWires<Logic>& pub,
                           const PrivateWires<Logic>& p) {
  const auto expected = StateCommitmentWires(logic, pub, p);
  proofs::check(expected.size() == kStateCommitmentBytes,
                "minimal clearance state commitment shape mismatch");
  for (size_t index = 0; index < expected.size(); ++index) {
    logic.vassert_eq(pub.state_commitment[index], expected[index]);
  }
}

template <class Logic>
void AssertPrivateBatchCommitment(const Logic& logic,
                                  const PublicWires<Logic>& pub,
                                  const PrivateWires<Logic>& p,
                                  proofs::Sha3Circuit<Logic>& sha3) {
  std::vector<V8<Logic>> input;
  AppendLiteral<Logic>(input, logic, "BL/NATIVE-V3/PRIVATE-BATCH/v2",
                       sizeof("BL/NATIVE-V3/PRIVATE-BATCH/v2") - 1);
  AppendByte<Logic>(input, logic.vbit8(0));
  AppendDigest<Logic>(input, pub.source_registry_snapshot);
  AppendDigest<Logic>(input, pub.source_profile);
  AppendDigest<Logic>(input, pub.subject_id);
  AppendDigest<Logic>(input, pub.source_root_id);
  AppendDigest<Logic>(input, pub.completeness_id);
  AppendDigest<Logic>(input, p.provider);
  AppendDigest<Logic>(input, p.credential);
  AppendDigest<Logic>(input, p.enrollment);
  AppendDigest<Logic>(input, p.source_payload);
  AppendByte<Logic>(input, p.active);
  AppendByte<Logic>(input, p.complete);
  AppendByte<Logic>(input, p.membership);
  AppendByte<Logic>(input, p.absence);
  std::vector<V8<Logic>> output;
  sha3.assert_sha3_512_no_witness(input, output);
  for (size_t index = 0; index < kDigestBytes; ++index) {
    logic.vassert_eq(pub.private_batch_commitment[index], output[index]);
  }
}

template <class Logic>
void AssertDirective(const Logic& logic, const PublicWires<Logic>& pub,
                     const PrivateWires<Logic>& p) {
  logic.vassert_eq(pub.active, p.active);
  logic.vassert_eq(pub.complete, p.complete);
  logic.vassert_eq(pub.membership, p.membership);
  logic.vassert_eq(pub.absence, p.absence);
  (void)logic.assert1(logic.lor(EqualConstant(logic, p.active, 0),
                                EqualConstant(logic, p.active, 1)));
  (void)logic.assert1(logic.lor(EqualConstant(logic, p.complete, 0),
                                EqualConstant(logic, p.complete, 1)));
  (void)logic.assert1(logic.lor(EqualConstant(logic, p.membership, 0),
                                EqualConstant(logic, p.membership, 1)));
  (void)logic.assert1(logic.lor(EqualConstant(logic, p.absence, 0),
                                EqualConstant(logic, p.absence, 1)));
  (void)logic.assert1(logic.lor(EqualConstant(logic, p.exception_present, 0),
                                EqualConstant(logic, p.exception_present, 1)));
  (void)logic.assert1(logic.lor(EqualConstant(logic, p.exception_authorized, 0),
                                EqualConstant(logic, p.exception_authorized, 1)));
  (void)logic.assert1(logic.lor(EqualConstant(logic, p.economic_mutation, 0),
                                EqualConstant(logic, p.economic_mutation, 1)));

  const auto clear = EqualConstant(logic, p.directive, kClear);
  const auto hold = EqualConstant(logic, p.directive, kHold);
  const auto human = EqualConstant(logic, p.directive, kHumanReview);
  const auto block = EqualConstant(logic, p.directive, kBlock);
  const auto exception = EqualConstant(logic, p.directive, kExceptionApproved);
  const auto valid = logic.lor(clear, logic.lor(hold, logic.lor(human,
                              logic.lor(block, exception))));
  (void)logic.assert1(valid);
  Implies(logic, clear, EqualConstant(logic, p.policy, kPolicyPass));
  Implies(logic, hold, EqualConstant(logic, p.policy, kPolicyMissing));
  Implies(logic, human, EqualConstant(logic, p.policy, kPolicyAmbiguous));
  Implies(logic, block, EqualConstant(logic, p.policy, kPolicyFail));
  Implies(logic, exception, EqualConstant(logic, p.policy, kPolicyFail));
  Implies(logic, clear, EqualConstant(logic, p.complete, 1));
  Implies(logic, hold, EqualConstant(logic, p.complete, 1));
  Implies(logic, human, EqualConstant(logic, p.complete, 0));
  Implies(logic, block, EqualConstant(logic, p.complete, 1));
  Implies(logic, exception, EqualConstant(logic, p.complete, 1));
  Implies(logic, clear, EqualConstant(logic, p.membership, 1));
  Implies(logic, hold, EqualConstant(logic, p.membership, 0));
  Implies(logic, human, EqualConstant(logic, p.membership, 0));
  Implies(logic, block, EqualConstant(logic, p.membership, 1));
  Implies(logic, exception, EqualConstant(logic, p.membership, 1));
  Implies(logic, clear, EqualConstant(logic, p.absence, 0));
  Implies(logic, hold, EqualConstant(logic, p.absence, 1));
  Implies(logic, human, EqualConstant(logic, p.absence, 0));
  Implies(logic, block, EqualConstant(logic, p.absence, 0));
  Implies(logic, exception, EqualConstant(logic, p.absence, 0));
  Implies(logic, clear, EqualConstant(logic, p.active, 1));
  Implies(logic, hold, EqualConstant(logic, p.active, 0));
  Implies(logic, human, EqualConstant(logic, p.active, 0));
  Implies(logic, block, EqualConstant(logic, p.active, 0));
  Implies(logic, exception, EqualConstant(logic, p.active, 0));
  Implies(logic, exception, EqualConstant(logic, p.exception_present, 1));
  Implies(logic, logic.lnot(exception), EqualConstant(logic, p.exception_present, 0));
  Implies(logic, exception, EqualConstant(logic, p.exception_authorized, 1));
  Implies(logic, logic.lnot(exception), EqualConstant(logic, p.exception_authorized, 0));
  (void)logic.assert0(logic.as_scalar(p.economic_mutation));
  const Digest sentinel = Sentinel();
  Implies(logic, logic.lnot(exception),
          EqualDigestConstant(logic, pub.exception_id, sentinel));
}

template <class Logic>
void AssertIndicesAndTimes(const Logic& logic, const PublicWires<Logic>& pub,
                           const PrivateWires<Logic>& p) {
  (void)logic.assert1(LessThan(logic, p.rule_effective, p.event));
  (void)logic.assert1(LessThan(logic, p.event, p.observation));
  (void)logic.assert1(LessThan(logic, p.observation, p.decision));
  logic.vassert_eq(p.read_time, p.observation);
  logic.vassert_eq(p.write_time, p.decision);
  logic.vassert_eq(p.decision_index, 0);
  logic.vassert_eq(p.decision_count, 1);
  logic.vassert_eq(p.read_access_index, 0);
  logic.vassert_eq(p.write_access_index, 1);
  logic.vassert_eq(p.access_count, 2);
  logic.vassert_eq(p.read_decision_index, 0);
  logic.vassert_eq(p.write_decision_index, 0);
  logic.vassert_eq(p.read_mode, 1);
  logic.vassert_eq(p.write_mode, 2);
  (void)logic.assert1(
      logic.lor(EqualConstant(logic, p.clearance_marker_before, 0),
                EqualConstant(logic, p.clearance_marker_before, 1)));
  (void)logic.assert1(
      logic.lor(EqualConstant(logic, p.clearance_marker_after, 0),
                EqualConstant(logic, p.clearance_marker_after, 1)));
  const auto exception = EqualConstant(logic, p.directive, kExceptionApproved);
  Implies(logic, exception,
          LessOrEqual(logic, p.exception_valid_from, p.event));
  Implies(logic, exception,
          LessOrEqual(logic, p.decision, p.exception_valid_until));
  Implies(logic, logic.lnot(exception),
          EqualDigestConstant(logic, pub.exception_scope_id, Sentinel()));
}

template <class Logic>
void AssertAccessAndTransition(const Logic& logic,
                               const PublicWires<Logic>& pub,
                               const PrivateWires<Logic>& p) {
  AssertDigest(logic, p.read_decision_id, pub.decision_id);
  AssertDigest(logic, p.write_decision_id, pub.decision_id);
  AssertDigest(logic, p.read_address, pub.source_address);
  AssertDigest(logic, p.read_key, pub.source_key);
  AssertDigest(logic, p.write_address, pub.audit_address);
  AssertDigest(logic, p.write_key, pub.decision_id);
  AssertDigest(logic, p.read_before, pub.source_root_id);
  AssertDigest(logic, p.read_after, pub.source_root_id);
  AssertDigest(logic, p.write_before, p.before_audit);
  AssertDigest(logic, p.write_after, p.after_audit);

  const auto clear_or_exception = logic.lor(
      EqualConstant(logic, p.directive, kClear),
      EqualConstant(logic, p.directive, kExceptionApproved));
  Implies(logic, clear_or_exception,
          EqualConstant(logic, p.clearance_marker_after, 1));
  Implies(logic, logic.lnot(clear_or_exception),
          EqualBits(logic, p.clearance_marker_after,
                    p.clearance_marker_before));
  typename Logic::BitW carry = clear_or_exception;
  for (size_t index = 0; index < 64; ++index) {
    const auto sum = logic.lxor(p.clearance_count_before[index], carry);
    logic.assert_eq(p.clearance_count_after[index], sum);
    carry = logic.land(p.clearance_count_before[index], carry);
  }
  carry = logic.bit(1);
  for (size_t index = 0; index < 64; ++index) {
    const auto sum = logic.lxor(pub.sequence_before[index], carry);
    logic.assert_eq(p.sequence_after[index], sum);
    carry = logic.land(pub.sequence_before[index], carry);
  }
}

}  // namespace

std::vector<uint8_t> private_batch_commitment_input(const Case& value) {
  std::vector<uint8_t> output = Domain("BL/NATIVE-V3/PRIVATE-BATCH/v2");
  Append(output, value.statement.source_registry_snapshot);
  Append(output, value.statement.source_profile);
  Append(output, value.statement.subject_id);
  Append(output, value.statement.source_root_id);
  Append(output, value.statement.completeness_id);
  Append(output, value.provider_id);
  Append(output, value.credential_id);
  Append(output, value.enrollment_id);
  Append(output, value.source_payload);
  AppendU8(output, value.statement.active);
  AppendU8(output, value.statement.complete);
  AppendU8(output, value.statement.authoritative_membership);
  AppendU8(output, value.statement.authoritative_absence);
  return output;
}

std::vector<uint8_t> endpoint_input(const Case& value, size_t endpoint_index) {
  proofs::check(endpoint_index < kSha3EndpointCount,
                "minimal clearance endpoint index out of range");
  switch (endpoint_index) {
    case 0:
      return private_batch_commitment_input(value);
  }
  return {};
}

const char* endpoint_name(size_t endpoint_index) {
  switch (endpoint_index) {
    case 0:
      return "private_source_registry_commitment";
  }
  return "unknown";
}

std::vector<uint8_t> state_commitment_bytes(const Case& value) {
  std::vector<uint8_t> output;
  output.reserve(kStateCommitmentBytes);
  output.insert(output.end(), {'B', 'L', 'S', 'T'});
  AppendU8(output, 1);
  AppendU8(output, value.policy_result);
  AppendU8(output, value.effective_directive);
  AppendU8(output, value.statement.complete);
  AppendU8(output, value.statement.authoritative_membership);
  AppendU8(output, value.statement.authoritative_absence);
  AppendU8(output, value.statement.active);
  AppendU8(output, value.exception_present);
  AppendU8(output, value.exception_authorized);
  AppendU8(output, value.economic_mutation);
  AppendU8(output, value.clearance_marker_before);
  AppendU8(output, value.clearance_marker_after);
  AppendU64(output, value.statement.epoch);
  AppendU64(output, value.statement.sequence_before);
  AppendU64(output, value.rule_effective_time);
  AppendU64(output, value.event_time);
  AppendU64(output, value.observation_time);
  AppendU64(output, value.decision_time);
  AppendU64(output, value.read_time);
  AppendU64(output, value.write_time);
  AppendU64(output, value.exception_valid_from);
  AppendU64(output, value.exception_valid_until);
  AppendU64(output, value.sequence_after);
  AppendU32(output, value.decision_index);
  AppendU32(output, value.decision_count);
  AppendU32(output, value.read_access_index);
  AppendU32(output, value.write_access_index);
  AppendU32(output, value.access_count);
  AppendU32(output, value.read_decision_index);
  AppendU32(output, value.write_decision_index);
  AppendU8(output, value.read_mode);
  AppendU8(output, value.write_mode);
  AppendU64(output, value.clearance_count_before);
  AppendU64(output, value.clearance_count_after);
  AppendStateDigests(output, value);
  return output;
}

void rebuild_state_binding(Case& value) {
  value.statement.state_commitment_bytes.fill(0);
  const auto state_bytes = state_commitment_bytes(value);
  std::copy(state_bytes.begin(), state_bytes.end(),
            value.statement.state_commitment_bytes.begin());
  value.statement.state_after_id = HashParts(
      Domain("BL/NATIVE-V3/MINIMAL-STATE-ID/v1"),
      {std::vector<uint8_t>{1}, state_bytes});
}

std::vector<uint8_t> public_statement_bytes(const Case& value) {
  std::vector<uint8_t> output;
  output.reserve(3000);
  AppendU8(output, value.statement.protocol_version);
  output.insert(output.end(), value.statement.proof_role.begin(),
                value.statement.proof_role.end());
  const Digest* digests[] = {
      &value.statement.proof_suite,
      &value.statement.execution_context,
      &value.statement.source_registry_snapshot,
      &value.statement.source_profile,
      &value.statement.governance_snapshot,
      &value.statement.automatic_control_set,
      &value.statement.settlement_domain,
      &value.statement.evaluator_id,
      &value.statement.schema_id,
      &value.statement.program_id,
      &value.statement.policy_id,
      &value.statement.subject_id,
      &value.statement.attempt_id,
      &value.statement.request_id,
      &value.statement.source_root_id,
      &value.statement.completeness_id,
      &value.statement.private_batch_commitment,
      &value.statement.source_address,
      &value.statement.source_key,
      &value.statement.audit_address,
      &value.statement.exception_id,
      &value.statement.exception_scope_id,
      &value.statement.rule_id,
      &value.statement.decision_id,
      &value.statement.state_before_id,
      &value.statement.state_after_id,
  };
  for (const Digest* digest : digests) Append(output, *digest);
  AppendU64(output, value.statement.epoch);
  AppendU64(output, value.statement.sequence_before);
  AppendU8(output, value.statement.active);
  AppendU8(output, value.statement.complete);
  AppendU8(output, value.statement.authoritative_membership);
  AppendU8(output, value.statement.authoritative_absence);
  Append(output, std::vector<uint8_t>(value.statement.state_commitment_bytes.begin(),
                                     value.statement.state_commitment_bytes.end()));
  return output;
}

DerivedIdentities derive_identities(const Case& value) {
  DerivedIdentities output;
  output.decision_id = DecisionId(value);
  output.join_id = HashParts(
      Domain("BL/NATIVE-V3/MINIMAL-DECISION-ACCESS-JOIN/v1"),
      {ToVector(value.statement.decision_id), ToVector(value.read_decision_id),
       ToVector(value.read_address), ToVector(value.read_key),
       ToVector(value.read_before), ToVector(value.read_after),
       ToVector(value.write_decision_id), ToVector(value.write_address),
       ToVector(value.write_key), ToVector(value.write_before),
       ToVector(value.write_after), ToVector(value.statement.state_before_id),
       ToVector(value.statement.state_after_id)});
  output.receipt_id = HashParts(
      Domain("BL/NATIVE-V3/MINIMAL-RECEIPT-ID/v1"),
      {ToVector(value.statement.automatic_control_set),
       ToVector(value.statement.decision_id), ToVector(output.join_id),
       ToVector(value.statement.state_before_id),
       ToVector(value.statement.state_after_id),
       std::vector<uint8_t>(value.statement.state_commitment_bytes.begin(),
                            value.statement.state_commitment_bytes.end())});
  output.settlement_id = HashParts(
      Domain("BL/NATIVE-V3/MINIMAL-SETTLEMENT-REFERENCE/v1"),
      {ToVector(value.statement.settlement_domain),
       std::vector<uint8_t>{value.effective_directive},
       ToVector(value.statement.decision_id),
       ToVector(value.statement.state_after_id)});
  return output;
}

Fixture make_fixture() {
  Fixture fixture;
  const NativeV3Fixture base = make_native_v3_fixture();
  for (size_t index = 0; index < fixture.cases.size(); ++index) {
    const RelationCase& source = base.cases[index];
    Case& value = fixture.cases[index];
    value.provider_id = source.provider_id;
    value.credential_id = source.credential_id;
    value.enrollment_id = source.enrollment_id;
    value.source_payload = source.source_payload;
    value.policy_result = source.policy_result;
    value.effective_directive = source.effective_directive;
    value.exception_present = source.exception_present;
    value.exception_authorized = source.exception_present;
    value.economic_mutation = 0;
    value.rule_effective_time = source.rule_effective_time;
    value.event_time = source.event_time;
    value.observation_time = source.observation_time;
    value.decision_time = source.decision_time;
    value.read_time = source.read_time;
    value.write_time = source.write_time;
    value.exception_valid_from = source.exception_present ? 6998 : 0;
    value.exception_valid_until = source.exception_present ? 7003 : 0;
    value.decision_index = source.decision_index;
    value.decision_count = source.decision_count;
    value.read_access_index = source.read_access_index;
    value.write_access_index = source.write_access_index;
    value.access_count = source.access_count;
    value.read_decision_index = source.read_decision_index;
    value.write_decision_index = source.write_decision_index;
    value.read_mode = source.read_mode;
    value.write_mode = source.write_mode;
    value.clearance_marker_before = 0;
    value.clearance_marker_after =
        (value.effective_directive == kClear ||
         value.effective_directive == kExceptionApproved)
            ? 1
            : 0;
    value.clearance_count_before = 0;
    value.clearance_count_after = value.clearance_marker_after;
    value.before_audit_head = source.before_audit_head;
    value.before_continuity_root = source.before_continuity_root;

    value.statement.protocol_version = 3;
    FillRole(value.statement.proof_role);
    value.statement.proof_suite.fill(0);
    value.statement.execution_context =
        HashText("BL/NATIVE-V3/EXECUTION-CONTEXT/v2", "minimal-linked");
    value.statement.source_registry_snapshot =
        HashText("BL/NATIVE-V3/SOURCE-REGISTRY-SNAPSHOT/v1", "snapshot-1");
    value.statement.source_profile =
        HashText("BL/NATIVE-V3/SOURCE-PROFILE/v1", "synthetic-authoritative");
    value.statement.governance_snapshot =
        HashText("BL/NATIVE-V3/GOVERNANCE-SNAPSHOT/v2", "governance-1");
    value.statement.automatic_control_set =
        HashText("BL/NATIVE-V3/CONTROL-SET/v2",
                 "CLEAR,HOLD,HUMAN_REVIEW,BLOCK,EXCEPTION_APPROVED");
    value.statement.settlement_domain =
        HashText("BL/NATIVE-V3/SETTLEMENT-DOMAIN/v2", "official-state-rail");
    value.statement.evaluator_id =
        HashText("BL/NATIVE-V3/EVALUATOR/v1", "minimal-linked-evaluator");
    value.statement.schema_id =
        HashText("BL/NATIVE-V3/SCHEMA/v1", "minimal-linked-schema");
    value.statement.program_id =
        HashText("BL/NATIVE-V3/PROGRAM/v1", "minimal-linked-program");
    value.statement.policy_id =
        HashText("BL/NATIVE-V3/POLICY/v1", "minimal-five-directive-policy");
    value.statement.subject_id = source.credential_id;
    value.statement.attempt_id = source.attempt_id;
    value.statement.active = source.active_status;
    value.statement.complete = source.complete;
    value.statement.authoritative_membership = source.authoritative_membership;
    value.statement.authoritative_absence = source.authoritative_absence;
    value.statement.epoch = 7;
    value.statement.sequence_before = 11;
    value.statement.state_before_id = BeforeStateId(value);
    value.statement.source_root_id = HashBytes(SourceRootInput(value));
    value.statement.completeness_id = HashBytes(CompletenessInput(value));
    proofs::check(value.statement.source_root_id == source.source_root,
                  "minimal clearance source-root fixture mismatch");
    proofs::check(value.statement.completeness_id == source.completeness_id,
                  "minimal clearance completeness fixture mismatch");
    value.statement.source_address = source.read_address;
    value.statement.source_key = source.read_key;
    value.statement.audit_address = source.write_address;
    value.statement.exception_id = source.exception_id;
    value.statement.rule_id = source.rule_id;
    value.sequence_after = value.statement.sequence_before + 1;
    value.statement.exception_scope_id = ScopeId(value);
    value.statement.request_id = RequestId(value);
    value.statement.decision_id = DecisionId(value);
    value.read_decision_id = value.statement.decision_id;
    value.write_decision_id = value.statement.decision_id;
    value.read_address = value.statement.source_address;
    value.read_key = value.statement.source_key;
    value.read_before = value.statement.source_root_id;
    value.read_after = value.statement.source_root_id;
    value.write_address = value.statement.audit_address;
    value.write_key = value.statement.decision_id;
    value.write_before = value.before_audit_head;
    value.after_audit_head = AfterAudit(value);
    value.write_after = value.after_audit_head;
    value.after_continuity_root = AfterRoot(value);
    value.statement.private_batch_commitment =
        HashBytes(private_batch_commitment_input(value));
    rebuild_state_binding(value);
  }
  return fixture;
}

template <class Logic>
void AssertRelation(const Logic& logic, const PublicWires<Logic>& pub,
                    const PrivateWires<Logic>& p) {
  logic.vassert_eq(pub.protocol, 3);
  for (size_t index = 0; index < kProofRoleBytes; ++index) {
    logic.vassert_eq(pub.proof_role[index],
                     static_cast<uint8_t>(kProofRole[index]));
  }
  for (const auto& byte : pub.proof_suite) logic.vassert_eq(byte, 0);
  AssertDirective(logic, pub, p);
  AssertIndicesAndTimes(logic, pub, p);
  AssertAccessAndTransition(logic, pub, p);
  AssertStateCommitment(logic, pub, p);
}

std::unique_ptr<proofs::Circuit<RelationField>> build_circuit_stage(
    size_t endpoint_count) {
  proofs::check(endpoint_count <= kSha3EndpointCount,
                "minimal clearance endpoint stage exceeds endpoint count");
  using Backend = proofs::CompilerBackend<RelationField>;
  using Logic = proofs::Logic<RelationField, Backend>;
  auto field = std::make_unique<RelationField>();
  auto builder = std::make_unique<proofs::QuadCircuit<RelationField>>(*field);
  const Backend backend(builder.get());
  const Logic logic(&backend, *field);
  std::fprintf(stderr, "MINIMAL_CLEARANCE_BUILD phase=public\n");
  auto pub = std::make_unique<PublicWires<Logic>>();
  InputPublic(logic, *pub);
  builder->private_input();
  std::fprintf(stderr, "MINIMAL_CLEARANCE_BUILD phase=private\n");
  auto priv = std::make_unique<PrivateWires<Logic>>();
  InputPrivate(logic, *priv);
  proofs::Sha3Circuit<Logic> sha3(logic);
  std::fprintf(stderr, "MINIMAL_CLEARANCE_BUILD phase=assertions\n");
  AssertRelation(logic, *pub, *priv);
  if (endpoint_count >= 1) {
    AssertPrivateBatchCommitment(logic, *pub, *priv, sha3);
  }
  std::fprintf(stderr, "MINIMAL_CLEARANCE_BUILD phase=mkcircuit\n");
  auto circuit = builder->mkcircuit(1);
  std::fprintf(stderr,
               "MINIMAL_CLEARANCE_BUILD phase=complete inputs=%zu public_inputs=%zu layers=%zu terms=%zu\n",
               circuit->ninputs, circuit->npub_in, circuit->nl,
               circuit->nterms());
  return circuit;
}

std::unique_ptr<proofs::Circuit<RelationField>> build_circuit() {
  return build_circuit_stage(kSha3EndpointCount);
}

void fill_public(const Case& value,
                 proofs::Dense<RelationField>& public_input) {
  const RelationField field;
  proofs::DenseFiller<RelationField> filler(public_input);
  using Logic = proofs::Logic<RelationField,
                              proofs::CompilerBackend<RelationField>>;
  PushPublic<Logic>(filler, value, field);
}

template <class Logic>
void PushPrivate(proofs::DenseFiller<RelationField>& filler, const Case& value,
                 const RelationField& field) {
  PushDigest<Logic>(filler, value.provider_id, field);
  PushDigest<Logic>(filler, value.credential_id, field);
  PushDigest<Logic>(filler, value.enrollment_id, field);
  PushDigest<Logic>(filler, value.source_payload, field);
  filler.push_back(value.statement.active, 8, field);
  filler.push_back(value.statement.complete, 8, field);
  filler.push_back(value.statement.authoritative_membership, 8, field);
  filler.push_back(value.statement.authoritative_absence, 8, field);
  filler.push_back(value.policy_result, 8, field);
  filler.push_back(value.effective_directive, 8, field);
  filler.push_back(value.exception_present, 8, field);
  filler.push_back(value.exception_authorized, 8, field);
  filler.push_back(value.economic_mutation, 8, field);
  filler.push_back(value.rule_effective_time, 64, field);
  filler.push_back(value.event_time, 64, field);
  filler.push_back(value.observation_time, 64, field);
  filler.push_back(value.decision_time, 64, field);
  filler.push_back(value.read_time, 64, field);
  filler.push_back(value.write_time, 64, field);
  filler.push_back(value.exception_valid_from, 64, field);
  filler.push_back(value.exception_valid_until, 64, field);
  filler.push_back(value.sequence_after, 64, field);
  filler.push_back(value.decision_index, 32, field);
  filler.push_back(value.decision_count, 32, field);
  filler.push_back(value.read_access_index, 32, field);
  filler.push_back(value.write_access_index, 32, field);
  filler.push_back(value.access_count, 32, field);
  filler.push_back(value.read_decision_index, 32, field);
  filler.push_back(value.write_decision_index, 32, field);
  filler.push_back(value.read_mode, 8, field);
  filler.push_back(value.write_mode, 8, field);
  filler.push_back(value.clearance_marker_before, 8, field);
  filler.push_back(value.clearance_marker_after, 8, field);
  filler.push_back(value.clearance_count_before, 64, field);
  filler.push_back(value.clearance_count_after, 64, field);
  PushDigest<Logic>(filler, value.before_audit_head, field);
  PushDigest<Logic>(filler, value.after_audit_head, field);
  PushDigest<Logic>(filler, value.before_continuity_root, field);
  PushDigest<Logic>(filler, value.after_continuity_root, field);
  PushDigest<Logic>(filler, value.read_decision_id, field);
  PushDigest<Logic>(filler, value.read_address, field);
  PushDigest<Logic>(filler, value.read_key, field);
  PushDigest<Logic>(filler, value.read_before, field);
  PushDigest<Logic>(filler, value.read_after, field);
  PushDigest<Logic>(filler, value.write_decision_id, field);
  PushDigest<Logic>(filler, value.write_address, field);
  PushDigest<Logic>(filler, value.write_key, field);
  PushDigest<Logic>(filler, value.write_before, field);
  PushDigest<Logic>(filler, value.write_after, field);
}

void fill_witness(const Case& value,
                  proofs::Dense<RelationField>& witness) {
  const RelationField field;
  proofs::DenseFiller<RelationField> filler(witness);
  using Logic = proofs::Logic<RelationField,
                              proofs::CompilerBackend<RelationField>>;
  PushPublic<Logic>(filler, value, field);
  PushPrivate<Logic>(filler, value, field);
}

bool evaluate_case(const Case& value, std::string& reason) {
  const auto fail = [&](const char* text) {
    reason = text;
    return false;
  };
  const Fixture registry = make_fixture();
  const Case* selected = nullptr;
  for (const Case& candidate : registry.cases) {
    if (candidate.statement.attempt_id == value.statement.attempt_id) {
      selected = &candidate;
      break;
    }
  }
  if (selected == nullptr) return fail("registry.attempt");
  const auto same_registry = [&](const PublicStatement& left,
                                 const PublicStatement& right) {
    return left.protocol_version == right.protocol_version &&
           left.proof_role == right.proof_role &&
           left.proof_suite == right.proof_suite &&
           left.execution_context == right.execution_context &&
           left.source_registry_snapshot == right.source_registry_snapshot &&
           left.source_profile == right.source_profile &&
           left.governance_snapshot == right.governance_snapshot &&
           left.automatic_control_set == right.automatic_control_set &&
           left.settlement_domain == right.settlement_domain &&
           left.evaluator_id == right.evaluator_id &&
           left.schema_id == right.schema_id &&
           left.program_id == right.program_id &&
           left.policy_id == right.policy_id &&
           left.subject_id == right.subject_id &&
           left.attempt_id == right.attempt_id &&
           left.request_id == right.request_id &&
           left.source_root_id == right.source_root_id &&
           left.completeness_id == right.completeness_id &&
           left.source_address == right.source_address &&
           left.source_key == right.source_key &&
           left.audit_address == right.audit_address &&
           left.exception_id == right.exception_id &&
           left.exception_scope_id == right.exception_scope_id &&
           left.rule_id == right.rule_id &&
           left.decision_id == right.decision_id &&
           left.epoch == right.epoch &&
           left.sequence_before == right.sequence_before;
  };
  if (!same_registry(value.statement, selected->statement)) {
    return fail("registry.binding");
  }
  if (value.statement.state_before_id != selected->statement.state_before_id) {
    return fail("state.before-id");
  }
  if (value.statement.protocol_version != 3) return fail("statement.protocol");
  ProofRole expected_role{};
  FillRole(expected_role);
  if (value.statement.proof_role != expected_role) {
    return fail("statement.role");
  }
  if (std::any_of(value.statement.proof_suite.begin(),
                  value.statement.proof_suite.end(),
                  [](uint8_t byte) { return byte != 0; })) {
    return fail("statement.proof-suite");
  }
  if (value.statement.complete != value.statement.authoritative_membership &&
      value.effective_directive == kClear) {
    return fail("source.flags");
  }
  if (value.statement.active > 1 || value.statement.complete > 1 ||
      value.statement.authoritative_membership > 1 ||
      value.statement.authoritative_absence > 1 ||
      value.exception_present > 1 || value.exception_authorized > 1 ||
      value.economic_mutation > 1) {
    return fail("source.flags.binary");
  }
  if (value.statement.authoritative_absence &&
      (!value.statement.complete || value.statement.authoritative_membership)) {
    return fail("source.incomplete-absence");
  }
  const bool directive_valid = value.effective_directive >= kClear &&
                               value.effective_directive <= kExceptionApproved;
  if (!directive_valid) return fail("directive.value");
  const bool clear = value.effective_directive == kClear;
  const bool hold = value.effective_directive == kHold;
  const bool human = value.effective_directive == kHumanReview;
  const bool block = value.effective_directive == kBlock;
  const bool exception = value.effective_directive == kExceptionApproved;
  if ((clear && (value.policy_result != kPolicyPass || !value.statement.complete ||
                 !value.statement.authoritative_membership ||
                 value.statement.authoritative_absence || !value.statement.active ||
                 value.exception_present)) ||
      (hold && (value.policy_result != kPolicyMissing || !value.statement.complete ||
                value.statement.authoritative_membership ||
                !value.statement.authoritative_absence || value.exception_present)) ||
      (human && (value.policy_result != kPolicyAmbiguous || value.statement.complete ||
                 value.statement.authoritative_membership ||
                 value.statement.authoritative_absence || value.exception_present)) ||
      (block && (value.policy_result != kPolicyFail || !value.statement.complete ||
                 !value.statement.authoritative_membership ||
                 value.statement.authoritative_absence || value.statement.active ||
                 value.exception_present)) ||
      (exception && (value.policy_result != kPolicyFail || !value.statement.complete ||
                     !value.statement.authoritative_membership ||
                     value.statement.authoritative_absence || value.statement.active ||
                     !value.exception_present || !value.exception_authorized))) {
    return fail("directive.mapping");
  }
  if (value.economic_mutation != 0) return fail("economic-mutation");
  if (!(value.rule_effective_time < value.event_time &&
        value.event_time < value.observation_time &&
        value.observation_time < value.decision_time)) {
    return fail("chronology");
  }
  if (value.read_time != value.observation_time ||
      value.write_time != value.decision_time) {
    return fail("access.time");
  }
  if (value.decision_index != 0 || value.decision_count != 1 ||
      value.read_access_index != 0 || value.write_access_index != 1 ||
      value.access_count != 2 || value.read_decision_index != 0 ||
      value.write_decision_index != 0 || value.read_mode != 1 ||
      value.write_mode != 2) {
    return fail("access.shape");
  }
  if (exception) {
    if (value.exception_valid_from > value.event_time ||
        value.decision_time > value.exception_valid_until) {
      return fail("exception.interval");
    }
  } else if (value.statement.exception_id != Sentinel() ||
             value.statement.exception_scope_id != Sentinel() ||
             value.exception_authorized != 0) {
    return fail("exception.sentinel");
  }
  if (value.read_decision_id != value.statement.decision_id ||
      value.write_decision_id != value.statement.decision_id ||
      value.read_address != value.statement.source_address ||
      value.read_key != value.statement.source_key ||
      value.write_address != value.statement.audit_address ||
      value.write_key != value.statement.decision_id ||
      value.read_before != value.statement.source_root_id ||
      value.read_after != value.statement.source_root_id ||
      value.write_before != value.before_audit_head ||
      value.write_after != value.after_audit_head) {
    return fail("access.binding");
  }
  const uint8_t clear_transition = (clear || exception) ? 1 : 0;
  if (value.sequence_after != value.statement.sequence_before + 1) {
    return fail("state.sequence-after");
  }
  if (value.statement.request_id != RequestId(value) ||
      value.statement.exception_scope_id != ScopeId(value) ||
      value.statement.decision_id != DecisionId(value) ||
      value.after_audit_head != AfterAudit(value) ||
      value.after_continuity_root != AfterRoot(value)) {
    return fail("state.derived-binding");
  }
  if (value.clearance_marker_after !=
          static_cast<uint8_t>(value.clearance_marker_before || clear_transition) ||
      value.clearance_count_after !=
          value.clearance_count_before + clear_transition) {
    return fail("state.clearance-transition");
  }
  if (HashBytes(private_batch_commitment_input(value)) !=
      value.statement.private_batch_commitment) {
    return fail("private-batch.commitment");
  }
  const std::vector<uint8_t> expected_state = state_commitment_bytes(value);
  if (!std::equal(expected_state.begin(), expected_state.end(),
                  value.statement.state_commitment_bytes.begin(),
                  value.statement.state_commitment_bytes.end())) {
    return fail("state.commitment-bytes");
  }
  const std::vector<uint8_t> state = state_commitment_bytes(value);
  if (HashParts(Domain("BL/NATIVE-V3/MINIMAL-STATE-ID/v1"),
                {std::vector<uint8_t>{1}, state}) != value.statement.state_after_id) {
    return fail("state.ids");
  }
  const DerivedIdentities ids = derive_identities(value);
  if (ids.decision_id != value.statement.decision_id) return fail("decision.id");
  return true;
}

}  // namespace blind_ledger_longfellow::minimal_linked
