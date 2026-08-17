#include "native_v3_relation.h"

#include <array>
#include <chrono>
#include <cstdio>
#include <cstring>

#include "circuits/compiler/compiler.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/tests/sha3/sha3_circuit.h"
#include "circuits/tests/sha3/sha3_witness.h"
#include "sha3_512_witness.h"

namespace blind_ledger_longfellow {
namespace {

enum ByteField : size_t {
  kProvider,
  kCredential,
  kEnrollment,
  kAttempt,
  kMode,
  kRule,
  kPhase0,
  kSourcePayload,
  kSourceRoot,
  kCompletenessPayload,
  kCompletenessId,
  kChronologyId,
  kReplayId,
  kExceptionId,
  kReasonId,
  kRequestId,
  kDecisionId,
  kDecisionPathId,
  kBeforeAudit,
  kBeforeRoot,
  kAfterAudit,
  kAfterRoot,
  kReadDecision,
  kReadAddress,
  kReadKey,
  kReadBefore,
  kReadAfter,
  kWriteDecision,
  kWriteAddress,
  kWriteKey,
  kWriteBefore,
  kWriteAfter,
  kJoinId,
  kReceiptId,
  kByteFieldCount,
};

template <class Logic>
using V8 = typename Logic::template bitvec<8>;
template <class Logic>
using V32 = typename Logic::template bitvec<32>;
template <class Logic>
using V64 = typename Logic::template bitvec<64>;
template <class Logic>
using Byte64 = std::array<V8<Logic>, kDigestBytes>;

constexpr size_t kHashKindCount =
    static_cast<size_t>(HashKind::kSettlement) + 1;

template <class Logic>
using HashWires = std::array<Byte64<Logic>, kHashKindCount>;

template <class Logic>
const Byte64<Logic>& H(const HashWires<Logic>& hashes, HashKind kind) {
  return hashes[static_cast<size_t>(kind)];
}

bool IsComputedDigestField(ByteField field) {
  switch (field) {
    case kSourceRoot:
    case kCompletenessId:
    case kRequestId:
    case kDecisionId:
    case kDecisionPathId:
    case kAfterAudit:
    case kAfterRoot:
    case kJoinId:
      return true;
    default:
      return false;
  }
}

template <class Logic>
struct PublicWires {
  V8<Logic> protocol;
  Byte64<Logic> proof_suite;
  Byte64<Logic> execution_context;
  Byte64<Logic> settlement_domain;
  V64<Logic> epoch;
  V64<Logic> sequence_before;
  Byte64<Logic> state_before_id;
  Byte64<Logic> state_after_id;
  Byte64<Logic> governance_snapshot;
  Byte64<Logic> control_set;
  Byte64<Logic> private_batch_commitment;
  Byte64<Logic> settlement_commitment;
};

template <class Logic>
struct PrivateWires {
  V8<Logic> directive;
  V8<Logic> policy;
  V8<Logic> complete;
  V8<Logic> membership;
  V8<Logic> absence;
  V8<Logic> active;
  V8<Logic> exception_present;
  V8<Logic> proof_accepted;
  V8<Logic> economic_mutation;
  V64<Logic> event_time;
  V64<Logic> observation_time;
  V64<Logic> rule_effective_time;
  V64<Logic> decision_time;
  V64<Logic> read_time;
  V64<Logic> write_time;
  V32<Logic> decision_index;
  V32<Logic> decision_count;
  V32<Logic> read_access_index;
  V32<Logic> write_access_index;
  V32<Logic> access_count;
  V32<Logic> read_decision_index;
  V32<Logic> write_decision_index;
  V8<Logic> read_mode;
  V8<Logic> write_mode;
  std::array<Byte64<Logic>, kByteFieldCount> bytes;
};

template <class Logic>
void InputPublic(const Logic& logic, PublicWires<Logic>& p) {
  p.protocol = logic.template vinput<8>();
  auto input_digest = [&]() {
    Byte64<Logic> result;
    for (auto& byte : result) byte = logic.template vinput<8>();
    return result;
  };
  p.proof_suite = input_digest();
  p.execution_context = input_digest();
  p.settlement_domain = input_digest();
  p.epoch = logic.template vinput<64>();
  p.sequence_before = logic.template vinput<64>();
  p.state_before_id = input_digest();
  p.state_after_id = input_digest();
  p.governance_snapshot = input_digest();
  p.control_set = input_digest();
  p.private_batch_commitment = input_digest();
  p.settlement_commitment = input_digest();
}

template <class Logic>
void InputPrivate(const Logic& logic, PrivateWires<Logic>& p) {
  p.directive = logic.template vinput<8>();
  p.policy = logic.template vinput<8>();
  p.complete = logic.template vinput<8>();
  p.membership = logic.template vinput<8>();
  p.absence = logic.template vinput<8>();
  p.active = logic.template vinput<8>();
  p.exception_present = logic.template vinput<8>();
  p.proof_accepted = logic.template vinput<8>();
  p.economic_mutation = logic.template vinput<8>();
  p.event_time = logic.template vinput<64>();
  p.observation_time = logic.template vinput<64>();
  p.rule_effective_time = logic.template vinput<64>();
  p.decision_time = logic.template vinput<64>();
  p.read_time = logic.template vinput<64>();
  p.write_time = logic.template vinput<64>();
  p.decision_index = logic.template vinput<32>();
  p.decision_count = logic.template vinput<32>();
  p.read_access_index = logic.template vinput<32>();
  p.write_access_index = logic.template vinput<32>();
  p.access_count = logic.template vinput<32>();
  p.read_decision_index = logic.template vinput<32>();
  p.write_decision_index = logic.template vinput<32>();
  p.read_mode = logic.template vinput<8>();
  p.write_mode = logic.template vinput<8>();
  for (auto& digest : p.bytes) {
    const auto field = static_cast<ByteField>(&digest - p.bytes.data());
    if (IsComputedDigestField(field)) continue;
    for (auto& byte : digest) byte = logic.template vinput<8>();
  }
}

template <class Logic>
void AppendByte(std::vector<V8<Logic>>& seed, const V8<Logic>& byte) {
  seed.push_back(byte);
}

template <class Logic>
void AppendBytes(std::vector<V8<Logic>>& seed, const Byte64<Logic>& bytes) {
  seed.insert(seed.end(), bytes.begin(), bytes.end());
}

template <class Logic>
void AppendDomain(std::vector<V8<Logic>>& seed, const char* text,
                  const Logic& logic) {
  const size_t n = std::strlen(text);
  for (size_t i = 0; i < n; ++i) seed.push_back(logic.vbit8(text[i]));
  seed.push_back(logic.vbit8(0));
}

template <class Logic>
void AppendU8(std::vector<V8<Logic>>& seed, const V8<Logic>& value) {
  seed.push_back(value);
}

template <class Logic>
void AppendU32BE(std::vector<V8<Logic>>& seed, const V32<Logic>& value) {
  for (size_t byte = 0; byte < 4; ++byte) {
    V8<Logic> out;
    for (size_t bit = 0; bit < 8; ++bit) {
      out[bit] = value[(3 - byte) * 8 + bit];
    }
    seed.push_back(out);
  }
}

template <class Logic>
void AppendU64BE(std::vector<V8<Logic>>& seed, const V64<Logic>& value) {
  for (size_t byte = 0; byte < 8; ++byte) {
    V8<Logic> out;
    for (size_t bit = 0; bit < 8; ++bit) {
      out[bit] = value[(7 - byte) * 8 + bit];
    }
    seed.push_back(out);
  }
}

template <class Logic>
const Byte64<Logic>& B(const PrivateWires<Logic>& p, ByteField field) {
  return p.bytes[field];
}

template <class Logic>
std::vector<V8<Logic>> SeedFor(HashKind kind, const PublicWires<Logic>& pub,
                               const PrivateWires<Logic>& p,
                               const HashWires<Logic>& hashes,
                               const Logic& logic) {
  std::vector<V8<Logic>> result;
  switch (kind) {
    case HashKind::kSourceRoot:
      AppendDomain<Logic>(result, "BL/NATIVE-V3/SOURCE-ROOT/v1", logic);
      AppendBytes<Logic>(result, B(p, kProvider));
      AppendBytes<Logic>(result, B(p, kCredential));
      AppendBytes<Logic>(result, B(p, kEnrollment));
      AppendU8<Logic>(result, p.active);
      AppendU8<Logic>(result, p.complete);
      AppendU8<Logic>(result, p.membership);
      AppendU8<Logic>(result, p.absence);
      break;
    case HashKind::kCompleteness:
      AppendDomain<Logic>(result, "BL/NATIVE-V3/COMPLETENESS/v1", logic);
      AppendBytes<Logic>(result, B(p, kProvider));
      AppendBytes<Logic>(result, B(p, kCredential));
      AppendU8<Logic>(result, p.complete);
      AppendU8<Logic>(result, p.absence);
      break;
    case HashKind::kChronology:
      AppendDomain<Logic>(result, "BL/NATIVE-V3/CHRONOLOGY/v1", logic);
      AppendU64BE<Logic>(result, p.rule_effective_time);
      AppendU64BE<Logic>(result, p.event_time);
      AppendU64BE<Logic>(result, p.observation_time);
      AppendU64BE<Logic>(result, p.decision_time);
      break;
    case HashKind::kBeforeState: {
      AppendDomain<Logic>(result, "BL/NATIVE-V3/STATE-ID/v1", logic);
      AppendBytes<Logic>(result, pub.execution_context);
      AppendBytes<Logic>(result, B(p, kMode));
      V64<Logic> zero;
      for (size_t i = 0; i < 64; ++i) zero[i] = logic.bit(0);
      AppendU64BE<Logic>(result, zero);
      V32<Logic> zero32;
      for (size_t i = 0; i < 32; ++i) zero32[i] = logic.bit(0);
      AppendU32BE<Logic>(result, zero32);
      AppendBytes<Logic>(result, B(p, kBeforeAudit));
      AppendBytes<Logic>(result, B(p, kBeforeRoot));
      break;
    }
    case HashKind::kRequest:
      AppendDomain<Logic>(result, "BL/NATIVE-V3/REQUEST-ID/v1", logic);
      AppendBytes<Logic>(result, B(p, kProvider));
      AppendBytes<Logic>(result, B(p, kCredential));
      AppendBytes<Logic>(result, B(p, kEnrollment));
      AppendBytes<Logic>(result, B(p, kAttempt));
      AppendU64BE<Logic>(result, pub.epoch);
      AppendU64BE<Logic>(result, pub.sequence_before);
      AppendU64BE<Logic>(result, p.event_time);
      AppendU64BE<Logic>(result, p.observation_time);
      AppendU64BE<Logic>(result, p.rule_effective_time);
      AppendU64BE<Logic>(result, p.decision_time);
      AppendBytes<Logic>(result, pub.state_before_id);
      break;
    case HashKind::kReplay:
      AppendDomain<Logic>(result, "BL/NATIVE-V3/REPLAY/v1", logic);
      AppendBytes<Logic>(result, H<Logic>(hashes, HashKind::kRequest));
      AppendBytes<Logic>(result, pub.state_before_id);
      AppendBytes<Logic>(result, H<Logic>(hashes, HashKind::kSourceRoot));
      AppendBytes<Logic>(result, pub.control_set);
      break;
    case HashKind::kDecision:
      AppendDomain<Logic>(result, "BL/NATIVE-V3/DECISION-ID/v1", logic);
      AppendBytes<Logic>(result, H<Logic>(hashes, HashKind::kRequest));
      AppendBytes<Logic>(result, pub.state_before_id);
      AppendBytes<Logic>(result, H<Logic>(hashes, HashKind::kSourceRoot));
      AppendBytes<Logic>(result, H<Logic>(hashes, HashKind::kCompleteness));
      AppendU8<Logic>(result, p.policy);
      AppendU8<Logic>(result, p.directive);
      AppendBytes<Logic>(result, B(p, kExceptionId));
      break;
    case HashKind::kDecisionPath:
      AppendDomain<Logic>(result, "BL/NATIVE-V3/DECISION-PATH/v1", logic);
      AppendBytes<Logic>(result, pub.control_set);
      AppendBytes<Logic>(result, B(p, kRule));
      AppendBytes<Logic>(result, H<Logic>(hashes, HashKind::kSourceRoot));
      AppendBytes<Logic>(result, H<Logic>(hashes, HashKind::kCompleteness));
      AppendBytes<Logic>(result, B(p, kReasonId));
      AppendU8<Logic>(result, p.policy);
      AppendU8<Logic>(result, p.directive);
      AppendBytes<Logic>(result, B(p, kExceptionId));
      break;
    case HashKind::kAfterAudit:
      AppendDomain<Logic>(result, "BL/NATIVE-V3/AUDIT-HEAD/v1", logic);
      AppendBytes<Logic>(result, B(p, kBeforeAudit));
      AppendBytes<Logic>(result, H<Logic>(hashes, HashKind::kDecision));
      AppendU8<Logic>(result, p.directive);
      break;
    case HashKind::kAfterRoot:
      AppendDomain<Logic>(result, "BL/NATIVE-V3/ROOT/v1", logic);
      AppendBytes<Logic>(result, B(p, kBeforeRoot));
      AppendBytes<Logic>(result, H<Logic>(hashes, HashKind::kSourceRoot));
      AppendBytes<Logic>(result, H<Logic>(hashes, HashKind::kDecision));
      break;
    case HashKind::kAfterState: {
      AppendDomain<Logic>(result, "BL/NATIVE-V3/STATE-ID/v1", logic);
      AppendBytes<Logic>(result, pub.execution_context);
      AppendBytes<Logic>(result, B(p, kMode));
      V64<Logic> one;
      for (size_t i = 0; i < 64; ++i) one[i] = logic.bit(i == 0);
      AppendU64BE<Logic>(result, one);
      V32<Logic> one32;
      for (size_t i = 0; i < 32; ++i) one32[i] = logic.bit(i == 0);
      AppendU32BE<Logic>(result, one32);
      AppendBytes<Logic>(result, H<Logic>(hashes, HashKind::kAfterAudit));
      AppendBytes<Logic>(result, H<Logic>(hashes, HashKind::kAfterRoot));
      break;
    }
    case HashKind::kSourceAddress:
      AppendDomain<Logic>(result, "BL/NATIVE-V3/STATE-ADDRESS/v1", logic);
      for (uint8_t c : std::array<uint8_t, 6>{'s','o','u','r','c','e'}) {
        result.push_back(logic.vbit8(c));
      }
      AppendBytes<Logic>(result, B(p, kProvider));
      break;
    case HashKind::kSubjectKey:
      AppendDomain<Logic>(result, "BL/NATIVE-V3/SUBJECT-KEY/v1", logic);
      AppendBytes<Logic>(result, B(p, kProvider));
      AppendBytes<Logic>(result, B(p, kCredential));
      AppendBytes<Logic>(result, B(p, kEnrollment));
      break;
    case HashKind::kAuditAddress:
      AppendDomain<Logic>(result, "BL/NATIVE-V3/STATE-ADDRESS/v1", logic);
      for (uint8_t c : std::array<uint8_t, 5>{'a','u','d','i','t'}) {
        result.push_back(logic.vbit8(c));
      }
      AppendBytes<Logic>(result, B(p, kProvider));
      break;
    case HashKind::kJoin:
      AppendDomain<Logic>(result, "BL/NATIVE-V3/DECISION-ACCESS-JOIN/v1", logic);
      AppendBytes<Logic>(result, H<Logic>(hashes, HashKind::kDecision));
      AppendBytes<Logic>(result, B(p, kReadDecision));
      AppendBytes<Logic>(result, B(p, kReadAddress));
      AppendBytes<Logic>(result, B(p, kReadKey));
      AppendBytes<Logic>(result, B(p, kReadBefore));
      AppendBytes<Logic>(result, B(p, kReadAfter));
      AppendBytes<Logic>(result, B(p, kWriteDecision));
      AppendBytes<Logic>(result, B(p, kWriteAddress));
      AppendBytes<Logic>(result, B(p, kWriteKey));
      AppendBytes<Logic>(result, B(p, kWriteBefore));
      AppendBytes<Logic>(result, B(p, kWriteAfter));
      AppendBytes<Logic>(result, pub.state_before_id);
      AppendBytes<Logic>(result, pub.state_after_id);
      break;
    case HashKind::kReceipt:
      AppendDomain<Logic>(result, "BL/NATIVE-V3/RECEIPT-ID/v1", logic);
      AppendBytes<Logic>(result, B(p, kPhase0));
      AppendBytes<Logic>(result, pub.control_set);
      AppendBytes<Logic>(result, H<Logic>(hashes, HashKind::kDecision));
      AppendBytes<Logic>(result, H<Logic>(hashes, HashKind::kJoin));
      AppendBytes<Logic>(result, pub.state_before_id);
      AppendBytes<Logic>(result, pub.state_after_id);
      break;
    case HashKind::kPrivateBatch:
      AppendDomain<Logic>(result, "BL/NATIVE-V3/PRIVATE-BATCH/v1", logic);
      AppendBytes<Logic>(result, B(p, kSourcePayload));
      AppendBytes<Logic>(result, H<Logic>(hashes, HashKind::kDecisionPath));
      AppendBytes<Logic>(result, B(p, kExceptionId));
      AppendBytes<Logic>(result, H<Logic>(hashes, HashKind::kRequest));
      break;
    case HashKind::kSettlement:
      AppendDomain<Logic>(result, "BL/NATIVE-V3/SETTLEMENT/v1", logic);
      AppendU8<Logic>(result, p.directive);
      AppendBytes<Logic>(result, H<Logic>(hashes, HashKind::kDecision));
      AppendBytes<Logic>(result, pub.state_after_id);
      break;
  }
  return result;
}

template <class Logic>
typename Logic::BitW EqualByte(const Logic& logic, const V8<Logic>& a,
                               uint8_t value) {
  typename Logic::BitW result = logic.bit(1);
  const auto b = logic.vbit8(value);
  for (size_t i = 0; i < 8; ++i) {
    result = logic.land(result, logic.lnot(logic.lxor(a[i], b[i])));
  }
  return result;
}

template <class Logic>
typename Logic::BitW LessThan(const Logic& logic, const V64<Logic>& a,
                              const V64<Logic>& b) {
  typename Logic::BitW borrow = logic.bit(0);
  for (size_t i = 0; i < 64; ++i) {
    const auto x = logic.lxor(a[i], b[i]);
    borrow = logic.lor(logic.land(logic.lnot(a[i]), b[i]),
                       logic.land(borrow, logic.lnot(x)));
  }
  return borrow;
}

template <class Logic>
void AssertImplies(const Logic& logic, const typename Logic::BitW& selector,
                   const typename Logic::BitW& condition) {
  (void)logic.assert_implies(selector, condition);
}

template <class Logic>
void AssertDirectiveSemantics(const Logic& logic, const PrivateWires<Logic>& p) {
  const auto clear = EqualByte(logic, p.directive, 1);
  const auto hold = EqualByte(logic, p.directive, 2);
  const auto human = EqualByte(logic, p.directive, 3);
  const auto block = EqualByte(logic, p.directive, 4);
  const auto exception = EqualByte(logic, p.directive, 5);
  const auto valid = logic.lor(clear, logic.lor(hold, logic.lor(human,
                              logic.lor(block, exception))));
  (void)logic.assert1(valid);

  AssertImplies(logic, clear, EqualByte(logic, p.policy, 1));
  AssertImplies(logic, hold, EqualByte(logic, p.policy, 2));
  AssertImplies(logic, human, EqualByte(logic, p.policy, 3));
  AssertImplies(logic, block, EqualByte(logic, p.policy, 4));
  AssertImplies(logic, exception, EqualByte(logic, p.policy, 4));
  AssertImplies(logic, clear, EqualByte(logic, p.complete, 1));
  AssertImplies(logic, hold, EqualByte(logic, p.complete, 1));
  AssertImplies(logic, human, EqualByte(logic, p.complete, 0));
  AssertImplies(logic, block, EqualByte(logic, p.complete, 1));
  AssertImplies(logic, exception, EqualByte(logic, p.complete, 1));
  AssertImplies(logic, clear, EqualByte(logic, p.membership, 1));
  AssertImplies(logic, hold, EqualByte(logic, p.membership, 0));
  AssertImplies(logic, human, EqualByte(logic, p.membership, 0));
  AssertImplies(logic, block, EqualByte(logic, p.membership, 1));
  AssertImplies(logic, exception, EqualByte(logic, p.membership, 1));
  AssertImplies(logic, clear, EqualByte(logic, p.absence, 0));
  AssertImplies(logic, hold, EqualByte(logic, p.absence, 1));
  AssertImplies(logic, human, EqualByte(logic, p.absence, 0));
  AssertImplies(logic, block, EqualByte(logic, p.absence, 0));
  AssertImplies(logic, exception, EqualByte(logic, p.absence, 0));
  AssertImplies(logic, clear, EqualByte(logic, p.active, 1));
  AssertImplies(logic, hold, EqualByte(logic, p.active, 0));
  AssertImplies(logic, human, EqualByte(logic, p.active, 0));
  AssertImplies(logic, block, EqualByte(logic, p.active, 0));
  AssertImplies(logic, exception, EqualByte(logic, p.active, 0));
  AssertImplies(logic, clear, EqualByte(logic, p.exception_present, 0));
  AssertImplies(logic, hold, EqualByte(logic, p.exception_present, 0));
  AssertImplies(logic, human, EqualByte(logic, p.exception_present, 0));
  AssertImplies(logic, block, EqualByte(logic, p.exception_present, 0));
  AssertImplies(logic, exception, EqualByte(logic, p.exception_present, 1));
  (void)logic.assert0(logic.as_scalar(p.proof_accepted));
  (void)logic.assert0(logic.as_scalar(p.economic_mutation));
}

template <class Logic>
void BindHash(const Logic& logic, proofs::Sha3Circuit<Logic>& sha3,
              HashKind kind, const PublicWires<Logic>& pub,
              const PrivateWires<Logic>& p, HashWires<Logic>& hashes) {
  const auto seed = SeedFor(kind, pub, p, hashes, logic);
#if defined(BLIND_LEDGER_LONGFELLOW_NO_SHA3_WITNESS)
  std::vector<V8<Logic>> output;
  sha3.assert_sha3_512_no_witness(seed, output);
#else
  const size_t blocks = (seed.size() + 72) / 72;
  std::vector<typename proofs::Sha3Circuit<Logic>::BlockWitness> witnesses(
      blocks);
  for (auto& witness : witnesses) witness.input(logic);
  std::vector<V8<Logic>> output;
  sha3.assert_sha3_512(seed, output, witnesses);
#endif
  for (size_t i = 0; i < kDigestBytes; ++i) {
    hashes[static_cast<size_t>(kind)][i] = output[i];
  }
  const Byte64<Logic>* target = nullptr;
  switch (kind) {
    case HashKind::kSourceRoot: break;
    case HashKind::kCompleteness: break;
    case HashKind::kChronology: target = &B(p, kChronologyId); break;
    case HashKind::kBeforeState: target = &pub.state_before_id; break;
    case HashKind::kRequest: break;
    case HashKind::kReplay: target = &B(p, kReplayId); break;
    case HashKind::kDecision: break;
    case HashKind::kDecisionPath: break;
    case HashKind::kAfterAudit: break;
    case HashKind::kAfterRoot: break;
    case HashKind::kAfterState: target = &pub.state_after_id; break;
    case HashKind::kSourceAddress: target = &B(p, kReadAddress); break;
    case HashKind::kSubjectKey: target = &B(p, kReadKey); break;
    case HashKind::kAuditAddress: target = &B(p, kWriteAddress); break;
    case HashKind::kJoin: break;
    case HashKind::kReceipt: target = &B(p, kReceiptId); break;
    case HashKind::kPrivateBatch: target = &pub.private_batch_commitment; break;
    case HashKind::kSettlement: target = &pub.settlement_commitment; break;
  }
  if (target != nullptr) {
    for (size_t i = 0; i < kDigestBytes; ++i) {
      logic.vassert_eq((*target)[i], output[i]);
    }
  }
}

const HashKind kHashOrder[] = {
    HashKind::kSourceRoot, HashKind::kCompleteness, HashKind::kChronology,
    HashKind::kBeforeState, HashKind::kRequest, HashKind::kReplay,
    HashKind::kDecision, HashKind::kDecisionPath, HashKind::kAfterAudit,
    HashKind::kAfterRoot, HashKind::kAfterState, HashKind::kSourceAddress,
    HashKind::kSubjectKey, HashKind::kAuditAddress, HashKind::kJoin,
    HashKind::kReceipt, HashKind::kPrivateBatch, HashKind::kSettlement,
};

template <class Logic>
void AssertRelation(const Logic& logic, const PublicWires<Logic>& pub,
                    const PrivateWires<Logic>& p) {
  logic.vassert_eq(pub.protocol, 3);
  for (const auto& byte : pub.proof_suite) logic.vassert_eq(byte, 0);
  logic.vassert_eq(pub.epoch, 7);
  logic.vassert_eq(pub.sequence_before, 0);
  AssertDirectiveSemantics(logic, p);
  (void)logic.assert1(LessThan(logic, p.rule_effective_time, p.event_time));
  (void)logic.assert1(LessThan(logic, p.event_time, p.observation_time));
  (void)logic.assert1(LessThan(logic, p.observation_time, p.decision_time));
  logic.vassert_eq(p.read_time, p.observation_time);
  logic.vassert_eq(p.write_time, p.decision_time);
  logic.vassert_eq(p.decision_index, 0);
  logic.vassert_eq(p.decision_count, 1);
  logic.vassert_eq(p.read_access_index, 0);
  logic.vassert_eq(p.write_access_index, 1);
  logic.vassert_eq(p.access_count, 2);
  logic.vassert_eq(p.read_decision_index, 0);
  logic.vassert_eq(p.write_decision_index, 0);
  logic.vassert_eq(p.read_mode, 1);
  logic.vassert_eq(p.write_mode, 2);
}

template <class Logic>
void AssertDerivedAccessRelation(const Logic& logic,
                                 const HashWires<Logic>& hashes,
                                 const PrivateWires<Logic>& p) {
  for (size_t i = 0; i < kDigestBytes; ++i) {
    logic.vassert_eq(B(p, kReadDecision)[i],
                     H<Logic>(hashes, HashKind::kDecision)[i]);
    logic.vassert_eq(B(p, kWriteDecision)[i],
                     H<Logic>(hashes, HashKind::kDecision)[i]);
    logic.vassert_eq(B(p, kReadBefore)[i],
                     H<Logic>(hashes, HashKind::kSourceRoot)[i]);
    logic.vassert_eq(B(p, kReadAfter)[i],
                     H<Logic>(hashes, HashKind::kSourceRoot)[i]);
    logic.vassert_eq(B(p, kWriteKey)[i],
                     H<Logic>(hashes, HashKind::kDecision)[i]);
    logic.vassert_eq(B(p, kWriteBefore)[i], B(p, kBeforeAudit)[i]);
    logic.vassert_eq(B(p, kWriteAfter)[i],
                     H<Logic>(hashes, HashKind::kAfterAudit)[i]);
  }
}

template <class Logic>
void PushDigest(proofs::DenseFiller<RelationField>& filler, const Digest& value,
                const RelationField& field) {
  for (uint8_t byte : value) filler.push_back(byte, 8, field);
}

template <class Logic>
void PushPublic(proofs::DenseFiller<RelationField>& filler,
                const RelationCase& c, const RelationField& field) {
  filler.push_back(field.one());
  filler.push_back(c.statement.protocol_version, 8, field);
  PushDigest<Logic>(filler, c.statement.proof_suite, field);
  PushDigest<Logic>(filler, c.statement.execution_context, field);
  PushDigest<Logic>(filler, c.statement.settlement_domain, field);
  filler.push_back(c.statement.epoch, 64, field);
  filler.push_back(c.statement.sequence_before, 64, field);
  PushDigest<Logic>(filler, c.statement.state_before_id, field);
  PushDigest<Logic>(filler, c.statement.state_after_id, field);
  PushDigest<Logic>(filler, c.statement.governance_snapshot, field);
  PushDigest<Logic>(filler, c.statement.control_set, field);
  PushDigest<Logic>(filler, c.statement.private_batch_commitment, field);
  PushDigest<Logic>(filler, c.statement.settlement_commitment, field);
}

Digest FieldValue(const RelationCase& c, ByteField field) {
  switch (field) {
    case kProvider: return c.provider_id;
    case kCredential: return c.credential_id;
    case kEnrollment: return c.enrollment_id;
    case kAttempt: return c.attempt_id;
    case kMode: return c.mode_id;
    case kRule: return c.rule_id;
    case kPhase0: return c.phase0_receipt_binding;
    case kSourcePayload: return c.source_payload;
    case kSourceRoot: return c.source_root;
    case kCompletenessPayload: return c.completeness_payload;
    case kCompletenessId: return c.completeness_id;
    case kChronologyId: return c.chronology_id;
    case kReplayId: return c.replay_id;
    case kExceptionId: return c.exception_id;
    case kReasonId: return c.reason_id;
    case kRequestId: return c.request_id;
    case kDecisionId: return c.decision_id;
    case kDecisionPathId: return c.decision_path_id;
    case kBeforeAudit: return c.before_audit_head;
    case kBeforeRoot: return c.before_continuity_root;
    case kAfterAudit: return c.after_audit_head;
    case kAfterRoot: return c.after_continuity_root;
    case kReadDecision: return c.read_decision_id;
    case kReadAddress: return c.read_address;
    case kReadKey: return c.read_key;
    case kReadBefore: return c.read_before;
    case kReadAfter: return c.read_after;
    case kWriteDecision: return c.write_decision_id;
    case kWriteAddress: return c.write_address;
    case kWriteKey: return c.write_key;
    case kWriteBefore: return c.write_before;
    case kWriteAfter: return c.write_after;
    case kJoinId: return c.join_id;
    case kReceiptId: return c.receipt_id;
    case kByteFieldCount: break;
  }
  return {};
}

template <class Logic>
void PushPrivate(proofs::DenseFiller<RelationField>& filler,
                 const RelationCase& c, const RelationField& field) {
  filler.push_back(c.effective_directive, 8, field);
  filler.push_back(c.policy_result, 8, field);
  filler.push_back(c.complete, 8, field);
  filler.push_back(c.authoritative_membership, 8, field);
  filler.push_back(c.authoritative_absence, 8, field);
  filler.push_back(c.active_status, 8, field);
  filler.push_back(c.exception_present, 8, field);
  filler.push_back(c.proof_session_accepted, 8, field);
  filler.push_back(c.economic_mutation, 8, field);
  filler.push_back(c.event_time, 64, field);
  filler.push_back(c.observation_time, 64, field);
  filler.push_back(c.rule_effective_time, 64, field);
  filler.push_back(c.decision_time, 64, field);
  filler.push_back(c.read_time, 64, field);
  filler.push_back(c.write_time, 64, field);
  filler.push_back(c.decision_index, 32, field);
  filler.push_back(c.decision_count, 32, field);
  filler.push_back(c.read_access_index, 32, field);
  filler.push_back(c.write_access_index, 32, field);
  filler.push_back(c.access_count, 32, field);
  filler.push_back(c.read_decision_index, 32, field);
  filler.push_back(c.write_decision_index, 32, field);
  filler.push_back(c.read_mode, 8, field);
  filler.push_back(c.write_mode, 8, field);
  for (size_t i = 0; i < kByteFieldCount; ++i) {
    if (IsComputedDigestField(static_cast<ByteField>(i))) continue;
    PushDigest<Logic>(filler, FieldValue(c, static_cast<ByteField>(i)), field);
  }
}

}  // namespace

size_t native_v3_hash_endpoint_count() {
  return sizeof(kHashOrder) / sizeof(kHashOrder[0]);
}

HashKind native_v3_hash_kind_at(size_t index) {
  proofs::check(index < native_v3_hash_endpoint_count(),
                "native-v3 hash endpoint index out of range");
  return kHashOrder[index];
}

std::unique_ptr<proofs::Circuit<RelationField>> build_native_v3_circuit_stage(
    size_t hash_count) {
  proofs::check(hash_count <= native_v3_hash_endpoint_count(),
                "native-v3 hash stage exceeds endpoint count");
  using Backend = proofs::CompilerBackend<RelationField>;
  using Logic = proofs::Logic<RelationField, Backend>;
  auto field = std::make_unique<RelationField>();
  auto builder =
      std::make_unique<proofs::QuadCircuit<RelationField>>(*field);
  const Backend backend(builder.get());
  const Logic logic(&backend, *field);
  std::fprintf(stderr, "RELATION_BUILD phase=public\n");
  auto pub = std::make_unique<PublicWires<Logic>>();
  InputPublic(logic, *pub);
  builder->private_input();
  std::fprintf(stderr, "RELATION_BUILD phase=private\n");
  auto priv = std::make_unique<PrivateWires<Logic>>();
  InputPrivate(logic, *priv);
  proofs::Sha3Circuit<Logic> sha3(logic);
  std::fprintf(stderr, "RELATION_BUILD phase=assertions\n");
  AssertRelation(logic, *pub, *priv);
  HashWires<Logic> hashes{};
  size_t hash_index = 0;
  for (HashKind kind : kHashOrder) {
    if (hash_index == hash_count) break;
    std::fprintf(stderr, "RELATION_BUILD phase=sha3 index=%zu kind=%zu\n",
                 hash_index++, static_cast<size_t>(kind));
    BindHash(logic, sha3, kind, *pub, *priv, hashes);
  }
  if (hash_count == native_v3_hash_endpoint_count()) {
    AssertDerivedAccessRelation(logic, hashes, *priv);
  }
  std::fprintf(stderr, "RELATION_BUILD phase=mkcircuit\n");
  const auto mkcircuit_start = std::chrono::steady_clock::now();
  auto circuit = builder->mkcircuit(1);
  const auto mkcircuit_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                std::chrono::steady_clock::now() -
                                mkcircuit_start)
                                .count();
  std::fprintf(stderr, "RELATION_BUILD phase=complete mkcircuit_ms=%lld\n",
               static_cast<long long>(mkcircuit_ms));
  return circuit;
}

std::unique_ptr<proofs::Circuit<RelationField>> build_native_v3_circuit() {
  return build_native_v3_circuit_stage(native_v3_hash_endpoint_count());
}

#ifndef BLIND_LEDGER_RELATION_CIRCUIT_ONLY
void fill_native_v3_public(const RelationCase& fixture,
                           proofs::Dense<RelationField>& public_input) {
  const RelationField field;
  proofs::DenseFiller<RelationField> filler(public_input);
  using Logic = proofs::Logic<RelationField, proofs::CompilerBackend<RelationField>>;
  PushPublic<Logic>(filler, fixture, field);
}

void fill_native_v3_witness(const RelationCase& fixture,
                            proofs::Dense<RelationField>& witness) {
  const RelationField field;
  proofs::DenseFiller<RelationField> filler(witness);
  using Logic = proofs::Logic<RelationField, proofs::CompilerBackend<RelationField>>;
  PushPublic<Logic>(filler, fixture, field);
  PushPrivate<Logic>(filler, fixture, field);
  for (HashKind kind : kHashOrder) {
#if !defined(BLIND_LEDGER_LONGFELLOW_NO_SHA3_WITNESS)
    const auto input = build_hash_input(fixture, kind);
    std::vector<Sha3BlockWitness> witnesses;
    compute_sha3_512_witness(input, witnesses);
    proofs::Sha3Witness::fill_witness(filler, witnesses, field);
#endif
  }
}

std::vector<uint8_t> native_v3_public_bytes(const RelationCase& fixture) {
  std::vector<uint8_t> bytes;
  bytes.push_back(fixture.statement.protocol_version);
  bytes.insert(bytes.end(), fixture.statement.proof_suite.begin(),
               fixture.statement.proof_suite.end());
  bytes.insert(bytes.end(), fixture.statement.execution_context.begin(),
               fixture.statement.execution_context.end());
  bytes.insert(bytes.end(), fixture.statement.settlement_domain.begin(),
               fixture.statement.settlement_domain.end());
  for (size_t i = 0; i < 8; ++i) bytes.push_back(fixture.statement.epoch >> (56 - 8 * i));
  for (size_t i = 0; i < 8; ++i) bytes.push_back(fixture.statement.sequence_before >> (56 - 8 * i));
  for (const Digest* d : {&fixture.statement.state_before_id,
                           &fixture.statement.state_after_id,
                           &fixture.statement.governance_snapshot,
                           &fixture.statement.control_set,
                           &fixture.statement.private_batch_commitment,
                           &fixture.statement.settlement_commitment}) {
    bytes.insert(bytes.end(), d->begin(), d->end());
  }
  return bytes;
}

#endif  // BLIND_LEDGER_RELATION_CIRCUIT_ONLY

std::string native_v3_hex(const uint8_t* bytes, size_t length) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string result;
  result.reserve(length * 2);
  for (size_t i = 0; i < length; ++i) {
    result.push_back(kHex[bytes[i] >> 4]);
    result.push_back(kHex[bytes[i] & 0x0f]);
  }
  return result;
}

}  // namespace blind_ledger_longfellow
