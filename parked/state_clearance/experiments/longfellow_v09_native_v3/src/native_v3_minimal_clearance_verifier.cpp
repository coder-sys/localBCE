#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#include <share.h>
#include <windows.h>
#include <psapi.h>
#endif
#include <memory>
#include <limits>
#include <string>
#include <vector>
#include <iostream>

#include "arrays/dense.h"
#include "circuits/tests/sha3/sha3_reference.h"
#include "gf2k/lch14_reed_solomon.h"
#include "native_v3_minimal_clearance_proof_artifact.h"
#include "native_v3_minimal_clearance_relation.h"
#include "random/transcript.h"
#include "util/log.h"
#include "util/readbuffer.h"
#include "zk/zk_proof.h"
#include "zk/zk_verifier.h"

namespace {

using blind_ledger_longfellow::minimal_clearance::Digest;
using blind_ledger_longfellow::minimal_clearance::PublicStatement;
using blind_ledger_longfellow::minimal_clearance::ProofRole;
using RelationField =
    blind_ledger_longfellow::minimal_clearance::RelationField;
using namespace blind_ledger_longfellow::minimal_clearance;
using namespace blind_ledger_longfellow::minimal_clearance_proof;

constexpr uint32_t kStreamingFrameVersion = 1;
inline constexpr std::array<uint8_t, 8> kStreamingFrameMagic = {
    'B', 'L', 'M', 'C', 'S', 'T', 'R', '1'};
constexpr uint32_t kStreamingCountOne = 1;
constexpr uint32_t kStreamingCountTwo = 2;
constexpr uint32_t kStreamingCountFour = 4;
constexpr uint32_t kStreamingCountEight = 8;
constexpr uint64_t kStreamingMaxAggregateBytes = 2ULL * 1024ULL * 1024ULL * 1024ULL;
constexpr uint64_t kStreamingMaxArtifactBytes =
    static_cast<uint64_t>(
        blind_ledger_longfellow::minimal_clearance_proof::kHeaderBytes) +
    blind_ledger_longfellow::minimal_clearance_proof::kPublicStatementBytes +
    blind_ledger_longfellow::minimal_clearance_proof::kMaxProofBytes;

using SteadyClock = std::chrono::steady_clock;

struct PrivateCommitSample {
  uint64_t bytes = 0;
  bool available = false;
};

PrivateCommitSample QueryCurrentPrivateCommit() {
#ifdef _WIN32
  using GetProcessMemoryInfoFunction = BOOL(WINAPI*)(
      HANDLE, PPROCESS_MEMORY_COUNTERS, DWORD);
  HMODULE psapi = LoadLibraryW(L"psapi.dll");
  if (psapi == nullptr) return {};
  const auto query = reinterpret_cast<GetProcessMemoryInfoFunction>(
      GetProcAddress(psapi, "GetProcessMemoryInfo"));
  if (query == nullptr) {
    FreeLibrary(psapi);
    return {};
  }
  PROCESS_MEMORY_COUNTERS_EX counters{};
  counters.cb = sizeof(counters);
  const BOOL ok = query(
      GetCurrentProcess(), reinterpret_cast<PPROCESS_MEMORY_COUNTERS>(&counters),
      sizeof(counters));
  const uint64_t bytes = ok ? static_cast<uint64_t>(counters.PrivateUsage) : 0;
  FreeLibrary(psapi);
  return {bytes, ok && bytes != 0};
#else
  return {};
#endif
}

struct VerificationTimings {
  uint64_t parse_reconstruct_ns = 0;
  uint64_t fresh_verifier_setup_ns = 0;
  uint64_t verify_final_check_ns = 0;
};

struct StreamingItemTelemetry {
  Digest statement_digest{};
  VerificationTimings timings{};
};

uint64_t ElapsedNanoseconds(SteadyClock::time_point start,
                            SteadyClock::time_point end) {
  return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                                   end - start)
                                   .count());
}

constexpr size_t kDigestCount = 26;
constexpr size_t kProtocolOffset = 0;
constexpr size_t kRoleOffset = 1;
constexpr size_t kDigestOffset = kRoleOffset + kProofRoleBytes;
constexpr size_t kEpochOffset = kDigestOffset + kDigestCount * kDigestBytes;
constexpr size_t kSequenceOffset = kEpochOffset + 8;
constexpr size_t kFlagsOffset = kEpochOffset + 16;
constexpr size_t kPredecessorOffset = kFlagsOffset + 4;
constexpr size_t kStateOffset = kPredecessorOffset + kPredecessorStateBytes;
constexpr size_t kStateHeaderAndScalars = 150;
constexpr size_t kStateDigestOffset = kStateOffset + kStateHeaderAndScalars;

static_assert(kStateOffset + kStateCommitmentBytes ==
              blind_ledger_longfellow::minimal_clearance::kPublicStatementBytes);

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

void PutU32(std::vector<uint8_t>& output, size_t offset, uint32_t value) {
  for (size_t index = 0; index < 4; ++index) {
    output[offset + index] = static_cast<uint8_t>(value >> (24 - index * 8));
  }
}

void PutU64(std::vector<uint8_t>& output, size_t offset, uint64_t value) {
  for (size_t index = 0; index < 8; ++index) {
    output[offset + index] = static_cast<uint8_t>(value >> (56 - index * 8));
  }
}

std::vector<uint8_t> Domain(const char* text) {
  const size_t length = std::strlen(text);
  std::vector<uint8_t> output(text, text + length);
  output.push_back(0);
  return output;
}

std::vector<uint8_t> ToVector(const Digest& value) {
  return std::vector<uint8_t>(value.begin(), value.end());
}

Digest HashBytes(const std::vector<uint8_t>& input) {
  proofs::Sha3Reference reference(kDigestBytes);
  reference.update(reinterpret_cast<const char*>(input.data()), input.size());
  Digest output{};
  reference.final(output.data());
  return output;
}

Digest HashParts(const std::vector<uint8_t>& domain,
                const std::vector<std::vector<uint8_t>>& parts) {
  std::vector<uint8_t> input = domain;
  for (const auto& part : parts) Append(input, part);
  return HashBytes(input);
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

Digest StateLayoutId() {
  std::vector<uint8_t> literal(kStateLayoutLiteral,
                               kStateLayoutLiteral + kStateLayoutLiteralBytes);
  return HashParts(Domain(kStateLayoutDomain), {literal});
}

std::vector<uint8_t> U64Bytes(uint64_t value) {
  std::vector<uint8_t> output;
  AppendU64(output, value);
  return output;
}

Digest NoAuthorizedAmountCommitment() {
  return HashParts(Domain(kNoAuthorizedAmountDomain), {});
}

Digest CanonicalStateId(const Digest& execution_context, uint64_t sequence,
                        const std::vector<uint8_t>& state_bytes) {
  return HashParts(
      Domain(kStateIdDomain),
      {ToVector(execution_context), U64Bytes(sequence),
       ToVector(StateLayoutId()), std::vector<uint8_t>{0, 0, 0, 1},
      U64Bytes(state_bytes.size()), state_bytes});
}

std::vector<uint8_t> GenesisStateBytes() {
  std::vector<uint8_t> state(kStateCommitmentBytes, 0);
  state[0] = 'B';
  state[1] = 'L';
  state[2] = 'S';
  state[3] = 'T';
  state[4] = kStateVersion;
  for (size_t index = 0; index < 8; ++index) {
    state[16 + index] = static_cast<uint8_t>(
        kStateGenesisEpoch >> (56 - index * 8));
  }
  state[470] = 0xe0;
  state[534] = 0xe0;
  const Digest no_authorized_amount = NoAuthorizedAmountCommitment();
  std::copy(no_authorized_amount.begin(), no_authorized_amount.end(),
            state.begin() + kStateProposedCommitmentOffset);
  return state;
}

std::vector<uint8_t> SourceRootInput(const Digest& provider,
                                     const Digest& credential,
                                     const Digest& enrollment,
                                     const Digest& subject,
                                     const Digest& attempt) {
  std::vector<uint8_t> output = Domain("BL/NATIVE-V3/SOURCE-ROOT/v1");
  Append(output, provider);
  Append(output, credential);
  Append(output, enrollment);
  Append(output, subject);
  Append(output, attempt);
  AppendU8(output, 1);
  AppendU8(output, 1);
  AppendU8(output, 1);
  AppendU8(output, 0);
  return output;
}

std::vector<uint8_t> CompletenessInput(const Digest& provider,
                                       const Digest& credential,
                                       const Digest& subject,
                                       const Digest& attempt) {
  std::vector<uint8_t> output = Domain("BL/NATIVE-V3/COMPLETENESS/v1");
  Append(output, provider);
  Append(output, credential);
  Append(output, subject);
  Append(output, attempt);
  AppendU8(output, 1);
  AppendU8(output, 0);
  return output;
}

void AppendStateDigests(std::vector<uint8_t>& output,
                        const PublicStatement& statement,
                        const Digest& before_audit, const Digest& after_audit,
                        const Digest& before_root, const Digest& after_root,
                        const Digest& source_address, const Digest& source_key,
                        const Digest& audit_address) {
  const Digest* digests[] = {
      &statement.source_root_id,
      &statement.completeness_id,
      &statement.subject_id,
      &statement.attempt_id,
      &statement.request_id,
      &statement.exception_id,
      &statement.exception_scope_id,
      &statement.rule_id,
      &statement.decision_id,
      &before_audit,
      &after_audit,
      &before_root,
      &after_root,
      &statement.decision_id,
      &source_address,
      &source_key,
      &statement.source_root_id,
      &statement.source_root_id,
      &statement.decision_id,
      &audit_address,
      &statement.decision_id,
      &before_audit,
      &after_audit,
  };
  for (const Digest* digest : digests) Append(output, *digest);
}

std::vector<uint8_t> StateCommitmentBytes(const PublicStatement& statement,
                                          const Digest& before_audit,
                                          const Digest& after_audit,
                                          const Digest& before_root,
                                          const Digest& after_root,
                                          const Digest& source_address,
                                          const Digest& source_key,
                                          const Digest& audit_address) {
  std::vector<uint8_t> output;
  output.reserve(kStateCommitmentBytes);
  output.insert(output.end(), {'B', 'L', 'S', 'T'});
  AppendU8(output, kStateVersion);
  AppendU8(output, 1);  // policyResult = PASS
  AppendU8(output, 1);  // effectiveDirective = CLEAR
  AppendU8(output, 1);  // complete
  AppendU8(output, 1);  // authoritative membership
  AppendU8(output, 0);  // authoritative absence
  AppendU8(output, 1);  // active
  AppendU8(output, 0);  // exception present
  AppendU8(output, 0);  // exception authorized
  AppendU8(output, 0);  // economic mutation
  AppendU8(output, 0);  // marker before
  AppendU8(output, 1);  // marker after
  AppendU64(output, statement.epoch);
  AppendU64(output, statement.sequence_before);
  AppendU64(output, 6999);
  AppendU64(output, 7000);
  AppendU64(output, 7001);
  AppendU64(output, 7002);
  AppendU64(output, 7001);
  AppendU64(output, 7002);
  AppendU64(output, 0);
  AppendU64(output, 0);
  AppendU64(output, 12);
  AppendU32(output, 0);
  AppendU32(output, 1);
  AppendU32(output, 0);
  AppendU32(output, 1);
  AppendU32(output, 2);
  AppendU32(output, 0);
  AppendU32(output, 0);
  AppendU8(output, 1);  // READ
  AppendU8(output, 2);  // WRITE
  AppendU64(output, 0);
  AppendU64(output, 1);
  AppendStateDigests(output, statement, before_audit, after_audit, before_root,
                     after_root, source_address, source_key, audit_address);
  const Digest no_authorized_amount = NoAuthorizedAmountCommitment();
  Append(output, no_authorized_amount);
  return output;
}

PublicStatement BuildVerifierStaticStatement() {
  PublicStatement statement;
  statement.protocol_version = 3;
  for (size_t index = 0; index < kProofRoleBytes; ++index) {
    statement.proof_role[index] = static_cast<uint8_t>(kProofRole[index]);
  }
  statement.proof_suite.fill(0);
  const Digest provider =
      HashText("BL/NATIVE-V3/SYNTHETIC-PROVIDER/v1", "provider-1");
  const Digest credential =
      HashText("BL/NATIVE-V3/SYNTHETIC-CREDENTIAL/v1", "credential-1");
  const Digest enrollment =
      HashText("BL/NATIVE-V3/SYNTHETIC-ENROLLMENT/v1", "enrollment-1");
  const Digest before_audit =
      HashText("BL/NATIVE-V3/AUDIT-HEAD/v1", "empty");
  const Digest before_root = HashText("BL/NATIVE-V3/ROOT/v1", "empty");

  statement.execution_context = ExecutionContextId();
  statement.source_registry_snapshot =
      HashText("BL/NATIVE-V3/SOURCE-REGISTRY-SNAPSHOT/v2", "snapshot-1");
  statement.source_profile =
      HashText("BL/NATIVE-V3/SOURCE-PROFILE/v2", "synthetic-authoritative");
  statement.governance_snapshot =
      HashText("BL/NATIVE-V3/GOVERNANCE-SNAPSHOT/v3", "governance-1");
  statement.automatic_control_set = HashText(
      "BL/NATIVE-V3/CONTROL-SET/v3",
      "CLEAR,HOLD,HUMAN_REVIEW,BLOCK,EXCEPTION_APPROVED");
  statement.settlement_domain =
      HashText("BL/NATIVE-V3/SETTLEMENT-DOMAIN/v3", "official-state-rail");
  statement.evaluator_id =
      HashText("BL/NATIVE-V3/EVALUATOR/v2", "minimal-clearance-evaluator");
  statement.schema_id =
      HashText("BL/NATIVE-V3/SCHEMA/v2", "minimal-clearance-schema");
  statement.program_id =
      HashText("BL/NATIVE-V3/PROGRAM/v2", "minimal-clearance-program");
  statement.policy_id =
      HashText("BL/NATIVE-V3/POLICY/v2", "minimal-five-directive-policy");
  statement.attempt_id =
      HashText("BL/NATIVE-V3/ATTEMPT/v1", "clear");
  statement.subject_id = HashParts(
      Domain("BL/NATIVE-V3/OPERATION-SUBJECT/v1"),
      {ToVector(statement.execution_context), ToVector(statement.attempt_id),
       U64Bytes(0)});
  statement.active = 1;
  statement.complete = 1;
  statement.authoritative_membership = 1;
  statement.authoritative_absence = 0;
  statement.epoch = 7;
  statement.sequence_before = 0;
  statement.source_root_id = HashBytes(SourceRootInput(
      provider, credential, enrollment, statement.subject_id,
      statement.attempt_id));
  statement.completeness_id =
      HashBytes(CompletenessInput(provider, credential, statement.subject_id,
                                  statement.attempt_id));
  statement.source_address =
      HashParts(Domain("BL/NATIVE-V3/STATE-ADDRESS/v2"),
                {std::vector<uint8_t>{'s', 'o', 'u', 'r', 'c', 'e'},
                 ToVector(statement.subject_id),
                 ToVector(statement.attempt_id)});
  statement.source_key =
      HashParts(Domain("BL/NATIVE-V3/SUBJECT-KEY/v2"),
                {ToVector(statement.subject_id),
                 ToVector(statement.attempt_id)});
  statement.audit_address =
      HashParts(Domain("BL/NATIVE-V3/STATE-ADDRESS/v2"),
                {std::vector<uint8_t>{'a', 'u', 'd', 'i', 't'},
                 ToVector(statement.subject_id),
                 ToVector(statement.attempt_id)});
  statement.exception_id = Sentinel();
  statement.exception_scope_id = Sentinel();
  statement.rule_id =
      HashText("BL/NATIVE-V3/RULE/v1", "synthetic-rule-v1");
  const std::vector<uint8_t> genesis_state = GenesisStateBytes();
  std::copy(genesis_state.begin(), genesis_state.end(),
            statement.predecessor_state_bytes.begin());
  statement.state_before_id = CanonicalStateId(
      statement.execution_context, statement.sequence_before, genesis_state);
  statement.request_id = HashParts(
      Domain("BL/NATIVE-V3/REQUEST-ID/v2"),
      {ToVector(statement.subject_id), ToVector(statement.attempt_id),
       U64Bytes(statement.epoch), U64Bytes(statement.sequence_before),
       ToVector(statement.state_before_id)});
  statement.decision_id = HashParts(
      Domain("BL/NATIVE-V3/MINIMAL-DECISION/v2"),
      {ToVector(statement.request_id), ToVector(statement.source_root_id),
       ToVector(statement.completeness_id), std::vector<uint8_t>{1, 1},
       ToVector(statement.exception_id),
       ToVector(NoAuthorizedAmountCommitment())});
  const Digest after_audit = HashParts(
      Domain("BL/NATIVE-V3/MINIMAL-AUDIT-HEAD/v1"),
      {ToVector(before_audit), ToVector(statement.decision_id),
       std::vector<uint8_t>{1}});
  const Digest after_root = HashParts(
      Domain("BL/NATIVE-V3/MINIMAL-CONTINUITY-ROOT/v1"),
      {ToVector(before_root), ToVector(statement.source_root_id),
       ToVector(statement.decision_id)});
  statement.state_commitment_bytes = {};
  const std::vector<uint8_t> state_bytes = StateCommitmentBytes(
      statement, before_audit, after_audit, before_root, after_root,
      statement.source_address, statement.source_key, statement.audit_address);
  std::copy(state_bytes.begin(), state_bytes.end(),
            statement.state_commitment_bytes.begin());
  statement.state_after_id = CanonicalStateId(
      statement.execution_context, statement.sequence_before + 1, state_bytes);
  const Digest source_payload = HashParts(
      Domain("BL/NATIVE-V3/SOURCE-PAYLOAD/v1"),
      {ToVector(provider), ToVector(credential), ToVector(enrollment),
       std::vector<uint8_t>{1, 1, 1, 0}});
  statement.private_batch_commitment = HashParts(
      Domain("BL/NATIVE-V3/PRIVATE-BATCH/v3"),
      {ToVector(statement.source_registry_snapshot),
       ToVector(statement.source_profile), ToVector(statement.subject_id),
       ToVector(statement.source_root_id), ToVector(statement.completeness_id),
       ToVector(provider), ToVector(credential), ToVector(enrollment),
       ToVector(source_payload),
       ToVector(HashParts(Domain("BL/NATIVE-V3/SOURCE-NONCE/v1"),
                          {ToVector(statement.execution_context),
                           ToVector(statement.attempt_id), U64Bytes(0)})),
       ToVector(statement.source_address), ToVector(statement.source_key),
       ToVector(statement.audit_address), ToVector(statement.rule_id),
       U64Bytes(6999), U64Bytes(7000), U64Bytes(7001), U64Bytes(7002),
       std::vector<uint8_t>{1, 1, 1, 0}});
  return statement;
}

std::vector<uint8_t> SerializeStatement(const PublicStatement& statement) {
  std::vector<uint8_t> output;
  output.reserve(
      blind_ledger_longfellow::minimal_clearance::kPublicStatementBytes);
  AppendU8(output, statement.protocol_version);
  output.insert(output.end(), statement.proof_role.begin(),
                statement.proof_role.end());
  const Digest* digests[] = {
      &statement.proof_suite,
      &statement.execution_context,
      &statement.source_registry_snapshot,
      &statement.source_profile,
      &statement.governance_snapshot,
      &statement.automatic_control_set,
      &statement.settlement_domain,
      &statement.evaluator_id,
      &statement.schema_id,
      &statement.program_id,
      &statement.policy_id,
      &statement.subject_id,
      &statement.attempt_id,
      &statement.request_id,
      &statement.source_root_id,
      &statement.completeness_id,
      &statement.private_batch_commitment,
      &statement.source_address,
      &statement.source_key,
      &statement.audit_address,
      &statement.exception_id,
      &statement.exception_scope_id,
      &statement.rule_id,
      &statement.decision_id,
      &statement.state_before_id,
      &statement.state_after_id,
  };
  for (const Digest* digest : digests) Append(output, *digest);
  AppendU64(output, statement.epoch);
  AppendU64(output, statement.sequence_before);
  AppendU8(output, statement.active);
  AppendU8(output, statement.complete);
  AppendU8(output, statement.authoritative_membership);
  AppendU8(output, statement.authoritative_absence);
  output.insert(output.end(), statement.predecessor_state_bytes.begin(),
                statement.predecessor_state_bytes.end());
  output.insert(output.end(), statement.state_commitment_bytes.begin(),
                statement.state_commitment_bytes.end());
  return output;
}

bool ReadBytes(const std::vector<uint8_t>& bytes, size_t& offset, size_t count,
               uint8_t* output) {
  if (offset > bytes.size() || count > bytes.size() - offset) return false;
  std::copy_n(bytes.begin() + offset, count, output);
  offset += count;
  return true;
}

bool ReadU8(const std::vector<uint8_t>& bytes, size_t& offset, uint8_t& value) {
  return ReadBytes(bytes, offset, 1, &value);
}

bool ReadU64(const std::vector<uint8_t>& bytes, size_t& offset,
             uint64_t& value) {
  uint8_t encoded[8]{};
  if (!ReadBytes(bytes, offset, sizeof(encoded), encoded)) return false;
  value = 0;
  for (uint8_t byte : encoded) value = (value << 8) | byte;
  return true;
}

bool DecodeStatement(const std::vector<uint8_t>& bytes,
                     PublicStatement& statement, std::string& reason) {
  if (bytes.size() !=
      blind_ledger_longfellow::minimal_clearance::kPublicStatementBytes) {
    reason = "statement.length";
    return false;
  }
  size_t offset = 0;
  if (!ReadU8(bytes, offset, statement.protocol_version) ||
      !ReadBytes(bytes, offset, kProofRoleBytes,
                 statement.proof_role.data())) {
    reason = "statement.header";
    return false;
  }
  Digest* digests[] = {
      &statement.proof_suite,
      &statement.execution_context,
      &statement.source_registry_snapshot,
      &statement.source_profile,
      &statement.governance_snapshot,
      &statement.automatic_control_set,
      &statement.settlement_domain,
      &statement.evaluator_id,
      &statement.schema_id,
      &statement.program_id,
      &statement.policy_id,
      &statement.subject_id,
      &statement.attempt_id,
      &statement.request_id,
      &statement.source_root_id,
      &statement.completeness_id,
      &statement.private_batch_commitment,
      &statement.source_address,
      &statement.source_key,
      &statement.audit_address,
      &statement.exception_id,
      &statement.exception_scope_id,
      &statement.rule_id,
      &statement.decision_id,
      &statement.state_before_id,
      &statement.state_after_id,
  };
  for (Digest* digest : digests) {
    if (!ReadBytes(bytes, offset, kDigestBytes, digest->data())) {
      reason = "statement.digest";
      return false;
    }
  }
  if (!ReadU64(bytes, offset, statement.epoch) ||
      !ReadU64(bytes, offset, statement.sequence_before) ||
      !ReadU8(bytes, offset, statement.active) ||
      !ReadU8(bytes, offset, statement.complete) ||
      !ReadU8(bytes, offset, statement.authoritative_membership) ||
      !ReadU8(bytes, offset, statement.authoritative_absence) ||
      !ReadBytes(bytes, offset, kPredecessorStateBytes,
                 statement.predecessor_state_bytes.data()) ||
      !ReadBytes(bytes, offset, kStateCommitmentBytes,
                 statement.state_commitment_bytes.data())) {
    reason = "statement.tail";
    return false;
  }
  if (offset != bytes.size()) {
    reason = "statement.trailing";
    return false;
  }
  return true;
}

bool ValidateStaticStatement(const PublicStatement& actual,
                             const PublicStatement& profile,
                             std::string& reason) {
  if (actual.protocol_version != 3) {
    reason = "statement.protocol";
    return false;
  }
  ProofRole role{};
  for (size_t index = 0; index < kProofRoleBytes; ++index) {
    role[index] = static_cast<uint8_t>(kProofRole[index]);
  }
  if (actual.proof_role != role) {
    reason = "statement.role";
    return false;
  }
  if (std::any_of(actual.proof_suite.begin(), actual.proof_suite.end(),
                  [](uint8_t byte) { return byte != 0; })) {
    reason = "statement.proof-suite";
    return false;
  }
  const Digest* actual_digests[] = {
      &actual.execution_context, &actual.source_registry_snapshot,
      &actual.source_profile, &actual.governance_snapshot,
      &actual.automatic_control_set, &actual.settlement_domain,
      &actual.evaluator_id, &actual.schema_id, &actual.program_id,
      &actual.policy_id, &actual.rule_id};
  const Digest* profile_digests[] = {
      &profile.execution_context, &profile.source_registry_snapshot,
      &profile.source_profile, &profile.governance_snapshot,
      &profile.automatic_control_set, &profile.settlement_domain,
      &profile.evaluator_id, &profile.schema_id, &profile.program_id,
      &profile.policy_id, &profile.rule_id};
  for (size_t index = 0; index < std::size(actual_digests); ++index) {
    if (*actual_digests[index] != *profile_digests[index]) {
      reason = "statement.static-profile";
      return false;
    }
  }
  if (actual.epoch != profile.epoch) {
    reason = "statement.epoch";
    return false;
  }
  return true;
}

std::string CircuitId(
    const std::unique_ptr<proofs::Circuit<RelationField>>& circuit) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string result;
  result.reserve(sizeof(circuit->id) * 2);
  for (uint8_t byte : circuit->id) {
    result.push_back(kHex[byte >> 4]);
    result.push_back(kHex[byte & 0xf]);
  }
  return result;
}

std::string HexDigest(const Digest& digest) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string result;
  result.reserve(digest.size() * 2);
  for (uint8_t byte : digest) {
    result.push_back(kHex[byte >> 4]);
    result.push_back(kHex[byte & 0xf]);
  }
  return result;
}

bool ReadVerifyStdinBytes(std::vector<uint8_t>& bytes, std::string& error) {
#ifdef _WIN32
  const HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
  if (input == nullptr || input == INVALID_HANDLE_VALUE ||
      GetFileType(input) != FILE_TYPE_DISK) {
    error = "stdin-handle";
    return false;
  }
  BY_HANDLE_FILE_INFORMATION before{};
  if (!GetFileInformationByHandle(input, &before) ||
      (before.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0 ||
      before.nNumberOfLinks != 1) {
    error = "stdin-identity";
    return false;
  }
  LARGE_INTEGER size{};
  if (!GetFileSizeEx(input, &size) || size.QuadPart < 0) {
    error = "stdin-size";
    return false;
  }
  const uint64_t before_size =
      (static_cast<uint64_t>(before.nFileSizeHigh) << 32) |
      static_cast<uint64_t>(before.nFileSizeLow);
  if (static_cast<uint64_t>(size.QuadPart) != before_size) {
    error = "stdin-identity";
    return false;
  }
  const uint64_t maximum = kHeaderBytes +
                           blind_ledger_longfellow::minimal_clearance::
                               kPublicStatementBytes +
                           kMaxProofBytes;
  if (static_cast<uint64_t>(size.QuadPart) > maximum) {
    error = "stdin-size-cap";
    return false;
  }
  bytes.assign(static_cast<size_t>(size.QuadPart), 0);
  LARGE_INTEGER origin{};
  if (!SetFilePointerEx(input, origin, nullptr, FILE_BEGIN)) {
    error = "stdin-seek";
    return false;
  }
  size_t offset = 0;
  while (offset < bytes.size()) {
    const DWORD request = static_cast<DWORD>(std::min<size_t>(
        bytes.size() - offset, 1u << 20));
    DWORD received = 0;
    if (!ReadFile(input, bytes.data() + offset, request, &received, nullptr) ||
        received == 0) {
      error = "stdin-short";
      return false;
    }
    offset += received;
  }
  uint8_t trailing = 0;
  DWORD received = 0;
  if (!ReadFile(input, &trailing, 1, &received, nullptr)) {
    error = "stdin-trailing-read";
    return false;
  }
  if (received != 0) {
    error = "stdin-trailing";
    return false;
  }
  if (!SetFilePointerEx(input, origin, nullptr, FILE_BEGIN)) {
    error = "stdin-reset";
    return false;
  }
  BY_HANDLE_FILE_INFORMATION after{};
  if (!GetFileInformationByHandle(input, &after) ||
      (after.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0 ||
      after.nNumberOfLinks != 1 ||
      after.dwVolumeSerialNumber != before.dwVolumeSerialNumber ||
      after.nFileIndexHigh != before.nFileIndexHigh ||
      after.nFileIndexLow != before.nFileIndexLow ||
      after.nFileSizeHigh != before.nFileSizeHigh ||
      after.nFileSizeLow != before.nFileSizeLow) {
    error = "stdin-identity";
    return false;
  }
  return true;
#else
  (void)bytes;
  error = "windows-only";
  return false;
#endif
}

bool FillPublicInput(const PublicStatement& statement,
                     const std::unique_ptr<proofs::Circuit<RelationField>>& circuit,
                     proofs::Dense<RelationField>& public_input,
                     std::string& reason) {
  if (circuit->npub_in !=
      1 + blind_ledger_longfellow::minimal_clearance::kPublicStatementBytes *
              8) {
    reason = "public-input.length";
    return false;
  }
  fill_public_statement(statement, public_input);
  if (public_input.n1_ != circuit->npub_in ||
      public_input.v_[0] != RelationField().one()) {
    reason = "public-input.leading-one";
    return false;
  }
  return true;
}

bool VerifyProof(const Artifact& artifact, const PublicStatement& statement,
                 const std::unique_ptr<proofs::Circuit<RelationField>>& circuit,
                 std::string& reason, VerificationTimings* timings = nullptr,
                 bool emit_stage_logs = true) {
  const SteadyClock::time_point parse_start = SteadyClock::now();
  const RelationField field;
  proofs::Dense<RelationField> public_input(1, circuit->npub_in);
  if (!FillPublicInput(statement, circuit, public_input, reason)) return false;
  try {
    proofs::ZkProof<RelationField> proof(*circuit, kLigeroRate, kLigeroQueries);
    proofs::ReadBuffer buffer(artifact.proof);
    if (!proof.read(buffer, field) || buffer.remaining() != 0) {
      reason = "proof.serialization";
      if (emit_stage_logs) {
        std::fprintf(stderr,
                     "MINIMAL_CLEARANCE_VERIFIER_STAGE proof.read=reject "
                     "remaining=%zu\n",
                     buffer.remaining());
      }
      return false;
    }
    const SteadyClock::time_point setup_start = SteadyClock::now();
    if (timings != nullptr) {
      timings->parse_reconstruct_ns +=
          ElapsedNanoseconds(parse_start, setup_start);
    }
    if (emit_stage_logs) {
      std::fprintf(stderr,
                   "MINIMAL_CLEARANCE_VERIFIER_STAGE proof.read=accept "
                   "remaining=0\n");
    }
    using RSFactory = proofs::LCH14ReedSolomonFactory<RelationField>;
    const RSFactory rs_factory(field);
    proofs::Transcript transcript(
        reinterpret_cast<const uint8_t*>(kTranscriptLabel),
        sizeof(kTranscriptLabel) - 1, kTranscriptVersion);
    proofs::ZkVerifier<RelationField, RSFactory> verifier(
        *circuit, rs_factory, kLigeroRate, kLigeroQueries, field);
    const SteadyClock::time_point verify_start = SteadyClock::now();
    if (timings != nullptr) {
      timings->fresh_verifier_setup_ns =
          ElapsedNanoseconds(setup_start, verify_start);
    }
    verifier.recv_commitment(proof, transcript);
    if (emit_stage_logs) {
      std::fprintf(stderr,
                   "MINIMAL_CLEARANCE_VERIFIER_STAGE commitment=received\n");
    }
    if (!verifier.verify(proof, public_input, transcript)) {
      reason = "proof.semantic";
      if (emit_stage_logs) {
        std::fprintf(stderr,
                     "MINIMAL_CLEARANCE_VERIFIER_STAGE verify=reject "
                     "reason=proof.semantic\n");
      }
      return false;
    }
    if (timings != nullptr) {
      timings->verify_final_check_ns =
          ElapsedNanoseconds(verify_start, SteadyClock::now());
    }
    if (emit_stage_logs) {
      std::fprintf(stderr,
                   "MINIMAL_CLEARANCE_VERIFIER_STAGE verify=accept\n");
    }
    return true;
  } catch (const std::exception&) {
    reason = "proof.exception";
    return false;
  }
}

bool PrepareArtifact(
    const Artifact& artifact,
    const std::unique_ptr<proofs::Circuit<RelationField>>& circuit,
    const PublicStatement& profile, PublicStatement& actual,
    std::string& reason) {
  if (artifact.rate != kLigeroRate || artifact.queries != kLigeroQueries ||
      artifact.transcript_version != kTranscriptVersion) {
    reason = "artifact.parameters";
    return false;
  }
  std::array<uint8_t, kCircuitIdBytes> circuit_id{};
  std::copy(std::begin(circuit->id), std::end(circuit->id), circuit_id.begin());
  if (artifact.circuit_id != circuit_id) {
    reason = "circuit-id";
    return false;
  }
  if (!DecodeStatement(artifact.public_statement, actual, reason)) return false;
  if (SerializeStatement(actual) != artifact.public_statement) {
    reason = "statement.canonical";
    return false;
  }
  if (!ValidateStaticStatement(actual, profile, reason)) return false;
  return true;
}

bool ValidateParsedArtifact(
    const Artifact& artifact,
    const std::unique_ptr<proofs::Circuit<RelationField>>& circuit,
    const PublicStatement& profile, std::string& reason,
    VerificationTimings* timings = nullptr, bool emit_stage_logs = true) {
  const SteadyClock::time_point parse_start = SteadyClock::now();
  PublicStatement actual;
  if (!PrepareArtifact(artifact, circuit, profile, actual, reason)) return false;
  if (timings != nullptr) {
    timings->parse_reconstruct_ns +=
        ElapsedNanoseconds(parse_start, SteadyClock::now());
  }
  return VerifyProof(artifact, actual, circuit, reason, timings,
                     emit_stage_logs);
}

bool ValidateArtifact(
    const Artifact& artifact,
    const std::unique_ptr<proofs::Circuit<RelationField>>& circuit,
    std::string& reason) {
  const PublicStatement profile = BuildVerifierStaticStatement();
  return ValidateParsedArtifact(artifact, circuit, profile, reason);
}

int Reject(const std::string& reason) {
  std::printf("MINIMAL_CLEARANCE_VERIFIER_REJECT reason=%s "
              "state_mutations=0 clear_authorizations=0\n",
              reason.c_str());
  return 1;
}

int StreamReject(const char* code) {
  std::printf("MINIMAL_CLEARANCE_STREAM_REJECT code=%s state_mutations=0 "
              "payment_mutations=0 economic_mutation=0\n",
              code);
  return 1;
}

bool ReadStreamExact(std::istream& input, uint8_t* output, size_t size) {
  while (size != 0) {
    const size_t chunk = std::min<size_t>(size, 1024 * 1024);
    input.read(reinterpret_cast<char*>(output),
               static_cast<std::streamsize>(chunk));
    const std::streamsize received = input.gcount();
    if (received <= 0) return false;
    output += static_cast<size_t>(received);
    size -= static_cast<size_t>(received);
  }
  return true;
}

bool ReadStreamU32(std::istream& input, uint32_t& value) {
  uint8_t bytes[4]{};
  if (!ReadStreamExact(input, bytes, sizeof(bytes))) return false;
  value = (static_cast<uint32_t>(bytes[0]) << 24) |
          (static_cast<uint32_t>(bytes[1]) << 16) |
          (static_cast<uint32_t>(bytes[2]) << 8) |
          static_cast<uint32_t>(bytes[3]);
  return true;
}

bool ReadStreamU64(std::istream& input, uint64_t& value) {
  uint8_t bytes[8]{};
  if (!ReadStreamExact(input, bytes, sizeof(bytes))) return false;
  value = 0;
  for (uint8_t byte : bytes) value = (value << 8) | byte;
  return true;
}

bool CheckStreamingIdentity(
    const Digest& statement_digest, const Digest& artifact_digest,
    const std::vector<Digest>& previous_statement_digests,
    const std::vector<Digest>& previous_artifact_digests) {
  for (size_t index = 0; index < previous_statement_digests.size(); ++index) {
    if (statement_digest == previous_statement_digests[index] ||
        artifact_digest == previous_artifact_digests[index]) {
      return false;
    }
  }
  return true;
}

int VerifyStreaming() {
#ifdef _WIN32
  if (_setmode(_fileno(stdin), _O_BINARY) == -1) {
    return StreamReject("stdin-mode");
  }
#endif
  std::array<uint8_t, kStreamingFrameMagic.size()> magic{};
  uint32_t version = 0;
  uint32_t count = 0;
  uint64_t declared_aggregate_bytes = 0;
  if (!ReadStreamExact(std::cin, magic.data(), magic.size())) {
    return StreamReject("frame-truncated");
  }
  if (magic != kStreamingFrameMagic) return StreamReject("frame-magic");
  if (!ReadStreamU32(std::cin, version) || !ReadStreamU32(std::cin, count) ||
      !ReadStreamU64(std::cin, declared_aggregate_bytes)) {
    return StreamReject("frame-truncated");
  }
  if (version != kStreamingFrameVersion) return StreamReject("frame-version");
  if (count != kStreamingCountOne && count != kStreamingCountTwo &&
      count != kStreamingCountFour &&
      count != kStreamingCountEight) {
    return StreamReject("frame-count");
  }
  if (declared_aggregate_bytes == 0 ||
      declared_aggregate_bytes > kStreamingMaxAggregateBytes) {
    return StreamReject("frame-aggregate");
  }

  const SteadyClock::time_point wall_start = SteadyClock::now();
  std::vector<std::vector<uint8_t>> frame_artifacts;
  std::vector<Digest> frame_artifact_digests;
  frame_artifacts.reserve(count);
  frame_artifact_digests.reserve(count);
  uint64_t aggregate_bytes = 0;
  const uint64_t minimum_artifact_bytes =
      static_cast<uint64_t>(
          blind_ledger_longfellow::minimal_clearance_proof::kHeaderBytes) +
      blind_ledger_longfellow::minimal_clearance_proof::kPublicStatementBytes;

  try {
    for (uint32_t index = 0; index < count; ++index) {
      uint64_t artifact_length = 0;
      if (!ReadStreamU64(std::cin, artifact_length)) {
        return StreamReject("artifact-length");
      }
      if (artifact_length < minimum_artifact_bytes ||
          artifact_length > kStreamingMaxArtifactBytes ||
          aggregate_bytes > declared_aggregate_bytes ||
          artifact_length > declared_aggregate_bytes - aggregate_bytes) {
        return StreamReject("artifact-length");
      }
      aggregate_bytes += artifact_length;
      if (artifact_length > std::numeric_limits<size_t>::max()) {
        return StreamReject("artifact-length");
      }
      std::vector<uint8_t> bytes(static_cast<size_t>(artifact_length));
      if (!ReadStreamExact(std::cin, bytes.data(), bytes.size())) {
        return StreamReject("artifact-truncated");
      }
      const Digest artifact_digest = HashBytes(bytes);
      if (std::find(frame_artifact_digests.begin(),
                    frame_artifact_digests.end(),
                    artifact_digest) != frame_artifact_digests.end()) {
        return StreamReject("artifact-identity");
      }
      frame_artifact_digests.push_back(artifact_digest);
      frame_artifacts.push_back(std::move(bytes));
    }
  } catch (const std::exception&) {
    return StreamReject("stream-internal");
  }
  if (aggregate_bytes != declared_aggregate_bytes) {
    return StreamReject("frame-aggregate");
  }
  char trailing = 0;
  std::cin.read(&trailing, 1);
  if (std::cin.gcount() != 0) return StreamReject("frame-trailing");
  if (!std::cin.eof() && std::cin.fail()) {
    return StreamReject("frame-read");
  }

  const PublicStatement profile = BuildVerifierStaticStatement();
  const SteadyClock::time_point circuit_start = SteadyClock::now();
  std::unique_ptr<proofs::Circuit<RelationField>> circuit;
  try {
    circuit = build_circuit();
  } catch (const std::exception&) {
    return StreamReject("circuit-build");
  }
  if (circuit == nullptr) return StreamReject("circuit-build");
  const uint64_t cold_circuit_build_ns =
      ElapsedNanoseconds(circuit_start, SteadyClock::now());
  // This is deliberately a child-only current PrivateUsage sample.  It is
  // not PagefileUsage, working set, a parent sample, or a peak sum.  Both
  // samples must be available and nonzero before the runner may use their
  // minimum as a conservative live-circuit floor.
  const PrivateCommitSample circuit_resident_private_commit =
      QueryCurrentPrivateCommit();

  std::vector<StreamingItemTelemetry> telemetry;
  std::vector<Digest> previous_statement_digests;
  std::vector<Digest> previous_artifact_digests;
  telemetry.reserve(count);
  previous_statement_digests.reserve(count);
  previous_artifact_digests.reserve(count);
  try {
    for (uint32_t index = 0; index < count; ++index) {
      const SteadyClock::time_point parse_start = SteadyClock::now();
      Artifact artifact;
      std::string reason;
      if (!parse_artifact_bytes(frame_artifacts[index], artifact, reason)) {
        return StreamReject("artifact-invalid");
      }
      PublicStatement actual;
      if (!PrepareArtifact(artifact, circuit, profile, actual, reason)) {
        return StreamReject("artifact-invalid");
      }
      const Digest statement_digest = HashBytes(artifact.public_statement);
      const Digest& artifact_digest = frame_artifact_digests[index];
      if (!CheckStreamingIdentity(
              statement_digest, artifact_digest, previous_statement_digests,
              previous_artifact_digests)) {
        return StreamReject("artifact-identity");
      }
      StreamingItemTelemetry item;
      item.statement_digest = statement_digest;
      item.timings.parse_reconstruct_ns =
          ElapsedNanoseconds(parse_start, SteadyClock::now());
      if (!VerifyProof(artifact, actual, circuit, reason, &item.timings,
                       /*emit_stage_logs=*/false)) {
        return StreamReject("artifact-rejected");
      }
      telemetry.push_back(item);
      previous_statement_digests.push_back(statement_digest);
      previous_artifact_digests.push_back(artifact_digest);
    }
  } catch (const std::exception&) {
    return StreamReject("stream-internal");
  }
  const PrivateCommitSample circuit_live_private_commit =
      QueryCurrentPrivateCommit();
  const uint64_t circuit_live_private_commit_floor_bytes =
      circuit_resident_private_commit.available &&
              circuit_live_private_commit.available
          ? std::min(circuit_resident_private_commit.bytes,
                     circuit_live_private_commit.bytes)
          : 0;

  const uint64_t wall_ns = ElapsedNanoseconds(wall_start, SteadyClock::now());
  const uint64_t warm_wall_ns = wall_ns > cold_circuit_build_ns
                                    ? wall_ns - cold_circuit_build_ns
                                    : 1;
  const uint64_t warm_per_artifact_ns =
      std::max<uint64_t>(1, warm_wall_ns / count);
  const double rate = static_cast<double>(count) * 1'000'000'000.0 /
                      static_cast<double>(wall_ns == 0 ? 1 : wall_ns);
  const double warm_rate = static_cast<double>(count) * 1'000'000'000.0 /
                           static_cast<double>(warm_wall_ns);

  std::printf(
      "MINIMAL_CLEARANCE_STREAM_EXPERIMENTAL proofSuiteId=null "
      "production_usable=0 activation=0 state_mutations=0 payment_mutations=0 "
      "economic_mutation=0 shared_circuit_reused=1 mutable_verifier_reused=0 "
      "fresh_transcript_per_artifact=1\n");
  for (size_t index = 0; index < telemetry.size(); ++index) {
    const StreamingItemTelemetry& item = telemetry[index];
    std::printf(
        "MINIMAL_CLEARANCE_STREAM_ITEM index=%zu "
        "accepted=1 parse_reconstruct_ns=%llu fresh_verifier_setup_ns=%llu "
        "verify_final_check_ns=%llu\n",
        index,
        static_cast<unsigned long long>(item.timings.parse_reconstruct_ns),
        static_cast<unsigned long long>(item.timings.fresh_verifier_setup_ns),
        static_cast<unsigned long long>(item.timings.verify_final_check_ns));
  }
  std::printf(
      "MINIMAL_CLEARANCE_STREAM_RESULT count=%u cold_circuit_build_ns=%llu "
      "aggregate_wall_ns=%llu warm_wall_ns=%llu rate_per_second=%.9f "
      "warm_rate_per_second=%.9f warm_per_artifact_ns=%llu "
      "circuit_resident_private_commit_bytes=%llu "
      "circuit_live_private_commit_floor_bytes=%llu "
      "serial_artifact_loop=1 "
      "shared_work=circuit_only\n",
      count, static_cast<unsigned long long>(cold_circuit_build_ns),
      static_cast<unsigned long long>(wall_ns),
      static_cast<unsigned long long>(warm_wall_ns), rate, warm_rate,
      static_cast<unsigned long long>(warm_per_artifact_ns),
      static_cast<unsigned long long>(circuit_resident_private_commit.bytes),
      static_cast<unsigned long long>(circuit_live_private_commit_floor_bytes));
  // A structurally valid, independently accepted stream is a successful
  // measurement.  Aggregate qualification is intentionally performed by the
  // bounded evidence runner; malformed frames and rejected proofs still
  // return nonzero before this point.
  return 0;
}

int PublicParity(const char* path) {
  std::ifstream input(path, std::ios::binary | std::ios::ate);
  if (!input) return Reject("parity.open");
  const std::streamoff size = input.tellg();
  if (size < 16) return Reject("parity.length");
  std::vector<uint8_t> bytes(static_cast<size_t>(size));
  input.seekg(0, std::ios::beg);
  input.read(reinterpret_cast<char*>(bytes.data()),
             static_cast<std::streamsize>(bytes.size()));
  if (!input) return Reject("parity.read");
  constexpr char kMagic[] = "BLMCPAR1";
  if (!std::equal(bytes.begin(), bytes.begin() + 8,
                  reinterpret_cast<const uint8_t*>(kMagic))) {
    return Reject("parity.magic");
  }
  auto Read32 = [&](size_t offset) {
    return (static_cast<uint32_t>(bytes[offset]) << 24) |
           (static_cast<uint32_t>(bytes[offset + 1]) << 16) |
           (static_cast<uint32_t>(bytes[offset + 2]) << 8) |
           static_cast<uint32_t>(bytes[offset + 3]);
  };
  const uint32_t statement_size = Read32(8);
  const uint32_t field_count = Read32(12);
  if (statement_size !=
          blind_ledger_longfellow::minimal_clearance::kPublicStatementBytes ||
      field_count == 0 ||
      bytes.size() != 16 + statement_size +
                           static_cast<size_t>(field_count) * RelationField::kBytes) {
    return Reject("parity.length");
  }
  std::vector<uint8_t> statement_bytes(bytes.begin() + 16,
                                       bytes.begin() + 16 + statement_size);
  PublicStatement statement;
  std::string reason;
  if (!DecodeStatement(statement_bytes, statement, reason)) {
    return Reject("parity." + reason);
  }
  constexpr uint64_t kParityEpoch = 0x0102030405060708ULL;
  constexpr uint64_t kParitySequence = 0x1112131415161718ULL;
  if (statement.epoch != kParityEpoch ||
      statement.sequence_before != kParitySequence) {
    return Reject("parity.typed-endian");
  }
  const RelationField field;
  auto circuit = build_circuit();
  proofs::Dense<RelationField> public_input(1, circuit->npub_in);
  fill_public_statement(statement, public_input);
  if (public_input.n1_ != field_count || public_input.v_[0] != field.one()) {
    return Reject("parity.field-count-or-leading-one");
  }
  const uint8_t* expected_fields = bytes.data() + 16 + statement_size;
  for (size_t index = 0; index < field_count; ++index) {
    uint8_t encoded[RelationField::kBytes]{};
    field.to_bytes_field(encoded, public_input.v_[index]);
    if (!std::equal(encoded, encoded + RelationField::kBytes,
                    expected_fields + index * RelationField::kBytes)) {
      return Reject("parity.field-vector");
    }
  }
  std::printf("MINIMAL_CLEARANCE_PUBLIC_PARITY_VERIFIER_PASS epoch=%llu "
              "sequence_before=%llu fields=%u statement_bytes=%u "
              "field_vector_bytes=%zu digest=equal verifier_owned_decode=1\n",
              static_cast<unsigned long long>(statement.epoch),
              static_cast<unsigned long long>(statement.sequence_before),
              field_count, statement_size,
              static_cast<size_t>(field_count) * RelationField::kBytes);
  return 0;
}

int Preflight() {
  const PublicStatement profile = BuildVerifierStaticStatement();
  const std::vector<uint8_t> bytes = SerializeStatement(profile);
  PublicStatement decoded;
  std::string reason;
  if (bytes.size() !=
          blind_ledger_longfellow::minimal_clearance::kPublicStatementBytes ||
      !DecodeStatement(bytes, decoded, reason) ||
      SerializeStatement(decoded) != bytes ||
      !ValidateStaticStatement(decoded, profile, reason)) {
    return Reject("preflight." + reason);
  }
  const uint64_t epoch = 0x0102030405060708ULL;
  const uint64_t sequence = 0x1112131415161718ULL;
  std::vector<uint8_t> endian = bytes;
  PutU64(endian, kEpochOffset, epoch);
  PutU64(endian, kSequenceOffset, sequence);
  PublicStatement endian_statement;
  if (!DecodeStatement(endian, endian_statement, reason) ||
      endian_statement.epoch != epoch ||
      endian_statement.sequence_before != sequence) {
    return Reject("preflight.typed-endian");
  }
  auto circuit = build_circuit();
  proofs::Dense<RelationField> public_input(1, circuit->npub_in);
  fill_public_statement(decoded, public_input);
  if (circuit->npub_in !=
          1 + blind_ledger_longfellow::minimal_clearance::kPublicStatementBytes *
                  8 ||
      public_input.n1_ != circuit->npub_in ||
      public_input.v_[0] != RelationField().one()) {
    return Reject("preflight.circuit-or-public-layout");
  }
  std::printf("MINIMAL_CLEARANCE_PREFLIGHT_PASS proof_invocations=0 "
              "circuit_id=%s inputs=%zu public_inputs=%zu layers=%zu terms=%zu "
              "public_bytes=%zu epoch=%llu sequence_before=%llu "
              "endian_kat_epoch=%llu endian_kat_sequence=%llu "
              "verifier_owned_reconstruction=1 canonical_serialize=1\n",
              CircuitId(circuit).c_str(), circuit->ninputs, circuit->npub_in,
              circuit->nl, circuit->nterms(), bytes.size(),
              static_cast<unsigned long long>(profile.epoch),
              static_cast<unsigned long long>(profile.sequence_before),
              static_cast<unsigned long long>(epoch),
              static_cast<unsigned long long>(sequence));
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc == 2 && std::string(argv[1]) == "--preflight") return Preflight();
  if (argc == 3 && std::string(argv[1]) == "--public-parity") {
    return PublicParity(argv[2]);
  }
  if (argc == 2 && std::string(argv[1]) == "--verify-stdin") {
    std::vector<uint8_t> bytes;
    std::string error;
    if (!ReadVerifyStdinBytes(bytes, error)) return Reject("artifact." + error);
    Artifact artifact;
    if (!parse_artifact_bytes(bytes, artifact, error)) {
      return Reject("artifact." + error);
    }
    auto circuit = build_circuit();
    std::string reason;
    if (!ValidateArtifact(artifact, circuit, reason)) {
      return Reject(reason);
    }
    std::printf("MINIMAL_CLEARANCE_VERIFIER_ACCEPT inputs=%zu public_inputs=%zu "
                "layers=%zu terms=%zu public_bytes=%zu proof_bytes=%zu rate=%u "
                "queries=%u transcript_version=%u circuit_id=%s "
                "statement_sha3_512=%s state_mutations=0 clear_authorizations=0\n",
                circuit->ninputs, circuit->npub_in, circuit->nl, circuit->nterms(),
                artifact.public_statement.size(), artifact.proof.size(),
                kLigeroRate, kLigeroQueries, kTranscriptVersion,
                CircuitId(circuit).c_str(),
                HexDigest(HashBytes(artifact.public_statement)).c_str());
    return 0;
  }
  if (argc == 2 && std::string(argv[1]) == "--verify-stream-stdin") {
    return VerifyStreaming();
  }
  if (argc == 2 && std::string(argv[1]) == "--circuit-id") {
    auto circuit = build_circuit();
    std::printf("MINIMAL_CLEARANCE_VERIFIER_CIRCUIT circuit_id=%s inputs=%zu "
                "public_inputs=%zu layers=%zu terms=%zu\n",
                CircuitId(circuit).c_str(), circuit->ninputs, circuit->npub_in,
                circuit->nl, circuit->nterms());
    return 0;
  }
  return Reject("unsupported-argument");
}
