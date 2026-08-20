#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <fstream>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#include <share.h>
#endif
#include <memory>
#include <string>
#include <vector>

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

constexpr char kExpectedCircuitId[] =
    "1eaaf14f3b23db1ed02f3c378099627767f81142e0114f90448cac7c1cc66be0";
constexpr size_t kDigestCount = 26;
constexpr size_t kProtocolOffset = 0;
constexpr size_t kRoleOffset = 1;
constexpr size_t kDigestOffset = kRoleOffset + kProofRoleBytes;
constexpr size_t kEpochOffset = kDigestOffset + kDigestCount * kDigestBytes;
constexpr size_t kSequenceOffset = kEpochOffset + 8;
constexpr size_t kFlagsOffset = kEpochOffset + 16;
constexpr size_t kStateOffset = kFlagsOffset + 4;
constexpr size_t kStateHeaderAndScalars = 150;
constexpr size_t kStateDigestOffset = kStateOffset + kStateHeaderAndScalars;

static_assert(kStateOffset + kStateCommitmentBytes == kPublicStatementBytes);

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

std::vector<uint8_t> U64Bytes(uint64_t value) {
  std::vector<uint8_t> output;
  AppendU64(output, value);
  return output;
}

std::vector<uint8_t> SourceRootInput(const Digest& provider,
                                     const Digest& credential,
                                     const Digest& enrollment) {
  std::vector<uint8_t> output = Domain("BL/NATIVE-V3/SOURCE-ROOT/v1");
  Append(output, provider);
  Append(output, credential);
  Append(output, enrollment);
  AppendU8(output, 1);
  AppendU8(output, 1);
  AppendU8(output, 1);
  AppendU8(output, 0);
  return output;
}

std::vector<uint8_t> CompletenessInput(const Digest& provider,
                                       const Digest& credential) {
  std::vector<uint8_t> output = Domain("BL/NATIVE-V3/COMPLETENESS/v1");
  Append(output, provider);
  Append(output, credential);
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
  AppendU8(output, 1);
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
  return output;
}

PublicStatement BuildVerifierOwnedStatement() {
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

  statement.execution_context =
      HashText("BL/NATIVE-V3/EXECUTION-CONTEXT/v2", "minimal-clearance");
  statement.source_registry_snapshot =
      HashText("BL/NATIVE-V3/SOURCE-REGISTRY-SNAPSHOT/v1", "snapshot-1");
  statement.source_profile =
      HashText("BL/NATIVE-V3/SOURCE-PROFILE/v1", "synthetic-authoritative");
  statement.governance_snapshot =
      HashText("BL/NATIVE-V3/GOVERNANCE-SNAPSHOT/v2", "governance-1");
  statement.automatic_control_set = HashText(
      "BL/NATIVE-V3/CONTROL-SET/v2",
      "CLEAR,HOLD,HUMAN_REVIEW,BLOCK,EXCEPTION_APPROVED");
  statement.settlement_domain =
      HashText("BL/NATIVE-V3/SETTLEMENT-DOMAIN/v2", "official-state-rail");
  statement.evaluator_id =
      HashText("BL/NATIVE-V3/EVALUATOR/v1", "minimal-clearance-evaluator");
  statement.schema_id =
      HashText("BL/NATIVE-V3/SCHEMA/v1", "minimal-clearance-schema");
  statement.program_id =
      HashText("BL/NATIVE-V3/PROGRAM/v1", "minimal-clearance-program");
  statement.policy_id =
      HashText("BL/NATIVE-V3/POLICY/v1", "minimal-five-directive-policy");
  statement.subject_id = credential;
  statement.attempt_id =
      HashText("BL/NATIVE-V3/ATTEMPT/v1", "clear");
  statement.active = 1;
  statement.complete = 1;
  statement.authoritative_membership = 1;
  statement.authoritative_absence = 0;
  statement.epoch = 7;
  statement.sequence_before = 11;
  statement.source_root_id = HashBytes(SourceRootInput(provider, credential,
                                                        enrollment));
  statement.completeness_id =
      HashBytes(CompletenessInput(provider, credential));
  statement.source_address =
      HashParts(Domain("BL/NATIVE-V3/STATE-ADDRESS/v1"),
                {std::vector<uint8_t>{'s', 'o', 'u', 'r', 'c', 'e'},
                 ToVector(provider)});
  statement.source_key =
      HashParts(Domain("BL/NATIVE-V3/SUBJECT-KEY/v1"),
                {ToVector(provider), ToVector(credential),
                 ToVector(enrollment)});
  statement.audit_address =
      HashParts(Domain("BL/NATIVE-V3/STATE-ADDRESS/v1"),
                {std::vector<uint8_t>{'a', 'u', 'd', 'i', 't'},
                 ToVector(provider)});
  statement.exception_id = Sentinel();
  statement.exception_scope_id = Sentinel();
  statement.rule_id =
      HashText("BL/NATIVE-V3/RULE/v1", "synthetic-rule-v1");
  statement.state_before_id = HashParts(
      Domain("BL/NATIVE-V3/MINIMAL-BEFORE-STATE/v1"),
      {ToVector(statement.execution_context), U64Bytes(statement.epoch),
       U64Bytes(statement.sequence_before), ToVector(before_audit),
       ToVector(before_root)});
  statement.request_id = HashParts(
      Domain("BL/NATIVE-V3/REQUEST-ID/v2"),
      {ToVector(statement.subject_id), ToVector(statement.attempt_id),
       U64Bytes(statement.epoch), U64Bytes(statement.sequence_before),
       ToVector(statement.state_before_id)});
  statement.decision_id = HashParts(
      Domain("BL/NATIVE-V3/MINIMAL-DECISION/v1"),
      {ToVector(statement.request_id), ToVector(statement.source_root_id),
       ToVector(statement.completeness_id), std::vector<uint8_t>{1, 1},
       ToVector(statement.exception_id)});
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
  statement.state_after_id = HashParts(
      Domain("BL/NATIVE-V3/MINIMAL-STATE-ID/v1"),
      {std::vector<uint8_t>{1}, state_bytes});
  const Digest source_payload = HashParts(
      Domain("BL/NATIVE-V3/SOURCE-PAYLOAD/v1"),
      {ToVector(provider), ToVector(credential), ToVector(enrollment),
       std::vector<uint8_t>{1, 1, 1, 0}});
  statement.private_batch_commitment = HashParts(
      Domain("BL/NATIVE-V3/PRIVATE-BATCH/v2"),
      {ToVector(statement.source_registry_snapshot),
       ToVector(statement.source_profile), ToVector(statement.subject_id),
       ToVector(statement.source_root_id), ToVector(statement.completeness_id),
       ToVector(provider), ToVector(credential), ToVector(enrollment),
       ToVector(source_payload), std::vector<uint8_t>{1, 1, 1, 0}});
  return statement;
}

std::vector<uint8_t> SerializeStatement(const PublicStatement& statement) {
  std::vector<uint8_t> output;
  output.reserve(kPublicStatementBytes);
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
  if (bytes.size() != kPublicStatementBytes) {
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

bool SameStatement(const PublicStatement& actual,
                   const PublicStatement& expected, std::string& reason) {
  if (actual.protocol_version != expected.protocol_version) {
    reason = "statement.protocol";
    return false;
  }
  if (actual.proof_role != expected.proof_role) {
    reason = "statement.role";
    return false;
  }
  if (actual.proof_suite != expected.proof_suite) {
    reason = "statement.proof-suite";
    return false;
  }
  const Digest* actual_digests[] = {
      &actual.execution_context, &actual.source_registry_snapshot,
      &actual.source_profile, &actual.governance_snapshot,
      &actual.automatic_control_set, &actual.settlement_domain,
      &actual.evaluator_id, &actual.schema_id, &actual.program_id,
      &actual.policy_id, &actual.subject_id, &actual.attempt_id,
      &actual.request_id, &actual.source_root_id, &actual.completeness_id,
      &actual.private_batch_commitment, &actual.source_address,
      &actual.source_key, &actual.audit_address, &actual.exception_id,
      &actual.exception_scope_id, &actual.rule_id, &actual.decision_id,
      &actual.state_before_id, &actual.state_after_id};
  const Digest* expected_digests[] = {
      &expected.execution_context, &expected.source_registry_snapshot,
      &expected.source_profile, &expected.governance_snapshot,
      &expected.automatic_control_set, &expected.settlement_domain,
      &expected.evaluator_id, &expected.schema_id, &expected.program_id,
      &expected.policy_id, &expected.subject_id, &expected.attempt_id,
      &expected.request_id, &expected.source_root_id, &expected.completeness_id,
      &expected.private_batch_commitment, &expected.source_address,
      &expected.source_key, &expected.audit_address, &expected.exception_id,
      &expected.exception_scope_id, &expected.rule_id, &expected.decision_id,
      &expected.state_before_id, &expected.state_after_id};
  const char* names[] = {
      "context", "registry", "profile", "governance", "control-set",
      "settlement-domain", "evaluator", "schema", "program", "policy",
      "subject", "attempt", "request", "source-root", "completeness",
      "private-batch", "source-address", "source-key", "audit-address",
      "exception", "exception-scope", "rule", "decision", "state-before",
      "state-after"};
  for (size_t index = 0; index < std::size(actual_digests); ++index) {
    if (*actual_digests[index] != *expected_digests[index]) {
      reason = std::string("statement.") + names[index];
      return false;
    }
  }
  if (actual.epoch != expected.epoch) {
    reason = "statement.epoch";
    return false;
  }
  if (actual.sequence_before != expected.sequence_before) {
    reason = "statement.sequence-before";
    return false;
  }
  if (actual.active != expected.active ||
      actual.complete != expected.complete ||
      actual.authoritative_membership != expected.authoritative_membership ||
      actual.authoritative_absence != expected.authoritative_absence) {
    reason = "statement.assertion-flags";
    return false;
  }
  if (actual.state_commitment_bytes != expected.state_commitment_bytes) {
    reason = "statement.state-commitment";
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

bool FillPublicInput(const PublicStatement& statement,
                     const std::unique_ptr<proofs::Circuit<RelationField>>& circuit,
                     proofs::Dense<RelationField>& public_input,
                     std::string& reason) {
  if (circuit->npub_in != 1 + kPublicStatementBytes * 8) {
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
                 std::string& reason, bool diagnostic_logs) {
  const RelationField field;
  proofs::Dense<RelationField> public_input(1, circuit->npub_in);
  if (!FillPublicInput(statement, circuit, public_input, reason)) return false;
  try {
    proofs::ZkProof<RelationField> proof(*circuit, kLigeroRate, kLigeroQueries);
    proofs::ReadBuffer buffer(artifact.proof);
    if (!proof.read(buffer, field) || buffer.remaining() != 0) {
      reason = "proof.serialization";
      std::fprintf(stderr,
                   "MINIMAL_CLEARANCE_VERIFIER_STAGE proof.read=reject "
                   "remaining=%zu\n",
                   buffer.remaining());
      return false;
    }
    std::fprintf(stderr,
                 "MINIMAL_CLEARANCE_VERIFIER_STAGE proof.read=accept "
                 "remaining=0\n");
    using RSFactory = proofs::LCH14ReedSolomonFactory<RelationField>;
    const RSFactory rs_factory(field);
    proofs::Transcript transcript(
        reinterpret_cast<const uint8_t*>(kTranscriptLabel),
        sizeof(kTranscriptLabel) - 1, kTranscriptVersion);
    proofs::ZkVerifier<RelationField, RSFactory> verifier(
        *circuit, rs_factory, kLigeroRate, kLigeroQueries, field);
    if (diagnostic_logs) proofs::set_log_level(proofs::INFO);
    verifier.recv_commitment(proof, transcript);
    std::fprintf(stderr,
                 "MINIMAL_CLEARANCE_VERIFIER_STAGE commitment=received\n");
    if (!verifier.verify(proof, public_input, transcript)) {
      reason = "proof.semantic";
      std::fprintf(stderr,
                   "MINIMAL_CLEARANCE_VERIFIER_STAGE verify=reject "
                   "reason=proof.semantic\n");
      return false;
    }
    std::fprintf(stderr,
                 "MINIMAL_CLEARANCE_VERIFIER_STAGE verify=accept\n");
    return true;
  } catch (const std::exception& exception) {
    reason = std::string("proof.exception:") + exception.what();
    return false;
  }
}

bool ValidateArtifact(const Artifact& artifact, const PublicStatement& expected,
                      const std::unique_ptr<proofs::Circuit<RelationField>>& circuit,
                      std::string& reason, bool diagnostic_logs) {
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
  PublicStatement actual;
  if (!DecodeStatement(artifact.public_statement, actual, reason)) return false;
  if (SerializeStatement(actual) != artifact.public_statement) {
    reason = "statement.canonical";
    return false;
  }
  if (!SameStatement(actual, expected, reason)) return false;
  return VerifyProof(artifact, expected, circuit, reason, diagnostic_logs);
}

bool WriteNewStatementFile(const std::string& path,
                           const std::vector<uint8_t>& statement,
                           std::string& reason) {
#ifdef _WIN32
  int descriptor = -1;
  const errno_t open_result = _sopen_s(
      &descriptor, path.c_str(), _O_BINARY | _O_WRONLY | _O_CREAT | _O_EXCL,
      _SH_DENYRW, _S_IREAD);
  if (open_result != 0 || descriptor < 0) {
    reason = "create";
    return false;
  }
  const int written = _write(
      descriptor, statement.data(), static_cast<unsigned int>(statement.size()));
  bool success = written == static_cast<int>(statement.size());
  if (_commit(descriptor) != 0) success = false;
  if (_close(descriptor) != 0) success = false;
  if (!success) {
    descriptor = -1;
    reason = "write";
    std::remove(path.c_str());
    return false;
  }
  descriptor = -1;
  return true;
#else
  (void)path;
  (void)statement;
  reason = "windows-only";
  return false;
#endif
}

bool Flip(std::vector<uint8_t>& bytes, size_t offset) {
  if (offset >= bytes.size()) return false;
  bytes[offset] ^= 1;
  return true;
}

size_t DigestStatementOffset(size_t index) {
  return kHeaderBytes + kDigestOffset + index * kDigestBytes;
}

bool ApplyMutation(const std::string& name, std::vector<uint8_t>& bytes) {
  const size_t proof_offset = kHeaderBytes + kPublicStatementBytes;
  if (name == "artifact_bit_flip" || name == "proof_flip_begin") {
    return Flip(bytes, proof_offset);
  }
  if (name == "proof_flip_middle") {
    return Flip(bytes, proof_offset + (bytes.size() - proof_offset) / 2);
  }
  if (name == "proof_flip_end") return Flip(bytes, bytes.size() - 1);
  if (name == "truncation") {
    if (bytes.empty()) return false;
    bytes.pop_back();
    return true;
  }
  if (name == "trailing_bytes") {
    bytes.push_back(0xa5);
    return true;
  }
  if (name == "wrong_magic") return Flip(bytes, 0);
  if (name == "wrong_version") {
    PutU32(bytes, 8, 2);
    return true;
  }
  if (name == "wrong_circuit_id") return Flip(bytes, 12);
  if (name == "wrong_proof_length") {
    PutU64(bytes, 60, static_cast<uint64_t>(bytes.size()));
    return true;
  }
  if (name == "wrong_public_length") {
    PutU32(bytes, 56, static_cast<uint32_t>(kPublicStatementBytes - 1));
    return true;
  }
  if (name == "public_statement_byte") return Flip(bytes, kHeaderBytes);
  if (name == "public_statement_reorder") {
    std::swap(bytes[kHeaderBytes + kRoleOffset],
              bytes[kHeaderBytes + kRoleOffset + 1]);
    return true;
  }
  if (name == "epoch_endian") return Flip(bytes, kHeaderBytes + kEpochOffset);
  if (name == "sequence_endian") {
    return Flip(bytes, kHeaderBytes + kSequenceOffset + 7);
  }
  if (name == "source_commitment_target") return Flip(bytes, DigestStatementOffset(14));
  if (name == "registry_snapshot") return Flip(bytes, DigestStatementOffset(2));
  if (name == "profile_substitution") return Flip(bytes, DigestStatementOffset(3));
  if (name == "subject_substitution") return Flip(bytes, DigestStatementOffset(11));
  if (name == "request_replay_substitution") return Flip(bytes, DigestStatementOffset(13));
  if (name == "state_before_substitution") return Flip(bytes, DigestStatementOffset(24));
  if (name == "policy_result_conflation") return Flip(bytes, kHeaderBytes + kStateOffset + 5);
  if (name == "effective_directive_conflation") return Flip(bytes, kHeaderBytes + kStateOffset + 6);
  if (name == "chronology_equality") return Flip(bytes, kHeaderBytes + kStateOffset + 32);
  if (name == "chronology_order") return Flip(bytes, kHeaderBytes + kStateOffset + 48);
  if (name == "exception_substitution") return Flip(bytes, DigestStatementOffset(20));
  if (name == "read_write_role") return Flip(bytes, kHeaderBytes + kStateOffset + 132);
  if (name == "access_index") return Flip(bytes, kHeaderBytes + kStateOffset + 104);
  if (name == "access_value") {
    return Flip(bytes, kHeaderBytes + kStateDigestOffset + 21 * kDigestBytes);
  }
  if (name == "state_commitment") return Flip(bytes, kHeaderBytes + kStateOffset);
  if (name == "decision_id") return Flip(bytes, DigestStatementOffset(23));
  if (name == "state_after_substitution") return Flip(bytes, DigestStatementOffset(25));
  if (name == "receipt_derivation") return Flip(bytes, DigestStatementOffset(23) + 1);
  if (name == "settlement_derivation") return Flip(bytes, DigestStatementOffset(25) + 1);
  if (name == "cross_context") return Flip(bytes, DigestStatementOffset(1));
  return false;
}

int Reject(const std::string& reason) {
  std::printf("MINIMAL_CLEARANCE_VERIFIER_REJECT reason=%s "
              "state_mutations=0 clear_authorizations=0\n",
              reason.c_str());
  return 1;
}

int Mutation(const std::string& name, const std::string& path,
             bool diagnostic_logs) {
  std::vector<uint8_t> bytes;
  std::string error;
  if (!read_artifact_bytes(path, bytes, error)) {
    std::printf("MINIMAL_CLEARANCE_VERIFIER_MUTATION_PASS name=%s copy_only=1 "
                "reason=read.%s\n",
                name.c_str(), error.c_str());
    return 0;
  }
  if (!ApplyMutation(name, bytes)) {
    std::printf("MINIMAL_CLEARANCE_VERIFIER_MUTATION_FAIL name=%s "
                "reason=unsupported-or-short\n",
                name.c_str());
    return 1;
  }
  Artifact artifact;
  if (!parse_artifact_bytes(bytes, artifact, error)) {
    std::printf("MINIMAL_CLEARANCE_VERIFIER_MUTATION_PASS name=%s copy_only=1 "
                "reason=artifact.%s state_mutations=0\n",
                name.c_str(), error.c_str());
    return 0;
  }
  const PublicStatement expected = BuildVerifierOwnedStatement();
  auto circuit = build_circuit();
  std::string reason;
  if (!ValidateArtifact(artifact, expected, circuit, reason, diagnostic_logs)) {
    std::printf("MINIMAL_CLEARANCE_VERIFIER_MUTATION_PASS name=%s copy_only=1 "
                "reason=%s state_mutations=0\n",
                name.c_str(), reason.c_str());
    return 0;
  }
  std::printf("MINIMAL_CLEARANCE_VERIFIER_MUTATION_FAIL name=%s copy_only=1 "
              "reason=accepted state_mutations=0\n",
              name.c_str());
  return 1;
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
  if (statement_size != kPublicStatementBytes || field_count == 0 ||
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
  const PublicStatement expected = BuildVerifierOwnedStatement();
  const std::vector<uint8_t> bytes = SerializeStatement(expected);
  PublicStatement decoded;
  std::string reason;
  if (bytes.size() != kPublicStatementBytes ||
      !DecodeStatement(bytes, decoded, reason) ||
      SerializeStatement(decoded) != bytes ||
      !SameStatement(decoded, expected, reason)) {
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
  if (CircuitId(circuit) != kExpectedCircuitId ||
      circuit->npub_in != 1 + kPublicStatementBytes * 8 ||
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
              static_cast<unsigned long long>(expected.epoch),
              static_cast<unsigned long long>(expected.sequence_before),
              static_cast<unsigned long long>(epoch),
              static_cast<unsigned long long>(sequence));
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  bool diagnostic_logs = false;
  for (int index = 1; index < argc; ++index) {
    if (std::string(argv[index]) == "--diagnostic-logs") {
      diagnostic_logs = true;
    }
  }
  if (argc == 2 && std::string(argv[1]) == "--preflight") return Preflight();
  if (argc == 3 && std::string(argv[1]) == "--public-parity") {
    return PublicParity(argv[2]);
  }
  if (argc == 4 && std::string(argv[1]) == "--verified-statement-file") {
    std::ifstream existing(argv[2], std::ios::binary);
    if (existing.good()) return Reject("statement-output-exists");
    std::vector<uint8_t> bytes;
    std::string error;
    if (!read_artifact_bytes(argv[3], bytes, error)) {
      return Reject("artifact." + error);
    }
    Artifact artifact;
    if (!parse_artifact_bytes(bytes, artifact, error)) {
      return Reject("artifact." + error);
    }
    const PublicStatement expected = BuildVerifierOwnedStatement();
    const std::vector<uint8_t> expected_bytes = SerializeStatement(expected);
    auto circuit = build_circuit();
    std::string reason;
    if (!ValidateArtifact(artifact, expected, circuit, reason, diagnostic_logs) ||
        artifact.public_statement != expected_bytes) {
      if (reason.empty()) reason = "statement-byte-mismatch";
      return Reject(reason);
    }
    if (!WriteNewStatementFile(argv[2], expected_bytes, reason)) {
      return Reject("statement-output." + reason);
    }
    std::printf("MINIMAL_CLEARANCE_VERIFIER_ACCEPT inputs=%zu public_inputs=%zu "
                "layers=%zu terms=%zu public_bytes=%zu proof_bytes=%zu rate=%u "
                "queries=%u transcript_version=%u circuit_id=%s "
                "state_mutations=0 clear_authorizations=0\n",
                circuit->ninputs, circuit->npub_in, circuit->nl, circuit->nterms(),
                artifact.public_statement.size(), artifact.proof.size(),
                kLigeroRate, kLigeroQueries, kTranscriptVersion,
                CircuitId(circuit).c_str());
    return 0;
  }
  if (argc == 3 && std::string(argv[1]) == "--public-statement-file") {
    const std::vector<uint8_t> bytes =
        SerializeStatement(BuildVerifierOwnedStatement());
    std::ofstream output(argv[2], std::ios::binary | std::ios::trunc);
    if (!output) return 2;
    output.write(reinterpret_cast<const char*>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
    if (!output) return 2;
    std::printf("MINIMAL_CLEARANCE_VERIFIER_PUBLIC_STATEMENT bytes=%zu path=%s "
                "verifier_owned_reconstruction=1\n",
                bytes.size(), argv[2]);
    return 0;
  }
  if (argc == 2 && std::string(argv[1]) == "--circuit-id") {
    auto circuit = build_circuit();
    std::printf("MINIMAL_CLEARANCE_VERIFIER_CIRCUIT circuit_id=%s inputs=%zu "
                "public_inputs=%zu layers=%zu terms=%zu\n",
                CircuitId(circuit).c_str(), circuit->ninputs, circuit->npub_in,
                circuit->nl, circuit->nterms());
    return 0;
  }
  if ((argc == 4 || argc == 5) && std::string(argv[2]) == "--mutation") {
    if (argc == 5 && std::string(argv[4]) != "--diagnostic-logs") return 2;
    return Mutation(argv[3], argv[1], diagnostic_logs);
  }
  if (argc != 2 && argc != 3) {
    std::fprintf(stderr,
                 "usage: longfellow_minimal_clearance_verifier ARTIFACT | "
                 "ARTIFACT --mutation NAME [--diagnostic-logs] | "
                 "--preflight | --public-parity PATH | "
                 "--public-statement-file PATH | --circuit-id\n");
    return 2;
  }
  std::vector<uint8_t> bytes;
  std::string error;
  if (!read_artifact_bytes(argv[1], bytes, error)) return Reject("artifact." + error);
  Artifact artifact;
  if (!parse_artifact_bytes(bytes, artifact, error)) {
    return Reject("artifact." + error);
  }
  const PublicStatement expected = BuildVerifierOwnedStatement();
  auto circuit = build_circuit();
  std::string reason;
  if (!ValidateArtifact(artifact, expected, circuit, reason, diagnostic_logs)) {
    return Reject(reason);
  }
  std::printf("MINIMAL_CLEARANCE_VERIFIER_ACCEPT inputs=%zu public_inputs=%zu "
              "layers=%zu terms=%zu public_bytes=%zu proof_bytes=%zu rate=%u "
              "queries=%u transcript_version=%u circuit_id=%s "
              "state_mutations=0 clear_authorizations=0\n",
              circuit->ninputs, circuit->npub_in, circuit->nl, circuit->nterms(),
              artifact.public_statement.size(), artifact.proof.size(),
              kLigeroRate, kLigeroQueries, kTranscriptVersion,
              CircuitId(circuit).c_str());
  return 0;
}
