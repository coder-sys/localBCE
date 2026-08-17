#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

#include "arrays/dense.h"
#include "circuits/tests/sha3/sha3_reference.h"
#include "gf2k/lch14_reed_solomon.h"
#include "native_v3_source_assertion_proof_artifact.h"
#include "native_v3_source_assertion_relation.h"
#include "random/transcript.h"
#include "util/readbuffer.h"
#include "zk/zk_proof.h"
#include "zk/zk_verifier.h"

namespace {

using blind_ledger_longfellow::source_assertion::Digest;
using blind_ledger_longfellow::source_assertion::RelationField;
using blind_ledger_longfellow::source_assertion::Statement;
using blind_ledger_longfellow::source_assertion_proof::Artifact;

constexpr char kTranscriptLabel[] = "BL/NATIVE-V3/LONGFELLOW/TRANSCRIPT/v1";
constexpr size_t kPublicBase = blind_ledger_longfellow::source_assertion_proof::kHeaderBytes;
constexpr size_t kProofBase = kPublicBase +
                               blind_ledger_longfellow::source_assertion_proof::kPublicStatementBytes;

void Append(std::vector<uint8_t>& output, const Digest& value) {
  output.insert(output.end(), value.begin(), value.end());
}

void Append(std::vector<uint8_t>& output, const std::vector<uint8_t>& value) {
  output.insert(output.end(), value.begin(), value.end());
}

void AppendU64(std::vector<uint8_t>& output, uint64_t value) {
  for (size_t index = 0; index < 8; ++index) {
    output.push_back(static_cast<uint8_t>(value >> (56 - index * 8)));
  }
}

std::vector<uint8_t> Domain(const char* value) {
  const size_t length = std::strlen(value);
  std::vector<uint8_t> output(value, value + length);
  output.push_back(0);
  return output;
}

std::vector<uint8_t> ToVector(const Digest& value) {
  return std::vector<uint8_t>(value.begin(), value.end());
}

Digest HashBytes(const std::vector<uint8_t>& input) {
  proofs::Sha3Reference reference(blind_ledger_longfellow::source_assertion::kDigestBytes);
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

void SetRole(blind_ledger_longfellow::source_assertion::ProofRole& role) {
  std::copy_n(blind_ledger_longfellow::source_assertion::kProofRole,
              blind_ledger_longfellow::source_assertion::kProofRoleBytes,
              role.begin());
}

Statement BuildVerifierOwnedStatement() {
  Statement statement;
  SetRole(statement.proof_role);
  statement.proof_suite.fill(0);
  const Digest provider =
      HashText("BL/NATIVE-V3/SYNTHETIC-PROVIDER/v1", "provider-1");
  const Digest credential =
      HashText("BL/NATIVE-V3/SYNTHETIC-CREDENTIAL/v1", "credential-1");
  const Digest enrollment =
      HashText("BL/NATIVE-V3/SYNTHETIC-ENROLLMENT/v1", "enrollment-1");
  statement.execution_context = HashText(
      "BL/NATIVE-V3/SOURCE-ASSERTION/EXECUTION-CONTEXT/v1", "fixed-context");
  statement.source_registry_snapshot = HashText(
      "BL/NATIVE-V3/SOURCE-ASSERTION/REGISTRY-SNAPSHOT/v1", "immutable-v1");
  statement.source_profile = HashText(
      "BL/NATIVE-V3/SOURCE-ASSERTION/PROFILE/v1", "source-assertion-only-v1");
  statement.governance_snapshot = HashText(
      "BL/NATIVE-V3/SOURCE-ASSERTION/GOVERNANCE/v1", "governance-v1");
  statement.automatic_control_set = HashText(
      "BL/NATIVE-V3/SOURCE-ASSERTION/CONTROL-SET/v1", "five-directives-v1");
  statement.settlement_domain = HashText(
      "BL/NATIVE-V3/SOURCE-ASSERTION/SETTLEMENT-DOMAIN/v1",
      "official-state-rail");
  statement.subject_scope = HashText(
      "BL/NATIVE-V3/SOURCE-ASSERTION/SUBJECT-SCOPE/v1", "clear");
  statement.epoch = 7;
  statement.sequence_before = 0;
  statement.state_before_id = HashText(
      "BL/NATIVE-V3/SOURCE-ASSERTION/STATE-BEFORE/v1", "initial");

  const Digest attempt =
      HashText("BL/NATIVE-V3/SOURCE-ASSERTION/ATTEMPT/v1", "clear");
  const uint8_t active = 1;
  const uint8_t complete = 1;
  const uint8_t membership = 1;
  const uint8_t absence = 0;
  const Digest source_payload = HashParts(
      Domain("BL/NATIVE-V3/SOURCE-PAYLOAD/v1"),
      {ToVector(provider), ToVector(credential), ToVector(enrollment),
       std::vector<uint8_t>{active, complete, membership, absence}});
  statement.decision_path_id = HashText(
      "BL/NATIVE-V3/SOURCE-ASSERTION/DECISION-PATH/v1", "clear");
  statement.exception_id = Sentinel();
  statement.active = active;
  statement.complete = complete;
  statement.authoritative_membership = membership;
  statement.authoritative_absence = absence;
  statement.source_root_id = HashParts(
      Domain("BL/NATIVE-V3/SOURCE-ROOT/v1"),
      {ToVector(provider), ToVector(credential), ToVector(enrollment),
       std::vector<uint8_t>{active, complete, membership, absence}});
  statement.completeness_id = HashParts(
      Domain("BL/NATIVE-V3/COMPLETENESS/v1"),
      {ToVector(provider), ToVector(credential),
       std::vector<uint8_t>{complete, absence}});

  std::vector<uint8_t> request_input = Domain("BL/NATIVE-V3/REQUEST-ID/v1");
  Append(request_input, provider);
  Append(request_input, credential);
  Append(request_input, enrollment);
  Append(request_input, attempt);
  AppendU64(request_input, statement.epoch);
  AppendU64(request_input, statement.sequence_before);
  AppendU64(request_input, 7000);
  AppendU64(request_input, 7001);
  AppendU64(request_input, 6999);
  AppendU64(request_input, 7002);
  Append(request_input, statement.state_before_id);
  statement.request_id = HashBytes(request_input);
  statement.private_batch_commitment = HashParts(
      Domain("BL/NATIVE-V3/PRIVATE-BATCH/v1"),
      {ToVector(source_payload), ToVector(statement.decision_path_id),
       ToVector(statement.exception_id), ToVector(statement.request_id)});
  return statement;
}

std::vector<uint8_t> SerializeVerifierOwnedStatement(const Statement& statement) {
  std::vector<uint8_t> output;
  output.push_back(statement.protocol_version);
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
  output.push_back(statement.active);
  output.push_back(statement.complete);
  output.push_back(statement.authoritative_membership);
  output.push_back(statement.authoritative_absence);
  Append(output, statement.private_batch_commitment);
  return output;
}

bool EqualRange(const std::vector<uint8_t>& actual,
                const std::vector<uint8_t>& expected, size_t offset,
                size_t length) {
  return offset + length <= actual.size() &&
         std::equal(expected.begin() + offset,
                    expected.begin() + offset + length,
                    actual.begin() + offset);
}

bool ValidateStatement(const std::vector<uint8_t>& actual,
                       const std::vector<uint8_t>& expected,
                       std::string& reason) {
  if (actual.size() !=
      blind_ledger_longfellow::source_assertion_proof::kPublicStatementBytes) {
    reason = "statement.length";
    return false;
  }
  struct Field {
    size_t offset;
    size_t length;
    const char* reason;
  };
  const Field fields[] = {
      {0, 1, "statement.protocol"},
      {1, 64, "statement.proof-suite"},
      {65, blind_ledger_longfellow::source_assertion::kProofRoleBytes,
       "statement.proof-role"},
      {102, 64, "registry.execution-context"},
      {166, 64, "registry.source-snapshot"},
      {230, 64, "registry.profile"},
      {294, 64, "registry.governance"},
      {358, 64, "registry.control-set"},
      {422, 64, "registry.settlement-domain"},
      {486, 64, "registry.subject"},
      {550, 8, "state.epoch"},
      {558, 8, "state.sequence"},
      {566, 64, "state.before"},
      {630, 64, "request.id"},
      {694, 64, "source.root"},
      {758, 64, "source.completeness"},
      {822, 64, "decision-path"},
      {886, 64, "exception"},
      {950, 4, "assertion-flags"},
      {954, 64, "private-batch"},
  };
  for (const Field& field : fields) {
    if (!EqualRange(actual, expected, field.offset, field.length)) {
      reason = field.reason;
      return false;
    }
  }
  return true;
}

void PutU32(std::vector<uint8_t>& bytes, size_t offset, uint32_t value) {
  for (size_t index = 0; index < 4; ++index) {
    bytes[offset + index] = static_cast<uint8_t>(value >> (24 - index * 8));
  }
}

void PutU64(std::vector<uint8_t>& bytes, size_t offset, uint64_t value) {
  for (size_t index = 0; index < 8; ++index) {
    bytes[offset + index] = static_cast<uint8_t>(value >> (56 - index * 8));
  }
}

bool Flip(std::vector<uint8_t>& bytes, size_t offset) {
  if (offset >= bytes.size()) return false;
  bytes[offset] ^= 1;
  return true;
}

bool ApplyMutation(const std::string& name, std::vector<uint8_t>& bytes) {
  if (name == "wrong_circuit_id") return Flip(bytes, 12);
  if (name == "wrong_protocol") return Flip(bytes, kPublicBase + 0);
  if (name == "wrong_proof_suite") return Flip(bytes, kPublicBase + 1);
  if (name == "wrong_proof_role") return Flip(bytes, kPublicBase + 65);
  if (name == "wrong_execution_context" || name == "replayed_context")
    return Flip(bytes, kPublicBase + 102);
  if (name == "wrong_registry_snapshot") return Flip(bytes, kPublicBase + 166);
  if (name == "wrong_profile" || name == "source_profile_substitution")
    return Flip(bytes, kPublicBase + 230);
  if (name == "wrong_governance_snapshot") return Flip(bytes, kPublicBase + 294);
  if (name == "wrong_control_set" || name == "caller_downgraded_control")
    return Flip(bytes, kPublicBase + 358);
  if (name == "wrong_settlement_domain") return Flip(bytes, kPublicBase + 422);
  if (name == "wrong_subject" || name == "cross_subject")
    return Flip(bytes, kPublicBase + 486);
  if (name == "wrong_epoch") return Flip(bytes, kPublicBase + 550);
  if (name == "wrong_sequence") return Flip(bytes, kPublicBase + 558);
  if (name == "wrong_state") return Flip(bytes, kPublicBase + 566);
  if (name == "wrong_request" || name == "cross_request")
    return Flip(bytes, kPublicBase + 630);
  if (name == "wrong_source_root") return Flip(bytes, kPublicBase + 694);
  if (name == "wrong_completeness") return Flip(bytes, kPublicBase + 758);
  if (name == "wrong_decision_path") return Flip(bytes, kPublicBase + 822);
  if (name == "wrong_exception") return Flip(bytes, kPublicBase + 886);
  if (name == "incomplete_feed_absence") {
    bytes[kPublicBase + 951] = 0;
    bytes[kPublicBase + 953] = 1;
    return true;
  }
  if (name == "wrong_assertion_flag") return Flip(bytes, kPublicBase + 950);
  if (name == "wrong_private_batch") return Flip(bytes, kPublicBase + 954);
  if (name == "public_statement_order") {
    if (kPublicBase + 103 >= bytes.size()) return false;
    std::swap(bytes[kPublicBase + 102], bytes[kPublicBase + 103]);
    return true;
  }
  if (name == "public_statement_length") {
    if (bytes.size() < 60) return false;
    PutU32(bytes, 56, 1017);
    return true;
  }
  if (name == "wrong_version") {
    if (bytes.size() < 12) return false;
    PutU32(bytes, 8, 2);
    return true;
  }
  if (name == "wrong_parameters") {
    if (bytes.size() < 48) return false;
    PutU32(bytes, 44, 5);
    return true;
  }
  if (name == "oversized_length") {
    if (bytes.size() < 68) return false;
    PutU64(bytes, 60, 0xffffffffffffffffULL);
    return true;
  }
  if (name == "truncated" || name == "proof_truncated") {
    if (bytes.empty()) return false;
    bytes.pop_back();
    return true;
  }
  if (name == "trailing" || name == "proof_trailing") {
    bytes.push_back(0xa5);
    return true;
  }
  if (name == "proof_flip_begin") return Flip(bytes, kProofBase);
  if (name == "proof_flip_middle") return Flip(bytes, kProofBase +
                                                       (bytes.size() - kProofBase) / 2);
  if (name == "proof_flip_end") {
    return bytes.size() > kProofBase && Flip(bytes, bytes.size() - 1);
  }
  if (name == "malformed_serialization") {
    return bytes.size() > kProofBase && Flip(bytes, kProofBase);
  }
  return false;
}

bool FillPublicInput(const std::vector<uint8_t>& bytes,
                     const RelationField& field,
                     const proofs::Circuit<RelationField>& circuit,
                     proofs::Dense<RelationField>& public_input) {
  if (bytes.size() !=
          blind_ledger_longfellow::source_assertion_proof::kPublicStatementBytes ||
      circuit.npub_in != 1 + bytes.size() * 8) {
    return false;
  }
  proofs::DenseFiller<RelationField> filler(public_input);
  filler.push_back(field.one());
  for (uint8_t byte : bytes) filler.push_back(byte, 8, field);
  return filler.size() == public_input.n1_;
}

bool VerifyProof(const Artifact& artifact,
                 const std::vector<uint8_t>& expected_public,
                 const std::unique_ptr<proofs::Circuit<RelationField>>& circuit,
                 std::string& reason) {
  const RelationField field;
  proofs::Dense<RelationField> public_input(1, circuit->npub_in);
  if (!FillPublicInput(expected_public, field, *circuit, public_input)) {
    reason = "public-input";
    return false;
  }
  try {
    proofs::ZkProof<RelationField> proof(*circuit,
                                         blind_ledger_longfellow::source_assertion_proof::kLigeroRate,
                                         blind_ledger_longfellow::source_assertion_proof::kLigeroQueries);
    proofs::ReadBuffer buffer(artifact.proof);
    if (!proof.read(buffer, field) || buffer.remaining() != 0) {
      reason = "proof.serialization";
      return false;
    }
    using RSFactory = proofs::LCH14ReedSolomonFactory<RelationField>;
    const RSFactory rs_factory(field);
    proofs::Transcript transcript(
        reinterpret_cast<const uint8_t*>(kTranscriptLabel),
        sizeof(kTranscriptLabel) - 1,
        blind_ledger_longfellow::source_assertion_proof::kTranscriptVersion);
    proofs::ZkVerifier<RelationField, RSFactory> verifier(
        *circuit, rs_factory,
        blind_ledger_longfellow::source_assertion_proof::kLigeroRate,
        blind_ledger_longfellow::source_assertion_proof::kLigeroQueries, field);
    verifier.recv_commitment(proof, transcript);
    if (!verifier.verify(proof, public_input, transcript)) {
      reason = "proof.semantic";
      return false;
    }
    return true;
  } catch (const std::exception& exception) {
    reason = std::string("proof.exception:") + exception.what();
    return false;
  }
}

std::string CircuitId(const std::unique_ptr<proofs::Circuit<RelationField>>& circuit) {
  return blind_ledger_longfellow::source_assertion::source_assertion_hex(
      circuit->id, sizeof(circuit->id));
}

int Reject(const std::string& reason) {
  std::printf("SOURCE_ASSERTION_VERIFIER_REJECT reason=%s\n", reason.c_str());
  return 1;
}

int Mutation(const std::string& name, const std::string& path) {
  std::vector<uint8_t> bytes;
  std::string error;
  if (!blind_ledger_longfellow::source_assertion_proof::read_artifact_bytes(
          path, bytes, error)) {
    std::printf("SOURCE_ASSERTION_VERIFIER_MUTATION_PASS name=%s reason=read.%s\n",
                name.c_str(), error.c_str());
    return 0;
  }
  if (!ApplyMutation(name, bytes)) {
    std::printf("SOURCE_ASSERTION_VERIFIER_MUTATION_FAIL name=%s reason=unsupported-or-short\n",
                name.c_str());
    return 1;
  }
  Artifact artifact;
  if (!blind_ledger_longfellow::source_assertion_proof::parse_artifact_bytes(
          bytes, artifact, error)) {
    std::printf("SOURCE_ASSERTION_VERIFIER_MUTATION_PASS name=%s reason=artifact.%s\n",
                name.c_str(), error.c_str());
    return 0;
  }
  if (artifact.rate !=
          blind_ledger_longfellow::source_assertion_proof::kLigeroRate ||
      artifact.queries !=
          blind_ledger_longfellow::source_assertion_proof::kLigeroQueries ||
      artifact.transcript_version !=
          blind_ledger_longfellow::source_assertion_proof::kTranscriptVersion) {
    std::printf("SOURCE_ASSERTION_VERIFIER_MUTATION_PASS name=%s reason=artifact.parameters\n",
                name.c_str());
    return 0;
  }
  const std::vector<uint8_t> expected = SerializeVerifierOwnedStatement(
      BuildVerifierOwnedStatement());
  std::string reason;
  if (!ValidateStatement(artifact.public_statement, expected, reason)) {
    std::printf("SOURCE_ASSERTION_VERIFIER_MUTATION_PASS name=%s reason=%s\n",
                name.c_str(), reason.c_str());
    return 0;
  }
  auto circuit = blind_ledger_longfellow::source_assertion::build_source_assertion_circuit();
  std::array<uint8_t, 32> circuit_id{};
  std::copy(std::begin(circuit->id), std::end(circuit->id), circuit_id.begin());
  if (artifact.circuit_id != circuit_id) {
    std::printf("SOURCE_ASSERTION_VERIFIER_MUTATION_PASS name=%s reason=circuit-id\n",
                name.c_str());
    return 0;
  }
  if (!VerifyProof(artifact, expected, circuit, reason)) {
    std::printf("SOURCE_ASSERTION_VERIFIER_MUTATION_PASS name=%s reason=%s\n",
                name.c_str(), reason.c_str());
    return 0;
  }
  std::printf("SOURCE_ASSERTION_VERIFIER_MUTATION_FAIL name=%s reason=accepted\n",
              name.c_str());
  return 1;
}

}  // namespace

int main(int argc, char** argv) {
  using namespace blind_ledger_longfellow::source_assertion_proof;
  if (argc == 3 && std::string(argv[1]) == "--public-statement-file") {
    const std::vector<uint8_t> expected = SerializeVerifierOwnedStatement(
        BuildVerifierOwnedStatement());
    std::ofstream output(argv[2], std::ios::binary | std::ios::trunc);
    if (!output) return 2;
    output.write(reinterpret_cast<const char*>(expected.data()),
                 static_cast<std::streamsize>(expected.size()));
    if (!output) return 2;
    std::printf("SOURCE_ASSERTION_VERIFIER_PUBLIC_STATEMENT bytes=%zu path=%s\n",
                expected.size(), argv[2]);
    return 0;
  }
  if (argc == 2 && std::string(argv[1]) == "--circuit-id") {
    auto circuit = blind_ledger_longfellow::source_assertion::build_source_assertion_circuit();
    std::printf("SOURCE_ASSERTION_VERIFIER_CIRCUIT circuit_id=%s inputs=%zu "
                "public_inputs=%zu layers=%zu terms=%zu\n",
                CircuitId(circuit).c_str(), circuit->ninputs, circuit->npub_in,
                circuit->nl, circuit->nterms());
    return 0;
  }
  if (argc == 2 && std::string(argv[1]) == "--self-test") {
    const std::vector<uint8_t> expected = SerializeVerifierOwnedStatement(
        BuildVerifierOwnedStatement());
    if (expected.size() != kPublicStatementBytes) {
      return Reject("preflight.statement-length");
    }
    Artifact artifact;
    artifact.rate = kLigeroRate;
    artifact.queries = kLigeroQueries;
    artifact.transcript_version = kTranscriptVersion;
    artifact.public_statement = expected;
    std::vector<uint8_t> encoded;
    std::string error;
    if (!serialize_artifact(artifact, encoded, error)) {
      return Reject("preflight.serialize");
    }
    Artifact parsed;
    if (!parse_artifact_bytes(encoded, parsed, error)) {
      return Reject("preflight.parse");
    }
    std::string reason;
    if (!ValidateStatement(parsed.public_statement, expected, reason)) {
      return Reject("preflight." + reason);
    }
    encoded[kPublicBase] ^= 1;
    if (!parse_artifact_bytes(encoded, parsed, error) ||
        ValidateStatement(parsed.public_statement, expected, reason)) {
      return Reject("preflight.mutation");
    }
    std::printf("SOURCE_ASSERTION_PREFLIGHT_PASS public_bytes=%zu parser=1 "
                "verifier_owned_statement=1 proof_attempts=0\n",
                expected.size());
    return 0;
  }
  if (argc == 4 && std::string(argv[2]) == "--mutation") {
    return Mutation(argv[3], argv[1]);
  }
  if (argc != 2) {
    std::fprintf(stderr,
                 "usage: longfellow_source_assertion_verifier ARTIFACT | "
                 "ARTIFACT --mutation NAME | --self-test | --circuit-id\n");
    return 2;
  }
  std::vector<uint8_t> bytes;
  std::string error;
  if (!read_artifact_bytes(argv[1], bytes, error)) return Reject("artifact." + error);
  Artifact artifact;
  if (!parse_artifact_bytes(bytes, artifact, error)) return Reject("artifact." + error);
  if (artifact.rate != kLigeroRate || artifact.queries != kLigeroQueries ||
      artifact.transcript_version != kTranscriptVersion) {
    return Reject("artifact.parameters");
  }
  auto circuit = blind_ledger_longfellow::source_assertion::build_source_assertion_circuit();
  std::array<uint8_t, 32> circuit_id{};
  std::copy(std::begin(circuit->id), std::end(circuit->id), circuit_id.begin());
  if (artifact.circuit_id != circuit_id) return Reject("circuit-id");
  const std::vector<uint8_t> expected = SerializeVerifierOwnedStatement(
      BuildVerifierOwnedStatement());
  std::string reason;
  if (!ValidateStatement(artifact.public_statement, expected, reason)) {
    return Reject(reason);
  }
  if (!VerifyProof(artifact, expected, circuit, reason)) return Reject(reason);
  std::printf("SOURCE_ASSERTION_VERIFIER_ACCEPT inputs=%zu public_inputs=%zu "
              "layers=%zu terms=%zu public_bytes=%zu proof_bytes=%zu rate=%u "
              "queries=%u transcript_version=%u circuit_id=%s\n",
              circuit->ninputs, circuit->npub_in, circuit->nl, circuit->nterms(),
              artifact.public_statement.size(), artifact.proof.size(), kLigeroRate,
              kLigeroQueries, kTranscriptVersion, CircuitId(circuit).c_str());
  return 0;
}
