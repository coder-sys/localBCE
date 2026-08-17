#include "native_v3_source_assertion_relation.h"

#include <array>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>

#include "circuits/compiler/compiler.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/tests/sha3/sha3_circuit.h"
#include "circuits/tests/sha3/sha3_reference.h"
#include "circuits/tests/sha3/sha3_witness.h"
#include "sha3_512_witness.h"
#include "util/panic.h"

namespace blind_ledger_longfellow::source_assertion {
namespace {

constexpr size_t kEndpointCount = 4;

std::vector<uint8_t> Domain(const char* text) {
  const size_t length = std::strlen(text);
  std::vector<uint8_t> result(text, text + length);
  result.push_back(0);
  return result;
}

void Append(std::vector<uint8_t>& output, const std::vector<uint8_t>& value) {
  output.insert(output.end(), value.begin(), value.end());
}

void Append(std::vector<uint8_t>& output, const Digest& value) {
  output.insert(output.end(), value.begin(), value.end());
}

std::vector<uint8_t> ToVector(const Digest& value) {
  return std::vector<uint8_t>(value.begin(), value.end());
}

void AppendU8(std::vector<uint8_t>& output, uint8_t value) {
  output.push_back(value);
}

void AppendU64(std::vector<uint8_t>& output, uint64_t value) {
  for (size_t index = 0; index < 8; ++index) {
    output.push_back(static_cast<uint8_t>(value >> (56 - 8 * index)));
  }
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

void FillProofRole(ProofRole& role) {
  for (size_t index = 0; index < kProofRoleBytes; ++index) {
    role[index] = static_cast<uint8_t>(kProofRole[index]);
  }
}

template <class Logic>
using V8 = typename Logic::template bitvec<8>;

template <class Logic>
using V64 = typename Logic::template bitvec<64>;

template <class Logic>
using Byte64 = std::array<V8<Logic>, kDigestBytes>;

template <class Logic>
using Role = std::array<V8<Logic>, kProofRoleBytes>;

template <class Logic>
struct PublicWires {
  V8<Logic> protocol;
  Byte64<Logic> proof_suite;
  Role<Logic> proof_role;
  Byte64<Logic> execution_context;
  Byte64<Logic> source_registry_snapshot;
  Byte64<Logic> source_profile;
  Byte64<Logic> governance_snapshot;
  Byte64<Logic> automatic_control_set;
  Byte64<Logic> settlement_domain;
  Byte64<Logic> subject_scope;
  V64<Logic> epoch;
  V64<Logic> sequence_before;
  Byte64<Logic> state_before_id;
  Byte64<Logic> request_id;
  Byte64<Logic> source_root_id;
  Byte64<Logic> completeness_id;
  Byte64<Logic> decision_path_id;
  Byte64<Logic> exception_id;
  V8<Logic> active;
  V8<Logic> complete;
  V8<Logic> authoritative_membership;
  V8<Logic> authoritative_absence;
  Byte64<Logic> private_batch_commitment;
};

template <class Logic>
struct PrivateWires {
  Byte64<Logic> provider_id;
  Byte64<Logic> credential_id;
  Byte64<Logic> enrollment_id;
  Byte64<Logic> attempt_id;
  Byte64<Logic> source_payload;
  V8<Logic> active;
  V8<Logic> complete;
  V8<Logic> authoritative_membership;
  V8<Logic> authoritative_absence;
  V64<Logic> event_time;
  V64<Logic> observation_time;
  V64<Logic> rule_effective_time;
  V64<Logic> decision_time;
};

template <class Logic>
using HashWires = std::array<Byte64<Logic>, kEndpointCount>;

template <class Logic>
const Byte64<Logic>& H(const HashWires<Logic>& hashes, Endpoint endpoint) {
  return hashes[static_cast<size_t>(endpoint)];
}

template <class Logic>
void InputDigest(const Logic& logic, Byte64<Logic>& output) {
  for (auto& byte : output) byte = logic.template vinput<8>();
}

template <class Logic>
void InputPublic(const Logic& logic, PublicWires<Logic>& output) {
  output.protocol = logic.template vinput<8>();
  InputDigest(logic, output.proof_suite);
  for (auto& byte : output.proof_role) byte = logic.template vinput<8>();
  InputDigest(logic, output.execution_context);
  InputDigest(logic, output.source_registry_snapshot);
  InputDigest(logic, output.source_profile);
  InputDigest(logic, output.governance_snapshot);
  InputDigest(logic, output.automatic_control_set);
  InputDigest(logic, output.settlement_domain);
  InputDigest(logic, output.subject_scope);
  output.epoch = logic.template vinput<64>();
  output.sequence_before = logic.template vinput<64>();
  InputDigest(logic, output.state_before_id);
  InputDigest(logic, output.request_id);
  InputDigest(logic, output.source_root_id);
  InputDigest(logic, output.completeness_id);
  InputDigest(logic, output.decision_path_id);
  InputDigest(logic, output.exception_id);
  output.active = logic.template vinput<8>();
  output.complete = logic.template vinput<8>();
  output.authoritative_membership = logic.template vinput<8>();
  output.authoritative_absence = logic.template vinput<8>();
  InputDigest(logic, output.private_batch_commitment);
}

template <class Logic>
void InputPrivate(const Logic& logic, PrivateWires<Logic>& output) {
  InputDigest(logic, output.provider_id);
  InputDigest(logic, output.credential_id);
  InputDigest(logic, output.enrollment_id);
  InputDigest(logic, output.attempt_id);
  InputDigest(logic, output.source_payload);
  output.active = logic.template vinput<8>();
  output.complete = logic.template vinput<8>();
  output.authoritative_membership = logic.template vinput<8>();
  output.authoritative_absence = logic.template vinput<8>();
  output.event_time = logic.template vinput<64>();
  output.observation_time = logic.template vinput<64>();
  output.rule_effective_time = logic.template vinput<64>();
  output.decision_time = logic.template vinput<64>();
}

template <class Logic>
void AppendBytes(std::vector<V8<Logic>>& output, const Byte64<Logic>& value) {
  output.insert(output.end(), value.begin(), value.end());
}

template <class Logic>
void AppendDomain(std::vector<V8<Logic>>& output, const char* text,
                  const Logic& logic) {
  const size_t length = std::strlen(text);
  for (size_t index = 0; index < length; ++index) {
    output.push_back(logic.vbit8(static_cast<uint8_t>(text[index])));
  }
  output.push_back(logic.vbit8(0));
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
typename Logic::BitW EqualByte(const Logic& logic, const V8<Logic>& value,
                               uint8_t expected) {
  typename Logic::BitW result = logic.bit(1);
  const auto encoded = logic.vbit8(expected);
  for (size_t bit = 0; bit < 8; ++bit) {
    result = logic.land(result, logic.lnot(logic.lxor(value[bit], encoded[bit])));
  }
  return result;
}

template <class Logic>
void AssertBooleanByte(const Logic& logic, const V8<Logic>& value) {
  (void)logic.assert1(logic.lor(EqualByte(logic, value, 0),
                                EqualByte(logic, value, 1)));
}

template <class Logic>
void AssertImplies(const Logic& logic, const typename Logic::BitW& selector,
                   const typename Logic::BitW& condition) {
  (void)logic.assert_implies(selector, condition);
}

template <class Logic>
void AssertSourceFlags(const Logic& logic, const PublicWires<Logic>& pub,
                       const PrivateWires<Logic>& priv) {
  logic.vassert_eq(pub.active, priv.active);
  logic.vassert_eq(pub.complete, priv.complete);
  logic.vassert_eq(pub.authoritative_membership,
                   priv.authoritative_membership);
  logic.vassert_eq(pub.authoritative_absence, priv.authoritative_absence);
  AssertBooleanByte(logic, priv.active);
  AssertBooleanByte(logic, priv.complete);
  AssertBooleanByte(logic, priv.authoritative_membership);
  AssertBooleanByte(logic, priv.authoritative_absence);
  AssertImplies(logic, EqualByte(logic, priv.authoritative_absence, 1),
                EqualByte(logic, priv.complete, 1));
  AssertImplies(logic, EqualByte(logic, priv.authoritative_membership, 1),
                EqualByte(logic, priv.authoritative_absence, 0));
}

template <class Logic>
std::vector<V8<Logic>> SeedFor(Endpoint endpoint,
                               const PublicWires<Logic>& pub,
                               const PrivateWires<Logic>& priv,
                               const HashWires<Logic>& hashes,
                               const Logic& logic) {
  std::vector<V8<Logic>> result;
  switch (endpoint) {
    case Endpoint::kSourceRoot:
      AppendDomain<Logic>(result, "BL/NATIVE-V3/SOURCE-ROOT/v1", logic);
      AppendBytes<Logic>(result, priv.provider_id);
      AppendBytes<Logic>(result, priv.credential_id);
      AppendBytes<Logic>(result, priv.enrollment_id);
      result.push_back(priv.active);
      result.push_back(priv.complete);
      result.push_back(priv.authoritative_membership);
      result.push_back(priv.authoritative_absence);
      break;
    case Endpoint::kCompleteness:
      AppendDomain<Logic>(result, "BL/NATIVE-V3/COMPLETENESS/v1", logic);
      AppendBytes<Logic>(result, priv.provider_id);
      AppendBytes<Logic>(result, priv.credential_id);
      result.push_back(priv.complete);
      result.push_back(priv.authoritative_absence);
      break;
    case Endpoint::kRequest:
      AppendDomain<Logic>(result, "BL/NATIVE-V3/REQUEST-ID/v1", logic);
      AppendBytes<Logic>(result, priv.provider_id);
      AppendBytes<Logic>(result, priv.credential_id);
      AppendBytes<Logic>(result, priv.enrollment_id);
      AppendBytes<Logic>(result, priv.attempt_id);
      AppendU64BE<Logic>(result, pub.epoch);
      AppendU64BE<Logic>(result, pub.sequence_before);
      AppendU64BE<Logic>(result, priv.event_time);
      AppendU64BE<Logic>(result, priv.observation_time);
      AppendU64BE<Logic>(result, priv.rule_effective_time);
      AppendU64BE<Logic>(result, priv.decision_time);
      AppendBytes<Logic>(result, pub.state_before_id);
      break;
    case Endpoint::kPrivateBatch:
      AppendDomain<Logic>(result, "BL/NATIVE-V3/PRIVATE-BATCH/v1", logic);
      AppendBytes<Logic>(result, priv.source_payload);
      AppendBytes<Logic>(result, pub.decision_path_id);
      AppendBytes<Logic>(result, pub.exception_id);
      AppendBytes<Logic>(result, H<Logic>(hashes, Endpoint::kRequest));
      break;
  }
  return result;
}

template <class Logic>
void BindEndpoint(const Logic& logic, proofs::Sha3Circuit<Logic>& sha3,
                  Endpoint endpoint, const PublicWires<Logic>& pub,
                  const PrivateWires<Logic>& priv, HashWires<Logic>& hashes) {
  const auto seed = SeedFor(endpoint, pub, priv, hashes, logic);
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
  hashes[static_cast<size_t>(endpoint)] = {};
  auto& digest = hashes[static_cast<size_t>(endpoint)];
  for (size_t index = 0; index < kDigestBytes; ++index) {
    digest[index] = output[index];
  }
  const Byte64<Logic>* target = nullptr;
  switch (endpoint) {
    case Endpoint::kSourceRoot:
      target = &pub.source_root_id;
      break;
    case Endpoint::kCompleteness:
      target = &pub.completeness_id;
      break;
    case Endpoint::kRequest:
      target = &pub.request_id;
      break;
    case Endpoint::kPrivateBatch:
      target = &pub.private_batch_commitment;
      break;
  }
  for (size_t index = 0; index < kDigestBytes; ++index) {
    logic.vassert_eq((*target)[index], output[index]);
  }
}

template <class Logic>
void AssertPublicContract(const Logic& logic, const PublicWires<Logic>& pub) {
  logic.vassert_eq(pub.protocol, 3);
  for (const auto& byte : pub.proof_suite) logic.vassert_eq(byte, 0);
  for (size_t index = 0; index < kProofRoleBytes; ++index) {
    logic.vassert_eq(pub.proof_role[index],
                     static_cast<uint8_t>(kProofRole[index]));
  }
}

template <class Logic>
void PushDigest(proofs::DenseFiller<RelationField>& filler, const Digest& value,
                const RelationField& field) {
  for (uint8_t byte : value) filler.push_back(byte, 8, field);
}

template <class Logic>
void PushPublic(proofs::DenseFiller<RelationField>& filler,
                const Statement& statement, const RelationField& field) {
  filler.push_back(field.one());
  filler.push_back(statement.protocol_version, 8, field);
  PushDigest<Logic>(filler, statement.proof_suite, field);
  for (uint8_t byte : statement.proof_role) filler.push_back(byte, 8, field);
  PushDigest<Logic>(filler, statement.execution_context, field);
  PushDigest<Logic>(filler, statement.source_registry_snapshot, field);
  PushDigest<Logic>(filler, statement.source_profile, field);
  PushDigest<Logic>(filler, statement.governance_snapshot, field);
  PushDigest<Logic>(filler, statement.automatic_control_set, field);
  PushDigest<Logic>(filler, statement.settlement_domain, field);
  PushDigest<Logic>(filler, statement.subject_scope, field);
  filler.push_back(statement.epoch, 64, field);
  filler.push_back(statement.sequence_before, 64, field);
  PushDigest<Logic>(filler, statement.state_before_id, field);
  PushDigest<Logic>(filler, statement.request_id, field);
  PushDigest<Logic>(filler, statement.source_root_id, field);
  PushDigest<Logic>(filler, statement.completeness_id, field);
  PushDigest<Logic>(filler, statement.decision_path_id, field);
  PushDigest<Logic>(filler, statement.exception_id, field);
  filler.push_back(statement.active, 8, field);
  filler.push_back(statement.complete, 8, field);
  filler.push_back(statement.authoritative_membership, 8, field);
  filler.push_back(statement.authoritative_absence, 8, field);
  PushDigest<Logic>(filler, statement.private_batch_commitment, field);
}

template <class Logic>
void PushPrivate(proofs::DenseFiller<RelationField>& filler,
                 const Witness& witness, const RelationField& field) {
  PushDigest<Logic>(filler, witness.provider_id, field);
  PushDigest<Logic>(filler, witness.credential_id, field);
  PushDigest<Logic>(filler, witness.enrollment_id, field);
  PushDigest<Logic>(filler, witness.attempt_id, field);
  PushDigest<Logic>(filler, witness.source_payload, field);
  filler.push_back(witness.active, 8, field);
  filler.push_back(witness.complete, 8, field);
  filler.push_back(witness.authoritative_membership, 8, field);
  filler.push_back(witness.authoritative_absence, 8, field);
  filler.push_back(witness.event_time, 64, field);
  filler.push_back(witness.observation_time, 64, field);
  filler.push_back(witness.rule_effective_time, 64, field);
  filler.push_back(witness.decision_time, 64, field);
}

std::vector<uint8_t> EndpointInput(const SourceAssertionCase& source_case,
                                   Endpoint endpoint) {
  const Witness& witness = source_case.witness;
  const Statement& statement = source_case.statement;
  std::vector<uint8_t> result;
  switch (endpoint) {
    case Endpoint::kSourceRoot:
      Append(result, Domain("BL/NATIVE-V3/SOURCE-ROOT/v1"));
      Append(result, witness.provider_id);
      Append(result, witness.credential_id);
      Append(result, witness.enrollment_id);
      AppendU8(result, witness.active);
      AppendU8(result, witness.complete);
      AppendU8(result, witness.authoritative_membership);
      AppendU8(result, witness.authoritative_absence);
      break;
    case Endpoint::kCompleteness:
      Append(result, Domain("BL/NATIVE-V3/COMPLETENESS/v1"));
      Append(result, witness.provider_id);
      Append(result, witness.credential_id);
      AppendU8(result, witness.complete);
      AppendU8(result, witness.authoritative_absence);
      break;
    case Endpoint::kRequest:
      Append(result, Domain("BL/NATIVE-V3/REQUEST-ID/v1"));
      Append(result, witness.provider_id);
      Append(result, witness.credential_id);
      Append(result, witness.enrollment_id);
      Append(result, witness.attempt_id);
      AppendU64(result, statement.epoch);
      AppendU64(result, statement.sequence_before);
      AppendU64(result, witness.event_time);
      AppendU64(result, witness.observation_time);
      AppendU64(result, witness.rule_effective_time);
      AppendU64(result, witness.decision_time);
      Append(result, statement.state_before_id);
      break;
    case Endpoint::kPrivateBatch:
      Append(result, Domain("BL/NATIVE-V3/PRIVATE-BATCH/v1"));
      Append(result, witness.source_payload);
      Append(result, statement.decision_path_id);
      Append(result, statement.exception_id);
      Append(result, HashBytes(EndpointInput(source_case, Endpoint::kRequest)));
      break;
  }
  return result;
}

}  // namespace

SourceAssertionFixture make_source_assertion_fixture() {
  SourceAssertionFixture fixture;
  const Digest provider =
      HashText("BL/NATIVE-V3/SYNTHETIC-PROVIDER/v1", "provider-1");
  const Digest credential =
      HashText("BL/NATIVE-V3/SYNTHETIC-CREDENTIAL/v1", "credential-1");
  const Digest enrollment =
      HashText("BL/NATIVE-V3/SYNTHETIC-ENROLLMENT/v1", "enrollment-1");
  const Digest context = HashText(
      "BL/NATIVE-V3/SOURCE-ASSERTION/EXECUTION-CONTEXT/v1", "fixed-context");
  const Digest registry = HashText(
      "BL/NATIVE-V3/SOURCE-ASSERTION/REGISTRY-SNAPSHOT/v1", "immutable-v1");
  const Digest profile = HashText(
      "BL/NATIVE-V3/SOURCE-ASSERTION/PROFILE/v1", "source-assertion-only-v1");
  const Digest governance = HashText(
      "BL/NATIVE-V3/SOURCE-ASSERTION/GOVERNANCE/v1", "governance-v1");
  const Digest control = HashText(
      "BL/NATIVE-V3/SOURCE-ASSERTION/CONTROL-SET/v1",
      "five-directives-v1");
  const Digest settlement_domain = HashText(
      "BL/NATIVE-V3/SOURCE-ASSERTION/SETTLEMENT-DOMAIN/v1",
      "official-state-rail");
  const Digest state_before = HashText(
      "BL/NATIVE-V3/SOURCE-ASSERTION/STATE-BEFORE/v1", "initial");

  struct Spec {
    const char* label;
    uint8_t active;
    uint8_t complete;
    uint8_t membership;
    uint8_t absence;
    bool exception;
  };
  const Spec specs[] = {
      {"clear", 1, 1, 1, 0, false},
      {"hold", 0, 1, 0, 1, false},
      {"human-review", 0, 0, 0, 0, false},
      {"block", 0, 1, 1, 0, false},
      {"exception-approved", 0, 1, 1, 0, true},
  };

  for (size_t index = 0; index < fixture.cases.size(); ++index) {
    const Spec& spec = specs[index];
    SourceAssertionCase& source_case = fixture.cases[index];
    source_case.label = spec.label;
    Statement& statement = source_case.statement;
    Witness& witness = source_case.witness;
    FillProofRole(statement.proof_role);
    statement.proof_suite.fill(0);
    statement.execution_context = context;
    statement.source_registry_snapshot = registry;
    statement.source_profile = profile;
    statement.governance_snapshot = governance;
    statement.automatic_control_set = control;
    statement.settlement_domain = settlement_domain;
    statement.subject_scope =
        HashText("BL/NATIVE-V3/SOURCE-ASSERTION/SUBJECT-SCOPE/v1", spec.label);
    statement.epoch = 7;
    statement.sequence_before = 0;
    statement.state_before_id = state_before;

    witness.provider_id = provider;
    witness.credential_id = credential;
    witness.enrollment_id = enrollment;
    witness.attempt_id =
        HashText("BL/NATIVE-V3/SOURCE-ASSERTION/ATTEMPT/v1", spec.label);
    witness.active = spec.active;
    witness.complete = spec.complete;
    witness.authoritative_membership = spec.membership;
    witness.authoritative_absence = spec.absence;
    witness.event_time = 7000;
    witness.observation_time = 7001;
    witness.rule_effective_time = 6999;
    witness.decision_time = 7002;
    witness.source_payload = HashParts(
        Domain("BL/NATIVE-V3/SOURCE-PAYLOAD/v1"),
        {ToVector(provider), ToVector(credential), ToVector(enrollment),
         std::vector<uint8_t>{spec.active, spec.complete, spec.membership,
                              spec.absence}});
    statement.decision_path_id = HashText(
        "BL/NATIVE-V3/SOURCE-ASSERTION/DECISION-PATH/v1", spec.label);
    statement.exception_id = spec.exception
                                  ? HashText(
                                        "BL/NATIVE-V3/EXCEPTION-AUTHORIZATION-ID/v1",
                                        spec.label)
                                  : Sentinel();
    statement.active = spec.active;
    statement.complete = spec.complete;
    statement.authoritative_membership = spec.membership;
    statement.authoritative_absence = spec.absence;
    statement.source_root_id =
        HashBytes(EndpointInput(source_case, Endpoint::kSourceRoot));
    statement.completeness_id =
        HashBytes(EndpointInput(source_case, Endpoint::kCompleteness));
    statement.request_id =
        HashBytes(EndpointInput(source_case, Endpoint::kRequest));
    statement.private_batch_commitment =
        HashBytes(EndpointInput(source_case, Endpoint::kPrivateBatch));
  }
  return fixture;
}

std::vector<uint8_t> build_source_assertion_hash_input(
    const SourceAssertionCase& source_case, Endpoint endpoint) {
  return EndpointInput(source_case, endpoint);
}

std::vector<uint8_t> source_assertion_statement_bytes(
    const Statement& statement) {
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

size_t source_assertion_endpoint_count() { return kEndpointCount; }

Endpoint source_assertion_endpoint_at(size_t index) {
  proofs::check(index < kEndpointCount,
                "source assertion endpoint index out of range");
  return static_cast<Endpoint>(index);
}

std::unique_ptr<proofs::Circuit<RelationField>>
build_source_assertion_circuit_stage(size_t endpoint_count) {
  proofs::check(endpoint_count <= kEndpointCount,
                "source assertion endpoint stage exceeds endpoint count");
  using Backend = proofs::CompilerBackend<RelationField>;
  using Logic = proofs::Logic<RelationField, Backend>;
  auto field = std::make_unique<RelationField>();
  auto builder = std::make_unique<proofs::QuadCircuit<RelationField>>(*field);
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
  AssertPublicContract(logic, *pub);
  AssertSourceFlags(logic, *pub, *priv);
  HashWires<Logic> hashes{};
  for (size_t index = 0; index < endpoint_count; ++index) {
    std::fprintf(stderr, "RELATION_BUILD phase=sha3 index=%zu endpoint=%zu\n",
                 index, index);
    BindEndpoint(logic, sha3, source_assertion_endpoint_at(index), *pub,
                 *priv, hashes);
  }
  std::fprintf(stderr, "RELATION_BUILD phase=mkcircuit\n");
  const auto start = std::chrono::steady_clock::now();
  auto circuit = builder->mkcircuit(1);
  const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                           std::chrono::steady_clock::now() - start)
                           .count();
  std::fprintf(stderr, "RELATION_BUILD phase=complete mkcircuit_ms=%lld\n",
               static_cast<long long>(elapsed));
  return circuit;
}

std::unique_ptr<proofs::Circuit<RelationField>>
build_source_assertion_circuit() {
  return build_source_assertion_circuit_stage(kEndpointCount);
}

#ifndef BLIND_LEDGER_RELATION_CIRCUIT_ONLY
void fill_source_assertion_public(const SourceAssertionCase& source_case,
                                  proofs::Dense<RelationField>& public_input) {
  const RelationField field;
  proofs::DenseFiller<RelationField> filler(public_input);
  using Logic = proofs::Logic<RelationField,
                              proofs::CompilerBackend<RelationField>>;
  PushPublic<Logic>(filler, source_case.statement, field);
}

void fill_source_assertion_witness(const SourceAssertionCase& source_case,
                                   proofs::Dense<RelationField>& witness) {
  const RelationField field;
  proofs::DenseFiller<RelationField> filler(witness);
  using Logic = proofs::Logic<RelationField,
                              proofs::CompilerBackend<RelationField>>;
  PushPublic<Logic>(filler, source_case.statement, field);
  PushPrivate<Logic>(filler, source_case.witness, field);
#if !defined(BLIND_LEDGER_LONGFELLOW_NO_SHA3_WITNESS)
  for (size_t index = 0; index < kEndpointCount; ++index) {
    std::vector<blind_ledger_longfellow::Sha3BlockWitness> witnesses;
    compute_sha3_512_witness(
        EndpointInput(source_case, source_assertion_endpoint_at(index)),
        witnesses);
    proofs::Sha3Witness::fill_witness(filler, witnesses, field);
  }
#endif
}
#endif  // BLIND_LEDGER_RELATION_CIRCUIT_ONLY

std::string source_assertion_hex(const uint8_t* bytes, size_t length) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string output;
  output.reserve(length * 2);
  for (size_t index = 0; index < length; ++index) {
    output.push_back(kHex[bytes[index] >> 4]);
    output.push_back(kHex[bytes[index] & 0x0f]);
  }
  return output;
}

}  // namespace blind_ledger_longfellow::source_assertion
