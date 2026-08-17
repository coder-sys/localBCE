#include <cstdio>
#include <memory>

#include "native_v3_relation.h"
#include "sumcheck/prover_layers.h"

namespace {

bool Evaluates(const proofs::Circuit<blind_ledger_longfellow::RelationField>*
                   circuit,
               const blind_ledger_longfellow::RelationCase& fixture,
               const blind_ledger_longfellow::RelationField& field) {
  using namespace blind_ledger_longfellow;
  proofs::Dense<RelationField> witness(1, circuit->ninputs);
  fill_native_v3_witness(fixture, witness);
  proofs::ProverLayers<RelationField> evaluator(field);
  proofs::ProverLayers<RelationField>::inputs inputs;
  auto output = evaluator.eval_circuit(&inputs, circuit, witness.clone(), field);
  if (output == nullptr) return false;
  for (size_t j = 0; j < output->n1_; ++j) {
    if (output->v_[j] != field.zero()) return false;
  }
  return true;
}

}  // namespace

int main() {
  using namespace blind_ledger_longfellow;
  auto circuit = build_native_v3_circuit();
  const auto fixture = make_native_v3_fixture();
  const RelationField field;
  for (size_t i = 0; i < fixture.cases.size(); ++i) {
    if (!Evaluates(circuit.get(), fixture.cases[i], field)) {
      std::printf("NATIVE_V3_RELATION_EVAL_FAIL case=%zu reason=assertion\n", i);
      return 1;
    }
    std::printf("NATIVE_V3_RELATION_EVAL_PASS case=%zu inputs=%zu\n", i,
                circuit->ninputs);
  }

  struct Mutation {
    const char* name;
    RelationCase value;
  };
  std::vector<Mutation> mutations;

  Mutation chronology{"equal_chronology", fixture.cases[0]};
  chronology.value.event_time = chronology.value.rule_effective_time;
  mutations.push_back(chronology);

  Mutation role{"read_write_role_confusion", fixture.cases[0]};
  role.value.read_mode = role.value.write_mode;
  mutations.push_back(role);

  Mutation write_before{"wrong_write_before", fixture.cases[0]};
  write_before.value.write_before[0] ^= 0x01;
  mutations.push_back(write_before);

  Mutation directive{"policy_directive_mismatch", fixture.cases[0]};
  directive.value.effective_directive =
      static_cast<uint8_t>((directive.value.effective_directive + 1) % 5);
  mutations.push_back(directive);

  for (const Mutation& mutation : mutations) {
    if (Evaluates(circuit.get(), mutation.value, field)) {
      std::printf("NATIVE_V3_RELATION_EVAL_MUTATION_FAIL name=%s reason=accepted\n",
                  mutation.name);
      return 2;
    }
    std::printf("NATIVE_V3_RELATION_EVAL_MUTATION_PASS name=%s\n",
                mutation.name);
  }
  return 0;
}
