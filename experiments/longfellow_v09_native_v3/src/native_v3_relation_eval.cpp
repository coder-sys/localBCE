#include <cstdio>
#include <memory>

#include "native_v3_relation.h"
#include "sumcheck/prover_layers.h"

int main() {
  using namespace blind_ledger_longfellow;
  auto circuit = build_native_v3_circuit();
  const auto fixture = make_native_v3_fixture();
  const RelationField field;
  for (size_t i = 0; i < fixture.cases.size(); ++i) {
    proofs::Dense<RelationField> witness(1, circuit->ninputs);
    fill_native_v3_witness(fixture.cases[i], witness);
    proofs::ProverLayers<RelationField> evaluator(field);
    proofs::ProverLayers<RelationField>::inputs inputs;
    auto output = evaluator.eval_circuit(&inputs, circuit.get(),
                                         witness.clone(), field);
    if (output == nullptr) {
      std::printf("NATIVE_V3_RELATION_EVAL_FAIL case=%zu reason=assertion\n", i);
      return 1;
    }
    for (size_t j = 0; j < output->n1_; ++j) {
      if (output->v_[j] != field.zero()) {
        std::printf("NATIVE_V3_RELATION_EVAL_FAIL case=%zu reason=nonzero_output index=%zu\n",
                    i, j);
        return 1;
      }
    }
    std::printf("NATIVE_V3_RELATION_EVAL_PASS case=%zu inputs=%zu\n", i,
                witness.n1_);
  }
  return 0;
}
