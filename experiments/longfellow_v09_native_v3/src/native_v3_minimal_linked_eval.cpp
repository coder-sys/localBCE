#include <array>
#include <cstdio>
#include <memory>
#include <string>
#include <vector>

#include "native_v3_minimal_linked_relation.h"
#include "sumcheck/prover_layers.h"

namespace {

using blind_ledger_longfellow::minimal_linked::Case;
using blind_ledger_longfellow::minimal_linked::Fixture;
using blind_ledger_longfellow::minimal_linked::RelationField;
constexpr uint8_t kHold = 2;

bool CircuitAccepts(const proofs::Circuit<RelationField>& circuit,
                    const Case& value, std::string& reason) {
  const RelationField field;
  proofs::Dense<RelationField> witness(1, circuit.ninputs);
  blind_ledger_longfellow::minimal_linked::fill_witness(value, witness);
  if (witness.n1_ != circuit.ninputs) {
    reason = "witness.input-count";
    return false;
  }
  proofs::ProverLayers<RelationField> evaluator(field);
  proofs::ProverLayers<RelationField>::inputs inputs;
  auto output = evaluator.eval_circuit(&inputs, &circuit, witness.clone(), field);
  if (output == nullptr) {
    reason = "circuit.evaluator";
    return false;
  }
  for (size_t index = 0; index < output->n1_; ++index) {
    if (output->v_[index] != field.zero()) {
      reason = "circuit.assertion";
      return false;
    }
  }
  return true;
}

void Flip(blind_ledger_longfellow::Digest& value) { value[0] ^= 0x01; }

void FlipRole(blind_ledger_longfellow::minimal_linked::ProofRole& value) {
  value[0] ^= 0x01;
}

struct Mutation {
  const char* name;
  Case value;
  const char* owner = "circuit";
  bool require_circuit_rejection = true;
  bool rebind_state = false;
};

}  // namespace

int main() {
  using namespace blind_ledger_longfellow::minimal_linked;
  const Fixture fixture = make_fixture();
  const Fixture retry_fixture = make_fixture();
  for (size_t index = 0; index < fixture.cases.size(); ++index) {
    if (public_statement_bytes(fixture.cases[index]) !=
            public_statement_bytes(retry_fixture.cases[index]) ||
        state_commitment_bytes(fixture.cases[index]) !=
            state_commitment_bytes(retry_fixture.cases[index]) ||
        derive_identities(fixture.cases[index]).decision_id !=
            derive_identities(retry_fixture.cases[index]).decision_id ||
        endpoint_input(fixture.cases[index], 0) !=
            endpoint_input(retry_fixture.cases[index], 0)) {
      std::printf("MINIMAL_CLEARANCE_DETERMINISM_FAIL case=%zu\n", index);
      return 1;
    }
  }
  std::printf(
      "MINIMAL_CLEARANCE_DETERMINISM_PASS cases=%zu public_bytes=%zu "
      "state_commitment_bytes=%zu private_source_endpoints=%zu request_hash_endpoints=0\n",
      fixture.cases.size(), public_statement_bytes(fixture.cases[0]).size(),
      state_commitment_bytes(fixture.cases[0]).size(), kSha3EndpointCount);
  auto circuit = build_circuit();
  auto semantic_circuit = build_circuit_stage(0);
  std::printf(
      "MINIMAL_CLEARANCE_CASE0 directive=%u policy=%u active=%u complete=%u "
      "membership=%u absence=%u exception_present=%u exception_authorized=%u "
      "economic_mutation=%u times=%llu,%llu,%llu,%llu sequence=%llu->%llu "
      "counts=%llu->%llu markers=%u->%u\n",
      fixture.cases[0].effective_directive, fixture.cases[0].policy_result,
      fixture.cases[0].statement.active, fixture.cases[0].statement.complete,
      fixture.cases[0].statement.authoritative_membership,
      fixture.cases[0].statement.authoritative_absence,
      fixture.cases[0].exception_present, fixture.cases[0].exception_authorized,
      fixture.cases[0].economic_mutation,
      static_cast<unsigned long long>(fixture.cases[0].rule_effective_time),
      static_cast<unsigned long long>(fixture.cases[0].event_time),
      static_cast<unsigned long long>(fixture.cases[0].observation_time),
      static_cast<unsigned long long>(fixture.cases[0].decision_time),
      static_cast<unsigned long long>(fixture.cases[0].statement.sequence_before),
      static_cast<unsigned long long>(fixture.cases[0].sequence_after),
      static_cast<unsigned long long>(fixture.cases[0].clearance_count_before),
      static_cast<unsigned long long>(fixture.cases[0].clearance_count_after),
      fixture.cases[0].clearance_marker_before,
      fixture.cases[0].clearance_marker_after);
  std::printf(
      "MINIMAL_CLEARANCE_EVAL_START cases=%zu inputs=%zu public_inputs=%zu "
      "layers=%zu terms=%zu proof_acceptance_is_separate=1 "
      "state_ids_external_after_acceptance=1 proof_attempts=0\n",
      fixture.cases.size(), circuit->ninputs, circuit->npub_in, circuit->nl,
      circuit->nterms());

  std::string semantic_reason;
  if (!CircuitAccepts(*semantic_circuit, fixture.cases[0], semantic_reason)) {
    std::printf(
        "MINIMAL_CLEARANCE_EVAL_FAIL case=0 owner=semantic-circuit reason=%s\n",
        semantic_reason.c_str());
    return 1;
  }
  std::printf("MINIMAL_CLEARANCE_SEMANTIC_CIRCUIT_PASS case=0\n");

  for (size_t index = 0; index < fixture.cases.size(); ++index) {
    std::string reason;
    if (!evaluate_case(fixture.cases[index], reason)) {
      std::printf("MINIMAL_CLEARANCE_EVAL_FAIL case=%zu owner=state-evaluator reason=%s\n",
                  index, reason.c_str());
      return 1;
    }
    if (!CircuitAccepts(*circuit, fixture.cases[index], reason)) {
      std::printf("MINIMAL_CLEARANCE_EVAL_FAIL case=%zu owner=circuit reason=%s\n",
                  index, reason.c_str());
      return 1;
    }
    const DerivedIdentities ids = derive_identities(fixture.cases[index]);
    std::printf(
        "MINIMAL_CLEARANCE_EVAL_PASS case=%zu directive=%u policy=%u "
        "source_membership=%u source_absence=%u decision_id_first=%02x "
        "join_id_first=%02x receipt_id_first=%02x settlement_id_first=%02x\n",
        index, fixture.cases[index].effective_directive,
        fixture.cases[index].policy_result,
        fixture.cases[index].statement.authoritative_membership,
        fixture.cases[index].statement.authoritative_absence, ids.decision_id[0],
        ids.join_id[0], ids.receipt_id[0], ids.settlement_id[0]);
  }

  std::vector<Mutation> mutations;
  Mutation source_registry{"source_registry_substitution", fixture.cases[0]};
  Flip(source_registry.value.statement.source_registry_snapshot);
  mutations.push_back(source_registry);

  Mutation source_profile{"source_profile_substitution", fixture.cases[0]};
  Flip(source_profile.value.statement.source_profile);
  mutations.push_back(source_profile);

  Mutation source_root{"source_root_substitution", fixture.cases[0]};
  Flip(source_root.value.statement.source_root_id);
  mutations.push_back(source_root);

  Mutation source_payload{"source_payload_substitution", fixture.cases[0]};
  Flip(source_payload.value.source_payload);
  mutations.push_back(source_payload);

  Mutation private_batch{"private_batch_commitment_substitution", fixture.cases[0]};
  Flip(private_batch.value.statement.private_batch_commitment);
  mutations.push_back(private_batch);

  Mutation completeness{"completeness_target_substitution", fixture.cases[0]};
  Flip(completeness.value.statement.completeness_id);
  mutations.push_back(completeness);

  Mutation incomplete_absence{"incomplete_feed_absence", fixture.cases[1]};
  incomplete_absence.value.statement.complete = 0;
  mutations.push_back(incomplete_absence);

  Mutation public_flag{"public_assertion_flag", fixture.cases[0]};
  public_flag.value.statement.active ^= 1;
  mutations.push_back(public_flag);

  Mutation equal_time{"equal_chronology", fixture.cases[0]};
  equal_time.value.event_time = equal_time.value.rule_effective_time;
  equal_time.rebind_state = true;
  mutations.push_back(equal_time);

  Mutation out_of_order{"out_of_order_chronology", fixture.cases[0]};
  out_of_order.value.decision_time = out_of_order.value.observation_time - 1;
  out_of_order.rebind_state = true;
  mutations.push_back(out_of_order);

  Mutation directive{"policy_directive_conflation", fixture.cases[0]};
  directive.value.effective_directive = kHold;
  directive.rebind_state = true;
  mutations.push_back(directive);

  Mutation unauthorized_exception{"unauthorized_exception", fixture.cases[4]};
  unauthorized_exception.value.exception_authorized = 0;
  mutations.push_back(unauthorized_exception);

  Mutation exception_scope{"exception_scope_substitution", fixture.cases[4]};
  Flip(exception_scope.value.statement.exception_scope_id);
  exception_scope.owner = "state-side";
  exception_scope.require_circuit_rejection = false;
  exception_scope.rebind_state = true;
  mutations.push_back(exception_scope);

  Mutation exception_interval{"exception_interval_substitution", fixture.cases[4]};
  exception_interval.value.exception_valid_from =
      exception_interval.value.event_time + 1;
  exception_interval.rebind_state = true;
  mutations.push_back(exception_interval);

  Mutation role_confusion{"read_write_role_confusion", fixture.cases[0]};
  role_confusion.value.read_mode = role_confusion.value.write_mode;
  role_confusion.rebind_state = true;
  mutations.push_back(role_confusion);

  Mutation access_reorder{"access_row_reorder", fixture.cases[0]};
  access_reorder.value.read_address = access_reorder.value.write_address;
  access_reorder.rebind_state = true;
  mutations.push_back(access_reorder);

  Mutation access_count{"wrong_access_count", fixture.cases[0]};
  access_count.value.access_count = 3;
  access_count.rebind_state = true;
  mutations.push_back(access_count);

  Mutation decision_index{"wrong_decision_index", fixture.cases[0]};
  decision_index.value.decision_index = 1;
  decision_index.rebind_state = true;
  mutations.push_back(decision_index);

  Mutation decision_binding{"decision_access_binding", fixture.cases[0]};
  Flip(decision_binding.value.read_decision_id);
  decision_binding.rebind_state = true;
  mutations.push_back(decision_binding);

  Mutation write_before{"wrong_write_before", fixture.cases[0]};
  Flip(write_before.value.write_before);
  write_before.rebind_state = true;
  mutations.push_back(write_before);

  Mutation write_after{"wrong_write_after", fixture.cases[0]};
  Flip(write_after.value.write_after);
  write_after.rebind_state = true;
  mutations.push_back(write_after);

  Mutation request_binding{"request_attempt_substitution", fixture.cases[0]};
  Flip(request_binding.value.statement.attempt_id);
  mutations.push_back(request_binding);

  Mutation request_id{"request_id_substitution", fixture.cases[0]};
  Flip(request_id.value.statement.request_id);
  mutations.push_back(request_id);

  Mutation subject{"subject_substitution", fixture.cases[0]};
  Flip(subject.value.statement.subject_id);
  mutations.push_back(subject);

  Mutation role{"proof_role_substitution", fixture.cases[0]};
  FlipRole(role.value.statement.proof_role);
  mutations.push_back(role);

  Mutation execution_context{"execution_context_substitution", fixture.cases[0]};
  Flip(execution_context.value.statement.execution_context);
  execution_context.owner = "verifier-public-statement";
  execution_context.require_circuit_rejection = false;
  mutations.push_back(execution_context);

  Mutation governance{"governance_snapshot_substitution", fixture.cases[0]};
  Flip(governance.value.statement.governance_snapshot);
  governance.owner = "verifier-public-statement";
  governance.require_circuit_rejection = false;
  mutations.push_back(governance);

  Mutation control_set{"control_set_substitution", fixture.cases[0]};
  Flip(control_set.value.statement.automatic_control_set);
  control_set.owner = "verifier-public-statement";
  control_set.require_circuit_rejection = false;
  mutations.push_back(control_set);

  Mutation evaluator{"evaluator_substitution", fixture.cases[0]};
  Flip(evaluator.value.statement.evaluator_id);
  evaluator.owner = "verifier-public-statement";
  evaluator.require_circuit_rejection = false;
  mutations.push_back(evaluator);

  Mutation schema{"schema_substitution", fixture.cases[0]};
  Flip(schema.value.statement.schema_id);
  schema.owner = "verifier-public-statement";
  schema.require_circuit_rejection = false;
  mutations.push_back(schema);

  Mutation program{"program_substitution", fixture.cases[0]};
  Flip(program.value.statement.program_id);
  program.owner = "verifier-public-statement";
  program.require_circuit_rejection = false;
  mutations.push_back(program);

  Mutation policy_binding{"policy_binding_substitution", fixture.cases[0]};
  Flip(policy_binding.value.statement.policy_id);
  policy_binding.owner = "verifier-public-statement";
  policy_binding.require_circuit_rejection = false;
  mutations.push_back(policy_binding);

  Mutation settlement_domain{"settlement_domain_substitution", fixture.cases[0]};
  Flip(settlement_domain.value.statement.settlement_domain);
  settlement_domain.owner = "verifier-public-statement";
  settlement_domain.require_circuit_rejection = false;
  mutations.push_back(settlement_domain);

  Mutation epoch{"epoch_substitution", fixture.cases[0]};
  ++epoch.value.statement.epoch;
  mutations.push_back(epoch);

  Mutation sequence{"sequence_substitution", fixture.cases[0]};
  ++sequence.value.statement.sequence_before;
  mutations.push_back(sequence);

  Mutation stale_state{"stale_state_before", fixture.cases[0]};
  Flip(stale_state.value.statement.state_before_id);
  stale_state.owner = "state-side";
  stale_state.require_circuit_rejection = false;
  mutations.push_back(stale_state);

  Mutation forked_state{"forked_state_after", fixture.cases[0]};
  Flip(forked_state.value.statement.state_after_id);
  forked_state.owner = "state-side";
  forked_state.require_circuit_rejection = false;
  mutations.push_back(forked_state);

  Mutation state_bytes{"state_commitment_substitution", fixture.cases[0]};
  state_bytes.value.statement.state_commitment_bytes[100] ^= 1;
  mutations.push_back(state_bytes);

  Mutation economic{"economic_mutation_claim", fixture.cases[0]};
  economic.value.economic_mutation = 1;
  economic.rebind_state = true;
  mutations.push_back(economic);

  for (const Mutation& mutation : mutations) {
    Mutation candidate = mutation;
    if (candidate.rebind_state) {
      rebuild_state_binding(candidate.value);
    }
    std::string host_reason;
    const bool host_accepts = evaluate_case(candidate.value, host_reason);
    std::string circuit_reason;
    const bool circuit_accepts =
        CircuitAccepts(*circuit, candidate.value, circuit_reason);
    if (host_accepts ||
        (mutation.require_circuit_rejection && circuit_accepts)) {
      std::printf(
        "MINIMAL_CLEARANCE_MUTATION_FAIL name=%s host_accepts=%d "
          "circuit_accepts=%d owner=%s host_reason=%s circuit_reason=%s\n",
          candidate.name, host_accepts ? 1 : 0, circuit_accepts ? 1 : 0,
          candidate.owner, host_reason.c_str(), circuit_reason.c_str());
      return 2;
    }
    std::printf(
      "MINIMAL_CLEARANCE_MUTATION_PASS name=%s host_reason=%s "
        "circuit_accepts=%d owner=%s circuit_reason=%s\n",
        candidate.name, host_reason.c_str(), circuit_accepts ? 1 : 0,
        candidate.owner, circuit_reason.c_str());
  }
  std::printf("MINIMAL_CLEARANCE_EVAL_PASS valid_cases=5 mutation_cases=%zu\n",
              mutations.size());
  return 0;
}
