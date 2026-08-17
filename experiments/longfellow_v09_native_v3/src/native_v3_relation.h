#ifndef BLIND_LEDGER_LONGFELLOW_V09_NATIVE_V3_RELATION_H_
#define BLIND_LEDGER_LONGFELLOW_V09_NATIVE_V3_RELATION_H_

#include <memory>
#include <string>
#include <vector>

#include "arrays/dense.h"
#include "gf2k/gf2_128.h"
#include "sumcheck/circuit.h"
#include "native_v3_fixture.h"

namespace blind_ledger_longfellow {

using RelationField = proofs::GF2_128<>;

// Builds one fixed circuit shape for all five directives. The directive and
// policy result are private logical-row fields; the public statement remains
// commitment-only as required by the native-v3 architecture.
std::unique_ptr<proofs::Circuit<RelationField>> build_native_v3_circuit();

// Shape-only attribution entry point. The first hash_count endpoints in the
// canonical order are included; this is not a proving or acceptance path.
std::unique_ptr<proofs::Circuit<RelationField>> build_native_v3_circuit_stage(
    size_t hash_count);

size_t native_v3_hash_endpoint_count();
HashKind native_v3_hash_kind_at(size_t index);

void fill_native_v3_witness(const RelationCase& fixture,
                            proofs::Dense<RelationField>& witness);

void fill_native_v3_public(const RelationCase& fixture,
                           proofs::Dense<RelationField>& public_input);

std::vector<uint8_t> native_v3_public_bytes(const RelationCase& fixture);

std::string native_v3_hex(const uint8_t* bytes, size_t length);

}  // namespace blind_ledger_longfellow

#endif  // BLIND_LEDGER_LONGFELLOW_V09_NATIVE_V3_RELATION_H_
