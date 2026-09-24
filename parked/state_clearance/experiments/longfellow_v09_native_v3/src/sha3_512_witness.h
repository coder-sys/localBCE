// Host-side witness generation for the fixed experimental SHA3-512 circuit.
// The circuit, not this helper, is authoritative for hidden message bytes and
// digest equality. This helper only supplies selected Keccak intermediates.
#ifndef BLIND_LEDGER_LONGFELLOW_V09_SHA3_512_WITNESS_H_
#define BLIND_LEDGER_LONGFELLOW_V09_SHA3_512_WITNESS_H_

#include <cstddef>
#include <cstdint>
#include <vector>

#include "circuits/tests/sha3/sha3_witness.h"

namespace blind_ledger_longfellow {

using Sha3BlockWitness = proofs::Sha3Witness::BlockWitness;

// Defaults are fixed SHA3-512 parameters. Non-default values are exposed
// only for negative host-witness mutations; the circuit is fixed at rate 72
// and domain suffix 0x06.
void compute_sha3_512_witness(const std::vector<uint8_t>& message,
                              std::vector<Sha3BlockWitness>& witnesses,
                              size_t rate = 72, uint8_t domain = 0x06);

}  // namespace blind_ledger_longfellow

#endif  // BLIND_LEDGER_LONGFELLOW_V09_SHA3_512_WITNESS_H_
