#include "sha3_512_witness.h"

#include <cstring>

#include "circuits/tests/sha3/sha3_reference.h"
#include "util/panic.h"

namespace blind_ledger_longfellow {

void compute_sha3_512_witness(const std::vector<uint8_t>& message,
                              std::vector<Sha3BlockWitness>& witnesses,
                              size_t rate, uint8_t domain) {
  proofs::check(rate > 0 && rate <= 200, "invalid witness rate");
  witnesses.clear();

  uint64_t state[5][5];
  std::memset(state, 0, sizeof(state));
  uint8_t block[200];
  std::memset(block, 0, sizeof(block));
  size_t ptr = 0;

  for (uint8_t byte : message) {
    block[ptr++] = byte;
    if (ptr == rate) {
      proofs::Sha3Reference::xorin(state, block, rate);
      Sha3BlockWitness witness;
      proofs::Sha3Witness::compute_witness_block(state, witness);
      witnesses.push_back(witness);
      ptr = 0;
      std::memset(block, 0, rate);
    }
  }

  // SHA3-512 uses domain suffix 0x06 and the final 0x80 bit. The generic
  // parameters above are intentionally available only to negative tests.
  block[ptr] ^= domain;
  block[rate - 1] ^= 0x80;
  proofs::Sha3Reference::xorin(state, block, rate);
  Sha3BlockWitness final_witness;
  proofs::Sha3Witness::compute_witness_block(state, final_witness);
  witnesses.push_back(final_witness);
}

}  // namespace blind_ledger_longfellow
