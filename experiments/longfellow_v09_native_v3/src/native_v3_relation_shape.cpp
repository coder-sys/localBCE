#include <cstdio>

#include "native_v3_relation.h"

int main() {
  std::puts("NATIVE_V3_RELATION_SHAPE_START");
  std::fflush(stdout);
  auto circuit = blind_ledger_longfellow::build_native_v3_circuit();
  const auto fixture = blind_ledger_longfellow::make_native_v3_fixture();
  std::printf("NATIVE_V3_RELATION_SHAPE_PASS cases=%zu inputs=%zu public_inputs=%zu layers=%zu terms=%zu circuit_id=%s\n",
              fixture.cases.size(), circuit->ninputs, circuit->npub_in,
              circuit->nl, circuit->nterms(),
              blind_ledger_longfellow::native_v3_hex(circuit->id, sizeof(circuit->id)).c_str());
  return 0;
}
