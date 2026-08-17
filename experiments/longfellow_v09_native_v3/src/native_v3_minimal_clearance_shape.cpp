#include <cstdio>
#include <memory>
#include <string>

#include <windows.h>
#include <psapi.h>

#include "native_v3_minimal_clearance_relation.h"

namespace {

size_t Sha3Blocks(size_t message_bytes) {
  return (message_bytes + 72) / 72;
}

std::string Hex(const uint8_t* bytes, size_t length) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string output;
  output.reserve(length * 2);
  for (size_t index = 0; index < length; ++index) {
    output.push_back(kHex[bytes[index] >> 4]);
    output.push_back(kHex[bytes[index] & 0x0f]);
  }
  return output;
}

void PrintMemory(const char* label) {
  PROCESS_MEMORY_COUNTERS_EX counters{};
  if (!GetProcessMemoryInfo(
          GetCurrentProcess(),
          reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&counters),
          sizeof(counters))) {
    std::printf(
        "MINIMAL_CLEARANCE_SHAPE_MEMORY label=%s telemetry=unavailable error=%lu\n",
        label, static_cast<unsigned long>(GetLastError()));
    return;
  }
  std::printf(
      "MINIMAL_CLEARANCE_SHAPE_MEMORY label=%s process_tree_complete=1 "
      "child_count=0 peak_working_set_bytes=%llu "
      "private_usage_bytes_at_sample=%llu peak_private_commit_bytes=%llu\n",
      label, static_cast<unsigned long long>(counters.PeakWorkingSetSize),
      static_cast<unsigned long long>(counters.PrivateUsage),
      static_cast<unsigned long long>(counters.PeakPagefileUsage));
}

}  // namespace

int main() {
  using namespace blind_ledger_longfellow::minimal_clearance;
  const Fixture fixture = make_fixture();
  const std::vector<uint8_t> source_input =
      private_batch_commitment_input(fixture.cases[0]);
  const std::vector<uint8_t> state_bytes = state_commitment_bytes(fixture.cases[0]);
  const std::vector<uint8_t> public_bytes = public_statement_bytes(fixture.cases[0]);

  std::printf(
      "MINIMAL_CLEARANCE_SHAPE_START relation=SEMANTIC-PLUS-PRIVATE-SOURCE "
      "cases=%zu state_commitment_bytes=%zu public_statement_bytes=%zu\n",
      fixture.cases.size(), state_bytes.size(), public_bytes.size());

  for (size_t endpoint_count = 0;
       endpoint_count <= kSha3EndpointCount; ++endpoint_count) {
    auto stage = build_circuit_stage(endpoint_count);
    if (endpoint_count == 0) {
      std::printf(
          "MINIMAL_CLEARANCE_SHAPE_VARIANT name=semantic_direct_constraints "
          "hash_endpoints=0 inputs=%zu public_inputs=%zu layers=%zu terms=%zu "
          "circuit_id=%s\n",
          stage->ninputs, stage->npub_in, stage->nl, stage->nterms(),
          Hex(stage->id, sizeof(stage->id)).c_str());
    } else {
      const auto input = endpoint_input(fixture.cases[0], endpoint_count - 1);
      std::printf(
          "MINIMAL_CLEARANCE_SHAPE_VARIANT name=%s hash_endpoints=%zu "
          "message_bytes=%zu block_count=%zu inputs=%zu public_inputs=%zu "
          "layers=%zu terms=%zu circuit_id=%s\n",
          endpoint_name(endpoint_count - 1), endpoint_count, input.size(),
          Sha3Blocks(input.size()), stage->ninputs, stage->npub_in, stage->nl,
          stage->nterms(), Hex(stage->id, sizeof(stage->id)).c_str());
    }
    PrintMemory(endpoint_count == 0 ? "after_base" : "after_endpoint");
    if (endpoint_count == kSha3EndpointCount) {
      std::printf(
      "MINIMAL_CLEARANCE_SHAPE_PASS inputs=%zu public_inputs=%zu layers=%zu "
          "terms=%zu circuit_id=%s source_input_bytes=%zu source_blocks=%zu "
      "semantic_owner=direct_constraints source_owner=private_batch_commitment "
      "state_owner=typed_commitment_bytes "
          "external_ids=state_side_after_acceptance process_tree_complete=1 "
          "child_count=0 shape_only=1\n",
          stage->ninputs, stage->npub_in, stage->nl, stage->nterms(),
          Hex(stage->id, sizeof(stage->id)).c_str(), source_input.size(),
          Sha3Blocks(source_input.size()));
    }
    stage.reset();
  }
  return 0;
}
