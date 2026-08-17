#include <cstdio>
#include <cstdlib>

#include <windows.h>
#include <psapi.h>

#include "native_v3_source_assertion_relation.h"

namespace {

const char* EndpointName(
    blind_ledger_longfellow::source_assertion::Endpoint endpoint) {
  using blind_ledger_longfellow::source_assertion::Endpoint;
  switch (endpoint) {
    case Endpoint::kSourceRoot: return "source_root";
    case Endpoint::kCompleteness: return "completeness";
    case Endpoint::kRequest: return "request";
    case Endpoint::kPrivateBatch: return "private_batch";
  }
  return "unknown";
}

const char* EndpointDomain(
    blind_ledger_longfellow::source_assertion::Endpoint endpoint) {
  using blind_ledger_longfellow::source_assertion::Endpoint;
  switch (endpoint) {
    case Endpoint::kSourceRoot: return "BL/NATIVE-V3/SOURCE-ROOT/v1";
    case Endpoint::kCompleteness: return "BL/NATIVE-V3/COMPLETENESS/v1";
    case Endpoint::kRequest: return "BL/NATIVE-V3/REQUEST-ID/v1";
    case Endpoint::kPrivateBatch: return "BL/NATIVE-V3/PRIVATE-BATCH/v1";
  }
  return "unknown";
}

size_t BlockCount(size_t message_bytes) { return (message_bytes + 72) / 72; }

}  // namespace

int main(int argc, char** argv) {
  using namespace blind_ledger_longfellow::source_assertion;
  if (argc != 2) {
    std::fprintf(stderr, "usage: %s ENDPOINT_COUNT\n", argv[0]);
    return 2;
  }
  char* end = nullptr;
  const unsigned long parsed = std::strtoul(argv[1], &end, 10);
  if (end == argv[1] || *end != '\0' ||
      parsed > source_assertion_endpoint_count()) {
    std::fprintf(stderr, "invalid endpoint count: %s\n", argv[1]);
    return 2;
  }
  const size_t endpoint_count = static_cast<size_t>(parsed);
  const auto fixture = make_source_assertion_fixture();
  const auto circuit = build_source_assertion_circuit_stage(endpoint_count);
  std::printf(
      "{\"shape_only\":true,\"source_assertion_only\":true,"
      "\"stage\":%zu,\"endpoint_count\":%zu,\"inputs\":%zu,"
      "\"public_inputs\":%zu,\"layers\":%zu,\"terms\":%zu,"
      "\"circuit_id\":\"%s\",\"public_statement_bytes\":%zu",
      endpoint_count, endpoint_count, circuit->ninputs, circuit->npub_in,
      circuit->nl, circuit->nterms(),
      source_assertion_hex(circuit->id, sizeof(circuit->id)).c_str(),
      source_assertion_statement_bytes(fixture.cases[0].statement).size());
  if (endpoint_count != 0) {
    const auto endpoint = source_assertion_endpoint_at(endpoint_count - 1);
    const auto input =
        build_source_assertion_hash_input(fixture.cases[0], endpoint);
    bool uniform = true;
    for (const auto& source_case : fixture.cases) {
      uniform = uniform &&
                build_source_assertion_hash_input(source_case, endpoint).size() ==
                    input.size();
    }
    std::printf(
        ",\"endpoint\":\"%s\",\"domain\":\"%s\","
        "\"message_bytes\":%zu,\"block_count\":%zu,"
        "\"uniform_message_bytes\":%s",
        EndpointName(endpoint), EndpointDomain(endpoint), input.size(),
        BlockCount(input.size()), uniform ? "true" : "false");
  }
  PROCESS_MEMORY_COUNTERS_EX counters{};
  if (GetProcessMemoryInfo(
          GetCurrentProcess(),
          reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&counters),
          sizeof(counters))) {
    std::printf(
        ",\"self_peak_working\":%llu,\"self_peak_private\":%llu,"
        "\"self_peak_pagefile\":%llu",
        static_cast<unsigned long long>(counters.PeakWorkingSetSize),
        static_cast<unsigned long long>(counters.PrivateUsage),
        static_cast<unsigned long long>(counters.PeakPagefileUsage));
  } else {
    std::printf(
        ",\"self_peak_working\":null,\"self_peak_private\":null,"
        "\"self_peak_pagefile\":null,\"self_telemetry_error\":%lu",
        static_cast<unsigned long>(GetLastError()));
  }
  std::puts("}");
  return 0;
}
