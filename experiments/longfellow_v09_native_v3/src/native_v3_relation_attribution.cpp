#include <cstdio>
#include <cstdlib>
#include <string>

#include <windows.h>
#include <psapi.h>

#include "native_v3_relation.h"

namespace {

const char* HashKindName(blind_ledger_longfellow::HashKind kind) {
  using blind_ledger_longfellow::HashKind;
  switch (kind) {
    case HashKind::kSourceRoot: return "source_root";
    case HashKind::kCompleteness: return "completeness";
    case HashKind::kChronology: return "chronology";
    case HashKind::kBeforeState: return "before_state";
    case HashKind::kRequest: return "request";
    case HashKind::kReplay: return "replay";
    case HashKind::kDecision: return "decision";
    case HashKind::kDecisionPath: return "decision_path";
    case HashKind::kAfterAudit: return "after_audit";
    case HashKind::kAfterRoot: return "after_root";
    case HashKind::kAfterState: return "after_state";
    case HashKind::kSourceAddress: return "source_address";
    case HashKind::kSubjectKey: return "subject_key";
    case HashKind::kAuditAddress: return "audit_address";
    case HashKind::kJoin: return "join";
    case HashKind::kReceipt: return "receipt";
    case HashKind::kPrivateBatch: return "private_batch";
    case HashKind::kSettlement: return "settlement";
  }
  return "unknown";
}

const char* HashDomain(blind_ledger_longfellow::HashKind kind) {
  using blind_ledger_longfellow::HashKind;
  switch (kind) {
    case HashKind::kSourceRoot: return "BL/NATIVE-V3/SOURCE-ROOT/v1";
    case HashKind::kCompleteness: return "BL/NATIVE-V3/COMPLETENESS/v1";
    case HashKind::kChronology: return "BL/NATIVE-V3/CHRONOLOGY/v1";
    case HashKind::kBeforeState: return "BL/NATIVE-V3/STATE-ID/v1";
    case HashKind::kRequest: return "BL/NATIVE-V3/REQUEST-ID/v1";
    case HashKind::kReplay: return "BL/NATIVE-V3/REPLAY/v1";
    case HashKind::kDecision: return "BL/NATIVE-V3/DECISION-ID/v1";
    case HashKind::kDecisionPath: return "BL/NATIVE-V3/DECISION-PATH/v1";
    case HashKind::kAfterAudit: return "BL/NATIVE-V3/AUDIT-HEAD/v1";
    case HashKind::kAfterRoot: return "BL/NATIVE-V3/ROOT/v1";
    case HashKind::kAfterState: return "BL/NATIVE-V3/STATE-ID/v1";
    case HashKind::kSourceAddress: return "BL/NATIVE-V3/STATE-ADDRESS/v1";
    case HashKind::kSubjectKey: return "BL/NATIVE-V3/SUBJECT-KEY/v1";
    case HashKind::kAuditAddress: return "BL/NATIVE-V3/STATE-ADDRESS/v1";
    case HashKind::kJoin: return "BL/NATIVE-V3/DECISION-ACCESS-JOIN/v1";
    case HashKind::kReceipt: return "BL/NATIVE-V3/RECEIPT-ID/v1";
    case HashKind::kPrivateBatch: return "BL/NATIVE-V3/PRIVATE-BATCH/v1";
    case HashKind::kSettlement: return "BL/NATIVE-V3/SETTLEMENT/v1";
  }
  return "unknown";
}

size_t BlockCount(size_t message_bytes) { return (message_bytes + 72) / 72; }

}  // namespace

int main(int argc, char** argv) {
  if (argc != 2) {
    std::fprintf(stderr, "usage: %s HASH_COUNT\n", argv[0]);
    return 2;
  }
  char* end = nullptr;
  const unsigned long parsed = std::strtoul(argv[1], &end, 10);
  if (end == argv[1] || *end != '\0' ||
      parsed > blind_ledger_longfellow::native_v3_hash_endpoint_count()) {
    std::fprintf(stderr, "invalid hash count: %s\n", argv[1]);
    return 2;
  }
  const size_t hash_count = static_cast<size_t>(parsed);
  const auto fixture = blind_ledger_longfellow::make_native_v3_fixture();
  const auto circuit =
      blind_ledger_longfellow::build_native_v3_circuit_stage(hash_count);

  std::printf("{\"stage\":%zu,\"hash_count\":%zu,\"inputs\":%zu,"
              "\"public_inputs\":%zu,\"layers\":%zu,\"terms\":%zu,"
              "\"circuit_id\":\"%s\"",
              hash_count, hash_count, circuit->ninputs, circuit->npub_in,
              circuit->nl, circuit->nterms(),
              blind_ledger_longfellow::native_v3_hex(
                  circuit->id, sizeof(circuit->id))
                  .c_str());
  if (hash_count != 0) {
    const auto kind = blind_ledger_longfellow::native_v3_hash_kind_at(
        hash_count - 1);
    const auto input = blind_ledger_longfellow::build_hash_input(
        fixture.cases[0], kind);
    bool uniform = true;
    for (const auto& relation_case : fixture.cases) {
      uniform = uniform &&
                blind_ledger_longfellow::build_hash_input(relation_case, kind)
                        .size() == input.size();
    }
    std::printf(
        ",\"endpoint\":\"%s\",\"domain\":\"%s\","
        "\"message_bytes\":%zu,\"block_count\":%zu,"
        "\"uniform_message_bytes\":%s",
        HashKindName(kind), HashDomain(kind), input.size(),
        BlockCount(input.size()), uniform ? "true" : "false");
  }
  PROCESS_MEMORY_COUNTERS_EX counters{};
  if (GetProcessMemoryInfo(GetCurrentProcess(),
                           reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&counters),
                           sizeof(counters))) {
    std::printf(
        ",\"self_peak_working\":%llu,\"self_peak_private\":%llu,"
        "\"self_peak_pagefile\":%llu",
        static_cast<unsigned long long>(counters.PeakWorkingSetSize),
        static_cast<unsigned long long>(counters.PrivateUsage),
        static_cast<unsigned long long>(counters.PeakPagefileUsage));
  } else {
    std::printf(",\"self_peak_working\":null,\"self_peak_private\":null,"
                "\"self_peak_pagefile\":null,\"self_telemetry_error\":%lu",
                static_cast<unsigned long>(GetLastError()));
  }
  std::puts(",\"shape_only\":true}");
  return 0;
}
