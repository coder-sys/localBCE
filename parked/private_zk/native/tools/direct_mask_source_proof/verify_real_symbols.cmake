# Static closure gate for the source-owned producer archive.  The producer
# target uses the real source-auth, wire, native, FAEST, and ML-DSA archives;
# the deterministic key setup and the probe are test-only consumers.

foreach(required_var IN ITEMS REAL_SOURCE_PROOF_LIBRARY REAL_SOURCE_PROOF_SOURCE
                             REAL_SOURCE_PROOF_HEADER REAL_NATIVE_LIBRARY
                             REAL_AUTH_LIBRARY REAL_WIRE_LIBRARY REAL_FAEST_LIBRARY
                             REAL_MLDSA_LIBRARY)
  if (NOT DEFINED ${required_var} OR "${${required_var}}" STREQUAL "")
    message(FATAL_ERROR "missing required gate input ${required_var}")
  endif()
endforeach()

foreach(library IN ITEMS REAL_SOURCE_PROOF_LIBRARY REAL_NATIVE_LIBRARY REAL_AUTH_LIBRARY
                         REAL_WIRE_LIBRARY REAL_FAEST_LIBRARY REAL_MLDSA_LIBRARY)
  if (NOT EXISTS "${${library}}")
    message(FATAL_ERROR "missing real archive ${${library}}")
  endif()
endforeach()
if (NOT EXISTS "${REAL_SOURCE_PROOF_SOURCE}" OR
    NOT EXISTS "${REAL_SOURCE_PROOF_HEADER}")
  message(FATAL_ERROR "missing source-producer source/header")
endif()

if (WIN32)
  file(GLOB DM_SOURCE_PROOF_DUMPBIN_CANDIDATES
    "C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/VC/Tools/MSVC/*/bin/Hostx64/x64/dumpbin.exe"
    "C:/Program Files/Microsoft Visual Studio/2022/BuildTools/VC/Tools/MSVC/*/bin/Hostx64/x64/dumpbin.exe")
  if (DM_SOURCE_PROOF_DUMPBIN_CANDIDATES)
    list(GET DM_SOURCE_PROOF_DUMPBIN_CANDIDATES 0 DM_SOURCE_PROOF_DUMPBIN)
  endif()
  if (NOT DM_SOURCE_PROOF_DUMPBIN)
    find_program(DM_SOURCE_PROOF_DUMPBIN NAMES dumpbin dumpbin.exe)
  endif()
  if (NOT DM_SOURCE_PROOF_DUMPBIN)
    message(FATAL_ERROR "dumpbin is required for the Windows real symbol gate")
  endif()
else()
  find_program(DM_SOURCE_PROOF_NM NAMES nm llvm-nm)
  if (NOT DM_SOURCE_PROOF_NM)
    message(FATAL_ERROR "nm is required for the real symbol gate")
  endif()
endif()

function(read_symbols archive output_variable)
  if (WIN32)
    execute_process(
      COMMAND "${DM_SOURCE_PROOF_DUMPBIN}" /symbols "${archive}"
      RESULT_VARIABLE symbol_result
      OUTPUT_VARIABLE symbol_output
      ERROR_VARIABLE symbol_error)
  else()
    execute_process(
      COMMAND "${DM_SOURCE_PROOF_NM}" -g "${archive}"
      RESULT_VARIABLE symbol_result
      OUTPUT_VARIABLE symbol_output
      ERROR_VARIABLE symbol_error)
  endif()
  if (NOT symbol_result EQUAL 0)
    message(FATAL_ERROR "symbol inspection failed for ${archive}: ${symbol_error}")
  endif()
  set(${output_variable} "${symbol_output}" PARENT_SCOPE)
endfunction()

function(require_defined_symbol symbol_text symbol label)
  if (WIN32)
    string(REGEX MATCH "SECT[0-9A-F]+[^\n]*External[^\n]*\\|[ \t]*${symbol}([ \t\r\n]|$)"
           hit "${symbol_text}")
  else()
    string(REGEX MATCH "(^|[\r\n])[^\n]*[ \t][TDBRCSVW][ \t]+${symbol}([ \t\r\n]|$)"
           hit "${symbol_text}")
  endif()
  if ("${hit}" STREQUAL "")
    message(FATAL_ERROR "${label} missing required defined symbol ${symbol}")
  endif()
endfunction()

function(forbid_symbol symbol_text pattern label)
  if ("${symbol_text}" MATCHES "${pattern}")
    message(FATAL_ERROR "${label} contains forbidden symbol/text ${pattern}")
  endif()
endfunction()

read_symbols("${REAL_SOURCE_PROOF_LIBRARY}" source_proof_symbols)
read_symbols("${REAL_NATIVE_LIBRARY}" native_symbols)
read_symbols("${REAL_AUTH_LIBRARY}" auth_symbols)
read_symbols("${REAL_WIRE_LIBRARY}" wire_symbols)
read_symbols("${REAL_FAEST_LIBRARY}" faest_symbols)
read_symbols("${REAL_MLDSA_LIBRARY}" mldsa_symbols)

foreach(symbol IN ITEMS dm_source_proof_status_name dm_source_proof_output_clear
                       dm_source_proof_generate)
  require_defined_symbol("${source_proof_symbols}" "${symbol}"
                         "real source-producer archive")
endforeach()
foreach(symbol IN ITEMS dmn_extend dmn_clear)
  require_defined_symbol("${native_symbols}" "${symbol}" "real native archive")
endforeach()
foreach(symbol IN ITEMS dm_source_auth_sign)
  require_defined_symbol("${auth_symbols}" "${symbol}" "real source-auth archive")
endforeach()
foreach(symbol IN ITEMS dm_wire_os_random_bytes dm_wire_statement_encode
                       dm_wire_prove_kernel_os dm_wire_proof_size dm_wire_encode
                       dm_wire_proof_clear)
  require_defined_symbol("${wire_symbols}" "${symbol}" "real wire archive")
endforeach()
foreach(symbol IN ITEMS aes128_init_round_keys bf256_mul bavc_commit)
  require_defined_symbol("${faest_symbols}" "${symbol}" "real pinned FAEST archive")
endforeach()
foreach(symbol IN ITEMS blind_source_auth_mldsa87_v1_sign_hedged
                       PQCP_MLDSA_NATIVE_MLDSA87_signature_internal)
  require_defined_symbol("${mldsa_symbols}" "${symbol}" "real ML-DSA archive")
endforeach()

foreach(symbol_text IN ITEMS source_proof_symbols native_symbols auth_symbols wire_symbols
                              faest_symbols mldsa_symbols)
  forbid_symbol("${${symbol_text}}" "process_harness|_probe"
                "real archive ${symbol_text}")
endforeach()

file(READ "${REAL_SOURCE_PROOF_SOURCE}" source_proof_source_text)
file(READ "${REAL_SOURCE_PROOF_HEADER}" source_proof_header_text)
set(DM_SOURCE_PROOF_FORBIDDEN_PATTERNS
    "keypair_from_seed" "random_bytes_fn" "printf" "fprintf"
    "state_transition" "clearance_directive" "source_truth"
    "process_harness" "_probe")
list(LENGTH DM_SOURCE_PROOF_FORBIDDEN_PATTERNS DM_SOURCE_PROOF_FORBIDDEN_COUNT)
foreach(forbidden IN LISTS DM_SOURCE_PROOF_FORBIDDEN_PATTERNS)
  if ("${source_proof_source_text}" MATCHES "${forbidden}")
    message(FATAL_ERROR "source-producer implementation contains forbidden ${forbidden}")
  endif()
endforeach()
if ("${source_proof_header_text}" MATCHES
    "keypair_from_seed|FAEST_TESTS|process_harness|_probe")
  message(FATAL_ERROR "source-producer public header exposes test-only seams")
endif()

message("REAL_SOURCE_PROOF_SYMBOL_GATE=PASS checked=3")
message("REAL_NATIVE_PROOF_SYMBOL_GATE=PASS checked=2")
message("REAL_SOURCE_PROOF_CLOSURE_GATE=PASS forbidden=${DM_SOURCE_PROOF_FORBIDDEN_COUNT}")
