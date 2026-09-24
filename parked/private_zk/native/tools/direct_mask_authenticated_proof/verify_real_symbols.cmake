# Static closure gate for the real joint-verifier archive.  The native witness
# materializer is intentionally linked only to the focused probe, never to the
# real authenticated-proof target.

foreach(required_var IN ITEMS REAL_AUTHENTICATED_LIBRARY REAL_AUTHENTICATED_SOURCE
                             REAL_AUTHENTICATED_HEADER REAL_AUTH_LIBRARY REAL_WIRE_LIBRARY
                             REAL_FAEST_LIBRARY REAL_MLDSA_LIBRARY)
  if (NOT DEFINED ${required_var} OR "${${required_var}}" STREQUAL "")
    message(FATAL_ERROR "missing required gate input ${required_var}")
  endif()
endforeach()

foreach(library IN ITEMS REAL_AUTHENTICATED_LIBRARY REAL_AUTH_LIBRARY REAL_WIRE_LIBRARY
                         REAL_FAEST_LIBRARY REAL_MLDSA_LIBRARY)
  if (NOT EXISTS "${${library}}")
    message(FATAL_ERROR "missing real archive ${${library}}")
  endif()
endforeach()
if (NOT EXISTS "${REAL_AUTHENTICATED_SOURCE}" OR
    NOT EXISTS "${REAL_AUTHENTICATED_HEADER}")
  message(FATAL_ERROR "missing joint-verifier source/header")
endif()

if (WIN32)
  file(GLOB DM_AUTH_PROOF_DUMPBIN_CANDIDATES
    "C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/VC/Tools/MSVC/*/bin/Hostx64/x64/dumpbin.exe"
    "C:/Program Files/Microsoft Visual Studio/2022/BuildTools/VC/Tools/MSVC/*/bin/Hostx64/x64/dumpbin.exe")
  if (DM_AUTH_PROOF_DUMPBIN_CANDIDATES)
    list(GET DM_AUTH_PROOF_DUMPBIN_CANDIDATES 0 DM_AUTH_PROOF_DUMPBIN)
  endif()
  if (NOT DM_AUTH_PROOF_DUMPBIN)
    find_program(DM_AUTH_PROOF_DUMPBIN NAMES dumpbin dumpbin.exe)
  endif()
  if (NOT DM_AUTH_PROOF_DUMPBIN)
    message(FATAL_ERROR "dumpbin is required for the Windows real symbol gate")
  endif()
else()
  find_program(DM_AUTH_PROOF_NM NAMES nm llvm-nm)
  if (NOT DM_AUTH_PROOF_NM)
    message(FATAL_ERROR "nm is required for the real symbol gate")
  endif()
endif()

function(read_symbols archive output_variable)
  if (WIN32)
    execute_process(
      COMMAND "${DM_AUTH_PROOF_DUMPBIN}" /symbols "${archive}"
      RESULT_VARIABLE symbol_result
      OUTPUT_VARIABLE symbol_output
      ERROR_VARIABLE symbol_error)
  else()
    execute_process(
      COMMAND "${DM_AUTH_PROOF_NM}" -g "${archive}"
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

read_symbols("${REAL_AUTHENTICATED_LIBRARY}" authenticated_symbols)
read_symbols("${REAL_AUTH_LIBRARY}" auth_symbols)
read_symbols("${REAL_WIRE_LIBRARY}" wire_symbols)
read_symbols("${REAL_FAEST_LIBRARY}" faest_symbols)
read_symbols("${REAL_MLDSA_LIBRARY}" mldsa_symbols)

foreach(symbol IN ITEMS dm_authenticated_proof_status_name
                       dm_authenticated_proof_verified_clear
                       dm_authenticated_proof_verify)
  require_defined_symbol("${authenticated_symbols}" "${symbol}"
                         "real authenticated-proof archive")
endforeach()
foreach(symbol IN ITEMS dm_source_auth_verify dm_source_auth_verified_clear)
  require_defined_symbol("${auth_symbols}" "${symbol}" "real source-auth archive")
endforeach()
foreach(symbol IN ITEMS dm_wire_statement_decode dm_wire_decode
                       dm_wire_verify_kernel dm_wire_proof_clear)
  require_defined_symbol("${wire_symbols}" "${symbol}" "real wire archive")
endforeach()
foreach(symbol IN ITEMS aes128_init_round_keys bf256_mul bavc_commit)
  require_defined_symbol("${faest_symbols}" "${symbol}" "real pinned FAEST archive")
endforeach()
foreach(symbol IN ITEMS blind_source_auth_mldsa87_v1_verify
                       blind_source_auth_mldsa87_v1_sign_hedged
                       PQCP_MLDSA_NATIVE_MLDSA87_signature_internal)
  require_defined_symbol("${mldsa_symbols}" "${symbol}" "real ML-DSA archive")
endforeach()

foreach(symbol_text IN ITEMS authenticated_symbols auth_symbols wire_symbols
                              faest_symbols mldsa_symbols)
  forbid_symbol("${${symbol_text}}" "dm_native|direct_mask_native|process_harness|_probe"
                "real archive ${symbol_text}")
endforeach()

file(READ "${REAL_AUTHENTICATED_SOURCE}" authenticated_source_text)
file(READ "${REAL_AUTHENTICATED_HEADER}" authenticated_header_text)
foreach(forbidden IN ITEMS "dm_wire_prove_kernel" "dmn_extend" "direct_mask_native"
                            "process_harness" "state_transition" "clearance_directive"
                            "source_truth")
  if ("${authenticated_source_text}" MATCHES "${forbidden}")
    message(FATAL_ERROR "joint verifier implementation contains forbidden ${forbidden}")
  endif()
endforeach()
if ("${authenticated_header_text}" MATCHES "dm_wire_prove_kernel|dmn_extend|direct_mask_native")
  message(FATAL_ERROR "joint verifier public header exposes test-only producer seams")
endif()

message("REAL_AUTHENTICATED_PROOF_SYMBOL_GATE=PASS checked=3")
message("REAL_AUTHENTICATED_PROOF_CLOSURE_GATE=PASS forbidden=7")
