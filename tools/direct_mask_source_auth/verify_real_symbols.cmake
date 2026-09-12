# Static closure gate for the production-shaped source-authentication target.
# This gate intentionally inspects only the real archives.  The probe is the
# sole owner of deterministic key setup and is not part of this inspection.

foreach(required_var IN ITEMS REAL_AUTH_LIBRARY REAL_WIRE_LIBRARY REAL_FAEST_LIBRARY
                             REAL_MLDSA_LIBRARY REAL_AUTH_SOURCE REAL_AUTH_HEADER)
  if (NOT DEFINED ${required_var} OR "${${required_var}}" STREQUAL "")
    message(FATAL_ERROR "missing required gate input ${required_var}")
  endif()
endforeach()

foreach(library IN ITEMS REAL_AUTH_LIBRARY REAL_WIRE_LIBRARY REAL_FAEST_LIBRARY REAL_MLDSA_LIBRARY)
  if (NOT EXISTS "${${library}}")
    message(FATAL_ERROR "missing real archive ${${library}}")
  endif()
endforeach()

if (NOT EXISTS "${REAL_AUTH_SOURCE}" OR NOT EXISTS "${REAL_AUTH_HEADER}")
  message(FATAL_ERROR "missing source-auth gate input source/header")
endif()

if (WIN32)
  file(GLOB DM_SOURCE_AUTH_DUMPBIN_CANDIDATES
    "C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/VC/Tools/MSVC/*/bin/Hostx64/x64/dumpbin.exe"
    "C:/Program Files/Microsoft Visual Studio/2022/BuildTools/VC/Tools/MSVC/*/bin/Hostx64/x64/dumpbin.exe")
  if (DM_SOURCE_AUTH_DUMPBIN_CANDIDATES)
    list(GET DM_SOURCE_AUTH_DUMPBIN_CANDIDATES 0 DM_SOURCE_AUTH_DUMPBIN)
  endif()
  if (NOT DM_SOURCE_AUTH_DUMPBIN)
    find_program(DM_SOURCE_AUTH_DUMPBIN NAMES dumpbin dumpbin.exe)
  endif()
  if (NOT DM_SOURCE_AUTH_DUMPBIN)
    message(FATAL_ERROR "dumpbin is required for the Windows real symbol gate")
  endif()
else()
  find_program(DM_SOURCE_AUTH_NM NAMES nm llvm-nm)
  if (NOT DM_SOURCE_AUTH_NM)
    message(FATAL_ERROR "nm is required for the real symbol gate")
  endif()
endif()

function(read_symbols archive output_variable)
  if (WIN32)
    execute_process(
      COMMAND "${DM_SOURCE_AUTH_DUMPBIN}" /symbols "${archive}"
      RESULT_VARIABLE symbol_result
      OUTPUT_VARIABLE symbol_output
      ERROR_VARIABLE symbol_error)
  else()
    execute_process(
      COMMAND "${DM_SOURCE_AUTH_NM}" -g "${archive}"
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
    # A defined COFF implementation has a SECT record.  UNDEF records are
    # imports and must not satisfy this gate.
    string(REGEX MATCH "SECT[0-9A-F]+[^\n]*External[^\n]*\\|[ \t]*${symbol}([ \t\r\n]|$)" hit
           "${symbol_text}")
  else()
    # nm's defined global types include text/data/read-only/common symbols;
    # U (undefined) is deliberately excluded.
    string(REGEX MATCH "(^|[\r\n])[^\n]*[ \t][TDBRCSVW][ \t]+${symbol}([ \t\r\n]|$)" hit
           "${symbol_text}")
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

read_symbols("${REAL_AUTH_LIBRARY}" auth_symbols)
read_symbols("${REAL_WIRE_LIBRARY}" wire_symbols)
read_symbols("${REAL_FAEST_LIBRARY}" faest_symbols)
read_symbols("${REAL_MLDSA_LIBRARY}" mldsa_symbols)

set(auth_required
  dm_source_auth_request_init
  dm_source_auth_request_clear
  dm_source_auth_verified_clear
  dm_source_auth_sign
  dm_source_auth_verify
  dm_source_auth_status_name)
foreach(symbol IN LISTS auth_required)
  require_defined_symbol("${auth_symbols}" "${symbol}" "real source-auth archive")
endforeach()

foreach(symbol IN ITEMS dm_wire_statement_decode dm_wire_statement_encode
                       dm_wire_statement_validate dm_wire_os_random_bytes)
  require_defined_symbol("${wire_symbols}" "${symbol}" "real wire archive")
endforeach()

foreach(symbol IN ITEMS aes128_init_round_keys bf256_mul bavc_commit)
  require_defined_symbol("${faest_symbols}" "${symbol}" "real pinned FAEST archive")
endforeach()

foreach(symbol IN ITEMS blind_source_auth_mldsa87_v1_sign_hedged
                       blind_source_auth_mldsa87_v1_verify
                       PQCP_MLDSA_NATIVE_MLDSA87_signature_internal)
  require_defined_symbol("${mldsa_symbols}" "${symbol}" "real ML-DSA archive")
endforeach()

foreach(symbol_text IN ITEMS auth_symbols wire_symbols faest_symbols mldsa_symbols)
  forbid_symbol("${${symbol_text}}" "dm_native|direct_mask_native|process_harness|_probe"
                "real archive ${symbol_text}")
endforeach()

file(READ "${REAL_AUTH_SOURCE}" auth_source_text)
file(READ "${REAL_AUTH_HEADER}" auth_header_text)
foreach(forbidden IN ITEMS "sign_hedged_extmu" "compute_mu"
                            "keypair_from_seed" "dm_wire_prove" "dm_wire_verify"
                            "dm_wire_proof" "random_bytes_fn")
  if ("${auth_source_text}" MATCHES "${forbidden}")
    message(FATAL_ERROR "source-auth implementation contains forbidden ${forbidden}")
  endif()
endforeach()
if ("${auth_header_text}" MATCHES "sign_hedged_extmu|compute_mu|keypair_from_seed")
  message(FATAL_ERROR "source-auth public header exposes test-only ML-DSA seams")
endif()

message("REAL_SYMBOL_GATE=PASS checked=6")
message("WIRE_REAL_SYMBOL_GATE=PASS checked=4")
message("FAEST_REAL_SYMBOL_GATE=PASS checked=3")
message("MLDSA_REAL_SYMBOL_GATE=PASS checked=3")
message("SOURCE_CLOSURE_GATE=PASS forbidden=7")
