cmake_minimum_required(VERSION 3.20)

project(blind_ledger_direct_mask_source_auth C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# This is a detached, non-activating source-authentication boundary.  The
# vendor and ML-DSA trees are read-only inputs and are pinned below.  The
# direct-mask primitive is the explicitly marked candidate copy in this child;
# its immutable source identity is recorded in CANDIDATE_PROVENANCE.txt.
set(FAEST_REF_DIR
    "${CMAKE_CURRENT_LIST_DIR}/../../vendor/faest-ref"
    CACHE PATH "Read-only pinned FAEST reference checkout")
set(DMV_SOURCE_DIR
    "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_vole"
    CACHE PATH "Read-only pinned direct-mask primitive source directory")
set(MLDSA_ROOT
    "${CMAKE_CURRENT_LIST_DIR}/../../../../../../2026-08-31/blind-zkbpp-c-profile11-extmu-v1"
    CACHE PATH "Read-only pinned ML-DSA source-auth wrapper checkout")
get_filename_component(FAEST_REF_DIR "${FAEST_REF_DIR}" ABSOLUTE)
get_filename_component(DMV_SOURCE_DIR "${DMV_SOURCE_DIR}" ABSOLUTE)
get_filename_component(MLDSA_ROOT "${MLDSA_ROOT}" ABSOLUTE)
set(DIRECT_MASK_BF256_ACCEL_SOURCE
    "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_vole/direct_mask_bf256_accel.c")
set(DIRECT_MASK_BF256_ACCEL_HEADER
    "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_vole/direct_mask_bf256_accel.h")

function(require_git_identity path expected_commit expected_tree label)
  execute_process(
      COMMAND git -C "${path}" rev-parse HEAD
      RESULT_VARIABLE commit_result
      OUTPUT_VARIABLE actual_commit
      OUTPUT_STRIP_TRAILING_WHITESPACE
      ERROR_VARIABLE commit_error)
  if (NOT commit_result EQUAL 0 OR NOT actual_commit STREQUAL expected_commit)
    message(FATAL_ERROR
        "${label} commit mismatch: expected ${expected_commit}, got ${actual_commit}; ${commit_error}")
  endif()
  execute_process(
      COMMAND git -C "${path}" rev-parse "HEAD^{tree}"
      RESULT_VARIABLE tree_result
      OUTPUT_VARIABLE actual_tree
      OUTPUT_STRIP_TRAILING_WHITESPACE
      ERROR_VARIABLE tree_error)
  if (NOT tree_result EQUAL 0 OR NOT actual_tree STREQUAL expected_tree)
    message(FATAL_ERROR
        "${label} tree mismatch: expected ${expected_tree}, got ${actual_tree}; ${tree_error}")
  endif()
endfunction()

# Git's configured checkout may materialize tracked text with CRLF while the
# provenance records the committed LF bytes.  Canonicalize only that transport
# line-ending conversion before hashing; any content change still fails closed.
function(require_normalized_file_sha256 path expected_hash label)
  file(READ "${path}" file_contents)
  string(REPLACE "\r\n" "\n" normalized_contents "${file_contents}")
  string(SHA256 actual_hash "${normalized_contents}")
  string(TOUPPER "${actual_hash}" actual_hash_upper)
  if (NOT actual_hash_upper STREQUAL "${expected_hash}")
    message(FATAL_ERROR
      "${label} identity mismatch: expected ${expected_hash}, got ${actual_hash_upper}")
  endif()
endfunction()

if (NOT EXISTS "${FAEST_REF_DIR}/bavc.c" OR NOT EXISTS "${FAEST_REF_DIR}/aes.c")
  message(FATAL_ERROR "pinned FAEST vendor is not initialized at FAEST_REF_DIR")
endif()
if (NOT EXISTS "${DMV_SOURCE_DIR}/direct_mask_vole.c" OR
    NOT EXISTS "${DMV_SOURCE_DIR}/direct_mask_vole.h")
  message(FATAL_ERROR "pinned direct-mask primitive is required at DMV_SOURCE_DIR")
endif()
if (NOT EXISTS "${DIRECT_MASK_BF256_ACCEL_SOURCE}" OR
    NOT EXISTS "${DIRECT_MASK_BF256_ACCEL_HEADER}")
  message(FATAL_ERROR "child-local bf256 acceleration inputs are required")
endif()
if (NOT EXISTS "${MLDSA_ROOT}/third_party/mldsa_native/mldsa/mldsa_native.c" OR
    NOT EXISTS "${MLDSA_ROOT}/third_party/mldsa_native/blind/blind_source_auth_mldsa87_v1.c")
  message(FATAL_ERROR "pinned ML-DSA source-auth wrapper is required at MLDSA_ROOT")
endif()

require_git_identity("${FAEST_REF_DIR}"
  "ebefcbd8adda5faf447ef3dba5103794d17b4281"
  "f0c2e69f3eb0735fd544d04dc3dcfcc12e275e31"
  "FAEST reference")
if (EXISTS "${DMV_SOURCE_DIR}/CANDIDATE_PROVENANCE.txt")
  file(READ "${DMV_SOURCE_DIR}/CANDIDATE_PROVENANCE.txt" dmv_candidate_provenance)
  foreach(expected_line IN ITEMS
      "base_commit=392e53e2b3d5936cb9cb2681b9e2d803143b1e17"
      "base_tree=34dc614591712efd4faca0dedc064bfd63e51a92"
      "base_tracked_file_count=6"
      "base_file_sha256=CMakeLists.txt 41DB53B6D063B2274DC96BB8D2CF88A28831E344AD4812C693C28F19A60F4A3A"
      "base_file_sha256=direct_mask_vole.c 7DB95B4F69B2F9E6F2C349DAB5F279C31AE17E6C249521C985FB12F5D1B789F4"
      "base_file_sha256=direct_mask_vole.h 7B4BF7AE76A2717176AEC8225F7B056ADA64977A971C439CF6F226F6A80B93F7"
      "base_file_sha256=direct_mask_vole_probe.c 274BCD97A0F708C49E666891EC182AD38CB1DF38C14E45484A3C0EE1738AA47C"
      "base_file_sha256=parameters.h 2F4A5D7D7DE43CF3E4DD43B5C49F10E70D27499950B1FF236A2533B51F7321AD"
      "base_file_sha256=transcript_oracle.py 04B775EB28F4A36838272D463C91C71B0DB827C1ECE29C3B5C4AE483563A07BE"
      "acceleration_input_head=48268072892afe4db41d3acc50a62e555f0f2f4b"
      "acceleration_input_tree=3b720ca35b9943bb7b7be4f27f7c4cd0e8b20d46"
      "acceleration_source_commit=4dd3ea2ece80b43e29befe63c644e3b6b46eea61"
      "acceleration_source_tree=3061d6b77e60bb28f92ea4667bdbe72fcd7c2e50"
      "acceleration_source_parent=f73378a3bf33f5356887ba1e46b758a544392507"
      "acceleration_file_sha256=direct_mask_bf256_accel.c 08923E5EB209FFBFB89CC489D2C21770769F0AB45F31984BBC075DDDDCF52399"
      "acceleration_file_sha256=direct_mask_bf256_accel.h 00E1D9C1E078BD35BCCA95AE76865590ED1B78969DAFBD89D85EBB7C09FF21E2")
    string(FIND "${dmv_candidate_provenance}" "${expected_line}" expected_position)
    if (expected_position EQUAL -1)
      message(FATAL_ERROR "candidate direct-mask provenance mismatch: ${expected_line}")
    endif()
  endforeach()
else()
  require_git_identity("${DMV_SOURCE_DIR}"
    "392e53e2b3d5936cb9cb2681b9e2d803143b1e17"
    "34dc614591712efd4faca0dedc064bfd63e51a92"
    "direct-mask primitive")
endif()
require_normalized_file_sha256("${DIRECT_MASK_BF256_ACCEL_SOURCE}"
  "08923E5EB209FFBFB89CC489D2C21770769F0AB45F31984BBC075DDDDCF52399"
  "acceleration C")
require_normalized_file_sha256("${DIRECT_MASK_BF256_ACCEL_HEADER}"
  "00E1D9C1E078BD35BCCA95AE76865590ED1B78969DAFBD89D85EBB7C09FF21E2"
  "acceleration header")
require_git_identity("${MLDSA_ROOT}"
  "9ca1ba2ccb6fa78384e3c3e21cfd3dfd0cb38eb2"
  "178a5f20c6738f7272cd38f77315da83650bbac0"
  "ML-DSA source checkout")
execute_process(
  COMMAND git -C "${MLDSA_ROOT}" rev-parse "HEAD:third_party/mldsa_native"
  RESULT_VARIABLE mldsa_subtree_result
  OUTPUT_VARIABLE mldsa_subtree
  OUTPUT_STRIP_TRAILING_WHITESPACE
  ERROR_VARIABLE mldsa_subtree_error)
if (NOT mldsa_subtree_result EQUAL 0 OR
    NOT mldsa_subtree STREQUAL "d8c01098221d8eb3b1270c248a6a616048092e0c")
  message(FATAL_ERROR
    "ML-DSA native subtree mismatch: expected d8c01098221d8eb3b1270c248a6a616048092e0c, got ${mldsa_subtree}; ${mldsa_subtree_error}")
endif()

set_source_files_properties(
  "${FAEST_REF_DIR}/fields.c"
  PROPERTIES
    COMPILE_DEFINITIONS
      "bf256_mul=direct_mask_bf256_mul_portable;bf256_mul_inplace=direct_mask_bf256_mul_inplace_portable")

add_library(dm_faest_public STATIC
  "${FAEST_REF_DIR}/aes.c"
  "${FAEST_REF_DIR}/bavc.c"
  "${FAEST_REF_DIR}/compat.c"
  "${FAEST_REF_DIR}/cpu.c"
  "${FAEST_REF_DIR}/fields.c"
  "${DIRECT_MASK_BF256_ACCEL_SOURCE}"
  "${FAEST_REF_DIR}/random_oracle.c"
  "${FAEST_REF_DIR}/universal_hashing.c"
  "${FAEST_REF_DIR}/utils.c"
  "${FAEST_REF_DIR}/sha3/KeccakHash.c"
  "${FAEST_REF_DIR}/sha3/KeccakSponge.c"
  "${FAEST_REF_DIR}/sha3/opt64/KeccakP-1600-opt64.c")
target_include_directories(dm_faest_public PUBLIC
  "${DMV_SOURCE_DIR}"
  "${FAEST_REF_DIR}"
  "${FAEST_REF_DIR}/sha3"
  "${FAEST_REF_DIR}/sha3/opt64")
target_compile_definitions(dm_faest_public PRIVATE FAEST_STATIC HAVE_MM_LOADU_SI64)

add_library(dm_wire_codec STATIC
  "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_wire/direct_mask_wire.c"
  "${DMV_SOURCE_DIR}/direct_mask_vole.c"
  "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_kernel/direct_mask_kernel.c"
  "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_kernel/direct_mask_algebra.c"
  "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_circuit/dmc_tag_linear.c"
  "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_circuit/dmc_range_constraints.c")
target_include_directories(dm_wire_codec PUBLIC
  "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_wire"
  "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_kernel"
  "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_circuit"
  "${DMV_SOURCE_DIR}"
  "${FAEST_REF_DIR}"
  "${FAEST_REF_DIR}/sha3"
  "${FAEST_REF_DIR}/sha3/opt64")
target_compile_definitions(dm_wire_codec PRIVATE FAEST_STATIC HAVE_MM_LOADU_SI64)
target_link_libraries(dm_wire_codec PUBLIC dm_faest_public)

add_library(mldsa_source_auth_wrapper STATIC
  "${MLDSA_ROOT}/third_party/mldsa_native/mldsa/mldsa_native.c"
  "${MLDSA_ROOT}/third_party/mldsa_native/blind/blind_source_auth_mldsa87_v1.c")
target_include_directories(mldsa_source_auth_wrapper PUBLIC
  "${MLDSA_ROOT}/third_party/mldsa_native/blind")
target_include_directories(mldsa_source_auth_wrapper PRIVATE
  "${MLDSA_ROOT}/third_party/mldsa_native/mldsa"
  "${MLDSA_ROOT}/third_party/mldsa_native/mldsa/src"
  "${MLDSA_ROOT}/third_party/mldsa_native/mldsa/src/fips202"
  "${MLDSA_ROOT}/third_party/mldsa_native/mldsa/src/fips202/native"
  "${MLDSA_ROOT}/third_party/mldsa_native/mldsa/src/native")
target_compile_definitions(mldsa_source_auth_wrapper PRIVATE
  MLD_CONFIG_PARAMETER_SET=87
  MLD_CONFIG_NO_RANDOMIZED_API
  MLD_CONFIG_MAX_SIGNING_ATTEMPTS=821)

add_library(dm_source_auth STATIC direct_mask_source_auth.c)
target_include_directories(dm_source_auth PUBLIC "${CMAKE_CURRENT_LIST_DIR}")
target_include_directories(dm_source_auth PRIVATE
  "${MLDSA_ROOT}/third_party/mldsa_native/blind")
target_compile_definitions(dm_source_auth PRIVATE FAEST_STATIC HAVE_MM_LOADU_SI64)
target_link_libraries(dm_source_auth PUBLIC dm_wire_codec mldsa_source_auth_wrapper)

add_executable(dm_source_auth_probe direct_mask_source_auth_probe.c)
target_include_directories(dm_source_auth_probe PRIVATE
  "${CMAKE_CURRENT_LIST_DIR}"
  "${MLDSA_ROOT}/third_party/mldsa_native/blind")
target_compile_definitions(dm_source_auth_probe PRIVATE FAEST_STATIC HAVE_MM_LOADU_SI64)
target_link_libraries(dm_source_auth_probe PRIVATE dm_source_auth)

if (WIN32)
  target_link_libraries(dm_faest_public PUBLIC bcrypt)
endif()

if (MSVC)
  target_compile_options(dm_faest_public PRIVATE /W3)
  target_compile_options(dm_wire_codec PRIVATE /W4)
  target_compile_options(mldsa_source_auth_wrapper PRIVATE /W4)
  target_compile_options(dm_source_auth PRIVATE /W4)
  target_compile_options(dm_source_auth_probe PRIVATE /W4)
else()
  target_compile_options(dm_faest_public PRIVATE -Wall -Wextra -Wpedantic)
  target_compile_options(dm_wire_codec PRIVATE -Wall -Wextra -Wpedantic)
  target_compile_options(mldsa_source_auth_wrapper PRIVATE -Wall -Wextra -Wpedantic)
  target_compile_options(dm_source_auth PRIVATE -Wall -Wextra -Wpedantic)
  target_compile_options(dm_source_auth_probe PRIVATE -Wall -Wextra -Wpedantic)
endif()

include(CTest)
if (BUILD_TESTING AND NOT DM_EMBEDDED_NO_TESTS)
  add_test(NAME direct_mask_source_auth_probe COMMAND dm_source_auth_probe)
  add_test(NAME direct_mask_source_auth_real_symbol_gate
    COMMAND ${CMAKE_COMMAND}
      -DREAL_AUTH_LIBRARY=$<TARGET_FILE:dm_source_auth>
      -DREAL_WIRE_LIBRARY=$<TARGET_FILE:dm_wire_codec>
      -DREAL_FAEST_LIBRARY=$<TARGET_FILE:dm_faest_public>
      -DREAL_MLDSA_LIBRARY=$<TARGET_FILE:mldsa_source_auth_wrapper>
      -DREAL_AUTH_SOURCE=${CMAKE_CURRENT_LIST_DIR}/direct_mask_source_auth.c
      -DREAL_AUTH_HEADER=${CMAKE_CURRENT_LIST_DIR}/direct_mask_source_auth.h
      -P ${CMAKE_CURRENT_LIST_DIR}/verify_real_symbols.cmake)
endif()
