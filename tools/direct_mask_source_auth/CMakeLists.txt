cmake_minimum_required(VERSION 3.20)

project(blind_ledger_direct_mask_source_auth C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# This is a detached, non-activating source-authentication boundary.  The
# primitive, vendor, and ML-DSA trees are read-only inputs and are pinned below
# so a differently resolved checkout cannot silently qualify this build.
set(FAEST_REF_DIR
    "${CMAKE_CURRENT_LIST_DIR}/../../../pq-direct-mask-vole-20260907/vendor/faest-ref"
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

function(require_direct_mask_import_identity path)
  get_filename_component(expected_path
    "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_vole" ABSOLUTE)
  get_filename_component(actual_path "${path}" ABSOLUTE)
  if (NOT actual_path STREQUAL expected_path)
    message(FATAL_ERROR
      "direct-mask primitive must use the exact child import: expected ${expected_path}, got ${actual_path}")
  endif()

  set(expected_files
    "tools/direct_mask_vole/direct_mask_vole.c|36a076a4e3b7daf35719e036973659c0aac22496"
    "tools/direct_mask_vole/direct_mask_vole.h|7deb1bd0239c4f4138d9551a93bbb0ddd2db758b"
    "tools/direct_mask_vole/direct_mask_vole_probe.c|f5e2581ff35eb1756bc6b90e2ce43f9b33b7a741"
    "tools/direct_mask_vole/parameters.h|414b892f00d56ad6492988e87f36957836ecf6e2"
    "tools/direct_mask_vole/transcript_oracle.py|d2b40d239a2cd4796bab90bf87d42923de37efb0")
  foreach(expected_file IN LISTS expected_files)
    string(REPLACE "|" ";" expected_parts "${expected_file}")
    list(GET expected_parts 0 relative_path)
    list(GET expected_parts 1 expected_blob)
    execute_process(
      COMMAND git -C "${CMAKE_CURRENT_LIST_DIR}/../.." hash-object -- "${relative_path}"
      RESULT_VARIABLE blob_result
      OUTPUT_VARIABLE actual_blob
      OUTPUT_STRIP_TRAILING_WHITESPACE
      ERROR_VARIABLE blob_error)
    if (NOT blob_result EQUAL 0 OR NOT actual_blob STREQUAL expected_blob)
      message(FATAL_ERROR
        "direct-mask primitive blob mismatch for ${relative_path}: "
        "expected ${expected_blob}, got ${actual_blob}; ${blob_error}")
    endif()
  endforeach()
endfunction()

if (NOT EXISTS "${FAEST_REF_DIR}/bavc.c" OR NOT EXISTS "${FAEST_REF_DIR}/aes.c")
  message(FATAL_ERROR "pinned FAEST vendor is not initialized at FAEST_REF_DIR")
endif()
if (NOT EXISTS "${DMV_SOURCE_DIR}/direct_mask_vole.c" OR
    NOT EXISTS "${DMV_SOURCE_DIR}/direct_mask_vole.h")
  message(FATAL_ERROR "pinned direct-mask primitive is required at DMV_SOURCE_DIR")
endif()
if (NOT EXISTS "${MLDSA_ROOT}/third_party/mldsa_native/mldsa/mldsa_native.c" OR
    NOT EXISTS "${MLDSA_ROOT}/third_party/mldsa_native/blind/blind_source_auth_mldsa87_v1.c")
  message(FATAL_ERROR "pinned ML-DSA source-auth wrapper is required at MLDSA_ROOT")
endif()
if (NOT EXISTS "${DIRECT_MASK_BF256_ACCEL_SOURCE}")
  message(FATAL_ERROR "child-local bf256 acceleration source is required")
endif()

require_git_identity("${FAEST_REF_DIR}"
  "ebefcbd8adda5faf447ef3dba5103794d17b4281"
  "f0c2e69f3eb0735fd544d04dc3dcfcc12e275e31"
  "FAEST reference")
require_direct_mask_import_identity("${DMV_SOURCE_DIR}")
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
if (BUILD_TESTING)
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
