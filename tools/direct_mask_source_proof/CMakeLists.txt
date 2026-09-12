cmake_minimum_required(VERSION 3.20)

project(blind_ledger_direct_mask_source_proof C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# The accepted source-authenticated verifier owns the pinned wire/auth closure.
# This producer adds only its source-local native materializer and producer seam.
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

if (NOT EXISTS "${FAEST_REF_DIR}/aes.h" OR
    NOT EXISTS "${DMV_SOURCE_DIR}/direct_mask_vole.h" OR
    NOT EXISTS "${MLDSA_ROOT}/third_party/mldsa_native/blind/blind_source_auth_mldsa87_v1.c")
  message(FATAL_ERROR "pinned producer dependencies are not initialized")
endif()

add_subdirectory(
  "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_authenticated_proof"
  dm_authenticated_proof_build
  EXCLUDE_FROM_ALL)

add_library(dm_native_fixture_source_proof STATIC
  "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_native/direct_mask_native.c")
target_include_directories(dm_native_fixture_source_proof PUBLIC
  "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_native"
  "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_kernel"
  "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_circuit"
  "${DMV_SOURCE_DIR}"
  "${FAEST_REF_DIR}"
  "${FAEST_REF_DIR}/sha3"
  "${FAEST_REF_DIR}/sha3/opt64")
target_compile_definitions(dm_native_fixture_source_proof PRIVATE
  FAEST_STATIC HAVE_MM_LOADU_SI64)
target_link_libraries(dm_native_fixture_source_proof PUBLIC dm_faest_public)

add_library(dm_source_proof STATIC direct_mask_source_proof.c)
target_include_directories(dm_source_proof PUBLIC
  "${CMAKE_CURRENT_LIST_DIR}")
target_include_directories(dm_source_proof PRIVATE
  "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_source_auth"
  "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_native"
  "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_kernel"
  "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_circuit"
  "${DMV_SOURCE_DIR}"
  "${FAEST_REF_DIR}"
  "${FAEST_REF_DIR}/sha3"
  "${FAEST_REF_DIR}/sha3/opt64")
target_compile_definitions(dm_source_proof PRIVATE
  FAEST_STATIC HAVE_MM_LOADU_SI64)
target_link_libraries(dm_source_proof PUBLIC
  dm_source_auth dm_native_fixture_source_proof)

add_executable(dm_source_proof_probe direct_mask_source_proof_probe.c)
target_include_directories(dm_source_proof_probe PRIVATE
  "${CMAKE_CURRENT_LIST_DIR}"
  "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_authenticated_proof"
  "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_source_auth"
  "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_native"
  "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_circuit"
  "${DMV_SOURCE_DIR}"
  "${FAEST_REF_DIR}"
  "${FAEST_REF_DIR}/sha3"
  "${FAEST_REF_DIR}/sha3/opt64"
  "${MLDSA_ROOT}/third_party/mldsa_native/blind")
target_compile_definitions(dm_source_proof_probe PRIVATE
  FAEST_STATIC FAEST_TESTS HAVE_MM_LOADU_SI64)
target_link_libraries(dm_source_proof_probe PRIVATE
  dm_source_proof dm_authenticated_proof)

if (MSVC)
  target_compile_options(dm_native_fixture_source_proof PRIVATE /W4)
  target_compile_options(dm_source_proof PRIVATE /W4)
  target_compile_options(dm_source_proof_probe PRIVATE /W4)
else()
  target_compile_options(dm_native_fixture_source_proof PRIVATE -Wall -Wextra -Wpedantic)
  target_compile_options(dm_source_proof PRIVATE -Wall -Wextra -Wpedantic)
  target_compile_options(dm_source_proof_probe PRIVATE -Wall -Wextra -Wpedantic)
endif()

include(CTest)
if (BUILD_TESTING)
  add_test(NAME direct_mask_source_proof_probe
    COMMAND dm_source_proof_probe)
  add_test(NAME direct_mask_source_proof_real_symbol_gate
    COMMAND ${CMAKE_COMMAND}
      -DREAL_SOURCE_PROOF_LIBRARY=$<TARGET_FILE:dm_source_proof>
      -DREAL_SOURCE_PROOF_SOURCE=${CMAKE_CURRENT_LIST_DIR}/direct_mask_source_proof.c
      -DREAL_SOURCE_PROOF_HEADER=${CMAKE_CURRENT_LIST_DIR}/direct_mask_source_proof.h
      -DREAL_NATIVE_LIBRARY=$<TARGET_FILE:dm_native_fixture_source_proof>
      -DREAL_AUTH_LIBRARY=$<TARGET_FILE:dm_source_auth>
      -DREAL_WIRE_LIBRARY=$<TARGET_FILE:dm_wire_codec>
      -DREAL_FAEST_LIBRARY=$<TARGET_FILE:dm_faest_public>
      -DREAL_MLDSA_LIBRARY=$<TARGET_FILE:mldsa_source_auth_wrapper>
      -P ${CMAKE_CURRENT_LIST_DIR}/verify_real_symbols.cmake)
endif()
