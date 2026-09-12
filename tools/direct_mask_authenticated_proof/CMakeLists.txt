cmake_minimum_required(VERSION 3.20)

project(blind_ledger_direct_mask_authenticated_proof C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# The source-authentication phase owns the pinned read-only cryptographic
# dependency closure and the wire/kernel target.  This subdirectory adds only
# the composition seam and its test-only native fixture.
add_subdirectory(
  "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_source_auth"
  dm_source_auth_build
  EXCLUDE_FROM_ALL)

set(FAEST_REF_DIR
    "${CMAKE_CURRENT_LIST_DIR}/../../../pq-direct-mask-vole-20260907/vendor/faest-ref"
    CACHE PATH "Read-only pinned FAEST reference checkout")
set(DMV_SOURCE_DIR
    "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_vole"
    CACHE PATH "Read-only pinned direct-mask primitive source directory")
get_filename_component(FAEST_REF_DIR "${FAEST_REF_DIR}" ABSOLUTE)
get_filename_component(DMV_SOURCE_DIR "${DMV_SOURCE_DIR}" ABSOLUTE)

if (NOT EXISTS "${FAEST_REF_DIR}/aes.h" OR
    NOT EXISTS "${DMV_SOURCE_DIR}/direct_mask_vole.h")
  message(FATAL_ERROR "pinned native-fixture dependencies are not initialized")
endif()

add_library(dm_native_fixture_authenticated STATIC
  "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_native/direct_mask_native.c")
target_include_directories(dm_native_fixture_authenticated PUBLIC
  "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_native"
  "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_kernel"
  "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_circuit"
  "${DMV_SOURCE_DIR}"
  "${FAEST_REF_DIR}"
  "${FAEST_REF_DIR}/sha3"
  "${FAEST_REF_DIR}/sha3/opt64")
target_compile_definitions(dm_native_fixture_authenticated PRIVATE
  FAEST_STATIC HAVE_MM_LOADU_SI64)
target_link_libraries(dm_native_fixture_authenticated PUBLIC dm_faest_public)

add_library(dm_authenticated_proof STATIC
  direct_mask_authenticated_proof.c)
target_include_directories(dm_authenticated_proof PUBLIC
  "${CMAKE_CURRENT_LIST_DIR}"
  "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_source_auth")
target_compile_definitions(dm_authenticated_proof PRIVATE
  FAEST_STATIC HAVE_MM_LOADU_SI64)
target_link_libraries(dm_authenticated_proof PUBLIC dm_source_auth)

add_executable(dm_authenticated_proof_probe
  direct_mask_authenticated_proof_probe.c)
target_include_directories(dm_authenticated_proof_probe PRIVATE
  "${CMAKE_CURRENT_LIST_DIR}"
  "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_source_auth"
  "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_native"
  "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_circuit"
  "${DMV_SOURCE_DIR}"
  "${FAEST_REF_DIR}"
  "${FAEST_REF_DIR}/sha3"
  "${FAEST_REF_DIR}/sha3/opt64")
target_compile_definitions(dm_authenticated_proof_probe PRIVATE
  FAEST_STATIC FAEST_TESTS HAVE_MM_LOADU_SI64)
target_link_libraries(dm_authenticated_proof_probe PRIVATE
  dm_authenticated_proof dm_native_fixture_authenticated)

if (WIN32)
  target_link_libraries(dm_faest_public PUBLIC bcrypt)
endif()

if (MSVC)
  target_compile_options(dm_native_fixture_authenticated PRIVATE /W4)
  target_compile_options(dm_authenticated_proof PRIVATE /W4)
  target_compile_options(dm_authenticated_proof_probe PRIVATE /W4)
else()
  target_compile_options(dm_native_fixture_authenticated PRIVATE -Wall -Wextra -Wpedantic)
  target_compile_options(dm_authenticated_proof PRIVATE -Wall -Wextra -Wpedantic)
  target_compile_options(dm_authenticated_proof_probe PRIVATE -Wall -Wextra -Wpedantic)
endif()

include(CTest)
if (BUILD_TESTING)
  add_test(NAME direct_mask_authenticated_proof_probe
    COMMAND dm_authenticated_proof_probe)
  add_test(NAME direct_mask_authenticated_proof_real_symbol_gate
    COMMAND ${CMAKE_COMMAND}
      -DREAL_AUTHENTICATED_LIBRARY=$<TARGET_FILE:dm_authenticated_proof>
      -DREAL_AUTHENTICATED_SOURCE=${CMAKE_CURRENT_LIST_DIR}/direct_mask_authenticated_proof.c
      -DREAL_AUTHENTICATED_HEADER=${CMAKE_CURRENT_LIST_DIR}/direct_mask_authenticated_proof.h
      -DREAL_AUTH_LIBRARY=$<TARGET_FILE:dm_source_auth>
      -DREAL_WIRE_LIBRARY=$<TARGET_FILE:dm_wire_codec>
      -DREAL_FAEST_LIBRARY=$<TARGET_FILE:dm_faest_public>
      -DREAL_MLDSA_LIBRARY=$<TARGET_FILE:mldsa_source_auth_wrapper>
      -P ${CMAKE_CURRENT_LIST_DIR}/verify_real_symbols.cmake)
endif()
