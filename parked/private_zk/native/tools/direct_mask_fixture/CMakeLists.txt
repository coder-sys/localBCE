cmake_minimum_required(VERSION 3.20)

project(blind_ledger_direct_mask_fixture C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(PMB_BUILD_DIR
    "C:/Users/neers/Documents/Codex/2026-09-04/pmb-20260908"
    CACHE PATH "Read-only accepted static-library build directory")
set(FAEST_REF_DIR
    "C:/Users/neers/Documents/Codex/2026-09-04/blind-ledger-astra-driver-v1/work/pq-direct-mask-source-auth-20260908/vendor/faest-ref"
    CACHE PATH "Read-only pinned FAEST source checkout")
set(DMV_SOURCE_DIR
    "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_vole"
    CACHE PATH "Read-only pinned direct-mask source checkout")
set(MLDSA_ROOT
    "C:/Users/neers/Documents/Codex/2026-08-31/blind-zkbpp-c-profile11-extmu-v1"
    CACHE PATH "Read-only pinned ML-DSA source checkout")

get_filename_component(PMB_BUILD_DIR "${PMB_BUILD_DIR}" ABSOLUTE)
get_filename_component(FAEST_REF_DIR "${FAEST_REF_DIR}" ABSOLUTE)
get_filename_component(DMV_SOURCE_DIR "${DMV_SOURCE_DIR}" ABSOLUTE)
get_filename_component(MLDSA_ROOT "${MLDSA_ROOT}" ABSOLUTE)

set(FIXTURE_SOURCE_DIR "${CMAKE_CURRENT_LIST_DIR}")
set(PIPELINE_SOURCE_DIR "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_pipeline")
set(SOURCE_PROOF_DIR "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_source_proof")
set(SOURCE_AUTH_DIR "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_source_auth")
set(AUTHENTICATED_PROOF_DIR "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_authenticated_proof")
set(NATIVE_DIR "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_native")
set(KERNEL_DIR "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_kernel")
set(CIRCUIT_DIR "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_circuit")
set(WIRE_DIR "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_wire")
set(MLDSA_BLIND_DIR "${MLDSA_ROOT}/third_party/mldsa_native/blind")

if (NOT EXISTS "${PIPELINE_SOURCE_DIR}/direct_mask_pipeline.h" OR
    NOT EXISTS "${SOURCE_PROOF_DIR}/direct_mask_source_proof.h" OR
    NOT EXISTS "${SOURCE_AUTH_DIR}/direct_mask_source_auth.h" OR
    NOT EXISTS "${MLDSA_BLIND_DIR}/blind_source_auth_mldsa87_v1.h" OR
    NOT EXISTS "${FAEST_REF_DIR}/aes.h" OR
    NOT EXISTS "${DMV_SOURCE_DIR}/direct_mask_vole.h")
  message(FATAL_ERROR "read-only fixture source/header inputs are incomplete")
endif()

# The old PMB import closure is intentionally not used by this candidate.
# Build the current producer/verifier graph from the child-local primitive
# and the separately pinned vendor/ML-DSA inputs.  The embedded graph must not
# register its own probes in this fixture's CTest registry; the standalone
# pipeline tree owns those tests.
set(DM_EMBEDDED_NO_TESTS ON)
add_subdirectory("${PIPELINE_SOURCE_DIR}" pipeline_build EXCLUDE_FROM_ALL)
unset(DM_EMBEDDED_NO_TESTS)

set(FIXTURE_INCLUDE_DIRS
  "${FIXTURE_SOURCE_DIR}"
  "${PIPELINE_SOURCE_DIR}"
  "${SOURCE_PROOF_DIR}"
  "${AUTHENTICATED_PROOF_DIR}"
  "${SOURCE_AUTH_DIR}"
  "${NATIVE_DIR}"
  "${KERNEL_DIR}"
  "${CIRCUIT_DIR}"
  "${WIRE_DIR}"
  "${DMV_SOURCE_DIR}"
  "${FAEST_REF_DIR}"
  "${FAEST_REF_DIR}/sha3"
  "${FAEST_REF_DIR}/sha3/opt64"
  "${MLDSA_BLIND_DIR}")

add_library(fixture_common STATIC direct_mask_fixture.c)
target_include_directories(fixture_common PUBLIC ${FIXTURE_INCLUDE_DIRS})
target_compile_definitions(fixture_common PRIVATE FAEST_STATIC HAVE_MM_LOADU_SI64)

add_executable(direct_mask_fixture_source direct_mask_fixture_source.c)
target_include_directories(direct_mask_fixture_source PRIVATE ${FIXTURE_INCLUDE_DIRS})
target_compile_definitions(direct_mask_fixture_source PRIVATE FAEST_STATIC HAVE_MM_LOADU_SI64)
target_link_libraries(direct_mask_fixture_source PRIVATE
  fixture_common
  dm_pipeline_source
  dm_pipeline_codec
  dm_source_proof
  dm_source_auth
  dm_wire_codec
  mldsa_source_auth_wrapper
  dm_native_fixture_source_proof
  dm_faest_public
  bcrypt.lib kernel32.lib user32.lib gdi32.lib winspool.lib shell32.lib
  ole32.lib oleaut32.lib uuid.lib comdlg32.lib advapi32.lib)

add_executable(direct_mask_fixture_public_key direct_mask_fixture_public_key.c)
target_include_directories(direct_mask_fixture_public_key PRIVATE ${MLDSA_BLIND_DIR})
target_link_libraries(direct_mask_fixture_public_key PRIVATE
  mldsa_source_auth_wrapper bcrypt.lib kernel32.lib)

add_executable(direct_mask_fixture_probe direct_mask_fixture_probe.c)
target_include_directories(direct_mask_fixture_probe PRIVATE ${FIXTURE_INCLUDE_DIRS})
target_compile_definitions(direct_mask_fixture_probe PRIVATE FAEST_STATIC HAVE_MM_LOADU_SI64)
target_link_libraries(direct_mask_fixture_probe PRIVATE fixture_common mldsa_source_auth_wrapper)

foreach(target IN ITEMS fixture_common direct_mask_fixture_source
                        direct_mask_fixture_public_key direct_mask_fixture_probe)
  if (MSVC)
    target_compile_options(${target} PRIVATE /W4)
  else()
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
  endif()
endforeach()

set_target_properties(direct_mask_fixture_source direct_mask_fixture_public_key
                      direct_mask_fixture_probe
  PROPERTIES RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/Release")

include(CTest)
if (BUILD_TESTING)
  add_test(NAME direct_mask_fixture_probe
    COMMAND direct_mask_fixture_probe)
endif()
