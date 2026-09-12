cmake_minimum_required(VERSION 3.20)

project(blind_ledger_direct_mask_fixture C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(PMB_BUILD_DIR
    "C:/Users/neers/Documents/Codex/2026-09-04/pmb-20260908"
    CACHE PATH "Read-only accepted static-library build directory")
set(FAEST_REF_DIR
    "${CMAKE_CURRENT_LIST_DIR}/../../../pq-direct-mask-vole-20260907/vendor/faest-ref"
    CACHE PATH "Read-only pinned FAEST source checkout")
set(DMV_SOURCE_DIR
    "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_vole"
    CACHE PATH "Read-only pinned direct-mask source checkout")
set(MLDSA_ROOT
    "C:/Users/neers/Documents/Codex/2026-08-31/blind-zkbpp-c-profile11-extmu-v1"
    CACHE PATH "Read-only pinned ML-DSA source checkout")
set(DIRECT_MASK_PERFORMANCE_PIPELINE_BUILD_DIR
    ""
    CACHE PATH "Optional child-local candidate pipeline build for performance executable")

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

set(FIXTURE_LIBRARY_ROOTS
  "${PMB_BUILD_DIR}/Release/dm_pipeline_source.lib"
  "${PMB_BUILD_DIR}/Release/dm_pipeline_codec.lib"
  "${PMB_BUILD_DIR}/dm_source_proof_build/Release/dm_source_proof.lib"
  "${PMB_BUILD_DIR}/dm_source_proof_build/dm_authenticated_proof_build/dm_source_auth_build/Release/dm_source_auth.lib"
  "${PMB_BUILD_DIR}/dm_source_proof_build/dm_authenticated_proof_build/dm_source_auth_build/Release/dm_wire_codec.lib"
  "${PMB_BUILD_DIR}/dm_source_proof_build/dm_authenticated_proof_build/dm_source_auth_build/Release/mldsa_source_auth_wrapper.lib"
  "${PMB_BUILD_DIR}/dm_source_proof_build/Release/dm_native_fixture_source_proof.lib"
  "${PMB_BUILD_DIR}/dm_source_proof_build/dm_authenticated_proof_build/dm_source_auth_build/Release/dm_faest_public.lib")
set(FIXTURE_LIBRARY_SIZES
  3464 8518 18518 18264 271118 141158 34030 326608)
set(FIXTURE_LIBRARY_HASHES
  B2267C377E9AFF052CD4B0133B59F6A31492F00A8A3214CAB8D7C65599698D95
  2117630F0E761687311B21C2C2B3F564DC29CE759C2EDC24D4252CD3351033E0
  E9932EA2D096F8A5CE15F5C25A56FA32112A9DF33486F5B8FCF117FD84C5B64E
  150374B3A5BB86D22BCC60833F62610ECF131EEF39EF9FAED3FA6C6E72E3A40C
  69209247032243C3B3C6D47C48968B084DB2710750D601B983086EFAC65BE73A
  E386DF41A59AC8A42E8DDC757E619D4DA0A6A589F5694824424AE6D9CFD76A0D
  E572607187E27B97828BB8CB7DC4DBBEE2AA753061F1647D22C8F88DD00DADAD
  D36ED7515AC70AE8FFED4A26C515EFB2300FB329377219B1033B4E3A10C9AB9A)

function(fixture_import_library target index relative_path)
  list(GET FIXTURE_LIBRARY_SIZES ${index} expected_size)
  list(GET FIXTURE_LIBRARY_HASHES ${index} expected_hash)
  set(library_path "${PMB_BUILD_DIR}/${relative_path}")
  if (NOT EXISTS "${library_path}")
    message(FATAL_ERROR "missing pinned library: ${library_path}")
  endif()
  file(SIZE "${library_path}" actual_size)
  file(SHA256 "${library_path}" actual_hash)
  string(TOUPPER "${actual_hash}" actual_hash)
  if (NOT actual_size EQUAL expected_size OR
      NOT actual_hash STREQUAL expected_hash)
    message(FATAL_ERROR
      "pinned library identity mismatch: ${library_path}; "
      "expected ${expected_size}/${expected_hash}, "
      "actual ${actual_size}/${actual_hash}")
  endif()
  add_library(${target} STATIC IMPORTED GLOBAL)
  set_target_properties(${target} PROPERTIES
    IMPORTED_CONFIGURATIONS RELEASE
    IMPORTED_LOCATION_RELEASE "${library_path}")
endfunction()

fixture_import_library(fixture_pipeline_source 0 "Release/dm_pipeline_source.lib")
fixture_import_library(fixture_pipeline_codec 1 "Release/dm_pipeline_codec.lib")
fixture_import_library(fixture_source_proof 2 "dm_source_proof_build/Release/dm_source_proof.lib")
fixture_import_library(fixture_source_auth 3 "dm_source_proof_build/dm_authenticated_proof_build/dm_source_auth_build/Release/dm_source_auth.lib")
fixture_import_library(fixture_wire_codec 4 "dm_source_proof_build/dm_authenticated_proof_build/dm_source_auth_build/Release/dm_wire_codec.lib")
fixture_import_library(fixture_mldsa_wrapper 5 "dm_source_proof_build/dm_authenticated_proof_build/dm_source_auth_build/Release/mldsa_source_auth_wrapper.lib")
fixture_import_library(fixture_native_source_proof 6 "dm_source_proof_build/Release/dm_native_fixture_source_proof.lib")
fixture_import_library(fixture_faest_public 7 "dm_source_proof_build/dm_authenticated_proof_build/dm_source_auth_build/Release/dm_faest_public.lib")

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

add_custom_target(fixture_imported_identity_check ALL
  COMMAND ${CMAKE_COMMAND}
    -DPMB_BUILD_DIR=${PMB_BUILD_DIR}
    -P "${FIXTURE_SOURCE_DIR}/verify_imported_libraries.cmake"
  VERBATIM)

add_library(fixture_common STATIC direct_mask_fixture.c)
target_include_directories(fixture_common PUBLIC ${FIXTURE_INCLUDE_DIRS})
target_compile_definitions(fixture_common PRIVATE FAEST_STATIC HAVE_MM_LOADU_SI64)

add_executable(direct_mask_fixture_source direct_mask_fixture_source.c)
target_include_directories(direct_mask_fixture_source PRIVATE ${FIXTURE_INCLUDE_DIRS})
target_compile_definitions(direct_mask_fixture_source PRIVATE FAEST_STATIC HAVE_MM_LOADU_SI64)
target_link_libraries(direct_mask_fixture_source PRIVATE
  fixture_common
  fixture_pipeline_source
  fixture_pipeline_codec
  fixture_source_proof
  fixture_source_auth
  fixture_wire_codec
  fixture_mldsa_wrapper
  fixture_native_source_proof
  fixture_faest_public
  bcrypt.lib kernel32.lib user32.lib gdi32.lib winspool.lib shell32.lib
  ole32.lib oleaut32.lib uuid.lib comdlg32.lib advapi32.lib)

if (DIRECT_MASK_PERFORMANCE_PIPELINE_BUILD_DIR)
  get_filename_component(DIRECT_MASK_PERFORMANCE_PIPELINE_BUILD_DIR
    "${DIRECT_MASK_PERFORMANCE_PIPELINE_BUILD_DIR}" ABSOLUTE)
  set(DIRECT_MASK_PERF_PIPELINE_SOURCE
    "${DIRECT_MASK_PERFORMANCE_PIPELINE_BUILD_DIR}/Release/dm_pipeline_source.lib")
  set(DIRECT_MASK_PERF_PIPELINE_CODEC
    "${DIRECT_MASK_PERFORMANCE_PIPELINE_BUILD_DIR}/Release/dm_pipeline_codec.lib")
  set(DIRECT_MASK_PERF_SOURCE_PROOF
    "${DIRECT_MASK_PERFORMANCE_PIPELINE_BUILD_DIR}/dm_source_proof_build/Release/dm_source_proof.lib")
  set(DIRECT_MASK_PERF_SOURCE_AUTH
    "${DIRECT_MASK_PERFORMANCE_PIPELINE_BUILD_DIR}/dm_source_proof_build/dm_authenticated_proof_build/dm_source_auth_build/Release/dm_source_auth.lib")
  set(DIRECT_MASK_PERF_WIRE_CODEC
    "${DIRECT_MASK_PERFORMANCE_PIPELINE_BUILD_DIR}/dm_source_proof_build/dm_authenticated_proof_build/dm_source_auth_build/Release/dm_wire_codec.lib")
  set(DIRECT_MASK_PERF_MLDSA_WRAPPER
    "${DIRECT_MASK_PERFORMANCE_PIPELINE_BUILD_DIR}/dm_source_proof_build/dm_authenticated_proof_build/dm_source_auth_build/Release/mldsa_source_auth_wrapper.lib")
  set(DIRECT_MASK_PERF_NATIVE_SOURCE_PROOF
    "${DIRECT_MASK_PERFORMANCE_PIPELINE_BUILD_DIR}/dm_source_proof_build/Release/dm_native_fixture_source_proof.lib")
  set(DIRECT_MASK_PERF_FAEST_PUBLIC
    "${DIRECT_MASK_PERFORMANCE_PIPELINE_BUILD_DIR}/dm_source_proof_build/dm_authenticated_proof_build/dm_source_auth_build/Release/dm_faest_public.lib")
  foreach(performance_library IN ITEMS
      DIRECT_MASK_PERF_PIPELINE_SOURCE
      DIRECT_MASK_PERF_PIPELINE_CODEC
      DIRECT_MASK_PERF_SOURCE_PROOF
      DIRECT_MASK_PERF_SOURCE_AUTH
      DIRECT_MASK_PERF_WIRE_CODEC
      DIRECT_MASK_PERF_MLDSA_WRAPPER
      DIRECT_MASK_PERF_NATIVE_SOURCE_PROOF
      DIRECT_MASK_PERF_FAEST_PUBLIC)
    if (NOT EXISTS "${${performance_library}}")
      message(FATAL_ERROR
        "candidate performance library is required: ${${performance_library}}")
    endif()
  endforeach()

  foreach(performance_target IN ITEMS
      direct_mask_performance_pipeline_source
      direct_mask_performance_pipeline_codec
      direct_mask_performance_source_proof
      direct_mask_performance_source_auth
      direct_mask_performance_wire_codec
      direct_mask_performance_mldsa_wrapper
      direct_mask_performance_native_source_proof
      direct_mask_performance_faest_public)
    add_library(${performance_target} STATIC IMPORTED GLOBAL)
    set_target_properties(${performance_target} PROPERTIES
      IMPORTED_CONFIGURATIONS RELEASE)
  endforeach()
  set_target_properties(direct_mask_performance_pipeline_source PROPERTIES
    IMPORTED_LOCATION_RELEASE "${DIRECT_MASK_PERF_PIPELINE_SOURCE}")
  set_target_properties(direct_mask_performance_pipeline_codec PROPERTIES
    IMPORTED_LOCATION_RELEASE "${DIRECT_MASK_PERF_PIPELINE_CODEC}")
  set_target_properties(direct_mask_performance_source_proof PROPERTIES
    IMPORTED_LOCATION_RELEASE "${DIRECT_MASK_PERF_SOURCE_PROOF}")
  set_target_properties(direct_mask_performance_source_auth PROPERTIES
    IMPORTED_LOCATION_RELEASE "${DIRECT_MASK_PERF_SOURCE_AUTH}")
  set_target_properties(direct_mask_performance_wire_codec PROPERTIES
    IMPORTED_LOCATION_RELEASE "${DIRECT_MASK_PERF_WIRE_CODEC}")
  set_target_properties(direct_mask_performance_mldsa_wrapper PROPERTIES
    IMPORTED_LOCATION_RELEASE "${DIRECT_MASK_PERF_MLDSA_WRAPPER}")
  set_target_properties(direct_mask_performance_native_source_proof PROPERTIES
    IMPORTED_LOCATION_RELEASE "${DIRECT_MASK_PERF_NATIVE_SOURCE_PROOF}")
  set_target_properties(direct_mask_performance_faest_public PROPERTIES
    IMPORTED_LOCATION_RELEASE "${DIRECT_MASK_PERF_FAEST_PUBLIC}")

  add_executable(direct_mask_fixture_source_performance direct_mask_fixture_source.c)
  target_include_directories(direct_mask_fixture_source_performance PRIVATE
    ${FIXTURE_INCLUDE_DIRS})
  target_compile_definitions(direct_mask_fixture_source_performance PRIVATE
    FAEST_STATIC HAVE_MM_LOADU_SI64)
  target_link_libraries(direct_mask_fixture_source_performance PRIVATE
    fixture_common
    direct_mask_performance_pipeline_source
    direct_mask_performance_pipeline_codec
    direct_mask_performance_source_proof
    direct_mask_performance_source_auth
    direct_mask_performance_wire_codec
    direct_mask_performance_mldsa_wrapper
    direct_mask_performance_native_source_proof
    direct_mask_performance_faest_public
    bcrypt.lib kernel32.lib user32.lib gdi32.lib winspool.lib shell32.lib
    ole32.lib oleaut32.lib uuid.lib comdlg32.lib advapi32.lib)
  set_target_properties(direct_mask_fixture_source_performance PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/Release")
endif()

add_executable(direct_mask_fixture_public_key direct_mask_fixture_public_key.c)
target_include_directories(direct_mask_fixture_public_key PRIVATE ${MLDSA_BLIND_DIR})
target_link_libraries(direct_mask_fixture_public_key PRIVATE
  fixture_mldsa_wrapper bcrypt.lib kernel32.lib)

add_executable(direct_mask_fixture_probe direct_mask_fixture_probe.c)
target_include_directories(direct_mask_fixture_probe PRIVATE ${FIXTURE_INCLUDE_DIRS})
target_compile_definitions(direct_mask_fixture_probe PRIVATE FAEST_STATIC HAVE_MM_LOADU_SI64)
target_link_libraries(direct_mask_fixture_probe PRIVATE fixture_common fixture_mldsa_wrapper)

foreach(target IN ITEMS fixture_common direct_mask_fixture_source
                        direct_mask_fixture_public_key direct_mask_fixture_probe)
  add_dependencies(${target} fixture_imported_identity_check)
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
