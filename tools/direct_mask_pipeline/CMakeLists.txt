cmake_minimum_required(VERSION 3.20)

project(blind_ledger_direct_mask_pipeline C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Reuse the accepted real producer/authenticated-proof graph without editing
# any inherited source, header, or CMake file.
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
  message(FATAL_ERROR "pinned pipeline dependencies are not initialized")
endif()

add_subdirectory(
  "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_source_proof"
  dm_source_proof_build
  EXCLUDE_FROM_ALL)

set(DM_PIPELINE_INCLUDE_DIRS
    "${CMAKE_CURRENT_LIST_DIR}"
    "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_source_proof"
    "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_authenticated_proof"
    "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_source_auth"
    "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_kernel"
    "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_circuit"
    "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_wire"
    "${DMV_SOURCE_DIR}"
    "${FAEST_REF_DIR}"
    "${FAEST_REF_DIR}/sha3"
    "${FAEST_REF_DIR}/sha3/opt64"
    "${MLDSA_ROOT}/third_party/mldsa_native/blind")

add_library(dm_pipeline_codec STATIC direct_mask_pipeline_codec.c)
target_include_directories(dm_pipeline_codec PUBLIC ${DM_PIPELINE_INCLUDE_DIRS})

add_library(dm_pipeline_source STATIC direct_mask_pipeline_source.c)
target_include_directories(dm_pipeline_source PUBLIC ${DM_PIPELINE_INCLUDE_DIRS})
target_link_libraries(dm_pipeline_source PRIVATE dm_pipeline_codec dm_source_proof)

add_library(dm_pipeline_verifier STATIC direct_mask_pipeline_verifier.c)
target_include_directories(dm_pipeline_verifier PUBLIC ${DM_PIPELINE_INCLUDE_DIRS})
target_link_libraries(dm_pipeline_verifier PRIVATE dm_pipeline_codec
                                                   dm_authenticated_proof)

add_executable(dm_pipeline_source_cli direct_mask_pipeline_source_main.c)
target_include_directories(dm_pipeline_source_cli PRIVATE ${DM_PIPELINE_INCLUDE_DIRS})
target_link_libraries(dm_pipeline_source_cli PRIVATE dm_pipeline_source)

add_executable(dm_pipeline_verifier_cli direct_mask_pipeline_verifier_main.c)
target_include_directories(dm_pipeline_verifier_cli PRIVATE ${DM_PIPELINE_INCLUDE_DIRS})
target_link_libraries(dm_pipeline_verifier_cli PRIVATE dm_pipeline_verifier)

add_executable(dm_pipeline_probe direct_mask_pipeline_probe.c)
target_include_directories(dm_pipeline_probe PRIVATE ${DM_PIPELINE_INCLUDE_DIRS})
target_compile_definitions(dm_pipeline_probe PRIVATE
  FAEST_STATIC FAEST_TESTS HAVE_MM_LOADU_SI64)
target_link_libraries(dm_pipeline_probe PRIVATE dm_pipeline_source
                                               dm_pipeline_verifier
                                               dm_source_proof
                                               dm_authenticated_proof)

foreach(target IN ITEMS dm_pipeline_codec dm_pipeline_source dm_pipeline_verifier
                        dm_pipeline_source_cli dm_pipeline_verifier_cli)
  target_compile_definitions(${target} PRIVATE FAEST_STATIC HAVE_MM_LOADU_SI64)
endforeach()

if (MSVC)
  target_compile_options(dm_pipeline_codec PRIVATE /W4)
  target_compile_options(dm_pipeline_source PRIVATE /W4)
  target_compile_options(dm_pipeline_verifier PRIVATE /W4)
  target_compile_options(dm_pipeline_source_cli PRIVATE /W4)
  target_compile_options(dm_pipeline_verifier_cli PRIVATE /W4)
  target_compile_options(dm_pipeline_probe PRIVATE /W4)
else()
  target_compile_options(dm_pipeline_codec PRIVATE -Wall -Wextra -Wpedantic)
  target_compile_options(dm_pipeline_source PRIVATE -Wall -Wextra -Wpedantic)
  target_compile_options(dm_pipeline_verifier PRIVATE -Wall -Wextra -Wpedantic)
  target_compile_options(dm_pipeline_source_cli PRIVATE -Wall -Wextra -Wpedantic)
  target_compile_options(dm_pipeline_verifier_cli PRIVATE -Wall -Wextra -Wpedantic)
  target_compile_options(dm_pipeline_probe PRIVATE -Wall -Wextra -Wpedantic)
endif()

include(CTest)
if (BUILD_TESTING)
  add_test(NAME direct_mask_pipeline_probe COMMAND dm_pipeline_probe)
  add_test(NAME direct_mask_pipeline_real_symbol_gate
    COMMAND ${CMAKE_COMMAND}
      -DREAL_PIPELINE_CODEC_LIBRARY=$<TARGET_FILE:dm_pipeline_codec>
      -DREAL_PIPELINE_SOURCE_LIBRARY=$<TARGET_FILE:dm_pipeline_source>
      -DREAL_PIPELINE_VERIFIER_LIBRARY=$<TARGET_FILE:dm_pipeline_verifier>
      -DREAL_SOURCE_PROOF_LIBRARY=$<TARGET_FILE:dm_source_proof>
      -DREAL_AUTHENTICATED_LIBRARY=$<TARGET_FILE:dm_authenticated_proof>
      -DREAL_SOURCE_EXECUTABLE=$<TARGET_FILE:dm_pipeline_source_cli>
      -DREAL_VERIFIER_EXECUTABLE=$<TARGET_FILE:dm_pipeline_verifier_cli>
      -DREAL_SOURCE_LINK_PROJECT=${CMAKE_CURRENT_BINARY_DIR}/dm_pipeline_source_cli.vcxproj
      -DREAL_VERIFIER_LINK_PROJECT=${CMAKE_CURRENT_BINARY_DIR}/dm_pipeline_verifier_cli.vcxproj
      -DREAL_FORBIDDEN_EDGE_FIXTURE=${CMAKE_CURRENT_LIST_DIR}/verifier_forbidden_edge_fixture.vcxproj
      -DREAL_FORBIDDEN_DIRECT_EDGE_FIXTURE=${CMAKE_CURRENT_LIST_DIR}/verifier_forbidden_direct_dependency_fixture.vcxproj
      -DREAL_MISSING_EVIDENCE_FIXTURE=${CMAKE_CURRENT_LIST_DIR}/missing_evidence_fixture.vcxproj
      -DREAL_PIPELINE_HEADER=${CMAKE_CURRENT_LIST_DIR}/direct_mask_pipeline.h
      -DREAL_PIPELINE_CODEC_SOURCE=${CMAKE_CURRENT_LIST_DIR}/direct_mask_pipeline_codec.c
      -DREAL_PIPELINE_SOURCE_SOURCE=${CMAKE_CURRENT_LIST_DIR}/direct_mask_pipeline_source.c
      -DREAL_PIPELINE_VERIFIER_SOURCE=${CMAKE_CURRENT_LIST_DIR}/direct_mask_pipeline_verifier.c
      -DREAL_SOURCE_MAIN=${CMAKE_CURRENT_LIST_DIR}/direct_mask_pipeline_source_main.c
      -DREAL_VERIFIER_MAIN=${CMAKE_CURRENT_LIST_DIR}/direct_mask_pipeline_verifier_main.c
      -P ${CMAKE_CURRENT_LIST_DIR}/verify_real_symbols.cmake)
endif()
