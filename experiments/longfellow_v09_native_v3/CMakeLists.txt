cmake_minimum_required(VERSION 3.25)
project(longfellow_v09_native_v3 LANGUAGES CXX)

option(LONGFELLOW_NATIVE_V3_NO_SHA3_WITNESS
       "Use the full in-circuit Keccak path without checkpoint witnesses"
       OFF)

set(LONGFELLOW_SOURCE "" CACHE PATH "Patched pinned Longfellow source")
if(NOT EXISTS "${LONGFELLOW_SOURCE}/lib/zk/zk_prover.h")
  message(FATAL_ERROR "LONGFELLOW_SOURCE must name the patched pinned source tree")
endif()

# Source provenance is generated from the pinned manifest and the actual
# patched source files. The manifest also defines the only allowed patched
# worktree bytes; every path, digest, and Git state set is checked before any
# source header is consumed by a target.
set(NATIVE_V3_UPSTREAM_MANIFEST
    "${CMAKE_CURRENT_SOURCE_DIR}/upstream_manifest.json")
if(NOT EXISTS "${NATIVE_V3_UPSTREAM_MANIFEST}")
  message(FATAL_ERROR "upstream manifest missing")
endif()
file(READ "${NATIVE_V3_UPSTREAM_MANIFEST}" NATIVE_V3_MANIFEST_JSON)

function(NATIVE_V3_JSON_GET OUTPUT)
  string(JSON _value ERROR_VARIABLE _error GET
         "${NATIVE_V3_MANIFEST_JSON}" ${ARGN})
  if(NOT "${_error}" STREQUAL "NOTFOUND")
    message(FATAL_ERROR "native-v3 manifest JSON value missing: ${ARGN}")
  endif()
  set(${OUTPUT} "${_value}" PARENT_SCOPE)
endfunction()

function(NATIVE_V3_JSON_TYPE OUTPUT)
  string(JSON _value ERROR_VARIABLE _error TYPE
         "${NATIVE_V3_MANIFEST_JSON}" ${ARGN})
  if(NOT "${_error}" STREQUAL "NOTFOUND")
    message(FATAL_ERROR "native-v3 manifest JSON type missing: ${ARGN}")
  endif()
  set(${OUTPUT} "${_value}" PARENT_SCOPE)
endfunction()

function(NATIVE_V3_JSON_LENGTH OUTPUT)
  string(JSON _value ERROR_VARIABLE _error LENGTH
         "${NATIVE_V3_MANIFEST_JSON}" ${ARGN})
  if(NOT "${_error}" STREQUAL "NOTFOUND")
    message(FATAL_ERROR "native-v3 manifest JSON array missing: ${ARGN}")
  endif()
  set(${OUTPUT} "${_value}" PARENT_SCOPE)
endfunction()

function(NATIVE_V3_GIT_LIST OUTPUT)
  execute_process(
    COMMAND git "-c" "safe.directory=${LONGFELLOW_SOURCE}"
            "-C" "${LONGFELLOW_SOURCE}" ${ARGN}
    OUTPUT_VARIABLE _raw
    ERROR_VARIABLE _error
    OUTPUT_STRIP_TRAILING_WHITESPACE
    RESULT_VARIABLE _result)
  if(NOT "${_result}" STREQUAL "0")
    message(FATAL_ERROR "native-v3 patched-source Git query failed: ${ARGN}")
  endif()
  if("${_raw}" STREQUAL "")
    set(_list)
  else()
    string(REPLACE "\r\n" ";" _list "${_raw}")
    string(REPLACE "\n" ";" _list "${_list}")
    string(REPLACE "\r" ";" _list "${_list}")
    list(FILTER _list EXCLUDE REGEX "^$")
  endif()
  set(${OUTPUT} "${_list}" PARENT_SCOPE)
endfunction()

NATIVE_V3_JSON_TYPE(_manifest_version_type manifest_version)
NATIVE_V3_JSON_GET(_manifest_version manifest_version)
if(NOT "${_manifest_version_type}" STREQUAL "NUMBER" OR
   NOT "${_manifest_version}" STREQUAL "2")
  message(FATAL_ERROR "native-v3 manifest version mismatch")
endif()
NATIVE_V3_JSON_GET(NATIVE_V3_MANIFEST_REMOTE upstream remote)
NATIVE_V3_JSON_GET(NATIVE_V3_MANIFEST_COMMIT upstream commit)
NATIVE_V3_JSON_GET(NATIVE_V3_MANIFEST_TREE upstream tree)
if(NOT NATIVE_V3_MANIFEST_REMOTE STREQUAL
       "https://github.com/google/longfellow-zk.git" OR
   NOT NATIVE_V3_MANIFEST_COMMIT STREQUAL
       "fe83ec6c4efa5f98bc2439c8b06e5eccd153aca0" OR
   NOT NATIVE_V3_MANIFEST_TREE STREQUAL
       "829f5dd115f3b5bdd77dc57c72293a5ccc3ca244")
  message(FATAL_ERROR "pinned upstream manifest identity mismatch")
endif()

set(_expected_patch_paths
    "patches/sha3_512_circuit.patch"
    "patches/quad_builder_uint32_bound.patch")
NATIVE_V3_JSON_TYPE(_patch_files_type patched_source_provenance patch_files)
NATIVE_V3_JSON_LENGTH(_patch_file_count patched_source_provenance patch_files)
if(NOT "${_patch_files_type}" STREQUAL "ARRAY" OR
   NOT "${_patch_file_count}" STREQUAL "2")
  message(FATAL_ERROR "native-v3 patch manifest shape mismatch")
endif()
set(_manifest_patch_paths)
set(_manifest_patch_hashes)
foreach(_index RANGE 0 1)
  NATIVE_V3_JSON_TYPE(_path_type patched_source_provenance patch_files
                      ${_index} path)
  NATIVE_V3_JSON_TYPE(_hash_type patched_source_provenance patch_files
                      ${_index} sha256)
  NATIVE_V3_JSON_GET(_path patched_source_provenance patch_files ${_index} path)
  NATIVE_V3_JSON_GET(_hash patched_source_provenance patch_files ${_index} sha256)
  if(NOT "${_path_type}" STREQUAL "STRING" OR
     NOT "${_hash_type}" STREQUAL "STRING")
    message(FATAL_ERROR "native-v3 patch manifest entry type mismatch")
  endif()
  list(APPEND _manifest_patch_paths "${_path}")
  list(APPEND _manifest_patch_hashes "${_hash}")
endforeach()
if(NOT "${_manifest_patch_paths}" STREQUAL "${_expected_patch_paths}")
  message(FATAL_ERROR "native-v3 patch path allowlist mismatch")
endif()
NATIVE_V3_JSON_GET(_legacy_sha3_patch_path sha3_512 patch)
NATIVE_V3_JSON_GET(_legacy_sha3_patch_hash sha3_512 patch_sha256)
list(GET _manifest_patch_paths 0 _expected_sha3_patch_path)
if(NOT "${_legacy_sha3_patch_path}" STREQUAL
       "${_expected_sha3_patch_path}")
  message(FATAL_ERROR "native-v3 SHA3 patch path binding mismatch")
endif()
list(GET _manifest_patch_hashes 0 _expected_sha3_patch_hash)
if(NOT "${_legacy_sha3_patch_hash}" STREQUAL
       "${_expected_sha3_patch_hash}")
  message(FATAL_ERROR "native-v3 SHA3 patch digest binding mismatch")
endif()
foreach(_index RANGE 0 1)
  list(GET _manifest_patch_paths ${_index} _patch_path)
  list(GET _manifest_patch_hashes ${_index} _expected_hash)
  string(LENGTH "${_expected_hash}" _hash_length)
  if(NOT "${_hash_length}" STREQUAL "64")
    message(FATAL_ERROR "native-v3 patch digest length mismatch")
  endif()
  file(SHA256 "${CMAKE_CURRENT_SOURCE_DIR}/${_patch_path}" _observed_hash)
  string(TOLOWER "${_expected_hash}" _expected_hash_lower)
  string(TOLOWER "${_observed_hash}" _observed_hash_lower)
  if(NOT "${_expected_hash_lower}" STREQUAL "${_observed_hash_lower}")
    message(FATAL_ERROR "native-v3 patch digest mismatch: ${_patch_path}")
  endif()
  if(_index EQUAL 0)
    set(NATIVE_V3_SHA3_PATCH
        "${CMAKE_CURRENT_SOURCE_DIR}/${_patch_path}")
    set(NATIVE_V3_SHA3_PATCH_SHA256 "${_observed_hash}")
  else()
    set(NATIVE_V3_QUAD_PATCH
        "${CMAKE_CURRENT_SOURCE_DIR}/${_patch_path}")
    set(NATIVE_V3_QUAD_PATCH_SHA256 "${_observed_hash}")
  endif()
endforeach()
set(NATIVE_V3_MANIFEST_SHA3_PATCH "${_legacy_sha3_patch_hash}")

set(_expected_unstaged_paths
    "lib/circuits/tests/sha3/sha3_circuit.h"
    "lib/sumcheck/quad_builder.h")
NATIVE_V3_JSON_TYPE(_unstaged_type patched_source_provenance
                    unstaged_diff_paths)
NATIVE_V3_JSON_LENGTH(_unstaged_count patched_source_provenance
                      unstaged_diff_paths)
if(NOT "${_unstaged_type}" STREQUAL "ARRAY" OR
   NOT "${_unstaged_count}" STREQUAL "2")
  message(FATAL_ERROR "native-v3 unstaged allowlist shape mismatch")
endif()
set(_manifest_unstaged_paths)
foreach(_index RANGE 0 1)
  NATIVE_V3_JSON_GET(_path patched_source_provenance unstaged_diff_paths
                     ${_index})
  list(APPEND _manifest_unstaged_paths "${_path}")
endforeach()
if(NOT "${_manifest_unstaged_paths}" STREQUAL
       "${_expected_unstaged_paths}")
  message(FATAL_ERROR "native-v3 unstaged path allowlist mismatch")
endif()

foreach(_empty_field IN ITEMS staged_paths untracked_paths)
  NATIVE_V3_JSON_TYPE(_empty_type patched_source_provenance ${_empty_field})
  NATIVE_V3_JSON_LENGTH(_empty_count patched_source_provenance ${_empty_field})
  if(NOT "${_empty_type}" STREQUAL "ARRAY" OR
     NOT "${_empty_count}" STREQUAL "0")
    message(FATAL_ERROR "native-v3 ${_empty_field} manifest must be empty")
  endif()
endforeach()

NATIVE_V3_GIT_LIST(_actual_unstaged diff --name-only HEAD --)
NATIVE_V3_GIT_LIST(_actual_staged diff --cached --name-only --)
NATIVE_V3_GIT_LIST(_actual_untracked ls-files --others --exclude-standard
                   --full-name)
if(NOT "${_actual_unstaged}" STREQUAL "${_expected_unstaged_paths}" OR
   NOT "${_actual_staged}" STREQUAL "" OR
   NOT "${_actual_untracked}" STREQUAL "")
  message(FATAL_ERROR "patched-source Git state is outside the manifest")
endif()

set(_expected_source_paths
    "lib/circuits/tests/sha3/sha3_circuit.h"
    "lib/circuits/tests/sha3/sha3_slicing.h"
    "lib/sumcheck/quad_builder.h")
NATIVE_V3_JSON_TYPE(_source_files_type patched_source_provenance
                    consumed_source_files)
NATIVE_V3_JSON_LENGTH(_source_file_count patched_source_provenance
                      consumed_source_files)
if(NOT "${_source_files_type}" STREQUAL "ARRAY" OR
   NOT "${_source_file_count}" STREQUAL "3")
  message(FATAL_ERROR "native-v3 consumed-source manifest shape mismatch")
endif()
set(_manifest_source_paths)
set(_manifest_source_hashes)
foreach(_index RANGE 0 2)
  NATIVE_V3_JSON_TYPE(_path_type patched_source_provenance
                      consumed_source_files ${_index} path)
  NATIVE_V3_JSON_TYPE(_hash_type patched_source_provenance
                      consumed_source_files ${_index} sha256)
  NATIVE_V3_JSON_GET(_path patched_source_provenance consumed_source_files
                     ${_index} path)
  NATIVE_V3_JSON_GET(_hash patched_source_provenance consumed_source_files
                     ${_index} sha256)
  if(NOT "${_path_type}" STREQUAL "STRING" OR
     NOT "${_hash_type}" STREQUAL "STRING")
    message(FATAL_ERROR "native-v3 consumed-source manifest entry type mismatch")
  endif()
  list(APPEND _manifest_source_paths "${_path}")
  list(APPEND _manifest_source_hashes "${_hash}")
endforeach()
if(NOT "${_manifest_source_paths}" STREQUAL "${_expected_source_paths}")
  message(FATAL_ERROR "native-v3 consumed-source path allowlist mismatch")
endif()
foreach(_index RANGE 0 2)
  list(GET _manifest_source_paths ${_index} _source_path)
  list(GET _manifest_source_hashes ${_index} _expected_hash)
  string(LENGTH "${_expected_hash}" _hash_length)
  if(NOT "${_hash_length}" STREQUAL "64")
    message(FATAL_ERROR "native-v3 consumed-source digest length mismatch")
  endif()
  set(_source_file "${LONGFELLOW_SOURCE}/${_source_path}")
  if(NOT EXISTS "${_source_file}")
    message(FATAL_ERROR "patched source file missing: ${_source_path}")
  endif()
  file(SHA256 "${_source_file}" _observed_hash)
  string(TOLOWER "${_expected_hash}" _expected_hash_lower)
  string(TOLOWER "${_observed_hash}" _observed_hash_lower)
  if(NOT "${_expected_hash_lower}" STREQUAL "${_observed_hash_lower}")
    message(FATAL_ERROR "native-v3 consumed-source digest mismatch: ${_source_path}")
  endif()
endforeach()

execute_process(
  COMMAND git -c safe.directory=${LONGFELLOW_SOURCE} -C ${LONGFELLOW_SOURCE}
          rev-parse HEAD
  OUTPUT_VARIABLE NATIVE_V3_SOURCE_COMMIT
  OUTPUT_STRIP_TRAILING_WHITESPACE
  RESULT_VARIABLE NATIVE_V3_SOURCE_COMMIT_RESULT)
execute_process(
  COMMAND git -c safe.directory=${LONGFELLOW_SOURCE} -C ${LONGFELLOW_SOURCE}
          rev-parse HEAD^{tree}
  OUTPUT_VARIABLE NATIVE_V3_SOURCE_TREE
  OUTPUT_STRIP_TRAILING_WHITESPACE
  RESULT_VARIABLE NATIVE_V3_SOURCE_TREE_RESULT)
if(NOT NATIVE_V3_SOURCE_COMMIT_RESULT EQUAL 0 OR
   NOT NATIVE_V3_SOURCE_TREE_RESULT EQUAL 0 OR
   NOT NATIVE_V3_SOURCE_COMMIT STREQUAL NATIVE_V3_MANIFEST_COMMIT OR
   NOT NATIVE_V3_SOURCE_TREE STREQUAL NATIVE_V3_MANIFEST_TREE)
  message(FATAL_ERROR "patched source commit/tree identity mismatch")
endif()

set(NATIVE_V3_SHA3_CIRCUIT_HEADER
    "${LONGFELLOW_SOURCE}/lib/circuits/tests/sha3/sha3_circuit.h")
set(NATIVE_V3_SHA3_SLICING_HEADER
    "${LONGFELLOW_SOURCE}/lib/circuits/tests/sha3/sha3_slicing.h")
set(NATIVE_V3_QUAD_BUILDER_HEADER
    "${LONGFELLOW_SOURCE}/lib/sumcheck/quad_builder.h")
foreach(NATIVE_V3_SOURCE_FILE IN ITEMS NATIVE_V3_SHA3_CIRCUIT_HEADER
        NATIVE_V3_SHA3_SLICING_HEADER NATIVE_V3_QUAD_BUILDER_HEADER)
  if(NOT EXISTS "${${NATIVE_V3_SOURCE_FILE}}")
    message(FATAL_ERROR "patched source file missing: ${NATIVE_V3_SOURCE_FILE}")
  endif()
endforeach()
file(SHA256 "${NATIVE_V3_SHA3_CIRCUIT_HEADER}"
     NATIVE_V3_SHA3_CIRCUIT_HEADER_SHA256)
file(SHA256 "${NATIVE_V3_SHA3_SLICING_HEADER}"
     NATIVE_V3_SHA3_SLICING_HEADER_SHA256)
file(SHA256 "${NATIVE_V3_QUAD_BUILDER_HEADER}"
     NATIVE_V3_QUAD_BUILDER_HEADER_SHA256)
string(SHA256 NATIVE_V3_PATCHED_SOURCE_IDENTITY
       "commit=${NATIVE_V3_SOURCE_COMMIT};tree=${NATIVE_V3_SOURCE_TREE};sha3_patch=${NATIVE_V3_SHA3_PATCH_SHA256};quad_patch=${NATIVE_V3_QUAD_PATCH_SHA256};sha3_circuit=${NATIVE_V3_SHA3_CIRCUIT_HEADER_SHA256};sha3_slicing=${NATIVE_V3_SHA3_SLICING_HEADER_SHA256};quad_builder=${NATIVE_V3_QUAD_BUILDER_HEADER_SHA256}")
set(NATIVE_V3_BUILD_PROVENANCE_GENERATED_DIR
    "${CMAKE_CURRENT_BINARY_DIR}/generated")
file(MAKE_DIRECTORY "${NATIVE_V3_BUILD_PROVENANCE_GENERATED_DIR}")
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/src/native_v3_build_provenance.h.in"
  "${NATIVE_V3_BUILD_PROVENANCE_GENERATED_DIR}/native_v3_build_provenance.h"
  @ONLY)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(MSVC)
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

add_library(longfellow_task_crypto STATIC
  src/crypto.cpp
  src/log.cpp
)
target_include_directories(longfellow_task_crypto PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/shim"
  "${LONGFELLOW_SOURCE}/lib"
)
target_compile_definitions(longfellow_task_crypto PUBLIC NOMINMAX WIN32_LEAN_AND_MEAN)
target_link_libraries(longfellow_task_crypto PUBLIC bcrypt)

add_executable(longfellow_sha3_512_kat
  src/sha3_512_kat.cpp
  src/sha3_512_witness.cc
  "${LONGFELLOW_SOURCE}/lib/circuits/tests/sha3/sha3_reference.cc"
  "${LONGFELLOW_SOURCE}/lib/circuits/tests/sha3/sha3_round_constants.cc"
  "${LONGFELLOW_SOURCE}/lib/circuits/tests/sha3/sha3_witness.cc"
)
target_include_directories(longfellow_sha3_512_kat PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/src"
  "${CMAKE_CURRENT_SOURCE_DIR}/shim"
  "${LONGFELLOW_SOURCE}/lib"
)
target_compile_definitions(longfellow_sha3_512_kat PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
target_link_libraries(longfellow_sha3_512_kat PRIVATE longfellow_task_crypto bcrypt)

add_library(longfellow_source_assertion_relation STATIC
  src/native_v3_source_assertion_relation.cc
  src/sha3_512_witness.cc
  "${LONGFELLOW_SOURCE}/lib/circuits/tests/sha3/sha3_reference.cc"
  "${LONGFELLOW_SOURCE}/lib/circuits/tests/sha3/sha3_round_constants.cc"
  "${LONGFELLOW_SOURCE}/lib/circuits/tests/sha3/sha3_witness.cc"
)
target_include_directories(longfellow_source_assertion_relation PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/src"
  "${CMAKE_CURRENT_SOURCE_DIR}/shim"
  "${LONGFELLOW_SOURCE}/lib"
)
target_compile_definitions(longfellow_source_assertion_relation PUBLIC
  NOMINMAX WIN32_LEAN_AND_MEAN
)
if(LONGFELLOW_NATIVE_V3_NO_SHA3_WITNESS)
  target_compile_definitions(longfellow_source_assertion_relation
                             PUBLIC BLIND_LEDGER_LONGFELLOW_NO_SHA3_WITNESS=1)
endif()
target_link_libraries(longfellow_source_assertion_relation PUBLIC
  longfellow_task_crypto bcrypt)

add_executable(longfellow_source_assertion_kat
  src/native_v3_source_assertion_kat.cpp
  src/sha3_512_witness.cc
  "${LONGFELLOW_SOURCE}/lib/circuits/tests/sha3/sha3_reference.cc"
  "${LONGFELLOW_SOURCE}/lib/circuits/tests/sha3/sha3_round_constants.cc"
  "${LONGFELLOW_SOURCE}/lib/circuits/tests/sha3/sha3_witness.cc"
)
target_include_directories(longfellow_source_assertion_kat PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/src"
  "${CMAKE_CURRENT_SOURCE_DIR}/shim"
  "${LONGFELLOW_SOURCE}/lib"
)
target_compile_definitions(longfellow_source_assertion_kat PRIVATE
  NOMINMAX WIN32_LEAN_AND_MEAN
)
target_link_libraries(longfellow_source_assertion_kat PRIVATE
  longfellow_task_crypto bcrypt)

add_executable(longfellow_source_assertion_eval
  src/native_v3_source_assertion_eval.cpp
)
target_include_directories(longfellow_source_assertion_eval PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/src"
  "${CMAKE_CURRENT_SOURCE_DIR}/shim"
  "${LONGFELLOW_SOURCE}/lib"
)
target_compile_definitions(longfellow_source_assertion_eval PRIVATE
  NOMINMAX WIN32_LEAN_AND_MEAN
)
target_link_libraries(longfellow_source_assertion_eval PRIVATE
  longfellow_source_assertion_relation)

add_executable(longfellow_source_assertion_attribution
  src/native_v3_source_assertion_attribution.cpp
)
target_include_directories(longfellow_source_assertion_attribution PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/src"
  "${CMAKE_CURRENT_SOURCE_DIR}/shim"
  "${LONGFELLOW_SOURCE}/lib"
)
target_compile_definitions(longfellow_source_assertion_attribution PRIVATE
  NOMINMAX WIN32_LEAN_AND_MEAN
)
target_link_libraries(longfellow_source_assertion_attribution PRIVATE
  longfellow_source_assertion_relation psapi)

add_library(longfellow_source_assertion_proof_artifact STATIC
  src/native_v3_source_assertion_proof_artifact.cc
)
target_include_directories(longfellow_source_assertion_proof_artifact PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/src"
)
target_compile_definitions(longfellow_source_assertion_proof_artifact PUBLIC
  NOMINMAX WIN32_LEAN_AND_MEAN
)

# The verifier circuit deliberately excludes fixture construction and witness
# filling. It contains only the fixed relation compiler and the circuit's
# pinned SHA3 implementation; public values are reconstructed independently by
# native_v3_source_assertion_verifier.cpp.
add_library(longfellow_source_assertion_verifier_circuit STATIC
  src/native_v3_source_assertion_relation.cc
  "${LONGFELLOW_SOURCE}/lib/circuits/tests/sha3/sha3_reference.cc"
  "${LONGFELLOW_SOURCE}/lib/circuits/tests/sha3/sha3_round_constants.cc"
  "${LONGFELLOW_SOURCE}/lib/circuits/tests/sha3/sha3_witness.cc"
)
target_include_directories(longfellow_source_assertion_verifier_circuit PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/src"
  "${CMAKE_CURRENT_SOURCE_DIR}/shim"
  "${LONGFELLOW_SOURCE}/lib"
)
target_compile_definitions(longfellow_source_assertion_verifier_circuit PUBLIC
  NOMINMAX WIN32_LEAN_AND_MEAN
  BLIND_LEDGER_SOURCE_ASSERTION_VERIFIER_ONLY=1
  BLIND_LEDGER_RELATION_CIRCUIT_ONLY=1
  BLIND_LEDGER_LONGFELLOW_NO_SHA3_WITNESS=1
)
target_link_libraries(longfellow_source_assertion_verifier_circuit PUBLIC
  longfellow_task_crypto bcrypt)

add_executable(longfellow_source_assertion_prover
  src/native_v3_source_assertion_prover.cpp
)
target_include_directories(longfellow_source_assertion_prover PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/src"
  "${CMAKE_CURRENT_SOURCE_DIR}/shim"
  "${LONGFELLOW_SOURCE}/lib"
)
target_compile_definitions(longfellow_source_assertion_prover PRIVATE
  NOMINMAX WIN32_LEAN_AND_MEAN
)
target_link_libraries(longfellow_source_assertion_prover PRIVATE
  longfellow_source_assertion_relation
  longfellow_source_assertion_proof_artifact)

add_executable(longfellow_source_assertion_verifier
  src/native_v3_source_assertion_verifier.cpp
  src/native_v3_source_assertion_canonical.cpp
  src/native_v3_source_assertion_public_parity_codec.cpp
)
target_include_directories(longfellow_source_assertion_verifier PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/src"
  "${CMAKE_CURRENT_SOURCE_DIR}/shim"
  "${LONGFELLOW_SOURCE}/lib"
)
target_compile_definitions(longfellow_source_assertion_verifier PRIVATE
  NOMINMAX WIN32_LEAN_AND_MEAN
)
target_link_libraries(longfellow_source_assertion_verifier PRIVATE
  longfellow_source_assertion_verifier_circuit
  longfellow_source_assertion_proof_artifact)

add_executable(longfellow_source_assertion_public_parity
  src/native_v3_source_assertion_public_parity.cpp
  src/native_v3_source_assertion_public_parity_codec.cpp
)
target_include_directories(longfellow_source_assertion_public_parity PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/src"
  "${CMAKE_CURRENT_SOURCE_DIR}/shim"
  "${LONGFELLOW_SOURCE}/lib"
)
target_compile_definitions(longfellow_source_assertion_public_parity PRIVATE
  NOMINMAX WIN32_LEAN_AND_MEAN
)
target_link_libraries(longfellow_source_assertion_public_parity PRIVATE
  longfellow_source_assertion_relation)

add_executable(longfellow_source_assertion_prover_runner
  src/native_v3_source_assertion_prover_runner.cpp
)
target_include_directories(longfellow_source_assertion_prover_runner PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/src"
  "${CMAKE_CURRENT_SOURCE_DIR}/shim"
  "${LONGFELLOW_SOURCE}/lib"
)
target_compile_definitions(longfellow_source_assertion_prover_runner PRIVATE
  NOMINMAX WIN32_LEAN_AND_MEAN
)
target_link_libraries(longfellow_source_assertion_prover_runner PRIVATE
  longfellow_task_crypto psapi)

# This is one monolithic relation and does not claim multi-component
# transcript linkage.
add_library(longfellow_minimal_clearance_relation STATIC
  src/native_v3_minimal_clearance_relation.cc
  src/native_v3_fixture.cc
  "${LONGFELLOW_SOURCE}/lib/circuits/tests/sha3/sha3_reference.cc"
  "${LONGFELLOW_SOURCE}/lib/circuits/tests/sha3/sha3_round_constants.cc"
)
target_include_directories(longfellow_minimal_clearance_relation PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/src"
  "${CMAKE_CURRENT_SOURCE_DIR}/shim"
  "${LONGFELLOW_SOURCE}/lib"
)
target_compile_definitions(longfellow_minimal_clearance_relation PUBLIC
  NOMINMAX WIN32_LEAN_AND_MEAN
  BLIND_LEDGER_LONGFELLOW_NO_SHA3_WITNESS=1
)
target_link_libraries(longfellow_minimal_clearance_relation PUBLIC
  longfellow_task_crypto bcrypt)

add_executable(longfellow_minimal_clearance_shape
  src/native_v3_minimal_clearance_shape.cpp
)
target_include_directories(longfellow_minimal_clearance_shape PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/src"
  "${CMAKE_CURRENT_SOURCE_DIR}/shim"
  "${LONGFELLOW_SOURCE}/lib"
)
target_compile_definitions(longfellow_minimal_clearance_shape PRIVATE
  NOMINMAX WIN32_LEAN_AND_MEAN
)
target_link_libraries(longfellow_minimal_clearance_shape PRIVATE
  longfellow_minimal_clearance_relation psapi)

add_executable(longfellow_minimal_clearance_eval
  src/native_v3_minimal_clearance_eval.cpp
)
target_include_directories(longfellow_minimal_clearance_eval PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/src"
  "${CMAKE_CURRENT_SOURCE_DIR}/shim"
  "${LONGFELLOW_SOURCE}/lib"
)
target_compile_definitions(longfellow_minimal_clearance_eval PRIVATE
  NOMINMAX WIN32_LEAN_AND_MEAN
)
target_link_libraries(longfellow_minimal_clearance_eval PRIVATE
  longfellow_minimal_clearance_relation)

# Proof-envelope seam for the one-endpoint minimal-clearance experiment. The
# verifier circuit is compiled from the relation only; it excludes fixture
# construction and witness filling, while the verifier executable rebuilds
# the typed public statement from its immutable synthetic registry constants.
add_library(longfellow_minimal_clearance_verifier_circuit STATIC
  src/native_v3_minimal_clearance_relation.cc
  "${LONGFELLOW_SOURCE}/lib/circuits/tests/sha3/sha3_reference.cc"
  "${LONGFELLOW_SOURCE}/lib/circuits/tests/sha3/sha3_round_constants.cc"
)
target_include_directories(longfellow_minimal_clearance_verifier_circuit PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/src"
  "${CMAKE_CURRENT_SOURCE_DIR}/shim"
  "${LONGFELLOW_SOURCE}/lib"
)
target_compile_definitions(longfellow_minimal_clearance_verifier_circuit PUBLIC
  NOMINMAX WIN32_LEAN_AND_MEAN
  BLIND_LEDGER_MINIMAL_CLEARANCE_VERIFIER_ONLY=1
  BLIND_LEDGER_RELATION_CIRCUIT_ONLY=1
  BLIND_LEDGER_LONGFELLOW_NO_SHA3_WITNESS=1
)
target_link_libraries(longfellow_minimal_clearance_verifier_circuit PUBLIC
  longfellow_task_crypto bcrypt)

add_library(longfellow_minimal_clearance_proof_artifact STATIC
  src/native_v3_minimal_clearance_proof_artifact.cc
)
target_include_directories(longfellow_minimal_clearance_proof_artifact PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/src"
)
target_compile_definitions(longfellow_minimal_clearance_proof_artifact PUBLIC
  NOMINMAX WIN32_LEAN_AND_MEAN
)

add_executable(longfellow_minimal_clearance_prover
  src/native_v3_minimal_clearance_prover.cpp
)
target_include_directories(longfellow_minimal_clearance_prover PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/src"
  "${CMAKE_CURRENT_SOURCE_DIR}/shim"
  "${LONGFELLOW_SOURCE}/lib"
)
target_compile_definitions(longfellow_minimal_clearance_prover PRIVATE
  NOMINMAX WIN32_LEAN_AND_MEAN
)
target_link_libraries(longfellow_minimal_clearance_prover PRIVATE
  longfellow_minimal_clearance_relation
  longfellow_minimal_clearance_proof_artifact)

add_executable(longfellow_minimal_clearance_verifier
  src/native_v3_minimal_clearance_verifier.cpp
)
target_include_directories(longfellow_minimal_clearance_verifier PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/src"
  "${CMAKE_CURRENT_SOURCE_DIR}/shim"
  "${LONGFELLOW_SOURCE}/lib"
)
target_compile_definitions(longfellow_minimal_clearance_verifier PRIVATE
  NOMINMAX WIN32_LEAN_AND_MEAN
)
target_link_libraries(longfellow_minimal_clearance_verifier PRIVATE
  longfellow_minimal_clearance_verifier_circuit
  longfellow_minimal_clearance_proof_artifact)
if(MSVC)
  target_link_options(longfellow_minimal_clearance_verifier PRIVATE
    "/DEPENDENTLOADFLAG:0x800")
endif()

add_executable(longfellow_minimal_clearance_public_parity
  src/native_v3_minimal_clearance_public_parity.cpp
)
target_include_directories(longfellow_minimal_clearance_public_parity PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/src"
  "${CMAKE_CURRENT_SOURCE_DIR}/shim"
  "${LONGFELLOW_SOURCE}/lib"
)
target_compile_definitions(longfellow_minimal_clearance_public_parity PRIVATE
  NOMINMAX WIN32_LEAN_AND_MEAN
)
target_link_libraries(longfellow_minimal_clearance_public_parity PRIVATE
  longfellow_minimal_clearance_relation)

add_executable(longfellow_minimal_clearance_prover_runner
  src/native_v3_minimal_clearance_prover_runner.cpp
)
target_include_directories(longfellow_minimal_clearance_prover_runner PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/src"
  "${CMAKE_CURRENT_SOURCE_DIR}/shim"
  "${LONGFELLOW_SOURCE}/lib"
)
target_compile_definitions(longfellow_minimal_clearance_prover_runner PRIVATE
  NOMINMAX WIN32_LEAN_AND_MEAN
)
target_link_libraries(longfellow_minimal_clearance_prover_runner PRIVATE
  psapi)

# Fixed compiled-fact reporter. It links only the verifier-side circuit and
# never constructs a fixture, witness, proof, or producer acceptance record.
add_executable(longfellow_minimal_clearance_parameter_reporter
  src/native_v3_minimal_clearance_parameter_reporter.cpp
)
target_include_directories(longfellow_minimal_clearance_parameter_reporter
  PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/src"
  "${CMAKE_CURRENT_SOURCE_DIR}/shim"
  "${LONGFELLOW_SOURCE}/lib"
  "${NATIVE_V3_BUILD_PROVENANCE_GENERATED_DIR}"
)
target_compile_definitions(longfellow_minimal_clearance_parameter_reporter
  PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
target_link_libraries(longfellow_minimal_clearance_parameter_reporter
  PRIVATE longfellow_minimal_clearance_verifier_circuit)
