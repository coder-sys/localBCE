cmake_minimum_required(VERSION 3.25)
project(longfellow_v09_native_v3 LANGUAGES CXX)

option(LONGFELLOW_NATIVE_V3_NO_SHA3_WITNESS
       "Use the full in-circuit Keccak path without checkpoint witnesses"
       OFF)

set(LONGFELLOW_SOURCE "" CACHE PATH "Patched pinned Longfellow source")
if(NOT EXISTS "${LONGFELLOW_SOURCE}/lib/zk/zk_prover.h")
  message(FATAL_ERROR "LONGFELLOW_SOURCE must name the patched pinned source tree")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(longfellow_task_crypto
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

add_library(longfellow_native_v3_relation STATIC
  src/native_v3_fixture.cc
  src/native_v3_relation.cc
  src/sha3_512_witness.cc
  "${LONGFELLOW_SOURCE}/lib/circuits/tests/sha3/sha3_reference.cc"
  "${LONGFELLOW_SOURCE}/lib/circuits/tests/sha3/sha3_round_constants.cc"
  "${LONGFELLOW_SOURCE}/lib/circuits/tests/sha3/sha3_witness.cc"
)
target_include_directories(longfellow_native_v3_relation PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/src"
  "${CMAKE_CURRENT_SOURCE_DIR}/shim"
  "${LONGFELLOW_SOURCE}/lib"
)
target_compile_definitions(longfellow_native_v3_relation PUBLIC NOMINMAX WIN32_LEAN_AND_MEAN)
if(LONGFELLOW_NATIVE_V3_NO_SHA3_WITNESS)
  target_compile_definitions(longfellow_native_v3_relation
                             PUBLIC BLIND_LEDGER_LONGFELLOW_NO_SHA3_WITNESS=1)
endif()
target_link_libraries(longfellow_native_v3_relation PUBLIC longfellow_task_crypto bcrypt)

add_library(longfellow_native_v3_circuit STATIC
  src/native_v3_relation.cc
  src/sha3_512_witness.cc
  "${LONGFELLOW_SOURCE}/lib/circuits/tests/sha3/sha3_round_constants.cc"
  "${LONGFELLOW_SOURCE}/lib/circuits/tests/sha3/sha3_witness.cc"
)
target_include_directories(longfellow_native_v3_circuit PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/src"
  "${CMAKE_CURRENT_SOURCE_DIR}/shim"
  "${LONGFELLOW_SOURCE}/lib"
)
target_compile_definitions(longfellow_native_v3_circuit PUBLIC
  NOMINMAX WIN32_LEAN_AND_MEAN BLIND_LEDGER_RELATION_CIRCUIT_ONLY
)
if(LONGFELLOW_NATIVE_V3_NO_SHA3_WITNESS)
  target_compile_definitions(longfellow_native_v3_circuit
                             PUBLIC BLIND_LEDGER_LONGFELLOW_NO_SHA3_WITNESS=1)
endif()
target_link_libraries(longfellow_native_v3_circuit PUBLIC longfellow_task_crypto bcrypt)

add_executable(longfellow_native_v3_relation_shape
  src/native_v3_relation_shape.cpp
)
target_include_directories(longfellow_native_v3_relation_shape PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/src"
  "${CMAKE_CURRENT_SOURCE_DIR}/shim"
  "${LONGFELLOW_SOURCE}/lib"
)
target_compile_definitions(longfellow_native_v3_relation_shape PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
target_link_libraries(longfellow_native_v3_relation_shape PRIVATE longfellow_native_v3_relation)

add_executable(longfellow_native_v3_relation_attribution
  src/native_v3_relation_attribution.cpp
)
target_include_directories(longfellow_native_v3_relation_attribution PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/src"
  "${CMAKE_CURRENT_SOURCE_DIR}/shim"
  "${LONGFELLOW_SOURCE}/lib"
)
target_compile_definitions(longfellow_native_v3_relation_attribution PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
target_link_libraries(longfellow_native_v3_relation_attribution PRIVATE longfellow_native_v3_relation psapi)

add_executable(longfellow_native_v3_relation_eval
  src/native_v3_relation_eval.cpp
)
target_include_directories(longfellow_native_v3_relation_eval PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/src"
  "${CMAKE_CURRENT_SOURCE_DIR}/shim"
  "${LONGFELLOW_SOURCE}/lib"
)
target_compile_definitions(longfellow_native_v3_relation_eval PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
target_link_libraries(longfellow_native_v3_relation_eval PRIVATE longfellow_native_v3_relation)

add_executable(longfellow_native_v3_prover
  src/native_v3_prover.cpp
  src/native_v3_artifact.cc
)
target_include_directories(longfellow_native_v3_prover PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/src"
  "${CMAKE_CURRENT_SOURCE_DIR}/shim"
  "${LONGFELLOW_SOURCE}/lib"
)
target_compile_definitions(longfellow_native_v3_prover PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
target_link_libraries(longfellow_native_v3_prover PRIVATE longfellow_native_v3_relation)

add_executable(longfellow_native_v3_verifier
  src/native_v3_verifier.cpp
  src/native_v3_artifact.cc
)
target_include_directories(longfellow_native_v3_verifier PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/src"
  "${CMAKE_CURRENT_SOURCE_DIR}/shim"
  "${LONGFELLOW_SOURCE}/lib"
)
target_compile_definitions(longfellow_native_v3_verifier PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
target_link_libraries(longfellow_native_v3_verifier PRIVATE longfellow_native_v3_circuit)

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

# Fresh shape-only architecture experiment. This is one monolithic relation;
# it does not claim multi-component transcript linkage and does not link or
# call the legacy 18-endpoint native_v3_relation builder.
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
