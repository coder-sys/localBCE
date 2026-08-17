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
