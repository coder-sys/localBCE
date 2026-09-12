cmake_minimum_required(VERSION 3.20)

project(blind_ledger_direct_mask_wire C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# The wire checkout deliberately consumes the pinned vendor and the primitive proof engine from
# separately governed, read-only siblings.  Override these paths when reproducing the build from
# another workspace layout.
set(FAEST_REF_DIR
    "${CMAKE_CURRENT_LIST_DIR}/../../../pq-direct-mask-vole-20260907/vendor/faest-ref"
    CACHE PATH "Read-only pinned FAEST reference checkout")
set(DMV_SOURCE_DIR
    "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_vole"
    CACHE PATH "Read-only direct-mask primitive source directory")
set(DMN_SOURCE_DIR
    "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_native"
    CACHE PATH "Immutable accepted native materializer imported into this checkout")
set(DIRECT_MASK_BF256_ACCEL_SOURCE
    "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_vole/direct_mask_bf256_accel.c")

if (NOT EXISTS "${FAEST_REF_DIR}/bavc.c")
  message(FATAL_ERROR "pinned vendor is not initialized at FAEST_REF_DIR")
endif()
if (NOT EXISTS "${DMV_SOURCE_DIR}/direct_mask_vole.c" OR
    NOT EXISTS "${DMV_SOURCE_DIR}/direct_mask_vole.h")
  message(FATAL_ERROR "direct-mask primitive is required at DMV_SOURCE_DIR")
endif()
if (NOT EXISTS "${DMN_SOURCE_DIR}/direct_mask_native.c" OR
    NOT EXISTS "${DMN_SOURCE_DIR}/direct_mask_native.h")
  message(FATAL_ERROR "accepted native materializer is required at DMN_SOURCE_DIR")
endif()
if (NOT EXISTS "${DIRECT_MASK_BF256_ACCEL_SOURCE}")
  message(FATAL_ERROR "child-local bf256 acceleration source is required")
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
  "${FAEST_REF_DIR}/sha3/opt64/KeccakP-1600-opt64.c"
)
target_include_directories(dm_faest_public PUBLIC
  "${DMV_SOURCE_DIR}"
  "${FAEST_REF_DIR}"
  "${FAEST_REF_DIR}/sha3"
  "${FAEST_REF_DIR}/sha3/opt64"
)
# This is the production-shaped target.  In particular, FAEST_TESTS is intentionally absent.
target_compile_definitions(dm_faest_public PRIVATE FAEST_STATIC HAVE_MM_LOADU_SI64)

add_library(direct_mask_wire STATIC
  direct_mask_wire.c
  "${DMV_SOURCE_DIR}/direct_mask_vole.c"
  "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_kernel/direct_mask_kernel.c"
  "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_kernel/direct_mask_algebra.c"
  "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_circuit/dmc_tag_linear.c"
  "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_circuit/dmc_range_constraints.c"
)
target_include_directories(direct_mask_wire PUBLIC
  "${CMAKE_CURRENT_LIST_DIR}"
  "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_kernel"
  "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_circuit"
  "${DMV_SOURCE_DIR}"
  "${FAEST_REF_DIR}"
  "${FAEST_REF_DIR}/sha3"
  "${FAEST_REF_DIR}/sha3/opt64"
)
target_compile_definitions(direct_mask_wire PRIVATE FAEST_STATIC HAVE_MM_LOADU_SI64)
target_link_libraries(direct_mask_wire PUBLIC dm_faest_public)

# The native source materializer is test-only and is not part of direct_mask_wire.
add_library(dm_native_fixture STATIC "${DMN_SOURCE_DIR}/direct_mask_native.c")
target_include_directories(dm_native_fixture PUBLIC
  "${DMN_SOURCE_DIR}"
  "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_circuit"
  "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_kernel"
  "${FAEST_REF_DIR}"
)
target_compile_definitions(dm_native_fixture PRIVATE FAEST_STATIC HAVE_MM_LOADU_SI64)
target_link_libraries(dm_native_fixture PUBLIC dm_faest_public)

add_executable(direct_mask_wire_probe direct_mask_wire_probe.c)
target_include_directories(direct_mask_wire_probe PRIVATE
  "${DMN_SOURCE_DIR}"
  "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_circuit"
)
target_compile_definitions(direct_mask_wire_probe PRIVATE FAEST_STATIC FAEST_TESTS HAVE_MM_LOADU_SI64)
target_link_libraries(direct_mask_wire_probe PRIVATE direct_mask_wire dm_native_fixture)

# The source-bound prover is intentionally test-only: it materializes the private witness from
# the native fixture, then emits only the canonical statement and frame for the process harness.
add_executable(direct_mask_wire_prover direct_mask_wire_prover.c)
target_include_directories(direct_mask_wire_prover PRIVATE
  "${DMN_SOURCE_DIR}"
  "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_circuit"
)
target_compile_definitions(direct_mask_wire_prover PRIVATE FAEST_STATIC HAVE_MM_LOADU_SI64)
target_link_libraries(direct_mask_wire_prover PRIVATE direct_mask_wire dm_native_fixture)

# The verifier is witness-free and deliberately links only the production-shaped wire library.
add_executable(direct_mask_wire_verifier direct_mask_wire_verifier.c)
target_include_directories(direct_mask_wire_verifier PRIVATE
  "${CMAKE_CURRENT_LIST_DIR}"
)
target_compile_definitions(direct_mask_wire_verifier PRIVATE FAEST_STATIC HAVE_MM_LOADU_SI64)
target_link_libraries(direct_mask_wire_verifier PRIVATE direct_mask_wire)

add_executable(direct_mask_driver direct_mask_driver.c)

if (WIN32)
  target_compile_definitions(direct_mask_driver PRIVATE _AMD64_)
  target_link_libraries(dm_faest_public PUBLIC bcrypt)

  add_executable(direct_mask_process_harness direct_mask_process_harness.c)
  target_include_directories(direct_mask_process_harness PRIVATE
    "${CMAKE_CURRENT_LIST_DIR}"
    "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_kernel"
    "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_circuit"
    "${DMV_SOURCE_DIR}"
    "${FAEST_REF_DIR}"
    "${FAEST_REF_DIR}/sha3"
    "${FAEST_REF_DIR}/sha3/opt64"
  )
  target_compile_definitions(direct_mask_process_harness PRIVATE FAEST_STATIC HAVE_MM_LOADU_SI64)
endif()

if (MSVC)
  target_compile_options(dm_faest_public PRIVATE /W3)
  target_compile_options(direct_mask_wire PRIVATE /W4)
  target_compile_options(dm_native_fixture PRIVATE /W4)
  target_compile_options(direct_mask_wire_probe PRIVATE /W4)
  target_compile_options(direct_mask_wire_prover PRIVATE /W4)
  target_compile_options(direct_mask_wire_verifier PRIVATE /W4)
  if (WIN32)
    target_compile_options(direct_mask_process_harness PRIVATE /W4)
  endif()
  target_compile_options(direct_mask_driver PRIVATE /W4)
else()
  target_compile_options(dm_faest_public PRIVATE -Wall -Wextra -Wpedantic)
  target_compile_options(direct_mask_wire PRIVATE -Wall -Wextra -Wpedantic)
  target_compile_options(dm_native_fixture PRIVATE -Wall -Wextra -Wpedantic)
  target_compile_options(direct_mask_wire_probe PRIVATE -Wall -Wextra -Wpedantic)
  target_compile_options(direct_mask_wire_prover PRIVATE -Wall -Wextra -Wpedantic)
  target_compile_options(direct_mask_wire_verifier PRIVATE -Wall -Wextra -Wpedantic)
  if (WIN32)
    target_compile_options(direct_mask_process_harness PRIVATE -Wall -Wextra -Wpedantic)
  endif()
  target_compile_options(direct_mask_driver PRIVATE -Wall -Wextra -Wpedantic)
endif()

enable_testing()
add_test(NAME direct_mask_wire_probe COMMAND direct_mask_wire_probe)
add_test(NAME direct_mask_driver_probe
         COMMAND direct_mask_driver --max-wall-ms 60000
                 $<TARGET_FILE:direct_mask_wire_probe> --child-fixture)
if (WIN32)
  add_test(NAME direct_mask_process_pipeline
           COMMAND direct_mask_process_harness
                   $<TARGET_FILE:direct_mask_wire_prover>
                   $<TARGET_FILE:direct_mask_wire_verifier>)
endif()
