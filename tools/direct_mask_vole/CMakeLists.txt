cmake_minimum_required(VERSION 3.20)

project(direct_mask_vole_probe C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(FAEST_REF_DIR
    "${CMAKE_CURRENT_LIST_DIR}/../../../pq-direct-mask-vole-20260907/vendor/faest-ref")
if (NOT EXISTS "${FAEST_REF_DIR}/bavc.c")
  message(FATAL_ERROR "vendor/faest-ref is not initialized at the pinned checkout")
endif()

set(DMC_SOURCE_DIR
    "${CMAKE_CURRENT_LIST_DIR}/../../../pq-aes-circuit-export-20260907/tools/direct_mask_circuit"
    CACHE PATH "Read-only source-bound native fixture directory for the focused probe")
if (NOT EXISTS "${DMC_SOURCE_DIR}/direct_mask_circuit.c" OR
    NOT EXISTS "${DMC_SOURCE_DIR}/direct_mask_circuit.h")
  message(FATAL_ERROR "source-bound native fixture is required for the focused proof probe")
endif()

set(DIRECT_MASK_BF256_ACCEL_SOURCE
    "${CMAKE_CURRENT_LIST_DIR}/direct_mask_bf256_accel.c")
if (NOT EXISTS "${DIRECT_MASK_BF256_ACCEL_SOURCE}")
  message(FATAL_ERROR "child-local bf256 acceleration source is required")
endif()

set_source_files_properties(
  "${FAEST_REF_DIR}/fields.c"
  PROPERTIES
    COMPILE_DEFINITIONS
      "bf256_mul=direct_mask_bf256_mul_portable;bf256_mul_inplace=direct_mask_bf256_mul_inplace_portable")

add_library(faest_direct_mask_primitives STATIC
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
target_include_directories(faest_direct_mask_primitives PUBLIC
  "${CMAKE_CURRENT_LIST_DIR}"
  "${FAEST_REF_DIR}"
  "${FAEST_REF_DIR}/sha3"
  "${FAEST_REF_DIR}/sha3/opt64"
)
target_compile_definitions(faest_direct_mask_primitives PRIVATE FAEST_STATIC FAEST_TESTS HAVE_MM_LOADU_SI64)

add_executable(direct_mask_vole_probe
  direct_mask_vole.c
  direct_mask_vole_probe.c
  "${DMC_SOURCE_DIR}/direct_mask_circuit.c"
  ../direct_mask_kernel/direct_mask_kernel.c
  ../direct_mask_kernel/direct_mask_algebra.c
  ../direct_mask_circuit/dmc_tag_linear.c
  ../direct_mask_circuit/dmc_range_constraints.c
)
target_include_directories(direct_mask_vole_probe PRIVATE
  "${CMAKE_CURRENT_LIST_DIR}"
  "${DMC_SOURCE_DIR}"
  "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_kernel"
  "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_circuit"
  "${FAEST_REF_DIR}"
  "${FAEST_REF_DIR}/sha3"
  "${FAEST_REF_DIR}/sha3/opt64"
)
target_compile_definitions(direct_mask_vole_probe PRIVATE FAEST_STATIC FAEST_TESTS HAVE_MM_LOADU_SI64)
target_link_libraries(direct_mask_vole_probe PRIVATE faest_direct_mask_primitives)

if (WIN32)
  target_link_libraries(faest_direct_mask_primitives PUBLIC bcrypt)
endif()

if (MSVC)
  target_compile_options(faest_direct_mask_primitives PRIVATE /W3)
  target_compile_options(direct_mask_vole_probe PRIVATE /W4)
else()
  target_compile_options(faest_direct_mask_primitives PRIVATE -Wall -Wextra -Wpedantic)
  target_compile_options(direct_mask_vole_probe PRIVATE -Wall -Wextra -Wpedantic)
endif()
