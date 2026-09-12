cmake_minimum_required(VERSION 3.20)
project(direct_mask_kernel C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(FAEST_REF_DIR "" CACHE PATH "Read-only FAEST ebefcbd8 input")
set(NATIVE_ORACLE_DIR "" CACHE PATH "Read-only native oracle 7b1e79d input")
set(DIRECT_MASK_BF256_ACCEL_SOURCE
    "${CMAKE_CURRENT_LIST_DIR}/../direct_mask_vole/direct_mask_bf256_accel.c")
if(NOT EXISTS "${FAEST_REF_DIR}/fields.c" OR
   NOT EXISTS "${NATIVE_ORACLE_DIR}/direct_mask_circuit.c" OR
   NOT EXISTS "${DIRECT_MASK_BF256_ACCEL_SOURCE}")
  message(FATAL_ERROR "Explicit pinned primitive and native oracle inputs required")
endif()
set_source_files_properties(
  "${FAEST_REF_DIR}/fields.c"
  PROPERTIES
    COMPILE_DEFINITIONS
      "bf256_mul=direct_mask_bf256_mul_portable;bf256_mul_inplace=direct_mask_bf256_mul_inplace_portable")
set_source_files_properties(
  "${DIRECT_MASK_BF256_ACCEL_SOURCE}"
  PROPERTIES
    COMPILE_DEFINITIONS "DIRECT_MASK_BF256_TEST_SEAM")
add_library(faest_primitives STATIC
  "${FAEST_REF_DIR}/aes.c" "${FAEST_REF_DIR}/compat.c" "${FAEST_REF_DIR}/cpu.c"
  "${FAEST_REF_DIR}/fields.c" "${DIRECT_MASK_BF256_ACCEL_SOURCE}"
  "${FAEST_REF_DIR}/utils.c")
target_include_directories(faest_primitives PUBLIC "${FAEST_REF_DIR}")
target_compile_definitions(faest_primitives PRIVATE FAEST_STATIC FAEST_TESTS HAVE_MM_LOADU_SI64)
if(WIN32)
  target_link_libraries(faest_primitives PUBLIC bcrypt)
endif()
add_library(direct_mask_kernel STATIC direct_mask_kernel.c
  ../direct_mask_circuit/dmc_tag_linear.c ../direct_mask_circuit/dmc_range_constraints.c)
target_include_directories(direct_mask_kernel PUBLIC "${CMAKE_CURRENT_LIST_DIR}")
target_link_libraries(direct_mask_kernel PUBLIC faest_primitives)
# The old donor relation/export API is never linked into the arithmetic library.
# Only the probe consumes its independent native AES witness and source oracle.
add_executable(direct_mask_kernel_probe direct_mask_kernel_probe.c
  "${NATIVE_ORACLE_DIR}/direct_mask_circuit.c")
target_include_directories(direct_mask_kernel_probe PRIVATE "${NATIVE_ORACLE_DIR}")
target_compile_definitions(direct_mask_kernel_probe PRIVATE
  FAEST_TESTS DIRECT_MASK_BF256_TEST_SEAM)
target_link_libraries(direct_mask_kernel_probe PRIVATE direct_mask_kernel)
if(MSVC)
  target_compile_options(direct_mask_kernel PRIVATE /W4)
  target_compile_options(direct_mask_kernel_probe PRIVATE /W4)
else()
  target_compile_options(direct_mask_kernel PRIVATE -Wall -Wextra -Wpedantic)
  target_compile_options(direct_mask_kernel_probe PRIVATE -Wall -Wextra -Wpedantic)
endif()
enable_testing()
add_test(NAME direct_mask_kernel_full_field COMMAND direct_mask_kernel_probe)
