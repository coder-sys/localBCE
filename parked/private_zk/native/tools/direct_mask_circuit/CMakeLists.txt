cmake_minimum_required(VERSION 3.20)

project(direct_mask_circuit_probe C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# This target is deliberately separate from every Rust and production target.  It consumes the
# pinned FAEST v3.0.0 submodule only as a read-only primitive fixture.
set(FAEST_REF_DIR "${CMAKE_CURRENT_LIST_DIR}/../../vendor/faest-ref")

add_library(faest_pinned_primitives STATIC
  "${FAEST_REF_DIR}/aes.c"
  "${FAEST_REF_DIR}/compat.c"
  "${FAEST_REF_DIR}/cpu.c"
  "${FAEST_REF_DIR}/fields.c"
  "${FAEST_REF_DIR}/universal_hashing.c"
  "${FAEST_REF_DIR}/utils.c"
)
target_include_directories(faest_pinned_primitives PUBLIC "${FAEST_REF_DIR}")
target_compile_definitions(faest_pinned_primitives PRIVATE FAEST_STATIC FAEST_TESTS HAVE_MM_LOADU_SI64)

if (WIN32)
  target_link_libraries(faest_pinned_primitives PUBLIC bcrypt)
endif()

add_executable(direct_mask_circuit_probe
  direct_mask_circuit.c
  direct_mask_circuit_probe.c
)
target_include_directories(direct_mask_circuit_probe PRIVATE "${CMAKE_CURRENT_LIST_DIR}")
target_compile_definitions(direct_mask_circuit_probe PRIVATE FAEST_TESTS)
target_link_libraries(direct_mask_circuit_probe PRIVATE faest_pinned_primitives)

if (MSVC)
  target_compile_options(faest_pinned_primitives PRIVATE /W3)
  target_compile_options(direct_mask_circuit_probe PRIVATE /W4)
else()
  target_compile_options(faest_pinned_primitives PRIVATE -Wall -Wextra -Wpedantic)
  target_compile_options(direct_mask_circuit_probe PRIVATE -Wall -Wextra -Wpedantic)
endif()
