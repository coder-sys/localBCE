cmake_minimum_required(VERSION 3.20)

project(dmc_tag_linear_probe C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# The pinned FAEST checkout is an explicit read-only input.  It is not copied into this
# checkout and is never modified by this standalone module build.
set(FAEST_REF_DIR "" CACHE PATH "Read-only pinned FAEST v3.0.0 checkout")
if (NOT EXISTS "${FAEST_REF_DIR}/fields.c" OR NOT EXISTS "${FAEST_REF_DIR}/universal_hashing.c")
  message(FATAL_ERROR "FAEST_REF_DIR must point to the pinned faest-ref checkout")
endif()

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

add_executable(dmc_tag_linear_probe
  "${CMAKE_CURRENT_LIST_DIR}/../dmc_tag_linear.c"
  "${CMAKE_CURRENT_LIST_DIR}/../dmc_tag_linear_probe.c"
)
target_include_directories(dmc_tag_linear_probe PRIVATE
  "${CMAKE_CURRENT_LIST_DIR}/.."
  "${FAEST_REF_DIR}"
)
target_link_libraries(dmc_tag_linear_probe PRIVATE faest_pinned_primitives)

if (WIN32)
  target_link_libraries(faest_pinned_primitives PUBLIC bcrypt)
endif()

if (MSVC)
  target_compile_options(faest_pinned_primitives PRIVATE /W3)
  target_compile_options(dmc_tag_linear_probe PRIVATE /W4)
else()
  target_compile_options(faest_pinned_primitives PRIVATE -Wall -Wextra -Wpedantic)
  target_compile_options(dmc_tag_linear_probe PRIVATE -Wall -Wextra -Wpedantic)
endif()
