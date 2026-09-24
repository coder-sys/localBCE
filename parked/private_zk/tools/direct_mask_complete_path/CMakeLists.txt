cmake_minimum_required(VERSION 3.24)
project(direct_mask_complete_path NONE)

include(CTest)

if(BUILD_TESTING)
  find_package(Python3 COMPONENTS Interpreter REQUIRED)
  add_test(
    NAME direct_mask_source_boundary_malformed
    COMMAND "${Python3_EXECUTABLE}" -B -m unittest -v parked.private_zk.tests.test_direct_mask_source_boundary
  )
  set_tests_properties(
    direct_mask_source_boundary_malformed
    PROPERTIES
      WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/../../../.."
  )
  add_test(
    NAME direct_mask_complete_path_integration
    COMMAND "${Python3_EXECUTABLE}" -B -m unittest -v parked.private_zk.tests.test_direct_mask_complete_path
  )
  set_tests_properties(
    direct_mask_complete_path_integration
    PROPERTIES
      WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/../../../.."
      ENVIRONMENT "DIRECT_MASK_COMPLETE_BUILD_ROOT=${CMAKE_CURRENT_BINARY_DIR}"
  )
endif()
