if (NOT DEFINED PMB_BUILD_DIR)
  message(FATAL_ERROR "PMB_BUILD_DIR is required")
endif()

set(paths
  "Release/dm_pipeline_source.lib"
  "Release/dm_pipeline_codec.lib"
  "dm_source_proof_build/Release/dm_source_proof.lib"
  "dm_source_proof_build/dm_authenticated_proof_build/dm_source_auth_build/Release/dm_source_auth.lib"
  "dm_source_proof_build/dm_authenticated_proof_build/dm_source_auth_build/Release/dm_wire_codec.lib"
  "dm_source_proof_build/dm_authenticated_proof_build/dm_source_auth_build/Release/mldsa_source_auth_wrapper.lib"
  "dm_source_proof_build/Release/dm_native_fixture_source_proof.lib"
  "dm_source_proof_build/dm_authenticated_proof_build/dm_source_auth_build/Release/dm_faest_public.lib")
set(sizes 3464 8518 18518 18264 271118 141158 34030 326608)
set(hashes
  B2267C377E9AFF052CD4B0133B59F6A31492F00A8A3214CAB8D7C65599698D95
  2117630F0E761687311B21C2C2B3F564DC29CE759C2EDC24D4252CD3351033E0
  E9932EA2D096F8A5CE15F5C25A56FA32112A9DF33486F5B8FCF117FD84C5B64E
  150374B3A5BB86D22BCC60833F62610ECF131EEF39EF9FAED3FA6C6E72E3A40C
  69209247032243C3B3C6D47C48968B084DB2710750D601B983086EFAC65BE73A
  E386DF41A59AC8A42E8DDC757E619D4DA0A6A589F5694824424AE6D9CFD76A0D
  E572607187E27B97828BB8CB7DC4DBBEE2AA753061F1647D22C8F88DD00DADAD
  D36ED7515AC70AE8FFED4A26C515EFB2300FB329377219B1033B4E3A10C9AB9A)

list(LENGTH paths count)
math(EXPR last "${count} - 1")
foreach(index RANGE ${last})
  list(GET paths ${index} relative_path)
  list(GET sizes ${index} expected_size)
  list(GET hashes ${index} expected_hash)
  set(path "${PMB_BUILD_DIR}/${relative_path}")
  if (NOT EXISTS "${path}")
    message(FATAL_ERROR "missing pinned library: ${path}")
  endif()
  file(SIZE "${path}" actual_size)
  file(SHA256 "${path}" actual_hash)
  string(TOUPPER "${actual_hash}" actual_hash)
  if (NOT actual_size EQUAL expected_size OR
      NOT actual_hash STREQUAL expected_hash)
    message(FATAL_ERROR
      "pinned library identity mismatch: ${path}; "
      "expected ${expected_size}/${expected_hash}, "
      "actual ${actual_size}/${actual_hash}")
  endif()
endforeach()

message(STATUS "FIXTURE_IMPORTED_LIBRARY_IDENTITY=PASS count=${count}")
