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

set(identity_label "FIXTURE_IMPORTED_LIBRARY_IDENTITY")
if (DEFINED DIRECT_MASK_PERFORMANCE_PIPELINE_BUILD_DIR AND
    NOT "${DIRECT_MASK_PERFORMANCE_PIPELINE_BUILD_DIR}" STREQUAL "")
  if (NOT DEFINED DIRECT_MASK_PERFORMANCE_EXPECTED_ROOT OR
      "${DIRECT_MASK_PERFORMANCE_EXPECTED_ROOT}" STREQUAL "")
    message(FATAL_ERROR "DIRECT_MASK_PERFORMANCE_EXPECTED_ROOT is required")
  endif()
  if (NOT IS_DIRECTORY "${DIRECT_MASK_PERFORMANCE_PIPELINE_BUILD_DIR}")
    message(FATAL_ERROR
      "candidate performance build root is not a directory: ${DIRECT_MASK_PERFORMANCE_PIPELINE_BUILD_DIR}")
  endif()
  get_filename_component(candidate_root
    "${DIRECT_MASK_PERFORMANCE_PIPELINE_BUILD_DIR}" REALPATH)
  get_filename_component(expected_root
    "${DIRECT_MASK_PERFORMANCE_EXPECTED_ROOT}" REALPATH)
  if (NOT candidate_root STREQUAL expected_root)
    message(FATAL_ERROR
      "candidate performance build root mismatch: expected ${expected_root}; "
      "actual ${candidate_root}")
  endif()
  set(PMB_BUILD_DIR "${candidate_root}")
  set(identity_label "FIXTURE_CANDIDATE_LIBRARY_IDENTITY")
  # These identities are the eight Release libraries consumed by the existing
  # direct_mask_fixture_source_performance target from this exact child root.
  set(sizes 3432 8486 18486 18232 270926 141094 33998 333932)
  set(hashes
    01809151898F2E7C9E814A0885D25EA3AF092FA412DAB7ECA0DE1C3DA44BFA94
    C5CD2229B8A92C704E1F290114D09FAC18011C01C50B5D771055E32E20A62755
    3AF9D80DA4EE4C26D2CD464D4488A0CBCC87819971A86CD48A7B7D9D85C167B2
    09735205900E2B2A1F19C02155113D1F60F171869ED537BBF0F58EC425443E6D
    89AC129A25A84870066114EDF61B978D274474BF95FD64AA6890B2691FF4EBE9
    5DD4B6DB42FBDF78F7C0090E975ECC834A74D2E42C5F810E6C5E743C4B2228DE
    13A79E7AA7D44D2EA3F09D37E60D2E601954E1F9B6F8A5BDBBC19C34A3E56CFC
    F023C33E752DE95DC9D04332212D47333792EEF2424377E1B6E047E9F9B76593)
else()
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
endif()

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
  if (identity_label STREQUAL "FIXTURE_CANDIDATE_LIBRARY_IDENTITY")
    message(STATUS
      "FIXTURE_CANDIDATE_LIBRARY index=${index} path=${path} "
      "size=${actual_size} sha256=${actual_hash}")
  endif()
endforeach()

if (identity_label STREQUAL "FIXTURE_CANDIDATE_LIBRARY_IDENTITY")
  message(STATUS
    "${identity_label}=PASS root=${PMB_BUILD_DIR} count=${count}")
else()
  message(STATUS "${identity_label}=PASS count=${count}")
endif()
