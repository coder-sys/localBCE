# Real symbol and link-input closure gate for the quiet source/verifier boundary.
# The verifier closure deliberately permits the shared source-auth signer.  It
# rejects a producer/native materializer edge and fails closed when the actual
# generated Release link evidence is absent, malformed, or incomplete.

set(DM_PIPELINE_SYSTEM_DIRECT_NAMES
    bcrypt.lib kernel32.lib user32.lib gdi32.lib winspool.lib shell32.lib
    ole32.lib oleaut32.lib uuid.lib comdlg32.lib advapi32.lib)

set(DM_PIPELINE_FORBIDDEN_SYMBOL_REGEX
    "dm_source_proof_generate|dmn_extend|dm_native_fixture_source_proof|direct_mask_native|dm_pipeline_source_process")

if (NOT DEFINED REAL_PIPELINE_XML_HELPER OR
    "${REAL_PIPELINE_XML_HELPER}" STREQUAL "")
  set(REAL_PIPELINE_XML_HELPER
      "${CMAKE_CURRENT_LIST_DIR}/verify_real_symbols_xml.py")
endif()

foreach(required_var IN ITEMS REAL_PIPELINE_CODEC_LIBRARY
                             REAL_PIPELINE_SOURCE_LIBRARY
                             REAL_PIPELINE_VERIFIER_LIBRARY
                             REAL_SOURCE_PROOF_LIBRARY
                             REAL_AUTHENTICATED_LIBRARY
                             REAL_SOURCE_EXECUTABLE
                             REAL_VERIFIER_EXECUTABLE
                             REAL_SOURCE_LINK_PROJECT
                             REAL_VERIFIER_LINK_PROJECT
                             REAL_PIPELINE_XML_HELPER
                             REAL_FORBIDDEN_EDGE_FIXTURE
                             REAL_FORBIDDEN_DIRECT_EDGE_FIXTURE
                             REAL_MISSING_EVIDENCE_FIXTURE
                             REAL_PIPELINE_HEADER
                             REAL_PIPELINE_CODEC_SOURCE
                             REAL_PIPELINE_SOURCE_SOURCE
                             REAL_PIPELINE_VERIFIER_SOURCE
                             REAL_SOURCE_MAIN
                             REAL_VERIFIER_MAIN)
  if (NOT DEFINED ${required_var} OR "${${required_var}}" STREQUAL "")
    message(FATAL_ERROR "missing required gate input ${required_var}")
  endif()
endforeach()

foreach(path IN ITEMS REAL_PIPELINE_CODEC_LIBRARY REAL_PIPELINE_SOURCE_LIBRARY
                      REAL_PIPELINE_VERIFIER_LIBRARY REAL_SOURCE_PROOF_LIBRARY
                      REAL_AUTHENTICATED_LIBRARY REAL_SOURCE_EXECUTABLE
                      REAL_VERIFIER_EXECUTABLE REAL_SOURCE_LINK_PROJECT
                      REAL_VERIFIER_LINK_PROJECT REAL_PIPELINE_XML_HELPER
                      REAL_FORBIDDEN_EDGE_FIXTURE
                      REAL_FORBIDDEN_DIRECT_EDGE_FIXTURE REAL_PIPELINE_HEADER
                      REAL_PIPELINE_CODEC_SOURCE REAL_PIPELINE_SOURCE_SOURCE
                      REAL_PIPELINE_VERIFIER_SOURCE REAL_SOURCE_MAIN
                      REAL_VERIFIER_MAIN)
  if (NOT EXISTS "${${path}}" OR IS_DIRECTORY "${${path}}")
    message(FATAL_ERROR "missing or non-file pipeline gate input ${${path}}")
  endif()
endforeach()

if (EXISTS "${REAL_MISSING_EVIDENCE_FIXTURE}")
  message(FATAL_ERROR
          "the controlled missing-evidence fixture unexpectedly exists: ${REAL_MISSING_EVIDENCE_FIXTURE}")
endif()

if (WIN32)
  file(GLOB DM_PIPELINE_DUMPBIN_CANDIDATES
    "C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/VC/Tools/MSVC/*/bin/Hostx64/x64/dumpbin.exe"
    "C:/Program Files/Microsoft Visual Studio/2022/BuildTools/VC/Tools/MSVC/*/bin/Hostx64/x64/dumpbin.exe")
  if (DM_PIPELINE_DUMPBIN_CANDIDATES)
    list(GET DM_PIPELINE_DUMPBIN_CANDIDATES 0 DM_PIPELINE_DUMPBIN)
  endif()
  if (NOT DM_PIPELINE_DUMPBIN)
    find_program(DM_PIPELINE_DUMPBIN NAMES dumpbin dumpbin.exe)
  endif()
  if (NOT DM_PIPELINE_DUMPBIN)
    message(FATAL_ERROR "dumpbin is required for the Windows pipeline gate")
  endif()
else()
  find_program(DM_PIPELINE_NM NAMES nm llvm-nm)
  if (NOT DM_PIPELINE_NM)
    message(FATAL_ERROR "nm is required for the pipeline gate")
  endif()
endif()

find_package(Python3 COMPONENTS Interpreter QUIET)
if (NOT Python3_Interpreter_FOUND)
  message(FATAL_ERROR "Python 3 is required for bounded XML project evidence")
endif()

function(read_symbols input_path output_variable)
  if (WIN32)
    execute_process(
      COMMAND "${DM_PIPELINE_DUMPBIN}" /symbols "${input_path}"
      RESULT_VARIABLE symbol_result
      OUTPUT_VARIABLE symbol_output
      ERROR_VARIABLE symbol_error)
  else()
    execute_process(
      COMMAND "${DM_PIPELINE_NM}" -g "${input_path}"
      RESULT_VARIABLE symbol_result
      OUTPUT_VARIABLE symbol_output
      ERROR_VARIABLE symbol_error)
  endif()
  if (NOT symbol_result EQUAL 0)
    message(FATAL_ERROR "symbol inspection failed for ${input_path}: ${symbol_error}")
  endif()
  set(${output_variable} "${symbol_output}" PARENT_SCOPE)
endfunction()

function(require_defined_symbol symbol_text symbol label)
  if (WIN32)
    string(REGEX MATCH "SECT[0-9A-F]+[^\n]*External[^\n]*\\|[ \t]*${symbol}([ \t\r\n]|$)"
           hit "${symbol_text}")
  else()
    string(REGEX MATCH "(^|[\r\n])[^\n]*[ \t][TDBRCSVW][ \t]+${symbol}([ \t\r\n]|$)"
           hit "${symbol_text}")
  endif()
  if ("${hit}" STREQUAL "")
    message(FATAL_ERROR "${label} missing required defined symbol ${symbol}")
  endif()
endfunction()

function(forbid_symbol symbol_text pattern label)
  if ("${symbol_text}" MATCHES "${pattern}")
    message(FATAL_ERROR "${label} contains forbidden symbol/text ${pattern}")
  endif()
endfunction()

function(input_closure_failure reason)
  get_property(existing GLOBAL PROPERTY DM_PIPELINE_INPUT_FAILURE)
  if ("${existing}" STREQUAL "")
    set_property(GLOBAL PROPERTY DM_PIPELINE_INPUT_FAILURE "${reason}")
  endif()
endfunction()

function(normalize_link_path raw_path base_directory output_variable)
  string(STRIP "${raw_path}" value)
  string(REGEX REPLACE "^\"|\"$" "" value "${value}")
  string(REPLACE "\\" "/" value "${value}")
  if (value MATCHES "^[A-Za-z]:/" OR value MATCHES "^/")
    set(candidate "${value}")
  else()
    get_filename_component(candidate "${value}" ABSOLUTE
                           BASE_DIR "${base_directory}")
  endif()
  file(TO_CMAKE_PATH "${candidate}" candidate)
  string(TOLOWER "${candidate}" candidate)
  set(${output_variable} "${candidate}" PARENT_SCOPE)
endfunction()

function(is_system_link_path input_path output_variable)
  string(TOLOWER "${input_path}" lower_path)
  if (lower_path MATCHES "^[a-z]:/program files \\(x86\\)/windows kits/" OR
      lower_path MATCHES "^[a-z]:/program files \\(x86\\)/microsoft visual studio/" OR
      lower_path MATCHES "^[a-z]:/program files/microsoft visual studio/" OR
      lower_path MATCHES "^[a-z]:/windows/")
    set(result TRUE)
  else()
    set(result FALSE)
  endif()
  set(${output_variable} "${result}" PARENT_SCOPE)
endfunction()

function(is_system_direct_name input_name output_variable)
  string(TOLOWER "${input_name}" lower_name)
  list(FIND DM_PIPELINE_SYSTEM_DIRECT_NAMES "${lower_name}" name_index)
  if (name_index EQUAL -1)
    set(result FALSE)
  else()
    set(result TRUE)
  endif()
  set(${output_variable} "${result}" PARENT_SCOPE)
endfunction()

function(read_xml_project_evidence project_path mode references_variable
                                     reference_names_variable project_names_variable
                                     dependencies_variable int_dir_variable
                                     ok_variable reason_variable)
  set(local_references "")
  set(local_reference_names "")
  set(local_project_names "")
  set(local_dependencies "")
  set(local_int_dir "")
  set(local_ok FALSE)
  set(local_reason "")
  if (NOT mode STREQUAL "--references" AND NOT mode STREQUAL "--release")
    set(local_reason "unsupported XML evidence mode ${mode}")
  else()
    execute_process(
      COMMAND "${Python3_EXECUTABLE}" "${REAL_PIPELINE_XML_HELPER}"
              "${project_path}" "${mode}"
      RESULT_VARIABLE parser_result
      OUTPUT_VARIABLE parser_output
      ERROR_VARIABLE parser_error)
    string(STRIP "${parser_output}" parser_output)
    string(STRIP "${parser_error}" parser_error)
    if (NOT parser_result EQUAL 0)
      set(local_reason
          "XML project evidence rejected ${project_path}: ${parser_error}")
    elseif("${parser_output}" STREQUAL "")
      set(local_reason "XML project evidence parser returned no result for ${project_path}")
    else()
      set(json_error "")
      string(JSON json_type ERROR_VARIABLE json_error TYPE "${parser_output}")
      if ((NOT "${json_error}" STREQUAL "" AND
           NOT "${json_error}" STREQUAL "NOTFOUND") OR
          NOT "${json_type}" STREQUAL "OBJECT")
        set(local_reason
            "XML project evidence parser returned malformed JSON for ${project_path}: ${json_error}")
      endif()
      if ("${local_reason}" STREQUAL "")
        foreach(array_name IN ITEMS references reference_names project_names)
          set(json_error "")
          string(JSON array_type ERROR_VARIABLE json_error TYPE "${parser_output}"
                 ${array_name})
          if ((NOT "${json_error}" STREQUAL "" AND
               NOT "${json_error}" STREQUAL "NOTFOUND") OR
              NOT "${array_type}" STREQUAL "ARRAY")
            set(local_reason
                "XML project evidence field ${array_name} is not an array for ${project_path}: ${json_error}")
            break()
          endif()
          set(json_error "")
          string(JSON array_count ERROR_VARIABLE json_error LENGTH "${parser_output}"
                 ${array_name})
          if (NOT "${json_error}" STREQUAL "" AND
              NOT "${json_error}" STREQUAL "NOTFOUND")
            set(local_reason
                "XML project evidence field ${array_name} has no bounded length for ${project_path}: ${json_error}")
            break()
          endif()
          if (array_count GREATER 0)
            math(EXPR last_array_index "${array_count} - 1")
            foreach(array_index RANGE 0 ${last_array_index})
              set(json_error "")
              string(JSON array_value ERROR_VARIABLE json_error GET
                     "${parser_output}" ${array_name} ${array_index})
              if (NOT "${json_error}" STREQUAL "" AND
                  NOT "${json_error}" STREQUAL "NOTFOUND")
                set(local_reason
                    "XML project evidence field ${array_name} contains an unreadable value for ${project_path}: ${json_error}")
                break()
              endif()
              if (array_name STREQUAL "references")
                list(APPEND local_references "${array_value}")
              elseif(array_name STREQUAL "reference_names")
                list(APPEND local_reference_names "${array_value}")
              else()
                list(APPEND local_project_names "${array_value}")
              endif()
            endforeach()
          endif()
          if (NOT "${local_reason}" STREQUAL "")
            break()
          endif()
        endforeach()
      endif()
      if ("${local_reason}" STREQUAL "" AND mode STREQUAL "--release")
        foreach(required_field IN ITEMS release_dependencies release_int_dir)
          set(json_error "")
          string(JSON field_type ERROR_VARIABLE json_error TYPE "${parser_output}"
                 ${required_field})
          if ((NOT "${json_error}" STREQUAL "" AND
               NOT "${json_error}" STREQUAL "NOTFOUND") OR
              NOT "${field_type}" STREQUAL "STRING")
            set(local_reason
                "XML project evidence field ${required_field} is not a string for ${project_path}: ${json_error}")
            break()
          endif()
          set(json_error "")
          string(JSON field_value ERROR_VARIABLE json_error GET "${parser_output}"
                 ${required_field})
          if (NOT "${json_error}" STREQUAL "" AND
              NOT "${json_error}" STREQUAL "NOTFOUND")
            set(local_reason
                "XML project evidence field ${required_field} is unreadable for ${project_path}: ${json_error}")
            break()
          endif()
          if (required_field STREQUAL "release_dependencies")
            set(local_dependencies "${field_value}")
          else()
            set(local_int_dir "${field_value}")
          endif()
        endforeach()
      endif()
      if ("${local_reason}" STREQUAL "")
        set(local_ok TRUE)
      endif()
    endif()
  endif()
  set(${references_variable} "${local_references}" PARENT_SCOPE)
  set(${reference_names_variable} "${local_reference_names}" PARENT_SCOPE)
  set(${project_names_variable} "${local_project_names}" PARENT_SCOPE)
  set(${dependencies_variable} "${local_dependencies}" PARENT_SCOPE)
  set(${int_dir_variable} "${local_int_dir}" PARENT_SCOPE)
  set(${ok_variable} "${local_ok}" PARENT_SCOPE)
  set(${reason_variable} "${local_reason}" PARENT_SCOPE)
endfunction()

function(inspect_non_system_input input_path label symbols_variable directives_variable
                                  ok_variable reason_variable)
  set(local_ok FALSE)
  set(local_reason "")
  if (NOT EXISTS "${input_path}" OR IS_DIRECTORY "${input_path}")
    set(local_reason "${label}: missing or non-file input ${input_path}")
  elseif(WIN32)
    execute_process(
      COMMAND "${DM_PIPELINE_DUMPBIN}" /headers "${input_path}"
      RESULT_VARIABLE header_result
      OUTPUT_VARIABLE header_output
      ERROR_VARIABLE header_error)
    if (NOT header_result EQUAL 0 OR "${header_output}" STREQUAL "")
      set(local_reason
          "${label}: uninspectable headers ${input_path}: ${header_error}")
    else()
      execute_process(
        COMMAND "${DM_PIPELINE_DUMPBIN}" /symbols "${input_path}"
        RESULT_VARIABLE symbol_result
        OUTPUT_VARIABLE symbol_output
        ERROR_VARIABLE symbol_error)
      if (NOT symbol_result EQUAL 0 OR "${symbol_output}" STREQUAL "")
        set(local_reason
            "${label}: uninspectable symbols ${input_path}: ${symbol_error}")
      else()
        execute_process(
          COMMAND "${DM_PIPELINE_DUMPBIN}" /directives "${input_path}"
          RESULT_VARIABLE directive_result
          OUTPUT_VARIABLE directive_output
          ERROR_VARIABLE directive_error)
        if (NOT directive_result EQUAL 0)
          set(local_reason
              "${label}: uninspectable directives ${input_path}: ${directive_error}")
        else()
          string(TOUPPER "${directive_output}" directive_upper)
          foreach(forbidden IN ITEMS "/WHOLEARCHIVE" "/INCLUDE:"
                                      "/LIBPATH:" "/DELAYLOAD:" "/ENTRY:"
                                      "/EXPORT:"
                                      "-WHOLEARCHIVE" "-INCLUDE:" "-LIBPATH:"
                                      "-DELAYLOAD:" "-ENTRY:" "-EXPORT:")
            if (directive_upper MATCHES "${forbidden}")
              set(local_reason
                  "${label}: forbidden link directive ${forbidden} in ${input_path}")
              break()
            endif()
          endforeach()
          if ("${local_reason}" STREQUAL "")
            set(local_ok TRUE)
            set(${symbols_variable} "${symbol_output}" PARENT_SCOPE)
            set(${directives_variable} "${directive_output}" PARENT_SCOPE)
          endif()
        endif()
      endif()
    endif()
  else()
    execute_process(
      COMMAND "${DM_PIPELINE_NM}" -g "${input_path}"
      RESULT_VARIABLE symbol_result
      OUTPUT_VARIABLE symbol_output
      ERROR_VARIABLE symbol_error)
    if (NOT symbol_result EQUAL 0 OR "${symbol_output}" STREQUAL "")
      set(local_reason
          "${label}: uninspectable symbols ${input_path}: ${symbol_error}")
    else()
      set(local_ok TRUE)
      set(${symbols_variable} "${symbol_output}" PARENT_SCOPE)
      set(${directives_variable} "" PARENT_SCOPE)
    endif()
  endif()
  set(${ok_variable} "${local_ok}" PARENT_SCOPE)
  set(${reason_variable} "${local_reason}" PARENT_SCOPE)
endfunction()

function(extract_release_dependencies project_path deps_variable node_variable
                                      text_variable int_dir_variable ok_variable
                                      reason_variable)
  set(local_ok FALSE)
  set(local_reason "")
  set(local_deps "")
  set(local_node "")
  set(local_text "")
  set(local_int_dir "")
  read_xml_project_evidence("${project_path}" "--release" ignored_references
                            ignored_reference_names ignored_project_names
                            local_text local_int_dir xml_ok xml_reason)
  if (NOT xml_ok)
    set(local_reason "${xml_reason}")
  else()
    set(local_node "<AdditionalDependencies>${local_text}</AdditionalDependencies>")
    set(local_deps "${local_text}")
    list(LENGTH local_deps dependency_count)
    if (dependency_count EQUAL 0)
      set(local_reason "Release AdditionalDependencies is empty")
    else()
      set(macro_count 0)
      foreach(dependency IN LISTS local_deps)
        string(STRIP "${dependency}" dependency)
        if ("${dependency}" STREQUAL "")
          set(local_reason "Release AdditionalDependencies contains an empty token")
          break()
        endif()
        if ("${dependency}" STREQUAL "%(AdditionalDependencies)")
          math(EXPR macro_count "${macro_count} + 1")
        endif()
      endforeach()
      math(EXPR last_index "${dependency_count} - 1")
      list(GET local_deps ${last_index} last_dependency)
      if (macro_count GREATER 1 OR
          (macro_count EQUAL 1 AND
           NOT "${last_dependency}" STREQUAL "%(AdditionalDependencies)"))
        set(local_reason
            "Release AdditionalDependencies contains a misplaced or repeated %(AdditionalDependencies) macro")
      elseif("${local_reason}" STREQUAL "")
        set(local_ok TRUE)
      endif()
    endif()
  endif()
  set(${deps_variable} "${local_deps}" PARENT_SCOPE)
  set(${node_variable} "${local_node}" PARENT_SCOPE)
  set(${text_variable} "${local_text}" PARENT_SCOPE)
  set(${int_dir_variable} "${local_int_dir}" PARENT_SCOPE)
  set(${ok_variable} "${local_ok}" PARENT_SCOPE)
  set(${reason_variable} "${local_reason}" PARENT_SCOPE)
endfunction()

function(read_tlog_text tlog_path text_variable ok_variable reason_variable)
  set(local_ok FALSE)
  set(local_reason "")
  set(local_text "")
  if (NOT EXISTS "${tlog_path}" OR IS_DIRECTORY "${tlog_path}")
    set(local_reason "missing or non-file tlog ${tlog_path}")
  elseif(WIN32)
    file(STRINGS "${tlog_path}" tlog_lines ENCODING UTF-16LE)
    list(LENGTH tlog_lines line_count)
    if (line_count EQUAL 0)
      set(local_reason "empty UTF-16LE tlog ${tlog_path}")
    else()
      string(REPLACE ";" "\n" local_text "${tlog_lines}")
      set(local_ok TRUE)
    endif()
  else()
    file(READ "${tlog_path}" local_text)
    if ("${local_text}" STREQUAL "")
      set(local_reason "empty tlog ${tlog_path}")
    else()
      set(local_ok TRUE)
    endif()
  endif()
  set(${text_variable} "${local_text}" PARENT_SCOPE)
  set(${ok_variable} "${local_ok}" PARENT_SCOPE)
  set(${reason_variable} "${local_reason}" PARENT_SCOPE)
endfunction()

function(read_link_input_tlog read_path inputs_variable ok_variable reason_variable)
  set(local_ok FALSE)
  set(local_reason "")
  set(local_inputs "")
  if (NOT EXISTS "${read_path}" OR IS_DIRECTORY "${read_path}")
    set(local_reason "missing or non-file link.read evidence ${read_path}")
  else()
    read_tlog_text("${read_path}" read_text tlog_ok tlog_reason)
    if (NOT tlog_ok)
      set(local_reason "${tlog_reason}")
    endif()
    string(REPLACE "\r\n" "\n" read_text "${read_text}")
    string(REPLACE "\r" "\n" read_text "${read_text}")
    if ("${local_reason}" STREQUAL "" AND
        ("${read_text}" STREQUAL "" OR NOT "${read_text}" MATCHES "^\\^"))
      set(local_reason "malformed link.read evidence ${read_path}")
    elseif("${local_reason}" STREQUAL "")
      string(REGEX REPLACE "^\\^" "" read_text "${read_text}")
      string(REPLACE "\n" ";" read_lines "${read_text}")
      foreach(line IN LISTS read_lines)
        string(STRIP "${line}" line)
        if ("${line}" STREQUAL "")
          continue()
        endif()
        string(REGEX REPLACE "^\\^" "" line "${line}")
        if (NOT "${line}" MATCHES "^[A-Za-z]:[\\\\/]" AND
            NOT "${line}" MATCHES "^/")
          set(local_reason "relative or unresolved link.read input ${line}")
          break()
        endif()
        normalize_link_path("${line}" "" normalized_line)
        list(APPEND local_inputs "${normalized_line}")
      endforeach()
      if ("${local_reason}" STREQUAL "")
        list(REMOVE_DUPLICATES local_inputs)
        list(LENGTH local_inputs input_count)
        if (input_count EQUAL 0)
          set(local_reason "link.read evidence contains no resolved inputs")
        else()
          set(local_ok TRUE)
        endif()
      endif()
    endif()
  endif()
  set(${inputs_variable} "${local_inputs}" PARENT_SCOPE)
  set(${ok_variable} "${local_ok}" PARENT_SCOPE)
  set(${reason_variable} "${local_reason}" PARENT_SCOPE)
endfunction()

function(read_link_command_tlog command_path executable_path output_variable
                                ok_variable reason_variable)
  set(local_ok FALSE)
  set(local_reason "")
  set(local_text "")
  if (NOT EXISTS "${command_path}" OR IS_DIRECTORY "${command_path}")
    set(local_reason "missing or non-file link.command evidence ${command_path}")
  else()
    read_tlog_text("${command_path}" command_text tlog_ok tlog_reason)
    if (NOT tlog_ok)
      set(local_reason "${tlog_reason}")
    endif()
    string(REPLACE "\r\n" " " command_text "${command_text}")
    string(REPLACE "\r" " " command_text "${command_text}")
    if ("${local_reason}" STREQUAL "" AND
        ("${command_text}" STREQUAL "" OR NOT "${command_text}" MATCHES "^\\^"))
      set(local_reason "malformed link.command evidence ${command_path}")
    elseif("${local_reason}" STREQUAL "")
      string(REGEX REPLACE "^\\^" "" command_text "${command_text}")
      string(TOUPPER "${command_text}" command_upper)
      normalize_link_path("${executable_path}" "" executable_normalized)
      string(TOUPPER "${executable_normalized}" executable_upper)
      string(REPLACE "/" "\\" executable_upper "${executable_upper}")
      string(FIND "${command_upper}" "${executable_upper}" executable_index)
      if (executable_index EQUAL -1 OR
          NOT "${command_upper}" MATCHES "DIRECT_MASK_PIPELINE_VERIFIER_MAIN\\.OBJ")
        set(local_reason "link.command does not name the expected Release executable and verifier main object")
      else()
        foreach(forbidden IN ITEMS "/WHOLEARCHIVE" "/DEFAULTLIB"
                                    "/INCLUDE:" "/LIBPATH:" "/DELAYLOAD:"
                                    "/ENTRY:" "/EXPORT:"
                                    "-WHOLEARCHIVE" "-DEFAULTLIB"
                                    "-INCLUDE:" "-LIBPATH:" "-DELAYLOAD:"
                                    "-ENTRY:" "-EXPORT:" "@")
          if (command_upper MATCHES "${forbidden}")
            set(local_reason "forbidden or opaque link option ${forbidden} in ${command_path}")
            break()
          endif()
        endforeach()
        if ("${local_reason}" STREQUAL "")
          set(local_ok TRUE)
          set(local_text "${command_text}")
        endif()
      endif()
    endif()
  endif()
  set(${output_variable} "${local_text}" PARENT_SCOPE)
  set(${ok_variable} "${local_ok}" PARENT_SCOPE)
  set(${reason_variable} "${local_reason}" PARENT_SCOPE)
endfunction()

function(run_link_closure project_path label forbidden_regex forbidden_name_regex
                          ok_variable failure_variable projects_variable edges_variable)
  set_property(GLOBAL PROPERTY DM_PIPELINE_CLOSURE_VISITED "")
  set_property(GLOBAL PROPERTY DM_PIPELINE_CLOSURE_FAILURE "")
  set_property(GLOBAL PROPERTY DM_PIPELINE_CLOSURE_EDGES 0)
  set_property(GLOBAL PROPERTY DM_PIPELINE_CLOSURE_FORBIDDEN_REGEX
               "${forbidden_regex}")
  set_property(GLOBAL PROPERTY DM_PIPELINE_CLOSURE_FORBIDDEN_NAME_REGEX
               "${forbidden_name_regex}")
  visit_link_project("${project_path}" "${label}")
  get_property(visited GLOBAL PROPERTY DM_PIPELINE_CLOSURE_VISITED)
  get_property(failure GLOBAL PROPERTY DM_PIPELINE_CLOSURE_FAILURE)
  get_property(edges GLOBAL PROPERTY DM_PIPELINE_CLOSURE_EDGES)
  if ("${failure}" STREQUAL "")
    set(ok TRUE)
  else()
    set(ok FALSE)
  endif()
  set(${ok_variable} "${ok}" PARENT_SCOPE)
  set(${failure_variable} "${failure}" PARENT_SCOPE)
  set(${projects_variable} "${visited}" PARENT_SCOPE)
  set(${edges_variable} "${edges}" PARENT_SCOPE)
endfunction()

function(visit_link_project project_path label)
  get_property(existing_failure GLOBAL PROPERTY DM_PIPELINE_CLOSURE_FAILURE)
  if (NOT "${existing_failure}" STREQUAL "")
    return()
  endif()

  get_filename_component(project_path "${project_path}" ABSOLUTE)
  if (NOT EXISTS "${project_path}" OR IS_DIRECTORY "${project_path}")
    set_property(GLOBAL PROPERTY DM_PIPELINE_CLOSURE_FAILURE
                 "${label}: missing or unreadable link evidence ${project_path}")
    return()
  endif()

  get_property(visited GLOBAL PROPERTY DM_PIPELINE_CLOSURE_VISITED)
  list(FIND visited "${project_path}" already_seen)
  if (NOT already_seen EQUAL -1)
    return()
  endif()
  list(APPEND visited "${project_path}")
  set_property(GLOBAL PROPERTY DM_PIPELINE_CLOSURE_VISITED "${visited}")

  read_xml_project_evidence("${project_path}" "--references" references
                            reference_names project_names ignored_dependencies
                            ignored_int_dir xml_ok xml_reason)
  if (NOT xml_ok)
    set_property(GLOBAL PROPERTY DM_PIPELINE_CLOSURE_FAILURE
                 "${label}: ${xml_reason}")
    return()
  endif()

  get_property(forbidden_regex GLOBAL PROPERTY DM_PIPELINE_CLOSURE_FORBIDDEN_REGEX)
  get_property(forbidden_name_regex GLOBAL PROPERTY DM_PIPELINE_CLOSURE_FORBIDDEN_NAME_REGEX)
  get_filename_component(project_name "${project_path}" NAME)
  set(forbidden_project_name FALSE)
  foreach(parsed_project_name IN LISTS project_names reference_names)
    if ("${parsed_project_name}" MATCHES "${forbidden_name_regex}")
      set(forbidden_project_name TRUE)
    endif()
  endforeach()
  if ("${project_name}" MATCHES "${forbidden_regex}" OR forbidden_project_name)
    set_property(GLOBAL PROPERTY DM_PIPELINE_CLOSURE_FAILURE
                 "${label}: forbidden transitive project ${project_path}")
    return()
  endif()

  get_filename_component(project_directory "${project_path}" DIRECTORY)
  foreach(reference IN LISTS references)
    string(REPLACE "\\" "/" reference_path "${reference}")
    get_filename_component(reference_path "${reference_path}" ABSOLUTE
                           BASE_DIR "${project_directory}")
    get_filename_component(reference_name "${reference_path}" NAME)
    if ("${reference_name}" MATCHES "${forbidden_regex}")
      set_property(GLOBAL PROPERTY DM_PIPELINE_CLOSURE_FAILURE
                   "${label}: forbidden project edge ${project_path} -> ${reference_path}")
      return()
    endif()
    get_property(edge_count GLOBAL PROPERTY DM_PIPELINE_CLOSURE_EDGES)
    math(EXPR edge_count "${edge_count} + 1")
    set_property(GLOBAL PROPERTY DM_PIPELINE_CLOSURE_EDGES "${edge_count}")
    visit_link_project("${reference_path}" "${label}")
    get_property(existing_failure GLOBAL PROPERTY DM_PIPELINE_CLOSURE_FAILURE)
    if (NOT "${existing_failure}" STREQUAL "")
      return()
    endif()
  endforeach()
endfunction()

function(run_actual_link_input_closure project_path executable_path label
                                       ok_variable failure_variable
                                       actual_variable expected_variable)
  set_property(GLOBAL PROPERTY DM_PIPELINE_INPUT_FAILURE "")
  get_filename_component(project_path "${project_path}" ABSOLUTE)
  get_filename_component(project_directory "${project_path}" DIRECTORY)
  get_filename_component(release_directory "${executable_path}" DIRECTORY)
  get_filename_component(build_directory "${release_directory}" DIRECTORY)

  extract_release_dependencies("${project_path}" release_dependencies
                               release_dependency_node release_dependency_text
                               release_int_directory release_dependencies_ok
                               release_dependencies_reason)
  if (NOT release_dependencies_ok)
    input_closure_failure("${label}: ${release_dependencies_reason}")
  endif()
  if (release_dependencies_ok)
    string(REPLACE "\\" "/" release_int_value "${release_int_directory}")
    get_filename_component(release_int_directory "${release_int_value}" ABSOLUTE
                           BASE_DIR "${project_directory}")
    file(TO_CMAKE_PATH "${release_int_directory}" release_int_directory)
  endif()

  normalize_link_path("${project_directory}" "" normalized_project_directory)
  normalize_link_path("${build_directory}" "" normalized_build_directory)
  if (NOT "${normalized_project_directory}" STREQUAL "${normalized_build_directory}")
    input_closure_failure("${label}: project directory is not the executable build root")
  endif()

  set(command_candidates "")
  set(read_candidates "")
  if (release_dependencies_ok)
    file(GLOB command_candidates
         "${release_int_directory}/*/link.command.*.tlog")
    file(GLOB read_candidates
         "${release_int_directory}/*/link.read.*.tlog")
  endif()
  list(LENGTH command_candidates command_count)
  list(LENGTH read_candidates read_count)
  if (NOT command_count EQUAL 1)
    input_closure_failure("${label}: expected one current Release link.command tlog, found ${command_count}")
  endif()
  if (NOT read_count EQUAL 1)
    input_closure_failure("${label}: expected one current Release link.read tlog, found ${read_count}")
  endif()

  set(actual_inputs "")
  if (read_count EQUAL 1)
    list(GET read_candidates 0 read_path)
    read_link_input_tlog("${read_path}" actual_inputs read_ok read_reason)
    if (NOT read_ok)
      input_closure_failure("${label}: ${read_reason}")
    endif()
  endif()
  if (command_count EQUAL 1)
    list(GET command_candidates 0 command_path)
    read_link_command_tlog("${command_path}" "${executable_path}" command_text
                           command_ok command_reason)
    if (NOT command_ok)
      input_closure_failure("${label}: ${command_reason}")
    endif()
  endif()

  set(expected_non_system "")
  set(expected_system_names "")
  if (release_dependencies_ok)
    get_filename_component(main_name "${REAL_VERIFIER_MAIN}" NAME_WE)
    normalize_link_path("${release_int_directory}/${main_name}.obj" ""
                         expected_main_object)
    list(APPEND expected_non_system "${expected_main_object}")
    foreach(dependency IN LISTS release_dependencies)
      string(STRIP "${dependency}" dependency)
      if ("${dependency}" STREQUAL "%(AdditionalDependencies)")
        continue()
      endif()
      string(REGEX REPLACE "^\"|\"$" "" dependency "${dependency}")
      if ("${dependency}" MATCHES "^[A-Za-z]:[\\\\/]" OR
          "${dependency}" MATCHES "[\\\\/]")
        normalize_link_path("${dependency}" "${project_directory}" normalized_dependency)
        is_system_link_path("${normalized_dependency}" dependency_is_system)
        if (dependency_is_system)
          get_filename_component(dependency_name "${normalized_dependency}" NAME)
          list(APPEND expected_system_names "${dependency_name}")
        else()
          list(APPEND expected_non_system "${normalized_dependency}")
        endif()
      else()
        is_system_direct_name("${dependency}" dependency_is_system)
        if (dependency_is_system)
          string(TOLOWER "${dependency}" dependency_lower)
          list(APPEND expected_system_names "${dependency_lower}")
        else()
          input_closure_failure("${label}: bare non-system AdditionalDependencies token is unresolved: ${dependency}")
        endif()
      endif()
    endforeach()
  endif()
  list(REMOVE_DUPLICATES expected_non_system)
  list(REMOVE_DUPLICATES expected_system_names)

  set(actual_non_system "")
  if (read_ok)
    foreach(input_path IN LISTS actual_inputs)
      if (NOT EXISTS "${input_path}" OR IS_DIRECTORY "${input_path}")
        input_closure_failure("${label}: resolved link input is missing or non-file: ${input_path}")
        continue()
      endif()
      is_system_link_path("${input_path}" input_is_system)
      if (NOT input_is_system)
        list(APPEND actual_non_system "${input_path}")
      endif()
    endforeach()
  endif()
  list(REMOVE_DUPLICATES actual_non_system)

  foreach(system_name IN LISTS expected_system_names)
    set(system_found FALSE)
    foreach(input_path IN LISTS actual_inputs)
      get_filename_component(input_name "${input_path}" NAME)
      string(TOLOWER "${input_name}" input_name_lower)
      if ("${input_name_lower}" STREQUAL "${system_name}")
        set(system_found TRUE)
      endif()
    endforeach()
    if (NOT system_found)
      input_closure_failure("${label}: direct system dependency was not resolved by link.read: ${system_name}")
    endif()
  endforeach()

  set(inputs_to_inspect ${actual_non_system} ${expected_non_system})
  list(REMOVE_DUPLICATES inputs_to_inspect)
  foreach(input_path IN LISTS inputs_to_inspect)
    inspect_non_system_input("${input_path}" "${label}" input_symbols input_directives
                             input_inspect_ok input_inspect_reason)
    if (NOT input_inspect_ok)
      input_closure_failure("${input_inspect_reason}")
    elseif("${input_symbols}" MATCHES "${DM_PIPELINE_FORBIDDEN_SYMBOL_REGEX}")
      input_closure_failure("${label}: non-system link input contains forbidden producer/materializer symbol: ${input_path}")
    endif()
  endforeach()

  list(SORT actual_non_system)
  list(SORT expected_non_system)
  if (NOT "${actual_non_system}" STREQUAL "${expected_non_system}")
    input_closure_failure("${label}: actual non-system link inputs differ from the closed expected allowlist; actual=${actual_non_system}; expected=${expected_non_system}")
  endif()

  normalize_link_path("${REAL_PIPELINE_VERIFIER_LIBRARY}" "" required_verifier_library)
  normalize_link_path("${REAL_PIPELINE_CODEC_LIBRARY}" "" required_codec_library)
  normalize_link_path("${REAL_AUTHENTICATED_LIBRARY}" "" required_authenticated_library)
  foreach(required_input IN ITEMS required_verifier_library required_codec_library
                                  required_authenticated_library)
    list(FIND actual_non_system "${${required_input}}" required_index)
    if (required_index EQUAL -1)
      input_closure_failure("${label}: required real Release input is absent from link.read: ${${required_input}}")
    endif()
  endforeach()
  normalize_link_path("${REAL_SOURCE_PROOF_LIBRARY}" "" forbidden_source_proof_library)
  list(FIND actual_non_system "${forbidden_source_proof_library}" forbidden_index)
  if (NOT forbidden_index EQUAL -1)
    input_closure_failure("${label}: source-proof producer archive reached the verifier executable: ${forbidden_source_proof_library}")
  endif()

  get_property(failure GLOBAL PROPERTY DM_PIPELINE_INPUT_FAILURE)
  if ("${failure}" STREQUAL "")
    set(ok TRUE)
  else()
    set(ok FALSE)
  endif()
  set(${ok_variable} "${ok}" PARENT_SCOPE)
  set(${failure_variable} "${failure}" PARENT_SCOPE)
  set(${actual_variable} "${actual_non_system}" PARENT_SCOPE)
  set(${expected_variable} "${expected_non_system}" PARENT_SCOPE)
endfunction()

read_symbols("${REAL_PIPELINE_CODEC_LIBRARY}" codec_symbols)
read_symbols("${REAL_PIPELINE_SOURCE_LIBRARY}" source_symbols)
read_symbols("${REAL_PIPELINE_VERIFIER_LIBRARY}" verifier_symbols)
read_symbols("${REAL_SOURCE_PROOF_LIBRARY}" source_proof_symbols)
read_symbols("${REAL_AUTHENTICATED_LIBRARY}" authenticated_symbols)
read_symbols("${REAL_SOURCE_EXECUTABLE}" source_executable_symbols)
read_symbols("${REAL_VERIFIER_EXECUTABLE}" verifier_executable_symbols)

foreach(symbol IN ITEMS dm_pipeline_capsule_encode dm_pipeline_capsule_decode
                       dm_pipeline_cli_args_valid)
  require_defined_symbol("${codec_symbols}" "${symbol}"
                         "real pipeline codec archive")
endforeach()
require_defined_symbol("${source_symbols}" "dm_pipeline_source_process"
                       "real pipeline source archive")
require_defined_symbol("${verifier_symbols}" "dm_pipeline_verifier_process"
                       "real pipeline verifier archive")
require_defined_symbol("${source_proof_symbols}" "dm_source_proof_generate"
                       "real inherited source-proof archive")
require_defined_symbol("${authenticated_symbols}"
                       "dm_authenticated_proof_verify"
                       "real inherited authenticated-proof archive")

# The generated Release project files remain the build graph, but the actual
# verifier executable's current MSBuild link.command/link.read evidence is the
# authoritative input boundary.  Every non-system object/archive is allowlisted
# and independently inspectable; direct dependencies and opaque link options do
# not disappear merely because ProjectReference traversal succeeds.
run_actual_link_input_closure(
  "${REAL_VERIFIER_LINK_PROJECT}" "${REAL_VERIFIER_EXECUTABLE}"
  "real verifier Release link-input closure" verifier_inputs_ok
  verifier_inputs_failure verifier_actual_inputs verifier_expected_inputs)
if (NOT verifier_inputs_ok)
  message(FATAL_ERROR "real verifier Release link-input closure failed: ${verifier_inputs_failure}")
endif()

run_link_closure(
  "${REAL_VERIFIER_LINK_PROJECT}" "real verifier closure"
  "^(dm_pipeline_source|dm_source_proof|dm_native.*)\\.vcxproj$"
  "^(dm_pipeline_source|dm_source_proof|dm_native.*)$"
  verifier_closure_ok verifier_closure_failure verifier_projects verifier_edges)
if (NOT verifier_closure_ok)
  message(FATAL_ERROR "real verifier closure gate failed: ${verifier_closure_failure}")
endif()
set(verifier_has_signer FALSE)
foreach(project IN LISTS verifier_projects)
  get_filename_component(project_name "${project}" NAME)
  if ("${project_name}" STREQUAL "dm_source_auth.vcxproj")
    set(verifier_has_signer TRUE)
  endif()
endforeach()
if (NOT verifier_has_signer)
  message(FATAL_ERROR "real verifier closure omitted the allowed source-auth signer")
endif()

# Keep the project-graph negative, and add a full-backed Release project clone
# that injects only a direct producer archive into the actual current project.
# The clone reuses the real Release IntDir and tlogs; it adds no ProjectReference.
file(READ "${REAL_FORBIDDEN_DIRECT_EDGE_FIXTURE}" direct_fixture_template)
if ("${direct_fixture_template}" STREQUAL "" OR
    "${direct_fixture_template}" MATCHES "<ProjectReference")
  message(FATAL_ERROR "controlled direct-dependency fixture template is malformed or adds a ProjectReference")
endif()
string(REGEX MATCH
       "<DirectForbiddenDependency>[^<]+</DirectForbiddenDependency>"
       direct_dependency_node "${direct_fixture_template}")
if ("${direct_dependency_node}" STREQUAL "")
  message(FATAL_ERROR "controlled direct-dependency fixture omitted its dependency token")
endif()
string(REGEX REPLACE "^<DirectForbiddenDependency>" "" direct_dependency_token
       "${direct_dependency_node}")
string(REGEX REPLACE "</DirectForbiddenDependency>$" ""
       direct_dependency_token "${direct_dependency_token}")
if (NOT "${direct_dependency_token}" STREQUAL "@REAL_SOURCE_PROOF_LIBRARY@")
  message(FATAL_ERROR
          "controlled direct-dependency fixture must use the REAL_SOURCE_PROOF_LIBRARY placeholder")
endif()
if (NOT EXISTS "${REAL_SOURCE_PROOF_LIBRARY}" OR IS_DIRECTORY "${REAL_SOURCE_PROOF_LIBRARY}")
  message(FATAL_ERROR
          "the supplied REAL_SOURCE_PROOF_LIBRARY is missing or non-file before direct injection: ${REAL_SOURCE_PROOF_LIBRARY}")
endif()
if ("${REAL_SOURCE_PROOF_LIBRARY}" MATCHES "[;%]" OR
    NOT "${REAL_SOURCE_PROOF_LIBRARY}" MATCHES "\\.lib$")
  message(FATAL_ERROR
          "the supplied REAL_SOURCE_PROOF_LIBRARY is not one bounded .lib path: ${REAL_SOURCE_PROOF_LIBRARY}")
endif()
normalize_link_path("${REAL_SOURCE_PROOF_LIBRARY}" "" direct_dependency_token)
if (NOT EXISTS "${direct_dependency_token}" OR IS_DIRECTORY "${direct_dependency_token}")
  message(FATAL_ERROR
          "the normalized REAL_SOURCE_PROOF_LIBRARY is missing or non-file before direct injection: ${direct_dependency_token}")
endif()
extract_release_dependencies("${REAL_VERIFIER_LINK_PROJECT}" release_dependencies
                             release_dependency_node release_dependency_text
                             release_dependency_int_dir release_dependencies_ok
                             release_dependencies_reason)
if (NOT release_dependencies_ok)
  message(FATAL_ERROR "cannot construct direct-dependency fixture: ${release_dependencies_reason}")
endif()
file(READ "${REAL_VERIFIER_LINK_PROJECT}" verifier_project_text)
string(FIND "${verifier_project_text}" "${release_dependency_node}" release_node_index)
if (release_node_index EQUAL -1)
  message(FATAL_ERROR "cannot locate Release dependency node in the actual verifier project")
endif()
string(LENGTH "${release_dependency_node}" release_node_length)
string(SUBSTRING "${verifier_project_text}" 0 ${release_node_index} direct_project_prefix)
math(EXPR release_node_after "${release_node_index} + ${release_node_length}")
string(SUBSTRING "${verifier_project_text}" ${release_node_after} -1 direct_project_suffix)
set(direct_release_node
    "<AdditionalDependencies>${direct_dependency_token};${release_dependency_text}</AdditionalDependencies>")
set(direct_project_text
    "${direct_project_prefix}${direct_release_node}${direct_project_suffix}")
get_filename_component(verifier_build_directory "${REAL_VERIFIER_LINK_PROJECT}" DIRECTORY)
set(direct_fixture_path
    "${verifier_build_directory}/dm_pipeline_verifier_cli.direct-forbidden.vcxproj")
set(direct_fixture_index 0)
while (EXISTS "${direct_fixture_path}")
  math(EXPR direct_fixture_index "${direct_fixture_index} + 1")
  set(direct_fixture_path
      "${verifier_build_directory}/dm_pipeline_verifier_cli.direct-forbidden-${direct_fixture_index}.vcxproj")
endwhile()
file(WRITE "${direct_fixture_path}" "${direct_project_text}")
if (NOT EXISTS "${direct_fixture_path}")
  message(FATAL_ERROR "controlled direct-dependency fixture could not be materialized")
endif()
string(FIND "${direct_project_text}" "${direct_dependency_token}" direct_dependency_index)
if (direct_dependency_index EQUAL -1)
  message(FATAL_ERROR
          "controlled direct-dependency clone did not inject the supplied REAL_SOURCE_PROOF_LIBRARY")
endif()
run_link_closure(
  "${direct_fixture_path}" "controlled direct forbidden-dependency project closure"
  "^(dm_pipeline_source|dm_source_proof|dm_native.*)\\.vcxproj$"
  "^(dm_pipeline_source|dm_source_proof|dm_native.*)$"
  direct_project_ok direct_project_failure direct_projects direct_edges)
if (NOT direct_project_ok)
  message(FATAL_ERROR
          "controlled direct-dependency fixture unexpectedly changed ProjectReference closure: ${direct_project_failure}")
endif()
run_actual_link_input_closure(
  "${direct_fixture_path}" "${REAL_VERIFIER_EXECUTABLE}"
  "controlled direct forbidden-dependency input closure" direct_input_ok
  direct_input_failure direct_actual_inputs direct_expected_inputs)
list(FIND direct_expected_inputs "${direct_dependency_token}" direct_expected_index)
list(FIND direct_actual_inputs "${direct_dependency_token}" direct_actual_index)
set(direct_symbol_reason
    "non-system link input contains forbidden producer/materializer symbol: ${direct_dependency_token}")
string(FIND "${direct_input_failure}" "${direct_symbol_reason}" direct_symbol_reason_index)
if (direct_input_ok OR direct_expected_index EQUAL -1 OR NOT direct_actual_index EQUAL -1 OR
    direct_symbol_reason_index EQUAL -1)
  message(FATAL_ERROR
          "controlled direct forbidden-dependency fixture was not rejected for the supplied producer archive: expected_index=${direct_expected_index}; actual_index=${direct_actual_index}; symbol_reason_index=${direct_symbol_reason_index}; failure=${direct_input_failure}")
endif()
message("REAL_PIPELINE_FORBIDDEN_DIRECT_LIBRARY_NEGATIVE=PASS reason=actual producer archive forbidden-symbol rejection; expected_index=${direct_expected_index}; actual_index=${direct_actual_index}; evidence=${direct_input_failure}")

# The same Release input predicate must fail closed on malformed XML and on
# duplicate/conflicting Release evidence.  These clones remain in the approved
# generated build directory and do not modify the actual project or tlogs.
set(malformed_project_text "NOT-XML${verifier_project_text}")
set(malformed_fixture_path
    "${verifier_build_directory}/dm_pipeline_verifier_cli.malformed-prefix.vcxproj")
set(malformed_fixture_index 0)
while (EXISTS "${malformed_fixture_path}")
  math(EXPR malformed_fixture_index "${malformed_fixture_index} + 1")
  set(malformed_fixture_path
      "${verifier_build_directory}/dm_pipeline_verifier_cli.malformed-prefix-${malformed_fixture_index}.vcxproj")
endwhile()
file(WRITE "${malformed_fixture_path}" "${malformed_project_text}")
run_actual_link_input_closure(
  "${malformed_fixture_path}" "${REAL_VERIFIER_EXECUTABLE}"
  "controlled malformed-prefix project" malformed_input_ok
  malformed_input_failure malformed_actual_inputs malformed_expected_inputs)
if (malformed_input_ok OR
    NOT "${malformed_input_failure}" MATCHES "XML project evidence rejected")
  message(FATAL_ERROR
          "controlled malformed-prefix project was not rejected by the XML input predicate: ${malformed_input_failure}")
endif()
message("REAL_PIPELINE_MALFORMED_PROJECT_NEGATIVE=PASS reason=${malformed_input_failure}")

set(duplicate_release_node
    "<AdditionalDependencies>${release_dependency_text}</AdditionalDependencies><AdditionalDependencies>${release_dependency_text}</AdditionalDependencies>")
string(LENGTH "${release_dependency_node}" release_node_length)
string(SUBSTRING "${verifier_project_text}" 0 ${release_node_index}
               duplicate_project_prefix)
math(EXPR release_node_after "${release_node_index} + ${release_node_length}")
string(SUBSTRING "${verifier_project_text}" ${release_node_after} -1
               duplicate_project_suffix)
set(duplicate_project_text
    "${duplicate_project_prefix}${duplicate_release_node}${duplicate_project_suffix}")
set(duplicate_fixture_path
    "${verifier_build_directory}/dm_pipeline_verifier_cli.duplicate-release-dependencies.vcxproj")
set(duplicate_fixture_index 0)
while (EXISTS "${duplicate_fixture_path}")
  math(EXPR duplicate_fixture_index "${duplicate_fixture_index} + 1")
  set(duplicate_fixture_path
      "${verifier_build_directory}/dm_pipeline_verifier_cli.duplicate-release-dependencies-${duplicate_fixture_index}.vcxproj")
endwhile()
file(WRITE "${duplicate_fixture_path}" "${duplicate_project_text}")
run_actual_link_input_closure(
  "${duplicate_fixture_path}" "${REAL_VERIFIER_EXECUTABLE}"
  "controlled duplicate Release dependencies" duplicate_input_ok
  duplicate_input_failure duplicate_actual_inputs duplicate_expected_inputs)
if (duplicate_input_ok OR
    NOT "${duplicate_input_failure}" MATCHES
       "expected exactly one Release AdditionalDependencies node")
  message(FATAL_ERROR
          "controlled duplicate Release dependencies were not rejected: ${duplicate_input_failure}")
endif()
message("REAL_PIPELINE_DUPLICATE_RELEASE_DEPENDENCIES_NEGATIVE=PASS reason=${duplicate_input_failure}")

set(conflicting_configuration_fragment
    "<PropertyGroup Condition=\"'$(Configuration)|$(Platform)'=='Release|x64'\" Label=\"Configuration\"><ConfigurationType>Application</ConfigurationType><PlatformToolset>v143</PlatformToolset></PropertyGroup>")
string(FIND "${verifier_project_text}" "\n</Project>" project_close_marker_index)
if (project_close_marker_index EQUAL -1)
  message(FATAL_ERROR "cannot locate XML project close tag for conflicting configuration fixture")
endif()
math(EXPR project_close_index "${project_close_marker_index} + 1")
string(SUBSTRING "${verifier_project_text}" 0 ${project_close_index}
               conflicting_project_prefix)
string(LENGTH "</Project>" project_close_length)
string(SUBSTRING "${verifier_project_text}" ${project_close_index}
               ${project_close_length} conflicting_project_suffix)
set(conflicting_project_text
    "${conflicting_project_prefix}${conflicting_configuration_fragment}${conflicting_project_suffix}")
set(conflicting_fixture_path
    "${verifier_build_directory}/dm_pipeline_verifier_cli.conflicting-release-configuration.vcxproj")
set(conflicting_fixture_index 0)
while (EXISTS "${conflicting_fixture_path}")
  math(EXPR conflicting_fixture_index "${conflicting_fixture_index} + 1")
  set(conflicting_fixture_path
      "${verifier_build_directory}/dm_pipeline_verifier_cli.conflicting-release-configuration-${conflicting_fixture_index}.vcxproj")
endwhile()
file(WRITE "${conflicting_fixture_path}" "${conflicting_project_text}")
run_actual_link_input_closure(
  "${conflicting_fixture_path}" "${REAL_VERIFIER_EXECUTABLE}"
  "controlled conflicting Release configuration" conflicting_input_ok
  conflicting_input_failure conflicting_actual_inputs conflicting_expected_inputs)
if (conflicting_input_ok OR
    NOT "${conflicting_input_failure}" MATCHES
       "expected exactly one Release\\|x64 Configuration PropertyGroup")
  message(FATAL_ERROR
          "controlled conflicting Release configuration was not rejected: ${conflicting_input_failure}")
endif()
message("REAL_PIPELINE_CONFLICTING_RELEASE_CONFIGURATION_NEGATIVE=PASS reason=${conflicting_input_failure}")

# Exercise the same bounded XML parser against structural and resource-bound
# counterexamples.  These fixtures are create-only in the generated build
# directory; none is used as build input or modifies the real project/tlogs.
function(write_unique_project_fixture fixture_stem fixture_text output_variable)
  set(fixture_path
      "${verifier_build_directory}/${fixture_stem}.vcxproj")
  set(fixture_index 0)
  while (EXISTS "${fixture_path}")
    math(EXPR fixture_index "${fixture_index} + 1")
    set(fixture_path
        "${verifier_build_directory}/${fixture_stem}-${fixture_index}.vcxproj")
  endwhile()
  file(WRITE "${fixture_path}" "${fixture_text}")
  if (NOT EXISTS "${fixture_path}")
    message(FATAL_ERROR "controlled ${fixture_stem} fixture could not be materialized")
  endif()
  set(${output_variable} "${fixture_path}" PARENT_SCOPE)
endfunction()

function(assert_rejected_project_fixture fixture_path fixture_label expected_text
                                         output_label)
  run_actual_link_input_closure(
    "${fixture_path}" "${REAL_VERIFIER_EXECUTABLE}" "${fixture_label}"
    fixture_ok fixture_failure fixture_actual_inputs fixture_expected_inputs)
  if (fixture_ok OR NOT "${fixture_failure}" MATCHES "${expected_text}")
    message(FATAL_ERROR
            "${fixture_label} was not rejected for the intended reason: ${fixture_failure}")
  endif()
  message("${output_label}=PASS reason=${fixture_failure}")
endfunction()

set(release_group_open_marker
    "<ItemDefinitionGroup Condition=\"'$(Configuration)|$(Platform)'=='Release|x64'\">")
string(FIND "${verifier_project_text}" "${release_group_open_marker}"
       release_group_open_index)
if (release_group_open_index EQUAL -1)
  message(FATAL_ERROR "cannot locate actual Release ItemDefinitionGroup for parser fixtures")
endif()
string(SUBSTRING "${verifier_project_text}" ${release_group_open_index} -1
               release_group_suffix)
string(FIND "${release_group_suffix}" "</ItemDefinitionGroup>"
       release_group_close_relative)
if (release_group_close_relative EQUAL -1)
  message(FATAL_ERROR "cannot locate actual Release ItemDefinitionGroup close tag")
endif()
string(LENGTH "</ItemDefinitionGroup>" release_group_close_length)
math(EXPR release_group_length
      "${release_group_close_relative} + ${release_group_close_length}")
string(SUBSTRING "${verifier_project_text}" ${release_group_open_index}
               ${release_group_length} release_group_text)

set(nested_release_project_text "${verifier_project_text}")
string(REPLACE "${release_group_text}"
               "<Target Name=\"nested-release-evidence\">${release_group_text}</Target>"
               nested_release_project_text "${nested_release_project_text}")
write_unique_project_fixture(
  "dm_pipeline_verifier_cli.nested-release-group" "${nested_release_project_text}"
  nested_release_fixture_path)
assert_rejected_project_fixture(
  "${nested_release_fixture_path}" "controlled nested Release group"
  "ItemDefinitionGroup must be a direct Project child"
  REAL_PIPELINE_NESTED_RELEASE_GROUP_NEGATIVE)

set(disabled_dependency_node
    "<AdditionalDependencies Condition=\"'false'=='true'\">${release_dependency_text}</AdditionalDependencies>")
set(disabled_dependency_project_text "${verifier_project_text}")
string(REPLACE "${release_dependency_node}" "${disabled_dependency_node}"
               disabled_dependency_project_text "${disabled_dependency_project_text}")
write_unique_project_fixture(
  "dm_pipeline_verifier_cli.disabled-release-dependency"
  "${disabled_dependency_project_text}" disabled_dependency_fixture_path)
assert_rejected_project_fixture(
  "${disabled_dependency_fixture_path}" "controlled disabled Release dependency"
  "Release AdditionalDependencies has unsupported attributes"
  REAL_PIPELINE_DISABLED_RELEASE_DEPENDENCY_NEGATIVE)

set(disabled_link_group_text "${release_group_text}")
string(FIND "${disabled_link_group_text}" "<Link>" disabled_link_open_index)
if (disabled_link_open_index EQUAL -1)
  message(FATAL_ERROR "cannot locate actual Release Link node for parser fixture")
endif()
string(REPLACE "<Link>" "<Link Condition=\"'false'=='true'\">"
               disabled_link_group_text "${disabled_link_group_text}")
set(disabled_link_project_text "${verifier_project_text}")
string(REPLACE "${release_group_text}" "${disabled_link_group_text}"
               disabled_link_project_text "${disabled_link_project_text}")
write_unique_project_fixture(
  "dm_pipeline_verifier_cli.disabled-release-link"
  "${disabled_link_project_text}" disabled_link_fixture_path)
assert_rejected_project_fixture(
  "${disabled_link_fixture_path}" "controlled disabled Release Link"
  "Release Link has unsupported or incomplete attributes"
  REAL_PIPELINE_DISABLED_RELEASE_LINK_NEGATIVE)

set(nested_dependency_node
    "<AdditionalDependencies>${release_dependency_text}<UnsupportedPayload>ignored</UnsupportedPayload></AdditionalDependencies>")
set(nested_dependency_project_text "${verifier_project_text}")
string(REPLACE "${release_dependency_node}" "${nested_dependency_node}"
               nested_dependency_project_text "${nested_dependency_project_text}")
write_unique_project_fixture(
  "dm_pipeline_verifier_cli.nested-release-dependency"
  "${nested_dependency_project_text}" nested_dependency_fixture_path)
assert_rejected_project_fixture(
  "${nested_dependency_fixture_path}" "controlled nested Release dependency payload"
  "Release AdditionalDependencies must be a scalar XML node without nested payload"
  REAL_PIPELINE_NESTED_RELEASE_DEPENDENCY_NEGATIVE)

set(comment_release_project_text "${verifier_project_text}")
string(REPLACE "${release_group_text}" "<!--${release_group_text}-->"
               comment_release_project_text "${comment_release_project_text}")
write_unique_project_fixture(
  "dm_pipeline_verifier_cli.comment-release-fragment"
  "${comment_release_project_text}" comment_release_fixture_path)
assert_rejected_project_fixture(
  "${comment_release_fixture_path}" "controlled commented Release fragment"
  "expected exactly one Release\\|x64 ItemDefinitionGroup, found 0"
  REAL_PIPELINE_COMMENT_RELEASE_FRAGMENT_NEGATIVE)

set(oversized_prefix
    "<?xml version=\"1.0\" encoding=\"utf-8\"?><Project xmlns=\"http://schemas.microsoft.com/developer/msbuild/2003\">")
set(oversized_suffix "</Project>")
string(LENGTH "${oversized_prefix}" oversized_prefix_length)
string(LENGTH "${oversized_suffix}" oversized_suffix_length)
math(EXPR oversized_padding_length
      "4194304 + 1 - ${oversized_prefix_length} - ${oversized_suffix_length}")
if (oversized_padding_length LESS 1)
  message(FATAL_ERROR "bounded oversized-project fixture length calculation underflowed")
endif()
string(REPEAT "X" ${oversized_padding_length} oversized_padding)
set(oversized_project_text
    "${oversized_prefix}${oversized_padding}${oversized_suffix}")
write_unique_project_fixture(
  "dm_pipeline_verifier_cli.oversized-project" "${oversized_project_text}"
  oversized_fixture_path)
assert_rejected_project_fixture(
  "${oversized_fixture_path}" "controlled oversized XML project"
  "project exceeds bounded XML size 4194304"
  REAL_PIPELINE_OVERSIZED_PROJECT_NEGATIVE)

run_link_closure(
  "${REAL_SOURCE_LINK_PROJECT}" "real source closure"
  "^(dm_pipeline_verifier|dm_authenticated_proof)\\.vcxproj$"
  "^(dm_pipeline_verifier|dm_authenticated_proof)$"
  source_closure_ok source_closure_failure source_projects source_edges)
if (NOT source_closure_ok)
  message(FATAL_ERROR "real source closure gate failed: ${source_closure_failure}")
endif()
set(source_has_producer FALSE)
foreach(project IN LISTS source_projects)
  get_filename_component(project_name "${project}" NAME)
  if ("${project_name}" STREQUAL "dm_source_proof.vcxproj")
    set(source_has_producer TRUE)
  endif()
endforeach()
if (NOT source_has_producer)
  message(FATAL_ERROR "real source closure omitted the source-proof producer")
endif()

# Controlled negative evidence: the same project closure must reject a producer
# edge, and a missing evidence path must fail closed.  The shared signer remains
# explicitly allowed by the verifier closure above.
run_link_closure(
  "${REAL_FORBIDDEN_EDGE_FIXTURE}" "controlled forbidden-edge fixture"
  "^(dm_pipeline_source|dm_source_proof|dm_native.*)\\.vcxproj$"
  "^(dm_pipeline_source|dm_source_proof|dm_native.*)$"
  forbidden_fixture_ok forbidden_fixture_failure forbidden_projects forbidden_edges)
if (forbidden_fixture_ok OR
    NOT "${forbidden_fixture_failure}" MATCHES
       "^controlled forbidden-edge fixture: forbidden project edge ")
  message(FATAL_ERROR
          "controlled forbidden-edge fixture was not rejected for the intended project edge: ${forbidden_fixture_failure}")
endif()
message("REAL_PIPELINE_FORBIDDEN_EDGE_NEGATIVE=PASS reason=${forbidden_fixture_failure}")

run_link_closure(
  "${REAL_MISSING_EVIDENCE_FIXTURE}" "controlled missing-evidence fixture"
  "^(dm_pipeline_source|dm_source_proof|dm_native.*)\\.vcxproj$"
  "^(dm_pipeline_source|dm_source_proof|dm_native.*)$"
  missing_fixture_ok missing_fixture_failure missing_projects missing_edges)
if (missing_fixture_ok)
  message(FATAL_ERROR "controlled missing-evidence fixture was accepted")
endif()
message("REAL_PIPELINE_MISSING_EVIDENCE_NEGATIVE=PASS reason=${missing_fixture_failure}")

foreach(symbol_text IN ITEMS verifier_symbols verifier_executable_symbols)
  forbid_symbol("${${symbol_text}}" "${DM_PIPELINE_FORBIDDEN_SYMBOL_REGEX}"
                "real verifier closure ${symbol_text}")
endforeach()
forbid_symbol("${source_executable_symbols}"
              "dm_authenticated_proof_verify|dm_native_fixture_authenticated|dm_pipeline_verifier_process"
              "real source closure")

file(READ "${REAL_PIPELINE_HEADER}" pipeline_header_text)
file(READ "${REAL_PIPELINE_CODEC_SOURCE}" codec_source_text)
file(READ "${REAL_PIPELINE_SOURCE_SOURCE}" source_source_text)
file(READ "${REAL_PIPELINE_VERIFIER_SOURCE}" verifier_source_text)
file(READ "${REAL_SOURCE_MAIN}" source_main_text)
file(READ "${REAL_VERIFIER_MAIN}" verifier_main_text)

foreach(forbidden IN ITEMS "FAEST_TESTS" "DMN_NATIVE_PROBE" "process_harness"
                            "state_transition" "clearance_directive" "source_truth"
                            "_probe")
  foreach(text_name IN ITEMS pipeline_header_text codec_source_text source_source_text
                             verifier_source_text source_main_text verifier_main_text)
    if ("${${text_name}}" MATCHES "${forbidden}")
      message(FATAL_ERROR "pipeline production source contains forbidden ${forbidden}")
    endif()
  endforeach()
endforeach()

foreach(forbidden IN ITEMS "dm_wire_prove_kernel" "dmn_extend" "direct_mask_native"
                            "dm_source_proof_generate" "keypair_from_seed")
  if ("${verifier_source_text}" MATCHES "${forbidden}")
    message(FATAL_ERROR "verifier implementation contains forbidden ${forbidden}")
  endif()
endforeach()

foreach(forbidden IN ITEMS "printf" "fprintf" "puts" "fputs")
  if ("${verifier_source_text}" MATCHES "${forbidden}" OR
      "${verifier_main_text}" MATCHES "${forbidden}")
    message(FATAL_ERROR "verifier path emits forbidden diagnostic text ${forbidden}")
  endif()
endforeach()

list(LENGTH verifier_actual_inputs verifier_actual_count)
list(LENGTH verifier_expected_inputs verifier_expected_count)
message("REAL_PIPELINE_CODEC_SYMBOL_GATE=PASS checked=3")
message("REAL_PIPELINE_SOURCE_SYMBOL_GATE=PASS checked=1")
message("REAL_PIPELINE_VERIFIER_SYMBOL_GATE=PASS checked=1")
message("REAL_PIPELINE_VERIFIER_NO_PRODUCER_DEPENDENCY_GATE=PASS checked=5")
message("REAL_PIPELINE_RELEASE_LINK_INPUT_GATE=PASS actual_non_system=${verifier_actual_count} expected_non_system=${verifier_expected_count} main_object=direct_mask_pipeline_verifier_main.obj")
message("REAL_PIPELINE_LINK_CLOSURE_GATE=PASS verifier_projects=${verifier_projects} verifier_edges=${verifier_edges} source_projects=${source_projects} source_edges=${source_edges} signer_allowance=dm_source_auth")
