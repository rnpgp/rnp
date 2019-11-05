# Copyright (c) 2018-2019 Ribose Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
# TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

# for rnp_tests
find_package(JSON-C 0.11 REQUIRED)
# for cli_tests
# Note that we do this call early because Google Test will also do
# this but with less strict version requirements, which will cause
# problems for us.
find_package(PythonInterp 2.7 EXACT)
find_package(GnuPG 2.2 COMPONENTS gpg gpgconf)

include(GoogleTest)

# download and buld googletest
configure_file(gtest-CMakeLists.txt.in googletest-download/CMakeLists.txt)
execute_process(COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
  RESULT_VARIABLE result
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/googletest-download )
if(result)
  message(FATAL_ERROR "CMake step for googletest failed: ${result}")
endif()
execute_process(COMMAND ${CMAKE_COMMAND} --build .
  RESULT_VARIABLE result
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/googletest-download )
if(result)
  message(FATAL_ERROR "Build step for googletest failed: ${result}")
endif()
# maintain compiler/linker settings on Windows
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
# add to our build (provides gtest_main target)
add_subdirectory(${CMAKE_CURRENT_BINARY_DIR}/googletest-src
                 ${CMAKE_CURRENT_BINARY_DIR}/googletest-build
                 EXCLUDE_FROM_ALL)

add_executable(rnp_tests
  ../rnp/rnpcfg.cpp
  ../rnp/rnpcli.cpp
  ../rnp/fficli.cpp
  ../rnp/rnp.cpp
  ../rnpkeys/rnpkeys.cpp
  ../rnpkeys/main.cpp
  ../rnpkeys/tui.cpp
  cipher.cpp
  cli.cpp
  exportkey.cpp
  ffi.cpp
  generatekey.cpp
  key-add-userid.cpp
  key-grip.cpp
  key-prefs.cpp
  key-protect.cpp
  key-store-search.cpp
  key-unlock.cpp
  key-validate.cpp
  large-packet.cpp
  load-g10.cpp
  load-pgp.cpp
  rnp_tests.cpp
  streams.cpp
  support.cpp
  user-prefs.cpp
  utils-list.cpp
  utils-rnpcfg.cpp
)

target_include_directories(rnp_tests
  PRIVATE
    "${PROJECT_SOURCE_DIR}/src"
    "${PROJECT_SOURCE_DIR}/src/lib"
)

target_link_libraries(rnp_tests
  PRIVATE
    librnp
    JSON-C::JSON-C
    gtest_main
)

target_compile_definitions(rnp_tests
  PRIVATE
    RNP_RUN_TESTS
)

# fixture to copy the test data directory
add_test(
  NAME setupTestData
  COMMAND "${CMAKE_COMMAND}" -E copy_directory
          "${CMAKE_CURRENT_SOURCE_DIR}/data" "${CMAKE_CURRENT_BINARY_DIR}/data"
)
set_tests_properties(setupTestData PROPERTIES FIXTURES_SETUP testdata)

add_test(
  NAME gpgVerifyLargePacket
  COMMAND gpg --keyring "${CMAKE_CURRENT_BINARY_DIR}/data/keyrings/1/pubring.gpg" --verify "${CMAKE_CURRENT_BINARY_DIR}/data/test_large_packet/4g.bzip2.gpg"
)
set_tests_properties(gpgVerifyLargePacket PROPERTIES FIXTURES_REQUIRED testdata)

gtest_discover_tests(rnp_tests
  PROPERTIES
    FIXTURES_REQUIRED testdata
    TIMEOUT 3000
    ENVIRONMENT "RNP_TEST_DATA=${CMAKE_CURRENT_SOURCE_DIR}/data"
)

function(add_cli_test suite)
  set(_test_name cli_tests-${suite})
  add_test(
    NAME ${_test_name}
    COMMAND "${PYTHON_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/cli_tests.py" -v -d "${suite}"
  )
  set(_env)
  list(APPEND _env
    "RNP_TESTS_RNP_PATH=$<TARGET_FILE:rnp>"
    "RNP_TESTS_RNPKEYS_PATH=$<TARGET_FILE:rnpkeys>"
    "RNP_TESTS_GPG_PATH=${GPG_EXECUTABLE}"
    "RNP_TESTS_GPGCONF_PATH=${GPGCONF_EXECUTABLE}"
  )
  set_tests_properties(${_test_name} PROPERTIES
    TIMEOUT 3000
    FIXTURES_REQUIRED testdata
    ENVIRONMENT "${_env}"
  )
endfunction()
# get a list of test suites
execute_process(
  COMMAND "${PYTHON_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/cli_tests.py" -ls
  RESULT_VARIABLE _ec
  OUTPUT_VARIABLE suitelist
  OUTPUT_STRIP_TRAILING_WHITESPACE
)
if (NOT _ec EQUAL 0)
  message(FATAL_ERROR "Failed to retrieve test suite list for cli_tests")
endif()
# convert to a CMake list
string(REGEX REPLACE ";" "\\\\;" suitelist "${suitelist}")
string(REGEX REPLACE "\n" ";" suitelist "${suitelist}")
# create a CTest test for each suite
foreach(suite IN LISTS suitelist)
  add_cli_test("${suite}")
endforeach()

# cruby does not currently play nice with ASaN et al.
if (NOT ENABLE_SANITIZERS AND BUILD_SHARED_LIBS)
  include(ExternalProject)
  set(_sourcedir "${CMAKE_BINARY_DIR}/ruby-rnp")
  if (DEFINED ENV{RUBY_RNP_INSTALL})
    set(_sourcedir "$ENV{RUBY_RNP_INSTALL}")
  endif()
  set(_ruby_rnp_ver "master")
  if (DEFINED ENV{RUBY_RNP_VERSION})
    set(_ruby_rnp_ver "$ENV{RUBY_RNP_VERSION}")
  endif()
  ExternalProject_Add(ruby-rnp
    GIT_REPOSITORY https://github.com/rnpgp/ruby-rnp.git
    GIT_TAG "${_ruby_rnp_ver}"
    GIT_SHALLOW yes
    SOURCE_DIR "${_sourcedir}"
    BUILD_IN_SOURCE yes
    CONFIGURE_COMMAND ""
    BUILD_COMMAND
      COMMAND bundle add ffi --version 1.9.25
      COMMAND bundle show parallel_tests || bundle add parallel_tests
      COMMAND bundle install --path .
    INSTALL_COMMAND ""
    TEST_COMMAND ""
  )
  set(_env "CI=false")
  if (WIN32)
    list(APPEND _env "PATH=$<TARGET_LINKER_FILE_DIR:librnp>\;$ENV{PATH}")
  else()
    list(APPEND _env "LD_LIBRARY_PATH=$<TARGET_LINKER_FILE_DIR:librnp>:$ENV{LD_LIBRARY_PATH}")
  endif()
  add_test(
    NAME ruby-rnp
    WORKING_DIRECTORY "${_sourcedir}"
    COMMAND bundle exec parallel_rspec spec/
  )
  set_tests_properties(ruby-rnp PROPERTIES
    TIMEOUT 1000
    ENVIRONMENT "${_env}"
  )
endif()

