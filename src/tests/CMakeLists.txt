# Copyright (c) 2018 Ribose Inc.
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
find_package(cmocka REQUIRED)
find_package(JSON-C 0.11 REQUIRED)
find_package(Threads)

add_executable(rnp_tests
  ../rnp/rnpcfg.cpp
  ../rnp/rnpcli.cpp
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
    cmocka::cmocka
  Threads::Threads
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

# rnp_tests
add_test(
  NAME rnp_tests
  COMMAND rnp_tests
)
set_tests_properties(rnp_tests PROPERTIES
  TIMEOUT 3000
  FIXTURES_REQUIRED testdata
)

# cli_tests
find_package(PythonInterp 2.7 EXACT)
find_package(GnuPG 2.2 COMPONENTS gpg gpgconf)
add_test(
  NAME cli_tests
  COMMAND "${PYTHON_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/cli_tests.py" -v -d
)
set_tests_properties(cli_tests PROPERTIES
  TIMEOUT 3000
  FIXTURES_REQUIRED testdata
  ENVIRONMENT "\
RNP_TESTS_RNP_PATH=$<TARGET_FILE:rnp>;\
RNP_TESTS_RNPKEYS_PATH=$<TARGET_FILE:rnpkeys>;\
RNP_TESTS_GPG_PATH=${GPG_EXECUTABLE};\
RNP_TESTS_GPGCONF_PATH=${GPGCONF_EXECUTABLE};\
"
)

