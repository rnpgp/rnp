# Copyright (c) 2020 Ribose Inc.
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


if(NOT DEFINED ENV{LIB_FUZZING_ENGINE})
  add_compile_options(-fsanitize=fuzzer-no-link)
  add_link_options(-fsanitize=fuzzer)
else()
  # This section is used by OSS-Fuzz
  add_link_options($ENV{LIB_FUZZING_ENGINE})
  if($ENV{FUZZING_ENGINE} STREQUAL "afl")
    link_libraries(-stdlib=libc++)
  endif()
endif()

add_executable(fuzz_dump dump.c)

target_include_directories(fuzz_dump
  PRIVATE
    "${PROJECT_SOURCE_DIR}/src"
    "${PROJECT_SOURCE_DIR}/src/lib"
)

target_link_libraries(fuzz_dump
  PRIVATE
    librnp
)

add_executable(fuzz_keyring keyring.c)

target_include_directories(fuzz_keyring
  PRIVATE
    "${PROJECT_SOURCE_DIR}/src"
    "${PROJECT_SOURCE_DIR}/src/lib"
)

target_link_libraries(fuzz_keyring
  PRIVATE
    librnp
)

add_executable(fuzz_keyimport keyimport.c)

target_include_directories(fuzz_keyimport
  PRIVATE
    "${PROJECT_SOURCE_DIR}/src"
    "${PROJECT_SOURCE_DIR}/src/lib"
)

target_link_libraries(fuzz_keyimport
  PRIVATE
    librnp
)

add_executable(fuzz_sigimport sigimport.c)

target_include_directories(fuzz_sigimport
  PRIVATE
    "${PROJECT_SOURCE_DIR}/src"
    "${PROJECT_SOURCE_DIR}/src/lib"
)

target_link_libraries(fuzz_sigimport
  PRIVATE
    librnp
)

add_executable(fuzz_verify verify.c)

target_include_directories(fuzz_verify
  PRIVATE
    "${PROJECT_SOURCE_DIR}/src"
    "${PROJECT_SOURCE_DIR}/src/lib"
)

target_link_libraries(fuzz_verify
  PRIVATE
    librnp
)

add_executable(fuzz_verify_detached verify_detached.c)

target_include_directories(fuzz_verify_detached
  PRIVATE
    "${PROJECT_SOURCE_DIR}/src"
    "${PROJECT_SOURCE_DIR}/src/lib"
)

target_link_libraries(fuzz_verify_detached
  PRIVATE
    librnp
)

add_executable(fuzz_keyring_kbx keyring_kbx.c)

target_include_directories(fuzz_keyring_kbx
  PRIVATE
    "${PROJECT_SOURCE_DIR}/src"
    "${PROJECT_SOURCE_DIR}/src/lib"
)

target_link_libraries(fuzz_keyring_kbx
  PRIVATE
    librnp
)

add_executable(fuzz_keyring_g10 keyring_g10.cpp)

target_include_directories(fuzz_keyring_g10
  PRIVATE
    "${PROJECT_SOURCE_DIR}/src"
    "${PROJECT_SOURCE_DIR}/src/lib"
)

target_link_libraries(fuzz_keyring_g10
  PRIVATE
    librnp-static
)

if (ENABLE_SANITIZERS)
  foreach(tgt fuzz_dump fuzz_keyring fuzz_keyimport fuzz_sigimport fuzz_verify fuzz_verify_detached fuzz_keyring_kbx fuzz_keyring_g10)
    set_target_properties(${tgt} PROPERTIES LINKER_LANGUAGE CXX)
  endforeach()
endif()
