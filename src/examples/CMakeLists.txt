# Copyright (c) 2018-2020 Ribose Inc.
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

if(MSVC)
  # remove extra ${Configuration} subfolder
  set(ArchiveOutputDir ${CMAKE_BINARY_DIR}\\src\\examples)
  set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_DEBUG ${ArchiveOutputDir})
  set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_MINSIZEREL ${ArchiveOutputDir})
  set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_RELEASE ${ArchiveOutputDir})
  set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_RELWITHDEBINFO ${ArchiveOutputDir})

  set(RuntimeOutputDir ${CMAKE_BINARY_DIR}\\src\\examples)
  set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG ${RuntimeOutputDir})
  set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_MINSIZEREL ${RuntimeOutputDir})
  set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE ${RuntimeOutputDir})
  set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO ${RuntimeOutputDir})

  find_path(GETOPT_INCLUDE_DIR
    NAMES getopt.h
  )
  find_library(GETOPT_LIBRARY
    NAMES getopt
  )
endif()

add_executable(generate generate.c)

target_include_directories(generate
  PRIVATE
    "${PROJECT_SOURCE_DIR}/src"
    "${PROJECT_SOURCE_DIR}/src/lib"
)

target_link_libraries(generate
  PRIVATE
    librnp
)

add_executable(encrypt encrypt.c)

target_include_directories(encrypt
  PRIVATE
    "${PROJECT_SOURCE_DIR}/src"
    "${PROJECT_SOURCE_DIR}/src/lib"
)

target_link_libraries(encrypt
  PRIVATE
    librnp
)

add_executable(decrypt decrypt.c)

target_include_directories(decrypt
  PRIVATE
    "${PROJECT_SOURCE_DIR}/src"
    "${PROJECT_SOURCE_DIR}/src/lib"
)

target_link_libraries(decrypt
  PRIVATE
    librnp
)

add_executable(sign sign.c)

target_include_directories(sign
  PRIVATE
    "${PROJECT_SOURCE_DIR}/src"
    "${PROJECT_SOURCE_DIR}/src/lib"
)

target_link_libraries(sign
  PRIVATE
    librnp
)

add_executable(verify verify.c)

target_include_directories(verify
  PRIVATE
    "${PROJECT_SOURCE_DIR}/src"
    "${PROJECT_SOURCE_DIR}/src/lib"
)

target_link_libraries(verify
  PRIVATE
    librnp
)

add_executable(dump dump.c)

target_include_directories(dump
  PRIVATE
    "${PROJECT_SOURCE_DIR}/src"
    "${PROJECT_SOURCE_DIR}/src/lib"
)

target_link_libraries(dump
  PRIVATE
    librnp
)

if(MSVC)
  target_include_directories(dump
    PRIVATE
      "${GETOPT_INCLUDE_DIR}"
  )
  target_link_libraries(dump
    PRIVATE
      "${GETOPT_LIBRARY}"
  )
endif()

if (ENABLE_SANITIZERS)
  foreach(tgt generate encrypt decrypt sign verify dump)
    set_target_properties(${tgt} PROPERTIES LINKER_LANGUAGE CXX)
  endforeach()
endif()
