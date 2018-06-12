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

# 3.7+ for the BZip2 target in the cmake-bundled finder
cmake_minimum_required(VERSION 3.7)

# determine version
include(cmake/version.cmake)
determine_version("${CMAKE_CURRENT_SOURCE_DIR}" RNP)

# project name, etc
project(RNP
  VERSION "${RNP_VERSION}"
  LANGUAGES C CXX
  DESCRIPTION "${PACKAGE_DESCRIPTION_SHORT}"
)

# contact email, other info
include(cmake/info.cmake)

# so we can use our bundled finders
set(CMAKE_MODULE_PATH "${CMAKE_MODULE_PATH}" "${PROJECT_SOURCE_DIR}/cmake/Modules")

# required modules
include(CTest)

# default to a release build
if (NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING
    "Build type. Options are: None Debug Release RelWithDebInfo MinSizeRel."
    FORCE
  )
endif()

# set warning flags at the top level
add_compile_options(
  -Wall -Wextra -Wpedantic
  -Wunreachable-code -Wpointer-arith
  -Wmissing-declarations
)
# relax some warnings a bit
add_compile_options(
  -Wno-ignored-qualifiers
  -Wno-unused-parameter
  -Wno-missing-field-initializers
  -fpermissive
)

# set a few other things at the top level to prevent incompatibilities
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD 11)
add_definitions(-D_GNU_SOURCE)

# everything else is in subdirs
add_subdirectory(src/apps/packet-dumper)
add_subdirectory(src/lib)
add_subdirectory(src/rnp)
add_subdirectory(src/rnpkeys)

# build tests, if desired
if (BUILD_TESTING)
  add_subdirectory(src/tests)
endif()

# cpack packaging (RPM etc)
include(cmake/packaging.cmake)

