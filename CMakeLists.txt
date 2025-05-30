# Copyright (c) 2018-2023 Ribose Inc.
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

# 3.7+ for the BZip2 target in the cmake-bundled finder (basic build)
# 3.8+ for CPACK_RPM_MAIN_COMPONENT (RPM packaging)
# 3.10+ for CPackFreeBSD (FreeBSD packaging)
# 3.10+ for gtest_discover_tests (parallel rnp_tests)
# 3.12+ for NAMELINK_COMPONENT (for better RPM packaging)
# 3.12+ for Python3 find module
# 3.14+ for object library link dependency propagation
# 3.18+ for OpenSSL::applink
cmake_minimum_required(VERSION 3.18)

# contact email, other info
include(cmake/info.cmake)

# determine version
if (NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/cmake/version.cmake")
  file(DOWNLOAD https://raw.githubusercontent.com/rnpgp/cmake-versioning/main/version.cmake
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/version.cmake")
endif()
include(cmake/version.cmake)
determine_version("${CMAKE_CURRENT_SOURCE_DIR}" RNP)

# project name, etc
project(RNP
  VERSION "${RNP_VERSION}"
  LANGUAGES C CXX
  DESCRIPTION "${PACKAGE_DESCRIPTION_SHORT}"
)

# tri-state options
set(TRISTATE_VALUES On Off Auto)

# options
option(ENABLE_COVERAGE "Enable code coverage testing.")
option(ENABLE_SANITIZERS "Enable ASan and other sanitizers.")
option(ENABLE_FUZZERS "Enable fuzz targets.")
option(DOWNLOAD_GTEST "Download Googletest" On)
option(SYSTEM_LIBSEXPP "Use system sexpp library" OFF)

# crypto components
function(tristate_feature_auto NAME DESCRIPTION)
  set(${NAME} Auto CACHE STRING ${DESCRIPTION})
  set_property(CACHE ${NAME} PROPERTY STRINGS ${TRISTATE_VALUES})
endfunction()
set(ENABLE_SM2 Auto CACHE STRING "Enable SM2/SM3/SM4 algorithms support.")
set_property(CACHE ENABLE_SM2 PROPERTY STRINGS ${TRISTATE_VALUES})
set(ENABLE_AEAD Auto CACHE STRING "Enable AEAD ciphers support.")
set_property(CACHE ENABLE_AEAD PROPERTY STRINGS ${TRISTATE_VALUES})
set(ENABLE_TWOFISH Auto CACHE STRING "Enable Twofish cipher support.")
set_property(CACHE ENABLE_TWOFISH PROPERTY STRINGS ${TRISTATE_VALUES})
set(ENABLE_BRAINPOOL Auto CACHE STRING "Enable Brainpool curves support.")
set_property(CACHE ENABLE_BRAINPOOL PROPERTY STRINGS ${TRISTATE_VALUES})
set(ENABLE_IDEA Auto CACHE STRING "Enable IDEA algorithm support.")
set_property(CACHE ENABLE_IDEA PROPERTY STRINGS ${TRISTATE_VALUES})
tristate_feature_auto(ENABLE_BLOWFISH "Enable Blowfish cipher support.")
tristate_feature_auto(ENABLE_CAST5 "Enable CAST5 cipher support.")
tristate_feature_auto(ENABLE_RIPEMD160 "Enable RIPEMD-160 hash support.")

option(ENABLE_CRYPTO_REFRESH "Enable crypto-refresh support (v6)")
option(ENABLE_PQC "Enable PQC support")

# Note: The following two flags are only temporary and will be removed once POC is in a stable state
if (DEFINED ENABLE_PQC_MLKEM_IPD)
  add_definitions(-DENABLE_PQC_MLKEM_IPD)
endif()
if (DEFINED ENABLE_PQC_DBG_LOG)
  add_definitions(-DENABLE_PQC_DBG_LOG)
endif()

set(ENABLE_DOC Auto CACHE STRING "Enable building documentation.")
set_property(CACHE ENABLE_DOC PROPERTY STRINGS ${TRISTATE_VALUES})

# so we can use our bundled finders
set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake/Modules")

# add source path prefix length to be able to crop it in logs
string(LENGTH "${CMAKE_SOURCE_DIR}/" SOURCE_PATH_SIZE)
add_definitions("-DSOURCE_PATH_SIZE=${SOURCE_PATH_SIZE}")

# required modules
include(CTest)
include(FetchContent)

# default to a release build
if (NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING
    "Build type. Options are: None Debug Release RelWithDebInfo MinSizeRel."
    FORCE
  )
endif()

# crypto backend
if (NOT CRYPTO_BACKEND)
  set(CRYPTO_BACKEND "botan" CACHE STRING
    "Crypto backend. Possible values are botan and openssl. Default is botan."
    FORCE
  )
endif()
string(TOLOWER ${CRYPTO_BACKEND} CRYPTO_BACKEND_LOWERCASE)
if(CRYPTO_BACKEND_LOWERCASE STREQUAL "botan")
  # Default value; version 2 or 3 of Botan
  set(CRYPTO_BACKEND_BOTAN 1)
elseif(CRYPTO_BACKEND_LOWERCASE STREQUAL "botan3")
  set(CRYPTO_BACKEND "botan")
  set(CRYPTO_BACKEND_LOWERCASE "botan")
  # Require version 3 of Botan
  set(CRYPTO_BACKEND_BOTAN 1)
  set(CRYPTO_BACKEND_BOTAN3 1)
elseif(CRYPTO_BACKEND_LOWERCASE STREQUAL "openssl")
  set(CRYPTO_BACKEND_OPENSSL 1)
else()
  message(FATAL_ERROR "Invalid crypto backend: ${CRYPTO_BACKEND}")
endif()

if(MSVC)
  # This works both for MSVC and CL on Windows
  # Recent version of MSVC toolset issues c++17 deprecation warning even if we use /std:c++11
  add_compile_definitions(
    _CRT_SECURE_NO_WARNINGS
    _CRT_NONSTDC_NO_DEPRECATE
    _SILENCE_CXX17_C_HEADER_DEPRECATION_WARNING
  )
else(MSVC)
  # set warning flags at the top level
  add_compile_options(
    -Wall -Wextra
    -Wunreachable-code -Wpointer-arith
    -Wmissing-declarations
  )
# relax some warnings a bit
  add_compile_options(
    -Wno-pedantic
    -Wno-ignored-qualifiers
    -Wno-unused-parameter
    -Wno-missing-field-initializers
  )
endif(MSVC)

# set a few other things at the top level to prevent incompatibilities
set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
add_definitions(-D_GNU_SOURCE)

if((ENABLE_COVERAGE OR ENABLE_SANITIZERS) AND NOT GENERATOR_IS_MULTI_CONFIG)
  message("Forcing build type to Debug (for code coverage or sanitizers).")
  set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type. Forced to Debug." FORCE)
endif((ENABLE_COVERAGE OR ENABLE_SANITIZERS) AND NOT GENERATOR_IS_MULTI_CONFIG)

# coverage
if(ENABLE_COVERAGE)
  if(NOT CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    message(FATAL_ERROR "Coverage has only been tested with the GNU compiler.")
  endif()
  add_compile_options(--coverage -O0)
  link_libraries(--coverage)
endif(ENABLE_COVERAGE)

# sanitizers
if(ENABLE_SANITIZERS)
  if(MSVC)
    add_compile_options(/fsanitize=address /Zi "$<$<CONFIG:Release>:/MT>" "$<$<CONFIG:Debug>:/MTd>")
    add_link_options(/INCREMENTAL:NO /DEBUG)
  elseif (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    add_compile_options(-fsanitize=leak,address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer -fno-common -O1)
    link_libraries(-fsanitize=leak,address,undefined)
  else()
    message(FATAL_ERROR "Sanitizers have only been tested with the Clang compiler or Microsoft Visual Studio.")
  endif()
endif(ENABLE_SANITIZERS)

# adoc for man generation
if (ENABLE_DOC)
  include(AdocMan)
endif()

# make sure that msvc set full path in __FILE__ macro
if(MSVC)
  add_compile_options(/FC)
endif()

# everything else is in subdirs
add_subdirectory(src/examples)
if (ENABLE_FUZZERS)
  add_subdirectory(src/fuzzing)
  add_compile_options(-DFUZZERS_ENABLED=1)
endif()
add_subdirectory(src/common)

if (SYSTEM_LIBSEXPP)
  find_package(PkgConfig QUIET)
  pkg_check_modules(SEXPP sexpp>=0.8.7 REQUIRED)
  find_library(SEXPP_LIBRARY
    NAMES
      "libsexpp"
      "sexpp"
    HINTS
      "${SEXPP_LIBRARY_DIRS}"
  )
  add_library(sexpp UNKNOWN IMPORTED)
  set_target_properties(sexpp
    PROPERTIES
      INTERFACE_INCLUDE_DIRECTORIES "${SEXPP_INCLUDE_DIR}"
      IMPORTED_LINK_INTERFACE_LANGUAGES "CXX"
      IMPORTED_LOCATION "${SEXPP_LIBRARY}"
  )
else (SYSTEM_LIBSEXPP)
# If we use system libsexpp is not used we build sexpp static library
# If librnp is shared, libsexpp.a is a transient artifact which is hidden from
# the end user.
# If librnp is static we install libsexpp.a aside
  set(SAVED_BUILD_SHARED_LIBS ${BUILD_SHARED_LIBS})
  set(BUILD_SHARED_LIBS OFF)
  set(WITH_SEXP_CLI OFF)
  set(WITH_SEXP_TESTS OFF)
  set(CMAKE_INSTALL_DEFAULT_COMPONENT_NAME development)
  add_subdirectory(src/libsexpp EXCLUDE_FROM_ALL)
  set(BUILD_SHARED_LIBS ${SAVED_BUILD_SHARED_LIBS})
endif (SYSTEM_LIBSEXPP)

add_subdirectory(src/lib)
add_subdirectory(src/rnp)
add_subdirectory(src/rnpkeys)

# build tests, if desired
if (BUILD_TESTING)
  # Googletest source path
  if (NOT GTEST_SOURCES)
    set(GTEST_SOURCES "" CACHE STRING
    "Path to the Googletest sources in case of download or linking to the precompiled library is disabled."
    FORCE
    )
  else()
    # Canonicalize path to the Googletest sources.
    get_filename_component(GTEST_SOURCES_FULL ${GTEST_SOURCES} REALPATH)
    set(GTEST_SOURCES ${GTEST_SOURCES_FULL})
  endif()
  add_subdirectory(src/tests)
endif()


# cpack packaging (RPM etc)
include(cmake/packaging.cmake)
