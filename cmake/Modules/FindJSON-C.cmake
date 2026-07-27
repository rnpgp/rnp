# Copyright (c) 2018, 2024 Ribose Inc.
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

#.rst:
# FindJSON-C
# -----------
#
# Find the json-c library.
#
# IMPORTED Targets
# ^^^^^^^^^^^^^^^^
#
# This module defines :prop_tgt:`IMPORTED` targets:
#
# ``JSON-C::JSON-C``
#   The json-c library, if found.
#
# Result variables
# ^^^^^^^^^^^^^^^^
#
# This module defines the following variables:
#
# ::
#
#   JSON-C_FOUND          - true if the headers and library were found
#   JSON-C_INCLUDE_DIRS   - where to find headers
#   JSON-C_LIBRARIES      - list of libraries to link
#   JSON-C_VERSION        - library version that was found, if any

# Use pkg-config to discover json-c on the host. When cross-compiling,
# pkg-config's compiled-in paths target the host root and would discover
# host-installed json-c even when CMAKE_FIND_ROOT_PATH is set. Callers who
# want pkg-config-driven discovery under cross-compile can force it on with
# -DJSON-C_USE_PKGCONFIG=ON and set PKG_CONFIG_LIBDIR / PKG_CONFIG_SYSROOT_DIR.
option(JSON-C_USE_PKGCONFIG "Use pkg-config to discover json-c" OFF)
if(NOT JSON-C_USE_PKGCONFIG AND NOT CMAKE_CROSSCOMPILING)
  find_package(PkgConfig QUIET)
endif()

if(PKG_CONFIG_FOUND)
  pkg_check_modules(PC_JSON-C QUIET json-c)
endif()

# RHEL-based systems may have json-c12
if(PKG_CONFIG_FOUND AND NOT PC_JSON-C_FOUND)
  pkg_check_modules(PC_JSON-C QUIET json-c12)
endif()

# ..or even json-c13, accompanied by non-develop json-c (RHEL 8 ubi)
if(PKG_CONFIG_FOUND AND NOT PC_JSON-C_FOUND)
  pkg_check_modules(PC_JSON-C QUIET json-c13)
endif()

if(DEFINED JSON-C_ROOT_DIR)
  set(_hints_include "${JSON-C_ROOT_DIR}/include")
  set(_hints_lib "${JSON-C_ROOT_DIR}/lib")
endif()
if(DEFINED ENV{JSON-C_ROOT_DIR})
  list(APPEND _hints_include "$ENV{JSON-C_ROOT_DIR}/include")
  list(APPEND _hints_lib "$ENV{JSON-C_ROOT_DIR}/lib")
endif()
# When cross-compiling, prepend CMAKE_FIND_ROOT_PATH entries so find_path /
# find_library look inside the target sysroot.
if(CMAKE_CROSSCOMPILING)
  foreach(_root ${CMAKE_FIND_ROOT_PATH})
    list(APPEND _hints_include "${_root}/include")
    list(APPEND _hints_lib "${_root}/lib")
  endforeach()
  set(_no_system_path "NO_CMAKE_SYSTEM_PATH")
endif()

# find the headers
find_path(JSON-C_INCLUDE_DIR
  NAMES json_c_version.h
  HINTS
    ${_hints_include}
    ${PC_JSON-C_INCLUDEDIR}
    ${PC_JSON-C_INCLUDE_DIRS}
  PATH_SUFFIXES json-c json-c12 json-c13
  ${_no_system_path}
)

# find the library
find_library(JSON-C_LIBRARY
  NAMES json-c libjson-c json-c12 libjson-c12 json-c13 libjson-c13
  HINTS
    ${_hints_lib}
    ${PC_JSON-C_LIBDIR}
    ${PC_JSON-C_LIBRARY_DIRS}
  ${_no_system_path}
)

# determine the version
if(PC_JSON-C_VERSION)
    set(JSON-C_VERSION ${PC_JSON-C_VERSION})
elseif(JSON-C_INCLUDE_DIR AND EXISTS "${JSON-C_INCLUDE_DIR}/json_c_version.h")
    file(STRINGS "${JSON-C_INCLUDE_DIR}/json_c_version.h" _json-c_version_h
      REGEX "^#define[\t ]+JSON_C_VERSION[\t ]+\"[^\"]*\"$")

    string(REGEX REPLACE ".*#define[\t ]+JSON_C_VERSION[\t ]+\"([^\"]*)\".*"
      "\\1" _json-c_version_str "${_json-c_version_h}")
    set(JSON-C_VERSION "${_json-c_version_str}"
                       CACHE INTERNAL "The version of json-c which was detected")
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(JSON-C
  REQUIRED_VARS JSON-C_LIBRARY JSON-C_INCLUDE_DIR JSON-C_VERSION
  VERSION_VAR JSON-C_VERSION
)

if (JSON-C_FOUND)
  set(JSON-C_INCLUDE_DIRS ${JSON-C_INCLUDE_DIR} ${PC_JSON-C_INCLUDE_DIRS})
  set(JSON-C_LIBRARIES ${JSON-C_LIBRARY})
endif()

if (JSON-C_FOUND AND NOT TARGET JSON-C::JSON-C)
  # create the new library target
  add_library(JSON-C::JSON-C UNKNOWN IMPORTED)
  # set the required include dirs for the target
  if (JSON-C_INCLUDE_DIRS)
    set_target_properties(JSON-C::JSON-C
      PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES "${JSON-C_INCLUDE_DIRS}"
    )
  endif()
  # set the required libraries for the target
  if (EXISTS "${JSON-C_LIBRARY}")
    set_target_properties(JSON-C::JSON-C
      PROPERTIES
        IMPORTED_LINK_INTERFACE_LANGUAGES "C"
        IMPORTED_LOCATION "${JSON-C_LIBRARY}"
    )
  endif()
endif()

mark_as_advanced(JSON-C_INCLUDE_DIR JSON-C_LIBRARY)
