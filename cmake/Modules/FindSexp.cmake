# Copyright (c) 2022 Ribose Inc.
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
# FindSexp
# -----------
#
# Find the botan-2 library.
#
# IMPORTED Targets
# ^^^^^^^^^^^^^^^^
#
# This module defines :prop_tgt:`IMPORTED` targets:
#
# ``Sexp::Sexp``
#   The botan-2 library, if found.
#
# Result variables
# ^^^^^^^^^^^^^^^^
#
# This module defines the following variables:
#
# ::
#
#   SEXP_FOUND          - true if the headers and library were found
#   SEXP_INCLUDE_DIRS   - where to find headers
#   SEXP_LIBRARIES      - list of libraries to link
#   SEXP_VERSION        - library version that was found, if any

# use pkg-config to get the directories and then use these values
# in the find_path() and find_library() calls
find_package(PkgConfig QUIET)
pkg_check_modules(PC_SEXP QUIET sexp)

# find the headers
find_path(SEXP_INCLUDE_DIR
  NAMES sexp/sexp.h
  HINTS
    ${PC_SEXP_INCLUDEDIR}
  PATH_SUFFIXES sexp
)

# find the library
find_library(SEXP_LIBRARY
  NAMES sexp
  HINTS
    ${PC_SEXP_LIBRARY_DIR}
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Sexp
  REQUIRED_VARS SEXP_LIBRARY SEXP_INCLUDE_DIR
  VERSION_VAR SEXP_VERSION
)

if (SEXP_FOUND)
  set(SEXP_VERSION ${PC_SEXP_VERSION})
  set(SEXP_INCLUDE_DIRS ${SEXP_INCLUDE_DIR})
  set(SEXP_LIBRARIES ${SEXP_LIBRARY})
endif()

if (SEXP_FOUND AND NOT TARGET Sexp::Sexp)
  # create the new library target
  add_library(Sexp::Sexp UNKNOWN IMPORTED)
  # set the required include dirs for the target
  if (SEXP_INCLUDE_DIRS)
    set_target_properties(Sexp::Sexp
      PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES "${SEXP_INCLUDE_DIRS}"
    )
  endif()
  # set the required libraries for the target
  if (EXISTS "${SEXP_LIBRARY}")
    set_target_properties(Sexp::Sexp
      PROPERTIES
        IMPORTED_LINK_INTERFACE_LANGUAGES "CXX"
        IMPORTED_LOCATION "${SEXP_LIBRARY}"
    )
  endif()
endif()

mark_as_advanced(SEXP_INCLUDE_DIR SEXP_LIBRARY)
