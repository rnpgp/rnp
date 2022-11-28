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
# DownloadSexp
# -----------
#
# Downloads and builds the sexp library with FetchContent.
#
# IMPORTED Targets
# ^^^^^^^^^^^^^^^^
#
# This module defines :prop_tgt:`IMPORTED` targets:
#
# ``Sexp::Sexp``
#   The sexp library
#
# Result variables
# ^^^^^^^^^^^^^^^^
#
# This module defines the following variables:
#
# ::
#
#   SEXP_FOUND          - true if the headers and library were found
#   SEXP_INCLUDE_DIR    - where to find headers
#   SEXP_LIBRARY        - a library to link
#   SEXP_VERSION        - library version that was found, if any

FetchContent_Declare(sexp
GIT_REPOSITORY  https://github.com/rnpgp/sexp.git
GIT_TAG         v0.6.0
)

set(WITH_SEXP_TESTS OFF CACHE BOOL "" FORCE)
set(WITH_SEXP_CLI OFF CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(sexp)

set(SEXP_FOUND true)
set(SEXP_VERSION "v0.6.0")
set(SEXP_INCLUDE_DIR "${sexp_SOURCE_DIR}/include")
if(MSVC)
  set(SEXP_LIBRARY "${sexp_BINARY_DIR}/${CMAKE_BUILD_TYPE}/sexp.lib")
else(MSVC)
  set(SEXP_LIBRARY "${sexp_BINARY_DIR}/libsexp.a")
endif(MSVC)

add_library(Sexp::Sexp UNKNOWN IMPORTED)
# set the required include dirs for the target
set_target_properties(Sexp::Sexp
PROPERTIES
  INTERFACE_INCLUDE_DIRECTORIES "${sexp_SOURCE_DIR}/include"
)
set_target_properties(Sexp::Sexp
PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES "CXX"
  IMPORTED_LOCATION "${SEXP_LIBRARY}"
)
mark_as_advanced(SEXP_INCLUDE_DIR SEXP_LIBRARY)
