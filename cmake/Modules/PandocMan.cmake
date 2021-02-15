# Copyright (c) 2021 Ribose Inc.
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
# add_pandoc_man
# -----------
#
# Convert markdown manual page to troff, using the pandoc, and install it via the custom target.
#
# Parameters
# ^^^^^^^^^^
# Required parameter is source with markdown file. Must have md extension with man category prepended, i.e. something like ${CMAKE_SOURCE_DIR}/src/utility.1.md
# DST - optional parameter, which overrides where generated man will be stored.
# If not specified then will be automatically set to ${CMAKE_BINARY_DIR}/src/utility.1
# 
# Generated man page will be installed via the target, named man_utility
#

set(PANDOC_FOUND 0)
find_program(PANDOC_PATH
  NAMES pandoc
  DOC "Path to the pandoc application. Used to generate man pages from the markdown."
)

if(NOT EXISTS ${PANDOC_PATH})
  message(WARNING "Pandoc not found, man pages will not be generated. Install pandoc or use CMAKE_PROGRAM_PATH variable.")
else()
  set(PANDOC_FOUND 1)
endif()

function(add_pandoc_man SRC)
  if (NOT ${PANDOC_FOUND})
    return()
  endif()

  cmake_parse_arguments(
    ARGS
    ""
    "DST"
    ""
    ${ARGN}
  )

  if(ARGS_DST)
    set(DST ${ARGS_DST})
  endif()

  # Extract man number and check SRC extension
  get_filename_component(FULL_EXT ${SRC} EXT)
  string(SUBSTRING ${FULL_EXT} 1 -1 FULL_EXT)
  get_filename_component(MD_EXT ${FULL_EXT} EXT)
  string(COMPARE EQUAL ${MD_EXT} ".md" _equal)
  if (NOT _equal)
    message(FATAL_ERROR "SRC must have .md extension.")
  endif()
  # man number
  get_filename_component(MAN_NUM ${FULL_EXT} NAME_WE)
  string(REGEX MATCH "^[1-9]$" _matches ${MAN_NUM})
  if (NOT _matches)
    message(FATAL_ERROR "Wrong man category: \"${MAN_NUM}\".")
  endif()
  # man name
  get_filename_component(FILE_NAME ${SRC} NAME_WE)
  get_filename_component(TARGET_NAME ${SRC} NAME_WE)
  string(PREPEND TARGET_NAME "man_")

  # Build output path if not specified.
  if(NOT DST)
    string(LENGTH ${CMAKE_SOURCE_DIR} CMAKE_SRC_LEN)
    string(SUBSTRING ${SRC} 0 ${CMAKE_SRC_LEN} SRC_PREFIX)
    string(COMPARE EQUAL ${CMAKE_SOURCE_DIR} ${SRC_PREFIX} _equal)
    if (NOT _equal)
      message(FATAL_ERROR "Cannot build DST path as SRC is out of CMake sources dir.")
    endif()
    
    # Strip '.md' from the output subpath
    string(LENGTH ${SRC} SRC_LEN)
    math(EXPR SUFFIX_LEN "${SRC_LEN} - ${CMAKE_SRC_LEN} - 3")
    string(SUBSTRING ${SRC} ${CMAKE_SRC_LEN} ${SUFFIX_LEN} SRC_SUFFIX)
    set(DST "${CMAKE_BINARY_DIR}${SRC_SUFFIX}")
  endif()

  add_custom_command(
    OUTPUT ${DST}
    COMMAND ${PANDOC_PATH} -s -t man ${SRC} -o ${DST}
    DEPENDS ${SRC}
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Generating man page ${FILE_NAME}.${MAN_NUM}"
    VERBATIM
  )
  add_custom_target("${TARGET_NAME}" ALL DEPENDS ${DST})
  install(FILES ${DST}
    DESTINATION "${CMAKE_INSTALL_FULL_MANDIR}/man${MAN_NUM}"
    COMPONENT doc
  )
endfunction(add_pandoc_man)
