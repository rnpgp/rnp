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

#.adoc:
# add_adoc_man
# -----------
#
# Convert adoc manual page to troff and install it via the custom target.
#
# Parameters
# ^^^^^^^^^^
# Required parameter is source with markdown file. Must have md extension with man category prepended, i.e. something like ${CMAKE_SOURCE_DIR}/src/utility.1.adoc
# DST - optional parameter, which overrides where generated man will be stored.
# If not specified then will be automatically set to ${CMAKE_BINARY_DIR}/src/utility.1
#
# Generated man page will be installed via the target, named man_utility
#

set(ADOCCOMMAND_FOUND 0)
set(ADOC_BACKEND "")
set(ADOC_MANPAGE_XSL "${CMAKE_CURRENT_LIST_DIR}/adoc-manpage.xsl")

# Man page generation supports two toolchains (#2395):
#  - asciidoctor with its native `manpage` backend (preferred, no extra deps);
#  - classic Python asciidoc (asciidoc-py) which has no manpage backend:
#    it goes through docbook XML and xsltproc/docbook-xsl instead
#    (the same a2x pipeline git uses). cmake/Modules/adoc-manpage.xsl
#    supplements stock docbook-xsl with the `<?asciidoc-br?>` handling
#    and suppressions a2x's bundled sheet applies.
find_program(ADOCCOMMAND_PATH
  NAMES asciidoctor
  DOC "Path to AsciiDoc processor. Used to generate man pages from AsciiDoc."
)
find_program(ADOC_ASCIIDOC_PATH
  NAMES asciidoc
  DOC "Path to classic Python asciidoc processor (man pages via docbook + xsltproc)."
)
find_program(ADOC_XSLTPROC_PATH
  NAMES xsltproc
  DOC "Path to xsltproc. Used with the asciidoc docbook backend to build man pages."
)

# Escape hatch for packagers who wire up a custom processor. Setting
# ASCIIDOC_TOOL=asciidoc selects the docbook+xsltproc backend; any other
# value must be a processor supporting -b manpage (e.g. a vendored
# asciidoctor under a different name).
if(DEFINED ASCIIDOC_TOOL)
  if("${ASCIIDOC_TOOL}" STREQUAL "asciidoc")
    set(ADOC_BACKEND "asciidoc")
    find_program(ADOC_ASCIIDOC_PATH
      NAMES ${ASCIIDOC_TOOL}
      DOC "Path to asciidoc processor (forced via ASCIIDOC_TOOL=${ASCIIDOC_TOOL})."
    )
  else()
    set(ADOC_BACKEND "asciidoctor")
    find_program(ADOCCOMMAND_PATH
      NAMES ${ASCIIDOC_TOOL}
      DOC "Path to AsciiDoc processor (forced via ASCIIDOC_TOOL=${ASCIIDOC_TOOL})."
    )
  endif()
elseif(ADOCCOMMAND_PATH)
  set(ADOC_BACKEND "asciidoctor")
elseif(ADOC_ASCIIDOC_PATH AND ADOC_XSLTPROC_PATH)
  set(ADOC_BACKEND "asciidoc")
endif()

if("${ADOC_BACKEND}" STREQUAL "asciidoc")
  if(NOT ADOC_ASCIIDOC_PATH OR NOT ADOC_XSLTPROC_PATH)
    message(FATAL_ERROR "ASCIIDOC_TOOL=asciidoc requires both asciidoc and xsltproc (plus the docbook-xsl stylesheets registered in the XML catalog).")
  endif()
  set(ADOCCOMMAND_FOUND 1)
elseif("${ADOC_BACKEND}" STREQUAL "asciidoctor")
  if(NOT EXISTS ${ADOCCOMMAND_PATH})
    set(ADOC_BACKEND "")
  else()
    set(ADOCCOMMAND_FOUND 1)
  endif()
endif()

if(NOT ADOC_BACKEND)
  if(EXISTS "${CMAKE_SOURCE_DIR}/docs/man")
    set(ADOC_USING_CACHE 1)
    set(ADOC_MISSING_MSG "No AsciiDoc toolchain found (asciidoctor, or asciidoc + xsltproc); installing pre-generated man pages from docs/man/. Refresh them with ci/regen-man-pages.sh when the .adoc sources change.")
  else()
    set(ADOC_MISSING_MSG "No AsciiDoc toolchain found (asciidoctor, or asciidoc + xsltproc) and no pre-generated man pages in docs/man/. Install a toolchain, or refresh the cache with ci/regen-man-pages.sh on a machine that has one.")
  endif()

  string(TOLOWER "${ENABLE_DOC}" ENABLE_DOC)
  if (ENABLE_DOC STREQUAL "auto")
    message(STATUS ${ADOC_MISSING_MSG})
  elseif(ENABLE_DOC AND NOT ADOC_USING_CACHE)
    message(FATAL_ERROR ${ADOC_MISSING_MSG})
  endif()
else()
  message(STATUS "Man pages: ${ADOC_BACKEND} backend")
endif()

function(add_adoc_man SRC COMPONENT_VERSION)
  if (NOT ${ADOCCOMMAND_FOUND} AND NOT ${ADOC_USING_CACHE})
    return()
  endif()

  cmake_parse_arguments(
    ARGS
    ""
    "DST"
    ""
    ${ARGN}
  )

  set(ADOC_EXT ".adoc")
  get_filename_component(FILE_NAME ${SRC} NAME)

  # The following procedures check against the expected file name
  # pattern: "{name}.{man-number}.adoc", and builds to a
  # destination file "{name}.{man-number}".

  # Check SRC extension
  get_filename_component(END_EXT ${SRC} LAST_EXT)
  string(COMPARE EQUAL ${END_EXT} ${ADOC_EXT} _equal)
  if (NOT _equal)
    message(FATAL_ERROR "SRC must have ${ADOC_EXT} extension.")
  endif()

  # Check man number
  get_filename_component(EXTS ${SRC} EXT)
  string(REGEX MATCH "^\.([1-9])\.+$" _matches ${EXTS})
  set(MAN_NUM ${CMAKE_MATCH_1})
  if (NOT _matches)
    message(FATAL_ERROR "Man file with wrong name pattern: ${FILE_NAME} must be in format {name}.[0-9]${ADOC_EXT}.")
  endif()

  # Set target name
  get_filename_component(TARGET_NAME ${SRC} NAME_WE)
  string(PREPEND TARGET_NAME "man_")

  # Build output path if not specified.
  if(NOT DST)
    get_filename_component(SRC_PREFIX ${SRC} DIRECTORY)

    # Ensure that SRC_PREFIX is within CMAKE_SOURCE_DIR
    if(NOT(SRC_PREFIX MATCHES "^${CMAKE_SOURCE_DIR}"))
      message(FATAL_ERROR "Cannot build DST path as SRC is outside of the CMake sources dir.")
    endif()
    STRING(REGEX REPLACE "^${CMAKE_SOURCE_DIR}/" "" SUBDIR_PATH ${SRC})

    # Strip '.adoc' from the output subpath
    get_filename_component(SUBDIR_PATH_NAME_WLE ${SUBDIR_PATH} NAME_WLE)
    get_filename_component(SUBDIR_PATH_DIRECTORY ${SUBDIR_PATH} DIRECTORY)
    set(DST "${CMAKE_BINARY_DIR}/${SUBDIR_PATH_DIRECTORY}/${SUBDIR_PATH_NAME_WLE}")
  endif()

  # Check conformance of destination file name to pattern
  get_filename_component(FILE_NAME_WE ${SRC} NAME_WE)
  get_filename_component(MAN_FILE_NAME ${DST} NAME)
  if(NOT(MAN_FILE_NAME MATCHES "^${FILE_NAME_WE}.${MAN_NUM}$"))
    message(FATAL_ERROR "File name of a man page must be in the format {name}.{man-number}${ADOC_EXT}.")
  endif()

  # Pre-generated roff cache: docs/man/{name}.{man-number}, refreshed via
  # ci/regen-man-pages.sh and shipped in the repo / release archives, so
  # packagers don't need asciidoctor installed (#2395).
  set(MAN_CACHE "${CMAKE_SOURCE_DIR}/docs/man/${FILE_NAME_WE}.${MAN_NUM}")

  if("${ADOC_BACKEND}" STREQUAL "asciidoctor")
    add_custom_command(
      OUTPUT ${DST}
      # Options must precede the source file: asciidoctor accepts any order,
      # but classic asciidoc treats anything after the first non-option
      # argument as additional input files ("Too many arguments").
      COMMAND ${ADOCCOMMAND_PATH} -b manpage -a component-version=${COMPONENT_VERSION} -o ${DST} ${SRC}
      DEPENDS ${SRC}
      WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
      COMMENT "Generating man page ${SUBDIR_PATH_DIRECTORY}/${SUBDIR_PATH_NAME_WLE}"
      VERBATIM
    )
  elseif("${ADOC_BACKEND}" STREQUAL "asciidoc")
    # docbook-xsl names its output file after the first refname of the NAME
    # section, not after the source file, so the refname must equal the
    # source file base name for the output to land on ${DST}.
    file(READ ${SRC} ADOC_SRC)
    string(REGEX MATCH "== NAME[^\n]*\n[^\n]*\n+[ \t]*([A-Za-z0-9_.+-]+)[ \t]+-" ADOC_NAME_MATCH "${ADOC_SRC}")
    set(ADOC_REFNAME "${CMAKE_MATCH_1}")
    if(NOT ADOC_REFNAME)
      message(FATAL_ERROR "Cannot find the NAME section in ${FILE_NAME}; it is required for man page generation.")
    endif()
    if(NOT ADOC_REFNAME STREQUAL FILE_NAME_WE)
      message(FATAL_ERROR "The NAME section of ${FILE_NAME} must start with '${FILE_NAME_WE}' (found '${ADOC_REFNAME}'): docbook-xsl names the man page after the first refname.")
    endif()

    set(ADOC_XML "${DST}.xml")
    get_filename_component(DST_DIR ${DST} DIRECTORY)
    # xsltproc resolves the stylesheet's docbook-xsl import through the system
    # XML catalog (/etc/xml/catalog), where distro docbook-xsl packages
    # register it; --nonet fails fast when the catalog is missing.
    add_custom_command(
      OUTPUT ${DST}
      COMMAND ${ADOC_ASCIIDOC_PATH} -b docbook -d manpage -a component-version=${COMPONENT_VERSION} -o ${ADOC_XML} ${SRC}
      COMMAND ${ADOC_XSLTPROC_PATH} --nonet ${ADOC_MANPAGE_XSL} ${ADOC_XML}
      COMMAND ${CMAKE_COMMAND} -E remove ${ADOC_XML}
      DEPENDS ${SRC} ${ADOC_MANPAGE_XSL}
      WORKING_DIRECTORY ${DST_DIR}
      COMMENT "Generating man page ${SUBDIR_PATH_DIRECTORY}/${SUBDIR_PATH_NAME_WLE} (asciidoc backend)"
      VERBATIM
    )
  elseif(EXISTS ${MAN_CACHE})
    add_custom_command(
      OUTPUT ${DST}
      COMMAND ${CMAKE_COMMAND} -E copy_if_different ${MAN_CACHE} ${DST}
      DEPENDS ${MAN_CACHE}
      COMMENT "Installing pre-generated man page ${SUBDIR_PATH_DIRECTORY}/${SUBDIR_PATH_NAME_WLE} (from docs/man)"
      VERBATIM
    )
  else()
    message(WARNING "No AsciiDoc processor and no cached man page for ${FILE_NAME}; skipping it.")
    return()
  endif()

  add_custom_target("${TARGET_NAME}" ALL DEPENDS ${DST})
  install(FILES ${DST}
    DESTINATION "${CMAKE_INSTALL_FULL_MANDIR}/man${MAN_NUM}"
    COMPONENT doc
  )
endfunction(add_adoc_man)
