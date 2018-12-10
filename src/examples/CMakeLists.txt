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

add_executable(generate generate.c)
set_target_properties(generate PROPERTIES LINKER_LANGUAGE C)

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
set_target_properties(encrypt PROPERTIES LINKER_LANGUAGE C)

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
set_target_properties(decrypt PROPERTIES LINKER_LANGUAGE C)

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
set_target_properties(sign PROPERTIES LINKER_LANGUAGE C)

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
set_target_properties(verify PROPERTIES LINKER_LANGUAGE C)

target_include_directories(verify
  PRIVATE
    "${PROJECT_SOURCE_DIR}/src"
    "${PROJECT_SOURCE_DIR}/src/lib"
)

target_link_libraries(verify
  PRIVATE
    librnp
)
