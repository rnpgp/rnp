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

include(GNUInstallDirs)
include(GenerateExportHeader)

# these could probably be optional but are currently not
find_package(BZip2 REQUIRED)
find_package(ZLIB REQUIRED)

# required packages
find_package(JSON-C 0.11 REQUIRED)
if (CRYPTO_BACKEND_BOTAN3)
  find_package(Botan 3.0.0 REQUIRED)
elseif (CRYPTO_BACKEND_BOTAN)
  find_package(Botan 2.14.0 REQUIRED)
  if(BOTAN_VERSION VERSION_GREATER_EQUAL 3.0.0)
    set(CRYPTO_BACKEND_BOTAN3 1)
  endif()
endif()
if (CRYPTO_BACKEND_OPENSSL)
  find_package(OpenSSL 1.1.1 REQUIRED)
  include(FindOpenSSLFeatures)
  if("${OPENSSL_VERSION}" VERSION_GREATER_EQUAL "3.0.0")
    set(CRYPTO_BACKEND_OPENSSL3 1)
  endif()
endif()

if(CRYPTO_BACKEND_BOTAN3)
  set(CMAKE_CXX_STANDARD 20)
endif()

# generate a config.h
include(CheckIncludeFileCXX)
include(CheckCXXSymbolExists)
check_include_file_cxx(fcntl.h HAVE_FCNTL_H)
check_include_file_cxx(inttypes.h HAVE_INTTYPES_H)
check_include_file_cxx(limits.h HAVE_LIMITS_H)
check_include_file_cxx(stdint.h HAVE_STDINT_H)
check_include_file_cxx(string.h HAVE_STRING_H)
check_include_file_cxx(sys/cdefs.h HAVE_SYS_CDEFS_H)
check_include_file_cxx(sys/cdefs.h HAVE_SYS_MMAN_H)
check_include_file_cxx(sys/resource.h HAVE_SYS_RESOURCE_H)
check_include_file_cxx(sys/stat.h HAVE_SYS_STAT_H)
check_include_file_cxx(sys/types.h HAVE_SYS_TYPES_H)
check_include_file_cxx(sys/param.h HAVE_SYS_PARAM_H)
check_include_file_cxx(unistd.h HAVE_UNISTD_H)
check_include_file_cxx(sys/wait.h HAVE_SYS_WAIT_H)
check_cxx_symbol_exists(mkdtemp "stdlib.h;unistd.h" HAVE_MKDTEMP)
check_cxx_symbol_exists(mkstemp "stdlib.h;unistd.h" HAVE_MKSTEMP)
check_cxx_symbol_exists(realpath stdlib.h HAVE_REALPATH)
check_cxx_symbol_exists(O_BINARY fcntl.h HAVE_O_BINARY)
check_cxx_symbol_exists(_O_BINARY fcntl.h HAVE__O_BINARY)
check_cxx_symbol_exists(_tempnam stdio.h HAVE__TEMPNAM)
set(HAVE_ZLIB_H "${ZLIB_FOUND}")
set(HAVE_BZLIB_H "${BZIP2_FOUND}")
# generate a version.h
configure_file(version.h.in version.h)

# Checks feature in CRYPTO_BACKEND and puts the result into variable whose name is stored in RESULT_VARNAME variable.
function(backend_has_feature FEATURE RESULT_VARNAME)
  if (CRYPTO_BACKEND_LOWERCASE STREQUAL "botan")
    check_cxx_symbol_exists("BOTAN_HAS_${FEATURE}" botan/build.h ${RESULT_VARNAME})
  else()
    message(STATUS "Looking for OpenSSL feature ${FEATURE}")
    OpenSSLHasFeature(${FEATURE} ${RESULT_VARNAME})
    if (${RESULT_VARNAME})
      message(STATUS "Looking for OpenSSL feature ${FEATURE} - found")
    endif()
    set(${RESULT_VARNAME} "${${RESULT_VARNAME}}" PARENT_SCOPE)
  endif()
endfunction()

function(resolve_feature_state RNP_FEATURE BACKEND_FEATURES)
  if (NOT ${RNP_FEATURE}) # User has explicitly disabled this feature
    return()
  endif()

  string(TOLOWER "${${RNP_FEATURE}}" ${RNP_FEATURE})
  if (${RNP_FEATURE} STREQUAL "auto")
    set(MESSAGE_TYPE "NOTICE")
    set(OUTCOME "Disabling")
  else() # User has explicitly enabled this feature
    set(MESSAGE_TYPE "FATAL_ERROR")
    set(OUTCOME "Aborting")
  endif()

  foreach(feature ${BACKEND_FEATURES})
    backend_has_feature("${feature}" _has_${feature})
    if (NOT _has_${feature})
      set(${RNP_FEATURE} Off CACHE STRING "Autodetected" FORCE)
      message(${MESSAGE_TYPE} "${RNP_FEATURE} requires ${CRYPTO_BACKEND} feature which is missing: ${feature}. ${OUTCOME}.")
      return()
    endif()
  endforeach()
  set(${RNP_FEATURE} On CACHE STRING "Autodetected" FORCE)
endfunction()

function(openssl_nope RNP_FEATURE REASON)
  if (NOT ${RNP_FEATURE}) # User has explicitly disabled this feature
    return()
  endif()

  string(TOLOWER "${${RNP_FEATURE}}" ${RNP_FEATURE})
  if (${RNP_FEATURE} STREQUAL "auto")
    set(MESSAGE_TYPE "NOTICE")
    set(OUTCOME "Disabling")
  else() # User has explicitly enabled this feature
    set(MESSAGE_TYPE "FATAL_ERROR")
    set(OUTCOME "Aborting")
  endif()

  set(${RNP_FEATURE} Off CACHE STRING "Auto -> Off as no support" FORCE)
  message(${MESSAGE_TYPE} "${RNP_FEATURE} doesn't work with OpenSSL backend (${REASON}). ${OUTCOME}.")
endfunction()

if(CRYPTO_BACKEND_BOTAN)
  # check botan's enabled features
  set(CMAKE_REQUIRED_INCLUDES "${BOTAN_INCLUDE_DIRS}")
  set(_botan_required_features
      # base
      BIGINT FFI HEX_CODEC PGP_S2K
      # symmetric ciphers
      BLOCK_CIPHER AES CAMELLIA DES
      # cipher modes
      MODE_CBC MODE_CFB
      # RNG
      AUTO_RNG AUTO_SEEDING_RNG HMAC HMAC_DRBG
      # hash
      CRC24 HASH MD5 SHA1 SHA2_32 SHA2_64 SHA3
      # public-key core
      DL_GROUP ECC_GROUP ECC_PUBLIC_KEY_CRYPTO PUBLIC_KEY_CRYPTO # Botan-2: DL_PUBLIC_KEY_FAMILY Botan-3: DL_SCHEME, see switch below
      # public-key algs
      CURVE_25519 DSA ECDH ECDSA ED25519 ELGAMAL RSA
      # public-key operations etc
      EME_PKCS1v15 EMSA_PKCS1 EMSA_RAW KDF_BASE RFC3394_KEYWRAP SP800_56A
  )
  if(BOTAN_VERSION VERSION_LESS 3.0.0)
    set(_botan_required_features ${_botan_required_features} DL_PUBLIC_KEY_FAMILY)
  else()
    set(_botan_required_features ${_botan_required_features} DL_SCHEME RAW_HASH_FN)
  endif()
  foreach(feature ${_botan_required_features})
    check_cxx_symbol_exists("BOTAN_HAS_${feature}" botan/build.h _botan_has_${feature})
    if (NOT _botan_has_${feature})
      message(FATAL_ERROR "A required botan feature is missing: ${feature}")
    endif()
  endforeach()

  resolve_feature_state(ENABLE_SM2 "SM2;SM3;SM4")
  resolve_feature_state(ENABLE_AEAD "AEAD_EAX;AEAD_OCB")
  resolve_feature_state(ENABLE_TWOFISH "TWOFISH")
  resolve_feature_state(ENABLE_IDEA "IDEA")
  # Botan supports Brainpool curves together with SECP via the ECC_GROUP define
  resolve_feature_state(ENABLE_BLOWFISH "BLOWFISH")
  resolve_feature_state(ENABLE_CAST5 "CAST_128")
  resolve_feature_state(ENABLE_RIPEMD160 "RIPEMD_160")
  set(CMAKE_REQUIRED_INCLUDES)
endif()
if(CRYPTO_BACKEND_OPENSSL)
  # check OpenSSL features
  set(_openssl_required_features
    # symmetric ciphers
    AES-128-ECB AES-192-ECB AES-256-ECB AES-128-CBC AES-192-CBC AES-256-CBC
    AES-128-OCB AES-192-OCB AES-256-OCB
    CAMELLIA-128-ECB CAMELLIA-192-ECB CAMELLIA-256-ECB
    DES-EDE3
    # hashes
    MD5 SHA1 SHA224 SHA256 SHA384 SHA512 SHA3-256 SHA3-512
    # curves
    PRIME256V1 SECP384R1 SECP521R1 SECP256K1
    # public key
    RSAENCRYPTION DSAENCRYPTION DHKEYAGREEMENT ID-ECPUBLICKEY X25519 ED25519
  )
  foreach(feature ${_openssl_required_features})
    backend_has_feature("${feature}" _openssl_has_${feature})
    if (NOT _openssl_has_${feature})
      message(FATAL_ERROR "A required OpenSSL feature is missing: ${feature}")
    endif()
  endforeach()

  if (CRYPTO_BACKEND_OPENSSL3)
    backend_has_feature("LEGACY" CRYPTO_BACKEND_OPENSSL3_LEGACY)
  endif()

  resolve_feature_state(ENABLE_BRAINPOOL "BRAINPOOLP256R1;BRAINPOOLP384R1;BRAINPOOLP512R1")
  # Not all of the OpenSSL installations have legacy crypto provider
  resolve_feature_state(ENABLE_IDEA "IDEA-ECB;IDEA-CBC;LEGACY")
  resolve_feature_state(ENABLE_BLOWFISH "BF-ECB;LEGACY")
  resolve_feature_state(ENABLE_CAST5 "CAST5-ECB;LEGACY")
  if("${OPENSSL_VERSION}" VERSION_GREATER_EQUAL "3.0.7")
    resolve_feature_state(ENABLE_RIPEMD160 "RIPEMD160")
  else()
    resolve_feature_state(ENABLE_RIPEMD160 "RIPEMD160;LEGACY")
  endif()
  resolve_feature_state(ENABLE_AEAD "AES-128-OCB;AES-192-OCB;AES-256-OCB")
  openssl_nope(ENABLE_SM2 "it's on our roadmap, see https://github.com/rnpgp/rnp/issues/1877")
  #resolve_feature_state(ENABLE_SM2 "SM2;SM3;SM4-ECB")
  openssl_nope(ENABLE_TWOFISH "Twofish isn't and won't be supported by OpenSSL, see https://github.com/openssl/openssl/issues/2046")
endif()

configure_file(config.h.in config.h)

if(CRYPTO_BACKEND_OPENSSL)
  set(CRYPTO_SOURCES
    crypto/bn_ossl.cpp
    crypto/dsa_ossl.cpp
    crypto/ec_curves.cpp
    crypto/ec_ossl.cpp
    crypto/ecdh_utils.cpp
    crypto/ecdh_ossl.cpp
    crypto/ecdsa_ossl.cpp
    crypto/eddsa_ossl.cpp
    crypto/dl_ossl.cpp
    crypto/elgamal_ossl.cpp
    crypto/hash_common.cpp
    crypto/hash_ossl.cpp
    crypto/hash_crc24.cpp
    crypto/mpi.cpp
    crypto/rng_ossl.cpp
    crypto/rsa_ossl.cpp
    crypto/s2k.cpp
    crypto/s2k_ossl.cpp
    crypto/symmetric_ossl.cpp
    crypto/signatures.cpp
    crypto/mem_ossl.cpp
    crypto/cipher.cpp
    crypto/cipher_ossl.cpp
  )
  if(ENABLE_SM2)
    list(APPEND CRYPTO_SOURCES crypto/sm2_ossl.cpp)
  endif()
elseif(CRYPTO_BACKEND_BOTAN)
  set(CRYPTO_SOURCES
    crypto/bn.cpp
    crypto/dsa.cpp
    crypto/ec_curves.cpp
    crypto/ec.cpp
    crypto/ecdh_utils.cpp
    crypto/ecdh.cpp
    crypto/ecdsa.cpp
    crypto/eddsa.cpp
    crypto/elgamal.cpp
    crypto/hash_common.cpp
    crypto/hash.cpp
    crypto/mpi.cpp
    crypto/rng.cpp
    crypto/rsa.cpp
    crypto/s2k.cpp
    crypto/symmetric.cpp
    crypto/signatures.cpp
    crypto/mem.cpp
    crypto/cipher.cpp
    crypto/cipher_botan.cpp
  )
  if(ENABLE_SM2)
    list(APPEND CRYPTO_SOURCES crypto/sm2.cpp)
  endif()
else()
  message(FATAL_ERROR "Unknown crypto backend: ${CRYPTO_BACKEND}.")
endif()
list(APPEND CRYPTO_SOURCES crypto/backend_version.cpp)

# sha11collisiondetection sources
list(APPEND CRYPTO_SOURCES crypto/hash_sha1cd.cpp crypto/sha1cd/sha1.c crypto/sha1cd/ubc_check.c)

add_library(librnp-obj OBJECT
  # librepgp
  ../librepgp/stream-armor.cpp
  ../librepgp/stream-common.cpp
  ../librepgp/stream-ctx.cpp
  ../librepgp/stream-dump.cpp
  ../librepgp/stream-key.cpp
  ../librepgp/stream-packet.cpp
  ../librepgp/stream-parse.cpp
  ../librepgp/stream-sig.cpp
  ../librepgp/stream-write.cpp

  # librekey
  ../librekey/key_store_g10.cpp
  ../librekey/key_store_kbx.cpp
  ../librekey/key_store_pgp.cpp
  ../librekey/rnp_key_store.cpp

  # cryptography
  ${CRYPTO_SOURCES}

  # other sources
  sec_profile.cpp
  crypto.cpp
  fingerprint.cpp
  generate-key.cpp
  key-provider.cpp
  logging.cpp
  json-utils.cpp
  utils.cpp
  pass-provider.cpp
  pgp-key.cpp
  rnp.cpp
)

get_target_property(_comp_options librnp-obj COMPILE_OPTIONS)
string(REGEX MATCH "\\-fsanitize=[a-z,]*undefined" _comp_sanitizers "${_comp_options}" "${CMAKE_C_FLAGS}")
if (ENABLE_SANITIZERS OR _comp_sanitizers)
  # sha1cd attempts to use unaligned access for optimisations on intel CPUs
  # CFLAGS is checked as sanitizers may be enabled without CMake var
  set_source_files_properties(crypto/sha1cd/sha1.c
    PROPERTIES COMPILE_DEFINITIONS "SHA1DC_FORCE_ALIGNED_ACCESS"
  )
endif()

set_target_properties(librnp-obj PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(librnp-obj
  PUBLIC
    "$<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/src/lib>"
    "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src/common>"
    "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>"
    "$<INSTALL_INTERFACE:include>"
  PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${PROJECT_SOURCE_DIR}/src"
    "${SEXPP_INCLUDE_DIRS}"
)
target_link_libraries(librnp-obj PRIVATE JSON-C::JSON-C)
if (CRYPTO_BACKEND_BOTAN)
  target_link_libraries(librnp-obj PRIVATE Botan::Botan)
elseif (CRYPTO_BACKEND_OPENSSL)
  target_link_libraries(librnp-obj PRIVATE OpenSSL::Crypto)
endif()

target_link_libraries(librnp-obj PRIVATE sexpp)

set_target_properties(librnp-obj PROPERTIES CXX_VISIBILITY_PRESET hidden)
if (TARGET BZip2::BZip2)
  target_link_libraries(librnp-obj PRIVATE BZip2::BZip2)
endif()
if (TARGET ZLIB::ZLIB)
  target_link_libraries(librnp-obj PRIVATE ZLIB::ZLIB)
endif()
if (BUILD_SHARED_LIBS)
  target_compile_definitions(librnp-obj PRIVATE librnp_EXPORTS)
else()
  target_compile_definitions(librnp-obj PRIVATE RNP_STATIC)
endif()

add_library(librnp $<TARGET_OBJECTS:librnp-obj> $<TARGET_OBJECTS:rnp-common>)
if (OpenSSL::applink)
  target_link_libraries(librnp PRIVATE OpenSSL::applink)
endif(OpenSSL::applink)

set_target_properties(librnp
  PROPERTIES
    VERSION "${RNP_VERSION}"
    SOVERSION "${RNP_VERSION_MAJOR}"
    OUTPUT_NAME "rnp"
)

if (BUILD_SHARED_LIBS)
  add_library(librnp-static STATIC $<TARGET_OBJECTS:librnp-obj> $<TARGET_OBJECTS:rnp-common>)
  if (OpenSSL::applink)
    target_link_libraries(librnp-static PRIVATE OpenSSL::applink)
  endif(OpenSSL::applink)
  if (WIN32)
    set_target_properties(librnp-static PROPERTIES OUTPUT_NAME "rnp-static")
  else (WIN32)
# On Unix like systems we will build/install/pack shared and static libraries librnp.so and librnp.a
# On Windows we will build/install/pack dynamic, import and  static libraries rnp.dll, rnp.lib and rnp-static.lib
    set_target_properties(librnp-static PROPERTIES OUTPUT_NAME "rnp")
  endif (WIN32)
 # Limit symbols export only to rnp_* functions.
  if (APPLE)
    # use -export_symbols_list on Apple OSs
    target_link_options(librnp PRIVATE -Wl,-exported_symbols_list "${CMAKE_CURRENT_SOURCE_DIR}/librnp.symbols")
    set_target_properties(librnp PROPERTIES LINK_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/librnp.symbols")
  elseif(NOT WIN32)
    target_link_options(librnp PRIVATE "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/librnp.vsc")
    set_target_properties(librnp PROPERTIES LINK_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/librnp.vsc")
  endif()
else()
  add_library(librnp-static ALIAS librnp)
endif()

foreach (prop LINK_LIBRARIES INTERFACE_LINK_LIBRARIES INCLUDE_DIRECTORIES INTERFACE_INCLUDE_DIRECTORIES)
  get_target_property(val librnp-obj ${prop})
  if (BUILD_SHARED_LIBS)
    set_property(TARGET librnp-static PROPERTY ${prop} ${val})
    list(REMOVE_ITEM val "$<LINK_ONLY:sexpp>")
    set_property(TARGET librnp PROPERTY ${prop} ${val})
  else()
    set_property(TARGET librnp PROPERTY ${prop} ${val})
  endif()

endforeach()

generate_export_header(librnp
  BASE_NAME rnp
  EXPORT_MACRO_NAME RNP_API
  EXPORT_FILE_NAME rnp/rnp_export.h
  STATIC_DEFINE RNP_STATIC
  INCLUDE_GUARD_NAME RNP_EXPORT
)

# This has precedence and can cause some confusion when the binary
# dir one isn't actually being used. To be improved.
if (NOT CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_CURRENT_BINARY_DIR)
  file(REMOVE "${CMAKE_CURRENT_SOURCE_DIR}/config.h")
  file(REMOVE "${CMAKE_CURRENT_SOURCE_DIR}/version.h")
endif()

if (${CMAKE_VERSION} VERSION_GREATER_EQUAL "3.12.0")
  set(namelink_component NAMELINK_COMPONENT development)
else()
  set(namelink_component)
endif()

# add these to the rnp-targets export
# On Unix like systems we will build/install/pack either shared library librnp.so or static  librnp.a
# On Windows we will build/install/pack either dynamic and import libraries rnp.dll, rnp.lib or static library rnp-static.lib

# If a client application uses shared rnp library, sexpp is statically linked to librnp.so and libsexpp.a is not installed
# If a client application uses static rnp library, it still needs libsexpp.a and it is installed

if (BUILD_SHARED_LIBS)
  install(TARGETS librnp
    EXPORT rnp-targets
    LIBRARY
      DESTINATION  "${CMAKE_INSTALL_LIBDIR}"
      COMPONENT runtime
      ${namelink_component}
    ARCHIVE
      DESTINATION  "${CMAKE_INSTALL_LIBDIR}"
      COMPONENT development
  )

# install dll only for windows
  if (WIN32)
    install(TARGETS librnp
      RUNTIME
        DESTINATION "${CMAKE_INSTALL_BINDIR}"
        COMPONENT runtime
    )
  endif(WIN32)
else(BUILD_SHARED_LIBS)
# static libraries
# install libsexpp unless system-installed libsexpp is used
  if (SYSTEM_LIBSEXPP)
    install(TARGETS librnp
      EXPORT rnp-targets
      ARCHIVE
        DESTINATION  "${CMAKE_INSTALL_LIBDIR}"
        COMPONENT development
    )
  else (SYSTEM_LIBSEXPP)
    install(TARGETS librnp sexpp
    EXPORT rnp-targets
    ARCHIVE
      DESTINATION  "${CMAKE_INSTALL_LIBDIR}"
      COMPONENT development
    )
  endif (SYSTEM_LIBSEXPP)
endif(BUILD_SHARED_LIBS)

# install headers
install(
  FILES
    "${PROJECT_SOURCE_DIR}/include/rnp/rnp.h"
  COMPONENT
    development
  DESTINATION
    "${CMAKE_INSTALL_INCLUDEDIR}/rnp"
  RENAME
    rnp.h
)
install(
  FILES
    "${PROJECT_SOURCE_DIR}/include/rnp/rnp_err.h"
  COMPONENT
    development
  DESTINATION
    "${CMAKE_INSTALL_INCLUDEDIR}/rnp"
  RENAME
    rnp_err.h
)
install(
  FILES
    "${PROJECT_BINARY_DIR}/src/lib/rnp/rnp_export.h"
  COMPONENT
    development
  DESTINATION
    "${CMAKE_INSTALL_INCLUDEDIR}/rnp"
  RENAME
    rnp_export.h
)

# .cmake installs
set(INSTALL_CMAKEDIR "${CMAKE_INSTALL_LIBDIR}/cmake/rnp")

install(EXPORT rnp-targets
  FILE rnp-targets.cmake
  NAMESPACE rnp::
  DESTINATION "${INSTALL_CMAKEDIR}"
  COMPONENT development
)

include(CMakePackageConfigHelpers)
configure_package_config_file(
  "${PROJECT_SOURCE_DIR}/cmake/rnp-config.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/rnp-config.cmake"
  INSTALL_DESTINATION "${INSTALL_CMAKEDIR}"
)
write_basic_package_version_file(rnp-config-version.cmake
  VERSION "${PROJECT_VERSION}"
  COMPATIBILITY SameMajorVersion
)
install (
  FILES
    "${CMAKE_CURRENT_BINARY_DIR}/rnp-config.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/rnp-config-version.cmake"
  DESTINATION "${INSTALL_CMAKEDIR}"
  COMPONENT development
)

function(get_linked_libs libsvar dirsvar tgt)
  get_target_property(imported ${tgt} IMPORTED)
  list(APPEND visited_targets ${tgt})
  if (imported)
    get_target_property(linkedlibs ${tgt} INTERFACE_LINK_LIBRARIES)
  endif()
  set(libs)
  foreach (lib ${linkedlibs})
    if (TARGET ${lib})
      list(FIND visited_targets ${lib} visited)
      if ((${visited} EQUAL -1) AND (${CMAKE_SHARED_LIBRARY_PREFIX}))
        # library
        get_target_property(liblocation ${lib} LOCATION)
        get_filename_component(linkedlib ${liblocation} NAME_WE)
        string(REGEX REPLACE "^${CMAKE_SHARED_LIBRARY_PREFIX}" "" linkedlib ${linkedlib})
        get_linked_libs(linkedlibs libdirs ${lib})
        list(APPEND libs ${linkedlib} ${linkedlibs})
        # directory
        get_filename_component(libdir ${liblocation} DIRECTORY)
        list(FIND ${dirsvar} ${libdir} seendir)
        if (${seendir} EQUAL -1)
          list(APPEND ${dirsvar} ${libdir} ${libdirs})
        endif()
      endif()
    endif()
  endforeach()
  set(visited_targets ${visited_targets} PARENT_SCOPE)
  set(${libsvar} ${libs} PARENT_SCOPE)
  set(${dirsvar} ${${dirsvar}} PARENT_SCOPE)
endfunction()

get_linked_libs(libs dirs librnp)
set(linkercmd)
foreach (dir ${dirs})
  string(APPEND linkercmd "-L${dir} ")
endforeach()
foreach (lib ${libs})
  string(APPEND linkercmd "-l${lib} ")
endforeach()
string(STRIP "${linkercmd}" linkercmd)
set(LIBRNP_PRIVATE_LIBS ${linkercmd})

# create a pkgconfig .pc too
find_package(PkgConfig)
if (PKG_CONFIG_FOUND)
  get_target_property(LIBRNP_OUTPUT_NAME librnp OUTPUT_NAME)

  if(IS_ABSOLUTE "${CMAKE_INSTALL_LIBDIR}")
    set(PKGCONFIG_LIBDIR "${CMAKE_INSTALL_LIBDIR}")
  else()
    set(PKGCONFIG_LIBDIR "\${prefix}/${CMAKE_INSTALL_LIBDIR}")
  endif()
  if(IS_ABSOLUTE "${CMAKE_INSTALL_INCLUDEDIR}")
    set(PKGCONFIG_INCLUDEDIR "${CMAKE_INSTALL_INCLUDEDIR}")
  else()
    set(PKGCONFIG_INCLUDEDIR "\${prefix}/${CMAKE_INSTALL_INCLUDEDIR}")
  endif()

  configure_file(
    "${PROJECT_SOURCE_DIR}/cmake/librnp.pc.in"
    "${PROJECT_BINARY_DIR}/librnp.pc"
    @ONLY
  )
  install(
    FILES "${PROJECT_BINARY_DIR}/librnp.pc"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig"
    COMPONENT development
  )
endif()

# Build and install man page
if (ENABLE_DOC)
  add_adoc_man("${CMAKE_CURRENT_SOURCE_DIR}/librnp.3.adoc" ${RNP_VERSION})
endif()
