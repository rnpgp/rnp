# SYNOPSIS
#
#   AX_CHECK_BOTAN([action-if-found[, action-if-not-found]])
#
# DESCRIPTION
#
#   Look for Botan in a number of default spots, or in a user-selected
#   spot (via --with-botan).  Sets
#
#     BOTAN_INCLUDES to the include directives required
#     BOTAN_LIBS to the -l directives required
#     BOTAN_LDFLAGS to the -L or -R flags required
#
#   and calls ACTION-IF-FOUND or ACTION-IF-NOT-FOUND appropriately
#
#   This macro sets BOTAN_INCLUDES such that source files should use the
#   botan/ directory in include directives:
#
#     #include <botan/hmac.h>
#
# LICENSE
# Based on
#     http://www.gnu.org/software/autoconf-archive/ax_check_openssl.html
#
#   Copyright (c) 2009 Zmanda Inc. <http://www.zmanda.com/>
#   Copyright (c) 2009 Dustin J. Mitchell <dustin@zmanda.com>
#
#   Copying and distribution of this file, with or without modification, are
#   permitted in any medium without royalty provided the copyright notice
#   and this notice are preserved. This file is offered as-is, without any
#   warranty.

#serial 5

AU_ALIAS([CHECK_SSL], [AX_CHECK_BOTAN])
AC_DEFUN([AX_CHECK_BOTAN], [
    found=false
    AC_ARG_WITH(botan,
        AS_HELP_STRING([--with-botan=DIR],
            [root of the Botan directory]),
        [
            case "$withval" in
            "" | y | ye | yes | n | no)
            AC_MSG_ERROR([Invalid --with-botan value])
              ;;
            *) botandirs="$withval"
              ;;
            esac
        ], [
            # if pkg-config is available, use that (botan always installs a pkg-config file)
            AC_PATH_PROG(PKG_CONFIG, pkg-config)
            if test x"$PKG_CONFIG" != x""; then
                BOTAN_LDFLAGS=`$PKG_CONFIG botan-2 --libs-only-L 2>/dev/null`
                if test $? = 0; then
                    BOTAN_LIBS=`$PKG_CONFIG botan-2 --libs-only-l 2>/dev/null`
                    BOTAN_INCLUDES=`$PKG_CONFIG botan-2 --cflags-only-I 2>/dev/null`
                    found=true
                fi
            fi

            # no such luck; use some default botandirs
            if ! $found; then
                botandirs="/usr/local /usr"
            fi
        ]
        )


    # note that we #include <botan/foo.h>, so the Botan headers have to be in
    # an 'botan' subdirectory

    if ! $found; then
        BOTAN_INCLUDES=
        for botandir in $botandirs; do
            AC_MSG_CHECKING([for botan/ffi.h in $botandir])
            if test -f "$botandir/include/botan-2/botan/ffi.h"; then
                BOTAN_INCLUDES="-I$botandir/include/botan-2"
                BOTAN_LDFLAGS="-L$botandir/lib"
                BOTAN_LIBS="-lbotan-2"
                found=true
                AC_MSG_RESULT([yes])
                break
            else
                AC_MSG_RESULT([no])
            fi
        done

        # if the file wasn't found, well, go ahead and try the link anyway -- maybe
        # it will just work!
    fi

    # try the preprocessor and linker with our new flags,
    # being careful not to pollute the global LIBS, LDFLAGS, and CPPFLAGS

    AC_MSG_CHECKING([whether compiling and linking against Botan works])
    echo "Trying link with BOTAN_LDFLAGS=$BOTAN_LDFLAGS;" \
        "BOTAN_LIBS=$BOTAN_LIBS; BOTAN_INCLUDES=$BOTAN_INCLUDES" >&AS_MESSAGE_LOG_FD

    save_LIBS="$LIBS"
    save_LDFLAGS="$LDFLAGS"
    save_CPPFLAGS="$CPPFLAGS"
    LDFLAGS="$LDFLAGS $BOTAN_LDFLAGS"
    LIBS="$BOTAN_LIBS $LIBS"
    CPPFLAGS="$BOTAN_INCLUDES $CPPFLAGS"
    AC_LINK_IFELSE(
        [AC_LANG_PROGRAM([#include <botan/ffi.h>], [botan_version_string()])],
        [
            AC_MSG_RESULT([yes])
            $1
        ], [
            AC_MSG_RESULT([no])
            $2
        ])

    AC_MSG_CHECKING([for botan version >= 2.2])
    AC_COMPILE_IFELSE(
      [AC_LANG_PROGRAM([[#include <botan/build.h>]], [[
      #if BOTAN_VERSION_MAJOR >= 2 && BOTAN_VERSION_MINOR >= 2
      #else
      #error Botan version is too old
      #endif
      ]])],
      [
          AC_MSG_RESULT([ok])
          $1
      ], [
          AC_MSG_RESULT([failed])
          $2
      ]
    )
    CPPFLAGS="$save_CPPFLAGS"
    LDFLAGS="$save_LDFLAGS"
    LIBS="$save_LIBS"

    AC_SUBST([BOTAN_INCLUDES])
    AC_SUBST([BOTAN_LIBS])
    AC_SUBST([BOTAN_LDFLAGS])
])

# Requires BOTAN_INCLUDES to be set
AC_DEFUN([AX_CHECK_BOTAN_DEFINES], [
    save_CPPFLAGS="$CPPFLAGS"
    CPPFLAGS="$BOTAN_INCLUDES"
    AC_CHECK_DECLS([BOTAN_HAS_AES,BOTAN_HAS_CAMELLIA,BOTAN_HAS_IDEA,BOTAN_HAS_BLOWFISH,BOTAN_HAS_TWOFISH,BOTAN_HAS_CAST,BOTAN_HAS_MD5,BOTAN_HAS_SHA1,BOTAN_HAS_SHA2_32,BOTAN_HAS_SHA2_64,BOTAN_HAS_RSA,BOTAN_HAS_EMSA_PKCS1,BOTAN_HAS_PGP_S2K,BOTAN_HAS_SM2,BOTAN_HAS_SM4,BOTAN_HAS_ED25519,BOTAN_HAS_ECDSA,BOTAN_HAS_ECDH,BOTAN_HAS_HMAC,BOTAN_HAS_SP800_56A,BOTAN_HAS_ELGAMAL,BOTAN_HAS_DSA,BOTAN_HAS_MODE_CBC,BOTAN_HAS_MODE_CFB,BOTAN_HAS_CRC24,BOTAN_HAS_SHA3],
        [
            $1
        ], [
            AC_MSG_ERROR([Botan build is missing a required feature])
            $2
        ],
        [#include <botan/build.h>])
    CPPFLAGS="$save_CPPFLAGS"
])
