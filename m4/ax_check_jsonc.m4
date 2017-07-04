# SYNOPSIS
#
#   AX_CHECK_JSONC([action-if-found[, action-if-not-found]])
#
# DESCRIPTION
#
#   Look for json-c in a number of default spots, or in a user-selected
#   spot (via --with-jsonc).  Sets
#
#     JSONC_INCLUDES to the include directives required
#     JSONC_LIBS to the -l directives required
#     JSONC_LDFLAGS to the -L or -R flags required
#
#   and calls ACTION-IF-FOUND or ACTION-IF-NOT-FOUND appropriately
#
#   This macro sets JSONC_INCLUDES such that source files should include
#   json.h like so:
#
#     #include <json.h>
#
# LICENSE
# Based on
#     https://www.gnu.org/software/autoconf-archive/ax_check_jsonc.html
#
#   Copyright (c) 2009,2010 Zmanda Inc. <http://www.zmanda.com/>
#   Copyright (c) 2009,2010 Dustin J. Mitchell <dustin@zmanda.com>
#
#   Copying and distribution of this file, with or without modification, are
#   permitted in any medium without royalty provided the copyright notice
#   and this notice are preserved. This file is offered as-is, without any
#   warranty.

AU_ALIAS([CHECK_JSONC], [AX_CHECK_JSONC])
AC_DEFUN([AX_CHECK_JSONC], [
    found=false
    AC_ARG_WITH([jsonc],
        [AS_HELP_STRING([--with-jsonc=DIR],
            [root of the json-c directory])],
        [
            case "$withval" in
            "" | y | ye | yes | n | no)
            AC_MSG_ERROR([Invalid --with-jsonc value])
              ;;
            *) jsoncdirs="$withval"
              ;;
            esac
        ], [
            # if pkg-config is installed and jsonc has installed a .pc file,
            # then use that information and don't search jsoncdirs
            AC_CHECK_TOOL([PKG_CONFIG], [pkg-config])
            if test x"$PKG_CONFIG" != x""; then
                JSONC_LDFLAGS=`$PKG_CONFIG json-c --libs-only-L 2>/dev/null`
                if test $? = 0; then
                    JSONC_LIBS=`$PKG_CONFIG json-c --libs-only-l 2>/dev/null`
                    JSONC_INCLUDES=`$PKG_CONFIG json-c --cflags-only-I 2>/dev/null`
                    found=true
                fi
            fi

            # no such luck; use some default jsoncdirs
            if ! $found; then
                jsoncdirs="/usr/local/json-c /usr/lib/json-c /usr/json-c /usr/pkg /usr/local /usr"
            fi
        ]
        )


    if ! $found; then
        JSONC_INCLUDES=
        for jsoncdir in $jsoncdirs; do
            AC_MSG_CHECKING([for json.h in $jsoncdir])
            if test -f "$jsoncdir/include/json-c/json.h"; then
                JSONC_INCLUDES="-I$jsoncdir/include/json-c"
                JSONC_LDFLAGS="-L$jsoncdir/lib"
                JSONC_LIBS="-ljson-c"
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

    AC_MSG_CHECKING([whether compiling and linking against json-c works])
    echo "Trying link with JSONC_LDFLAGS=$JSONC_LDFLAGS;" \
        "JSONC_LIBS=$JSONC_LIBS; JSONC_INCLUDES=$JSONC_INCLUDES" >&AS_MESSAGE_LOG_FD

    save_LIBS="$LIBS"
    save_LDFLAGS="$LDFLAGS"
    save_CPPFLAGS="$CPPFLAGS"
    LDFLAGS="$LDFLAGS $JSONC_LDFLAGS"
    LIBS="$JSONC_LIBS $LIBS"
    CPPFLAGS="$JSONC_INCLUDES $CPPFLAGS"
    AC_LINK_IFELSE(
        [AC_LANG_PROGRAM([#include <json.h>], [json_object_new_object()])],
        [
            AC_MSG_RESULT([yes])
            $1
        ], [
            AC_MSG_RESULT([no])
            $2
        ])
    CPPFLAGS="$save_CPPFLAGS"
    LDFLAGS="$save_LDFLAGS"
    LIBS="$save_LIBS"

    AC_SUBST([JSONC_INCLUDES])
    AC_SUBST([JSONC_LIBS])
    AC_SUBST([JSONC_LDFLAGS])
])
