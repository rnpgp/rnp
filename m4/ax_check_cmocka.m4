# SYNOPSIS
#
#   AX_CHECK_CMOCKA([action-if-found[, action-if-not-found]])
#
# DESCRIPTION
#
#   Look for cmocka in a number of default spots, or in a user-selected
#   spot (via --with-cmocka).  Sets
#
#     CMOCKA_INCLUDES to the include directives required
#     CMOCKA_LIBS to the -l directives required
#     CMOCKA_LDFLAGS to the -L or -R flags required
#
#   and calls ACTION-IF-FOUND or ACTION-IF-NOT-FOUND appropriately
#
#   This macro sets CMOCKA_INCLUDES such that source files should include
#   cmocka.h like so:
#
#     #include <cmocka.h>
#
# LICENSE
# Based on
#     https://www.gnu.org/software/autoconf-archive/ax_check_openssl.html
#
#   Copyright (c) 2009,2010 Zmanda Inc. <http://www.zmanda.com/>
#   Copyright (c) 2009,2010 Dustin J. Mitchell <dustin@zmanda.com>
#
#   Copying and distribution of this file, with or without modification, are
#   permitted in any medium without royalty provided the copyright notice
#   and this notice are preserved. This file is offered as-is, without any
#   warranty.

AU_ALIAS([CHECK_CMOCKA], [AX_CHECK_CMOCKA])
AC_DEFUN([AX_CHECK_CMOCKA], [
    found=false
    AC_ARG_WITH([cmocka],
        [AS_HELP_STRING([--with-cmocka=DIR],
            [root of the cmocka directory])],
        [
            case "$withval" in
            "" | y | ye | yes | n | no)
            AC_MSG_ERROR([Invalid --with-cmocka value])
              ;;
            *) cmockadirs="$withval"
              ;;
            esac
        ], [
            # if pkg-config is installed and cmocka has installed a .pc file,
            # then use that information and don't search cmockadirs
            AC_CHECK_TOOL([PKG_CONFIG], [pkg-config])
            if test x"$PKG_CONFIG" != x""; then
                CMOCKA_LDFLAGS=`$PKG_CONFIG cmocka --libs-only-L 2>/dev/null`
                if test $? = 0; then
                    CMOCKA_LIBS=`$PKG_CONFIG cmocka --libs-only-l 2>/dev/null`
                    CMOCKA_INCLUDES=`$PKG_CONFIG cmocka --cflags-only-I 2>/dev/null`
                    found=true
                fi
            fi

            # no such luck; use some default cmockadirs
            if ! $found; then
                cmockadirs="/usr/local/cmocka /usr/lib/cmocka /usr/cmocka /usr/pkg /usr/local /usr"
            fi
        ]
        )


    if ! $found; then
        CMOCKA_INCLUDES=
        for cmockadir in $cmockadirs; do
            AC_MSG_CHECKING([for cmocka.h in $cmockadir])
            if test -f "$cmockadir/include/cmocka/cmocka.h"; then
                CMOCKA_INCLUDES="-I$cmockadir/include/cmocka"
                CMOCKA_LDFLAGS="-L$cmockadir/lib"
                CMOCKA_LIBS="-lcmocka"
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

    AC_MSG_CHECKING([whether compiling and linking against cmocka works])
    echo "Trying link with CMOCKA_LDFLAGS=$CMOCKA_LDFLAGS;" \
        "CMOCKA_LIBS=$CMOCKA_LIBS; CMOCKA_INCLUDES=$CMOCKA_INCLUDES" >&AS_MESSAGE_LOG_FD

    save_LIBS="$LIBS"
    save_LDFLAGS="$LDFLAGS"
    save_CPPFLAGS="$CPPFLAGS"
    LDFLAGS="$LDFLAGS $CMOCKA_LDFLAGS"
    LIBS="$CMOCKA_LIBS $LIBS"
    CPPFLAGS="$CMOCKA_INCLUDES $CPPFLAGS"
    AC_LINK_IFELSE([
        AC_LANG_PROGRAM([[#include <stdarg.h>],
                         [#include <stddef.h>],
                         [#include <setjmp.h>],
                         [#include <cmocka.h>]],
                        [[cmocka_set_message_output(CM_OUTPUT_STDOUT)]]
          )],
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

    AC_SUBST([CMOCKA_INCLUDES])
    AC_SUBST([CMOCKA_LIBS])
    AC_SUBST([CMOCKA_LDFLAGS])
])

