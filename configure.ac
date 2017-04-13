# $NetBSD: configure.ac,v 1.42 2014/03/09 00:33:50 agc Exp $
#
# Process this file with autoconf to produce a configure script.

AC_INIT([rnp],[3.99.18],[Zoltan Gyarmati <mr.zoltan.gyarmati@gmail.com>])
AC_PREREQ(2.69)
AC_REVISION([$Revision: 1.42 $])

AS_SHELL_SANITIZE

AC_CONFIG_SRCDIR([src/rnp/rnp.c])
AC_CONFIG_AUX_DIR([buildaux])
AC_CONFIG_HEADER([src/lib/config.h])
AC_CONFIG_HEADER([src/rnpv/config.h])

AM_INIT_AUTOMAKE([-Wall -Wextra foreign])
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
LT_INIT
AM_MAINTAINER_MODE

AC_CANONICAL_HOST
CANONICAL_HOST=$host
AC_SUBST([CANONICAL_HOST])

# Checks for programs.
#
AC_PROG_MAKE_SET
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CC_STDC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_CONFIG_MACRO_DIR([m4])
AM_PROG_CC_C_O

dnl based on AC_PROG_RANLIB from autoconf
m4_ifndef([AC_PROG_AR],[dnl
AN_MAKEVAR([AR], [AC_PROG_AR])
AN_PROGRAM([ar], [AC_PROG_AR])
AC_DEFUN([AC_PROG_AR],
[AC_CHECK_TOOL(AR, ar, :)])
])

AC_PROG_AR

# Compiler characteristics
#
AC_MSG_CHECKING([if using gcc])
AS_IF([test "$GCC" = "yes"],
      [WARNCFLAGS="-Werror -Wall -Wpointer-arith"
       AC_MSG_RESULT([yes; adding to CFLAGS: "$WARNCFLAGS"])],
      [WARNCFLAGS=""
       AC_MSG_RESULT([no])])
AC_SUBST([WARNCFLAGS])

# try to see if we need to link with -ldl
AC_SEARCH_LIBS(dlopen, dl)

# Checks for header files.
#
AC_HEADER_STDC
AC_CHECK_HEADERS([CommonCrypto/CommonDigest.h])
AC_CHECK_HEADERS([dmalloc.h direct.h errno.h fcntl.h \
                 inttypes.h limits.h malloc.h zlib.h])
AC_CHECK_HEADERS([sys/cdefs.h sys/file.h sys/mman.h sys/param.h \
                  sys/resource.h sys/uio.h])
AC_CHECK_HEADERS([bzlib.h],
                 [],
                 [AC_MSG_FAILURE([missing <bzlib.h>; is bzip2 installed?])])

# Checks for typedefs, structures, and compiler characteristics.
#
AC_TYPE_LONG_LONG_INT
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Check for Botan

m4_include([ax_check_botan.m4])

# TODO: check botan version (2.1 or higher required)

AX_CHECK_BOTAN([CFLAGS="$CFLAGS $BOTAN_INCLUDES"
                LDFLAGS="$LDFLAGS $BOTAN_LDFLAGS $BOTAN_LIBS"],
               [AC_MSG_ERROR([Missing Botan])])

# Checks for library functions.
#
AC_SEARCH_LIBS([_cmocka_run_group_tests], [cmocka])
AC_SEARCH_LIBS([gzopen], [z])
AC_SEARCH_LIBS([BZ2_bzDecompress], [bz2])

# Initialize the testsuite
#
AC_CONFIG_TESTDIR([tests])
AM_MISSING_PROG([AUTOM4TE], [autom4te])

# Generate the Makefiles
#
AC_CONFIG_FILES([
        Makefile
        include/Makefile
        src/Makefile
        src/libmj/Makefile
        src/lib/Makefile
        src/rnp/Makefile
        src/rnpkeys/Makefile
        src/rnpv/Makefile
        src/cmocka/Makefile
        tests/Makefile
        tests/atlocal
])
AC_OUTPUT

# Display feature results
#
AC_MSG_NOTICE([ === Configuration results ===])
AC_MSG_NOTICE([Version:             $PACKAGE_VERSION])
AC_MSG_NOTICE([C compiler:          $CC])
AC_MSG_NOTICE([Warning CFLAGS:      $WARNCFLAGS])
AC_MSG_NOTICE([=============================])

