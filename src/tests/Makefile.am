AM_CFLAGS		    = $(WARNCFLAGS)
bin_PROGRAMS		= rnp_tests
rnp_tests_CPPFLAGS	= -I$(top_srcdir)/include -I$(top_srcdir)/src/lib $(JSONC_INCLUDES) $(BOTAN_INCLUDES) $(CMOCKA_INCLUDES) -I$(top_srcdir)/src/
rnp_tests_LDADD		= ../lib/librnp.la ../rnpkeys/librnpkeys.la ../librekey/librekey.la ../librepgp/librepgp.la $(JSONC_LIBS) $(CMOCKA_LIBS) $(BOTAN_LIBS)
rnp_tests_LDFLAGS	= $(JSONC_LDFLAGS) $(CMOCKA_LDFLAGS) $(BOTAN_LDFLAGS)
rnp_tests_SOURCES   = \
    support.c \
    cipher.c \
    ffi.c \
    generatekey.c \
    exportkey.c \
    rnp_tests.c \
    user-prefs.c \
    utils-list.c \
    pgp-parse.c \
    load-pgp.c \
    key-unlock.c \
    key-protect.c \
    key-add-userid.c

# don't install any test stuff
install-binPROGRAMS:
uninstall-binPROGRAMS:
