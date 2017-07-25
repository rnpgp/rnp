AM_CFLAGS		    = $(WARNCFLAGS)
bin_PROGRAMS		= rnp_tests
rnp_tests_CPPFLAGS	= -I$(top_srcdir)/include -I$(top_srcdir)/src/lib $(JSONC_INCLUDES) $(BOTAN_INCLUDES) $(CMOCKA_INCLUDES)
rnp_tests_LDADD		= ../lib/librnp.la ../rnpkeys/librnpkeys.la $(JSONC_LIBS) $(CMOCKA_LIBS)
rnp_tests_LDFLAGS	= $(JSONC_LDFLAGS) $(CMOCKA_LDFLAGS)
rnp_tests_SOURCES   = \
    support.c \
    cipher.c \
    generatekey.c \
    exportkey.c \
    rnp_tests.c \
    utils-list.c \
    pgp-parse.c

# don't install any test stuff
install-binPROGRAMS:
uninstall-binPROGRAMS:
