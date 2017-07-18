AM_CFLAGS		    = $(WARNCFLAGS)
bin_PROGRAMS		= rnp_tests
rnp_tests_CPPFLAGS	= -I$(top_srcdir)/include -I$(top_srcdir)/src/lib $(JSONC_INCLUDES) $(BOTAN_INCLUDES)
rnp_tests_LDADD		= ../lib/librnp.la ../rnpkeys/librnpkeys.la $(JSON_LIBS)
rnp_tests_SOURCES   = \
    support.c \
    cipher.c \
    generatekey.c \
    exportkey.c \
    rnp_tests.c
