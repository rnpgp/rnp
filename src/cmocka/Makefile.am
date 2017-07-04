AM_CFLAGS		= $(WARNCFLAGS)

bin_PROGRAMS		= rnp_tests

rnp_tests_SOURCES		= rnp_tests_support.c rnp_tests_cipher.c rnp_tests_generatekey.c rnp_tests_exportkey.c rnp_tests.c

rnp_tests_CPPFLAGS		= -I$(top_srcdir)/include -I$(top_srcdir)/src/lib $(JSONC_INCLUDES)

rnp_tests_LDADD		= ../lib/librnp.la $(JSONC_LIBS)
