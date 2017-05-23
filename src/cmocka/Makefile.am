
AM_CFLAGS		= $(WARNCFLAGS)

bin_PROGRAMS		= rnp_tests

rnp_tests_SOURCES		= rnp_tests.c

rnp_tests_CPPFLAGS		= -I$(top_srcdir)/include -I$(top_srcdir)/src/libmj -I$(top_srcdir)/src/lib $(JSON_CFLAGS)

rnp_tests_LDADD		= ../lib/librnp.la ../libmj/libmj.la $(JSON_LIBS)
