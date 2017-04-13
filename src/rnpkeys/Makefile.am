AM_CFLAGS		= $(WARNCFLAGS)

bin_PROGRAMS		= rnpkeys

rnpkeys_SOURCES	= rnpkeys.c

rnpkeys_CPPFLAGS	= -I$(top_srcdir)/include -I$(top_srcdir)/src/libmj

rnpkeys_LDADD	= ../lib/librnp.la ../libmj/libmj.la

dist_man_MANS		= rnpkeys.1
