AM_CFLAGS		= $(WARNCFLAGS) $(JSON_CFLAGS)

bin_PROGRAMS		= rnpv

rnpv_SOURCES	= \
	b64.c \
	bufgap.c \
	libverify.c \
	main.c \
	misc.c \
	pgpsum.c

rnpv_CPPFLAGS	= -I$(top_srcdir)/include -I$(top_srcdir)/src/libmj -I$(top_srcdir)/src/lib $(JSON_CFLAGS)

rnpv_LDADD	= ../lib/librnp.la ../libmj/libmj.la $(JSON_LIBS)

dist_man_MANS		= rnpv.1
