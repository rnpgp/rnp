AM_CFLAGS		= $(WARNCFLAGS)

bin_PROGRAMS		= rnpv

rnpv_SOURCES	= \
	b64.c \
	bufgap.c \
	digest.c \
	libverify.c \
	main.c \
	misc.c \
	pgpsum.c

rnpv_CPPFLAGS	= -I$(top_srcdir)/include -I$(top_srcdir)/src/libmj -I$(top_srcdir)/src/lib

rnpv_LDADD	= ../lib/librnp.la ../libmj/libmj.la

dist_man_MANS		= rnpv.1
