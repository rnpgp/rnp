## $NetBSD: Makefile.am,v 1.4 2010/11/06 00:03:34 agc Exp $

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

rnpv_CPPFLAGS	= -I$(top_srcdir)/include -I../libmj

rnpv_LDADD	= ../lib/librnp.la ../libmj/libmj.la

dist_man_MANS		= rnpv.1
