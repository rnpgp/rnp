## $NetBSD: Makefile.am,v 1.4 2010/11/06 00:03:34 agc Exp $

AM_CFLAGS		= $(WARNCFLAGS)

bin_PROGRAMS		= rnpv

rnpv_SOURCES	= \
	b64.c \
	bignum.c \
	bufgap.c \
	digest.c \
	libverify.c \
	main.c \
	md5c.c \
	misc.c \
	pgpsum.c \
	rmd160.c \
	rsa.c \
	sha1.c \
	sha2.c \
	tiger.c

rnpv_CPPFLAGS	= -I$(top_srcdir)/include -I$(top_srcdir)/src/libmj -I$(top_srcdir)/src/lib

rnpv_LDADD	= ../lib/librnp.la ../libmj/libmj.la

dist_man_MANS		= rnpv.1
