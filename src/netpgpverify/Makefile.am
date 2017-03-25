## $NetBSD: Makefile.am,v 1.4 2010/11/06 00:03:34 agc Exp $

AM_CFLAGS		= $(WARNCFLAGS)

bin_PROGRAMS		= netpgpverify

netpgpverify_SOURCES	= \
	b64.c \
	bignum.c \
	bufgap.c \
	bzlib.c \
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

netpgpverify_CPPFLAGS	= -I$(top_srcdir)/include -I../libmj

netpgpverify_LDADD	= ../lib/libnetpgp.la ../libmj/libmj.la

dist_man_MANS		= netpgpverify.1
