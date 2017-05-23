## $NetBSD: Makefile.am,v 1.10 2010/11/29 06:21:40 agc Exp $

AM_CFLAGS		= $(WARNCFLAGS) $(BOTAN_INCLUDES) $(JSON_CFLAGS)

AM_LDFLAGS              = $(BOTAN_LDFLAGS)

lib_LTLIBRARIES		= librnp.la

librnp_la_CPPFLAGS	= -I$(top_srcdir)/include -I$(top_srcdir)/src/libmj

librnp_la_SOURCES	= \
	bufgap.c \
	bn.c \
	compress.c \
	create.c \
	crypto.c \
	dsa.c \
	elgamal.c \
	hash.c \
	keyring.c \
	misc.c \
	pem.c \
	rnp.c \
	rsa.c \
	packet-parse.c \
	packet-print.c \
	packet-show.c \
	reader.c \
	signature.c \
	ssh2pgp.c \
	symmetric.c \
	validate.c \
	writer.c

librnp_la_LIBADD	= ../libmj/libmj.la $(BOTAN_LIBS) $(JSON_LIBS)

dist_man_MANS		= librnp.3
