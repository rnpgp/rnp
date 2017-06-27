## $NetBSD: Makefile.am,v 1.10 2010/11/29 06:21:40 agc Exp $

AM_CFLAGS			= $(WARNCFLAGS) $(BOTAN_INCLUDES) $(JSONC_INCLUDES)
AM_LDFLAGS          = $(BOTAN_LDFLAGS) $(JSONC_LDFLAGS)
lib_LTLIBRARIES		= librnp.la
librnp_la_CPPFLAGS	= -I$(top_srcdir)/include -I$(top_srcdir)/src/
librnp_la_LIBADD	= $(BOTAN_LIBS) $(JSONC_LIBS) ../librekey/librekey.la
dist_man_MANS		= librnp.3
librnp_la_SOURCES	= \
	bn.c \
	bufgap.c \
	compress.c \
	crypto.c \
	dsa.c \
	ecdh.c \
	ecdsa.c \
	eddsa.c \
	elgamal.c \
	hash.c \
	list.c \
	misc.c \
	packet-create.c \
	packet-parse.c \
	packet-print.c \
	packet-show.c \
	pem.c \
	pgp-key.c \
	reader.c \
	rnp.c \
	rsa.c \
	s2k.c \
	signature.c \
	sm2.c \
	symmetric.c \
	validate.c \
	writer.c
