## $NetBSD: Makefile.am,v 1.10 2010/11/29 06:21:40 agc Exp $

AM_CFLAGS			= $(WARNCFLAGS) $(BOTAN_INCLUDES) $(JSONC_INCLUDES)
AM_LDFLAGS          = $(BOTAN_LDFLAGS) $(JSONC_LDFLAGS)
lib_LTLIBRARIES		= librnp.la
librnp_la_CPPFLAGS	= -I$(top_srcdir)/include
librnp_la_LIBADD	= $(BOTAN_LIBS) $(JSONC_LIBS) ../librekey/librekey.la

if USE_BUNDLED_EXPLICIT_BZERO
librnp_la_LIBADD	+= ../compat/libcompatnoopt.la
endif

dist_man_MANS		= librnp.3
librnp_la_SOURCES	= \
	crypto/bn.c \
	crypto/dsa.c \
	crypto/ecdh.c \
	crypto/ecdsa.c \
	crypto/eddsa.c \
	crypto/elgamal.c \
	crypto/rsa.c \
	crypto/s2k.c \
	crypto/sm2.c \
	bufgap.c \
	compress.c \
	crypto.c \
	generate-key.c \
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
	signature.c \
	symmetric.c \
	validate.c \
	writer.c
