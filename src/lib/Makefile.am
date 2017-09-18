## $NetBSD: Makefile.am,v 1.10 2010/11/29 06:21:40 agc Exp $

AM_CFLAGS			= $(WARNCFLAGS) $(BOTAN_INCLUDES) $(JSONC_INCLUDES)
AM_LDFLAGS          = $(BOTAN_LDFLAGS) $(JSONC_LDFLAGS)
lib_LTLIBRARIES		= librnp.la
librnp_la_CPPFLAGS	= -I$(top_srcdir)/include -I$(top_srcdir)/src
librnp_la_LIBADD	= $(BOTAN_LIBS) $(JSONC_LIBS) ../librekey/librekey.la ../librekey/librekey.la ../librepgp/librepgp.la
dist_man_MANS		= librnp.3
librnp_la_SOURCES	= \
	crypto/bn.c \
	crypto/dsa.c \
	crypto/ec.c \
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
	fingerprint.c \
	generate-key.c \
	hash.c \
	list.c \
	misc.c \
	packet-create.c \
	pass-provider.c \
	pem.c \
	pgp-key.c \
	rnp.c \
	rnp2.c \
	signature.c \
	symmetric.c \
	writer.c
