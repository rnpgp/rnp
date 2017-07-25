AM_CFLAGS			 = $(WARNCFLAGS) $(BOTAN_INCLUDES) $(JSONC_INCLUDES)
AM_LDFLAGS           = $(BOTAN_LDFLAGS) $(JSONC_LDFLAGS)
lib_LTLIBRARIES		 = librekey.la
librekey_la_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/src/lib
librekey_la_LIBADD	 =
librekey_la_SOURCES	 = \
	rnp_key_store.c \
	key_store_pgp.c \
	key_store_kbx.c \
	key_store_ssh.c