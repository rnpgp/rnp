AM_CFLAGS   		    = $(WARNCFLAGS)
dist_man_MANS           = rnpkeys.1

lib_LTLIBRARIES         = librnpkeys.la
librnpkeys_la_CPPFLAGS  = -I$(top_srcdir)/include -I$(top_srcdir)/src $(JSONC_INCLUDES) $(BOTAN_INCLUDES)
librnpkeys_la_LIBADD    = ../lib/librnp.la ../librekey/librekey.la
librnpkeys_la_SOURCES   = \
    rnpkeys.c \
    tui.c \
    ../rnp/rnpcfg.c

bin_PROGRAMS            = rnpkeys
rnpkeys_SOURCES         = main.c
rnpkeys_CPPFLAGS        = -I$(top_srcdir)/include -I$(top_srcdir)/src $(JSONC_INCLUDES) $(BOTAN_INCLUDES)
rnpkeys_LDADD           = librnpkeys.la ../lib/librnp.la
