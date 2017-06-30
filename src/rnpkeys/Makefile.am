AM_CFLAGS   		    = $(WARNCFLAGS)
dist_man_MANS           = rnpkeys.1

lib_LTLIBRARIES         = librnpkeys.la
librnpkeys_la_CPPFLAGS  = -I$(top_srcdir)/include $(JSONC_INCLUDES)
librnpkeys_la_LIBADD    = ../lib/librnp.la
librnpkeys_la_SOURCES   = \
    rnpkeys.c \
    tui.c

bin_PROGRAMS            = rnpkeys
rnpkeys_SOURCES         = main.c
rnpkeys_LDADD           = librnpkeys.la
