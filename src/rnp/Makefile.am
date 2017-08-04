AM_CFLAGS		= $(WARNCFLAGS)

bin_PROGRAMS		= rnp

rnp_SOURCES		= \
    rnp.c \
    rnpcfg.c

rnp_CPPFLAGS		= -I$(top_srcdir)/include $(JSONC_INCLUDES) $(BOTAN_INCLUDES)

rnp_LDADD		= ../lib/librnp.la ../librekey/librekey.la

dist_man_MANS		= rnp.1
