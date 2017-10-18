AM_CFLAGS       = $(WARNCFLAGS)
dist_man_MANS   = rnp.1

bin_PROGRAMS	= rnp
rnp_CPPFLAGS	= -I$(top_srcdir)/include -I$(top_srcdir)/src/ $(JSONC_INCLUDES) $(BOTAN_INCLUDES)
rnp_LDADD		= ../lib/librnp.la ../librekey/librekey.la ../librepgp/librepgp.la
rnp_SOURCES     = \
    rnp.c \
    rnpcfg.c
