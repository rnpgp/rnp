AM_CFLAGS               = $(WARNCFLAGS) $(BOTAN_INCLUDES) $(JSONC_INCLUDES)
AM_LDFLAGS              = $(BOTAN_LDFLAGS) $(JSONC_LDFLAGS)
lib_LTLIBRARIES         = librepgp.la
librepgp_la_CPPFLAGS    = -I$(top_srcdir)/include -I$(top_srcdir)/src/lib -I$(top_srcdir)/src
librepgp_la_LIBADD      =
librepgp_la_SOURCES     =  \
    packet-parse.c \
    packet-print.c \
    packet-show.c \
    reader.c \
    repgp.c \
    validate.c \
    stream-parse.c