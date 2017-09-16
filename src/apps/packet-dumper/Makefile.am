AM_CFLAGS            = $(WARNCFLAGS) $(JSONC_INCLUDES) $(BOTAN_INCLUDES)
bin_PROGRAMS         = redumper
redumper_SOURCES     = redumper.c
redumper_CPPFLAGS    = -I$(top_srcdir)/include
redumper_LDADD       = ../../lib/librnp.la ../../librepgp/librepgp.la
