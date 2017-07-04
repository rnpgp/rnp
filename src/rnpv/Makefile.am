AM_CFLAGS		= $(WARNCFLAGS) $(JSONC_INCLUDES)
bin_PROGRAMS	= rnpv
rnpv_CPPFLAGS   = -I$(top_srcdir)/include -I$(top_srcdir)/src/lib
rnpv_LDADD	    = ../lib/librnp.la $(JSONC_LIBS)
dist_man_MANS	= rnpv.1
rnpv_SOURCES    = \
    b64.c \
    bufgap.c \
    libverify.c \
    main.c \
    misc.c \
    pgpsum.c
