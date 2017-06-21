AM_CFLAGS		= $(WARNCFLAGS)

bin_PROGRAMS		= rnpkeys

rnpkeys_SOURCES	=   rnpkeys.c \
                    tui.c

rnpkeys_CPPFLAGS	= -I$(top_srcdir)/include

rnpkeys_LDADD	= ../lib/librnp.la

dist_man_MANS		= rnpkeys.1
