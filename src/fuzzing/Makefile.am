AM_CFLAGS		= $(WARNCFLAGS)

bin_PROGRAMS		= fuzz_keys

fuzz_keys_SOURCES		= fuzz_keys.c

fuzz_keys_CPPFLAGS		= -I$(top_srcdir)/include -I$(top_srcdir)/src/lib $(JSONC_INCLUDES)

fuzz_keys_LDADD		= ../lib/librnp.la
