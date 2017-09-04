CC = clang

objectify = $(subst .c,.o, $1)

SRC = parser.c
OBJS = $(call objectify,$(SRC))
TARGETS = parser
SANS = -fsanitize=leak,address

INC=-I../../include -I/usr/include/json-c -I/usr/local/include/botan-2/

# Ideally this should be removed at some point
INC+=-I../../src/lib

CFLAGS=$(SANS) $(INC) -g -O0
LDFLAGS=

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

parser: $(OBJS)
	$(CC) -o $@ $^ $(CFLAGS) -L../librepgp/.libs -lrepgp -L../lib/.libs -lrnp -L../librekey/.libs -lrekey

all: $(TARGETS)

clean:
	rm -rf $(OBJS)
	rm -rf $(TARGETS)
