#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include <rnp/rnp.h>
#include <rnp/rnpcfg.h>
#include <repgp/repgp.h>
#include <rnp/rnp_def.h>

#include "internal_types.h"
#include "memory.h"
#include "utils.h"

repgp_stream_t
create_file_stream(const char *filename, size_t filename_len)
{
    struct repgp_stream *s = calloc(sizeof(struct repgp_stream), 1);
    if (!s) {
        return REPGP_STREAM_NULL;
    }

    s->filepath = strndup(filename, filename_len);
    s->type = REPGP_INPUT_FILE;
    return s;
}

/* Reads into memory everything from stdin */
repgp_stream_t
create_stdin_stream(void)
{
    char     buf[BUFSIZ * 8];
    uint8_t *data = NULL;
    size_t   size = 0;
    size_t   n;

    struct repgp_stream *s = calloc(sizeof(struct repgp_stream), 1);
    if (!s) {
        return REPGP_STREAM_NULL;
    }

    /* Read in everything and keeps it in memory.
     * For stdin it kind of makes sense as no one
     * should provide a lot of data on stdin.
     */
    while ((n = read(STDIN_FILENO, buf, sizeof(buf))) > 0) {
        /* round up the allocation */
        size_t newsize = size + ((n / BUFSIZ) + 1) * BUFSIZ;
        // OZAPTF: Check it
        uint8_t *loc = realloc(data, newsize);
        if (loc == NULL) {
            RNP_LOG("Short read");
            free(data);
            return REPGP_STREAM_NULL;
        }
        data = loc;
        memcpy(data + size, buf, n);
        size += n;
    }

    s->type = REPGP_INPUT_STDIN;
    s->std_in.size = size;
    s->std_in.in = data;
    return s;
}

void
destroy_stream(repgp_stream_t stream)
{
    struct repgp_stream *s = (struct repgp_stream *) stream;

    if (!s) {
        return;
    }

    if (s->type == REPGP_INPUT_STDIN) {
        free(s->std_in.in);
    } else if (s->type == REPGP_INPUT_FILE) {
        free(s->filepath);
    }

    free(s);
}

rnp_result
repgp_verify(const void *ctx, repgp_stream_t stream, const char *output_file)
{
    struct repgp_stream *s = (struct repgp_stream *) stream;
    if (!s) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    if (s->type == REPGP_INPUT_FILE) {
        return rnp_verify_file((void *) ctx, s->filepath, output_file);
    } else if (s->type == REPGP_INPUT_STDIN) {
        return rnp_verify_memory(
          (void *) ctx, s->std_in.in, s->std_in.size, NULL, STDOUT_FILENO, 0);
    }

    return RNP_ERROR_BAD_PARAMETERS;
}
