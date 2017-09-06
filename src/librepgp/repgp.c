/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <rnp/rnp_def.h>
#include <rnp/rnp.h>
#include <rnp/rnpcfg.h>
#include <repgp/repgp.h>
#include <rekey/rnp_key_store.h>

#include "internal_types.h"
#include "packet-print.h"
#include "memory.h"
#include "utils.h"
#include "crypto.h"
#include "reader.h"
#include "validate.h"

repgp_handle_t *
create_filepath_handle(const char *filename)
{
    if (!filename) {
        return REPGP_HANDLE_NULL;
    }

    struct repgp_handle *s = calloc(sizeof(struct repgp_handle), 1);
    if (!s) {
        return REPGP_HANDLE_NULL;
    }

    s->filepath = strndup(filename, strlen(filename));
    s->type = REPGP_HANDLE_FILE;
    return s;
}

repgp_handle_t *
create_buffer_handle(const size_t buffer_size)
{
    struct repgp_handle *s = calloc(sizeof(struct repgp_handle), 1);
    if (!s) {
        return REPGP_HANDLE_NULL;
    }

    s->buffer.data = (unsigned char *) malloc(buffer_size);
    if (!s->buffer.data) {
        return REPGP_HANDLE_NULL;
    }

    s->buffer.size = buffer_size;
    s->type = REPGP_HANDLE_BUFFER;
    return s;
}

repgp_handle_t *
create_data_handle(const uint8_t *data, size_t data_len)
{
    struct repgp_handle *s = calloc(sizeof(struct repgp_handle), 1);
    if (!s) {
        return REPGP_HANDLE_NULL;
    }

    s->buffer.data = (unsigned char *) malloc(data_len);
    if (!s->buffer.data) {
        return REPGP_HANDLE_NULL;
    }
    memcpy(s->buffer.data, data, data_len);

    s->buffer.size = data_len;
    s->type = REPGP_HANDLE_BUFFER;
    return s;
}

/* Reads into memory everything from stdin */
repgp_handle_t *
create_stdin_handle(void)
{
    char     buf[BUFSIZ * 8];
    uint8_t *data = NULL;
    size_t   size = 0;
    ssize_t  n;

    struct repgp_handle *s = calloc(sizeof(struct repgp_handle), 1);
    if (!s) {
        return REPGP_HANDLE_NULL;
    }

    /* Read in everything and keeps it in memory.
     * For stdin it kind of makes sense as no one
     * should provide a lot of data on stdin.
     */
    while ((n = read(STDIN_FILENO, buf, sizeof(buf))) > 0) {
        /* round up the allocation */
        size_t   newsize = size + ((n / BUFSIZ) + 1) * BUFSIZ;
        uint8_t *loc = realloc(data, newsize);
        if (loc == NULL) {
            RNP_LOG("Short read");
            free(data);
            return REPGP_HANDLE_NULL;
        }
        data = loc;
        memcpy(data + size, buf, n);
        size += n;
    }

    if (n < 0) {
        RNP_LOG("Error while reading from stdin [%s]", strerror(errno));
        free(data);
        return REPGP_HANDLE_NULL;
    }

    s->type = REPGP_HANDLE_BUFFER;
    s->buffer.size = size;
    s->buffer.data = data;
    return s;
}

rnp_result
repgp_copy_buffer_from_handle(uint8_t *out, size_t *out_size, const repgp_handle_t *handle)
{
    if (!out || !out_size || (*out_size == 0) || (handle == REPGP_HANDLE_NULL)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    const struct repgp_handle *rhandle = (const struct repgp_handle *) handle;
    if (rhandle->type != REPGP_HANDLE_BUFFER) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    *out_size = rhandle->buffer.size;
    if (rhandle->buffer.size > *out_size) {
        return RNP_ERROR_SHORT_BUFFER;
    }
    memcpy(out, rhandle->buffer.data, rhandle->buffer.size);

    return RNP_SUCCESS;
}

void
repgp_destroy_handle(repgp_handle_t *stream)
{
    if (!stream)
        return;

    if (stream->type == REPGP_HANDLE_FILE) {
        free(stream->filepath);
    } else if (stream->type == REPGP_HANDLE_BUFFER) {
        free(stream->buffer.data);
    } else {
        /* Must never happen */
        assert(false);
    }
    free(stream);
}

rnp_result
repgp_verify(const void *ctx, repgp_io_t *io)
{
    if (!io || !io->in) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    void * output = NULL;
    size_t output_size = 0;

    if (io->out) {
        /* Where should I output */
        switch (io->out->type) {
        case REPGP_HANDLE_FILE:
            output = io->out->filepath;
            break;
        case REPGP_HANDLE_BUFFER:
            output = io->out->buffer.data;
            output_size = io->out->buffer.size;
            break;
        default:
            RNP_LOG("Unsupported output handle");
            return RNP_ERROR_BAD_PARAMETERS;
        }
    }

    if (io->in->type == REPGP_HANDLE_FILE) {
        return rnp_verify_file((rnp_ctx_t *) ctx, io->in->filepath, output);
    } else if (io->in->type == REPGP_HANDLE_BUFFER) {
        const int i = rnp_verify_memory(
          (rnp_ctx_t *) ctx, io->in->buffer.data, io->in->buffer.size, output, output_size);
        return i ? RNP_SUCCESS : RNP_ERROR_SIGNATURE_INVALID;
    }

    RNP_LOG("Unsupported input handle");
    return RNP_ERROR_BAD_PARAMETERS;
}

rnp_result
repgp_decrypt(const void *ctx, repgp_io_t *io)
{
    if (!io || !io->in || !io->out) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    if (io->in->type == REPGP_HANDLE_FILE) {
        if (io->out->type != REPGP_HANDLE_FILE) {
            // Currently file must be decrypted to the file only
            return RNP_ERROR_BAD_PARAMETERS;
        }
        return rnp_decrypt_file((void *) ctx, io->in->filepath, io->out->filepath);
    } else if (io->in->type == REPGP_HANDLE_BUFFER) {
        const int ret = rnp_decrypt_memory((void *) ctx,
                                           io->in->buffer.data,
                                           io->in->buffer.size,
                                           (char *) io->out->buffer.data,
                                           io->out->buffer.size);
        return ret ? RNP_SUCCESS : RNP_ERROR_GENERIC;
    }

    return RNP_ERROR_BAD_PARAMETERS;
}

void
repgp_set_input(repgp_io_t *io, repgp_handle_t *stream)
{
    if (io) {
        repgp_destroy_handle(io->in);
        io->in = (struct repgp_handle *) stream;
    }
}

void
repgp_set_output(repgp_io_t *io, repgp_handle_t *stream)
{
    if (io) {
        repgp_destroy_handle(io->out);
        io->out = (struct repgp_handle *) stream;
    }
}

repgp_io_t *
repgp_create_io(void)
{
    struct repgp_io *io = malloc(sizeof(struct repgp_io));
    if (!io) {
        return REPGP_HANDLE_NULL;
    }

    io->in = REPGP_HANDLE_NULL;
    io->out = REPGP_HANDLE_NULL;

    return (repgp_io_t *) io;
}

void
repgp_destroy_io(repgp_io_t *io)
{
    if (io) {
        repgp_destroy_handle(io->in);
        repgp_destroy_handle(io->out);
    }
    free(io);
}

static pgp_cb_ret_t
cb_list_packets(const pgp_packet_t *pkt, pgp_cbdata_t *cbinfo)
{
    pgp_print_packet(&cbinfo->printstate, pkt);
    return PGP_RELEASE_MEMORY;
}

rnp_result
repgp_list_packets(const void *ctx, const repgp_handle_t *input)
{
    const rnp_ctx_t *rctx = (rnp_ctx_t *) ctx;
    if (!rctx || !rctx->rnp || (input == REPGP_HANDLE_NULL)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    const struct repgp_handle *i = (struct repgp_handle *) input;
    if ((i == REPGP_HANDLE_NULL) || (i->type != REPGP_HANDLE_FILE)) {
        RNP_LOG("Incorrectly initialized input handle");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    struct stat st;
    if (stat(i->filepath, &st) < 0) {
        RNP_LOG("No such file '%s'", i->filepath);
        return RNP_ERROR_ACCESS;
    }

    const rnp_t *rnp = rctx->rnp;
    if (!rnp_key_store_load_from_file(
          /*unconst */ (rnp_t *) rnp, rnp->pubring, rctx->armour)) {
        RNP_LOG("Keystore can't load data");
        return RNP_ERROR_GENERIC;
    }

    pgp_stream_t *stream = NULL;
    int           fd =
      pgp_setup_file_read(rctx->rnp->io, &stream, i->filepath, NULL, cb_list_packets, 1);
    repgp_parse_options(stream, PGP_PTAG_SS_ALL, REPGP_PARSE_PARSED);
    stream->cryptinfo.secring = rnp->secring;
    stream->cryptinfo.pubring = rnp->pubring;
    stream->cryptinfo.passphrase_provider = rnp->passphrase_provider;
    if (rctx->armour) {
        pgp_reader_push_dearmour(stream);
    }

    if (!repgp_parse(stream, true)) {
        pgp_teardown_file_read(stream, fd);
        return RNP_ERROR_GENERIC;
    }
    pgp_teardown_file_read(stream, fd);
    return RNP_SUCCESS;
}

rnp_result
repgp_validate_pubkeys_signatures(const void *ctx)
{
    const struct rnp_ctx_t *rctx = (rnp_ctx_t *) ctx;
    if (!rctx || !rctx->rnp) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    const rnp_key_store_t *ring = rctx->rnp->pubring;
    pgp_validation_t       result = {0};
    bool                   ret = true;
    for (size_t n = 0; n < ring->keyc; ++n) {
        ret &= pgp_validate_key_sigs(
          &result, &ring->keys[n], ring, NULL /* no pwd callback; validating public keys */);
    }

    ret &= validate_result_status("keyring", &result);
    return ret ? RNP_SUCCESS : RNP_ERROR_GENERIC;
}
