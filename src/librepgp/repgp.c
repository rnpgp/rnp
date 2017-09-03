#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>

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

repgp_handle_t
create_filepath_handle(const char *filename, size_t filename_len)
{
    if ((filename == NULL) || (filename_len == 0)) {
        return REPGP_HANDLE_NULL;
    }

    struct repgp_handle *s = calloc(sizeof(struct repgp_handle), 1);
    if (!s) {
        return REPGP_HANDLE_NULL;
    }

    s->filepath = strndup(filename, filename_len);
    s->type = REPGP_HANDLE_FILE;
    return s;
}

repgp_handle_t
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

/* Reads into memory everything from stdin */
repgp_handle_t create_stdin_handle(
  void) // OZAPTF: rename this to something that means "I've read from stdin all stuff"
{
    char     buf[BUFSIZ * 8];
    uint8_t *data = NULL;
    size_t   size = 0;
    size_t   n;

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
        size_t newsize = size + ((n / BUFSIZ) + 1) * BUFSIZ;
        // OZAPTF: Check it
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

    s->type = REPGP_HANDLE_STD;
    s->std.size = size;
    s->std.data = data;
    return s;
}

void
repgp_destroy_handle(repgp_handle_t stream)
{
    struct repgp_handle *s = (struct repgp_handle *) stream;

    if (!s)
        return;

    if (s->type == REPGP_HANDLE_STD) {
        free(s->filepath);
    } else if (s->type == REPGP_HANDLE_FILE) {
        free(s->filepath);
    } else if (s->type == REPGP_HANDLE_BUFFER) {
        free(s->buffer.data);
    } else {
        /* Must never happen */
        assert(false);
    }
    free(s);
}

rnp_result
repgp_verify(const void *ctx, repgp_io_t io)
{
    struct repgp_io *rio = (struct repgp_io *) io;
    if (!rio || !rio->in) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    void * output = NULL;
    size_t output_size = 0;

    if (rio->out) {
        /* Where should I output */
        switch (rio->out->type) {
        case REPGP_HANDLE_FILE:
            output = rio->out->filepath;
            break;
        case REPGP_HANDLE_STD:
            output = rio->out->std.data;
            break;
        case REPGP_HANDLE_BUFFER:
            output = rio->out->buffer.data;
            output_size = rio->out->buffer.size;
            break;
        default:
            RNP_LOG("Unsupported output stream");
            return RNP_ERROR_BAD_PARAMETERS;
        }
    }

    if (rio->in->type == REPGP_HANDLE_FILE) {
        return rnp_verify_file((rnp_ctx_t *) ctx, rio->in->filepath, output);
    } else if (rio->in->type == REPGP_HANDLE_STD) {
        return rnp_verify_memory(
          (rnp_ctx_t *) ctx, rio->in->std.data, rio->in->std.size, output, output_size);
    }

    RNP_LOG("Unsupported input stream");
    return RNP_ERROR_BAD_PARAMETERS;
}

rnp_result
repgp_decrypt(const void *ctx, repgp_io_t io)
{
    struct repgp_io *rio = (struct repgp_io *) io;
    if (!rio || !rio->in || !rio->out) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    if (rio->in->type == REPGP_HANDLE_FILE) {
        return rnp_decrypt_file((void *) ctx, rio->in->filepath, rio->out->filepath);
    } else if (rio->in->type == REPGP_HANDLE_STD) {
        return rnp_decrypt_memory((void *) ctx,
                                  rio->in->std.data,
                                  rio->in->std.size,
                                  (char *) rio->out->buffer.data,
                                  rio->out->buffer.size);
    }

    return RNP_SUCCESS;
}

void
repgp_set_input(repgp_io_t io, repgp_handle_t stream)
{
    struct repgp_io *rio = (struct repgp_io *) io;
    if (rio) {
        repgp_destroy_handle(rio->in);
        rio->in = (struct repgp_handle *) stream;
    }
}

void
repgp_set_output(repgp_io_t io, repgp_handle_t stream)
{
    struct repgp_io *rio = (struct repgp_io *) io;
    if (rio) {
        repgp_destroy_handle(rio->out);
        rio->out = (struct repgp_handle *) stream;
    }
}

repgp_io_t
repgp_create_io(void)
{
    struct repgp_io *io = malloc(sizeof(struct repgp_io));
    io->in = REPGP_HANDLE_NULL;
    io->out = REPGP_HANDLE_NULL;

    return (repgp_io_t) io;
}

void
repgp_destroy_io(repgp_io_t io)
{
    struct repgp_io *rio = (struct repgp_io *) io;
    if (rio) {
        repgp_destroy_handle(rio->in);
        repgp_destroy_handle(rio->out);
    }
    free(rio);
}

static pgp_cb_ret_t
cb_list_packets(const pgp_packet_t *pkt, pgp_cbdata_t *cbinfo)
{
    pgp_print_packet(&cbinfo->printstate, pkt);
    return PGP_RELEASE_MEMORY;
}

rnp_result
repgp_list_packets(const void *ctx, const repgp_handle_t input)
{
    const rnp_ctx_t *rctx = (rnp_ctx_t *) ctx;
    if (!rctx || !rctx->rnp || (input == REPGP_HANDLE_NULL)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    const struct repgp_handle *i = (struct repgp_handle *) input;
    if ((i == REPGP_HANDLE_NULL) || (i->type != REPGP_HANDLE_FILE)) {
        // Currently only file input is supported
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

/**
 * \ingroup HighLevel_Verify
 * \brief Validate all signatures on a single key against the given keyring
 * \param result Where to put the result
 * \param key Key to validate
 * \param keyring Keyring to use for validation
 * \param cb_get_passphrase Callback to use to get passphrase
 * \return 1 if all signatures OK; else 0
 * \note It is the caller's responsiblity to free result after use.
 * \sa pgp_validate_result_free()
 */
/**
   \ingroup HighLevel_Verify
   \param result Where to put the result
   \param ring Keyring to use
   \param cb_get_passphrase Callback to use to get passphrase
   \note It is the caller's responsibility to free result after use.
   \sa pgp_validate_result_free()
*/
rnp_result
repgp_validate_pubkeys_signatures(const void *ctx)
{
    const struct rnp_ctx_t *rctx = (rnp_ctx_t *) ctx;
    if (!rctx || !rctx->rnp) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    const rnp_key_store_t *ring = rctx->rnp->pubring;
    pgp_validation_t       result = {0};
    for (size_t n = 0; n < ring->keyc; ++n) {
        /* TODO: return value probably should be checked
         *       but I need to double check it
         */
        (void) pgp_validate_key_sigs(
          &result, &ring->keys[n], ring, NULL /* no pwd callback; validating public keys */);
    }
    return validate_result_status("keyring", &result);
}
