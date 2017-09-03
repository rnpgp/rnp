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

repgp_stream_t
create_filepath_stream(const char *filename, size_t filename_len)
{
    if ((filename == NULL) || (filename_len == 0)) {
        return REPGP_HANDLE_NULL;
    }

    struct repgp_stream *s = calloc(sizeof(struct repgp_stream), 1);
    if (!s) {
        return REPGP_HANDLE_NULL;
    }

    s->filepath = strndup(filename, filename_len);
    s->type = REPGP_STREAM_FILE;
    return s;
}

repgp_stream_t
create_buffer_stream(const size_t buffer_size)
{
    struct repgp_stream *s = calloc(sizeof(struct repgp_stream), 1);
    if (!s) {
        return REPGP_HANDLE_NULL;
    }

    s->buffer.data = (unsigned char *) malloc(buffer_size);
    if (!s->buffer.data) {
        return REPGP_HANDLE_NULL;
    }

    s->buffer.size = buffer_size;
    s->type = REPGP_STREAM_BUFFER;
    return s;
}

/* Reads into memory everything from stdin */
repgp_stream_t create_stdin_stream(
  void) // OZAPTF: rename this to something that means "I've read from stdin all stuff"
{
    char     buf[BUFSIZ * 8];
    uint8_t *data = NULL;
    size_t   size = 0;
    size_t   n;

    struct repgp_stream *s = calloc(sizeof(struct repgp_stream), 1);
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

    s->type = REPGP_STREAM_STD;
    s->std.size = size;
    s->std.data = data;
    return s;
}

void
repgp_destroy_stream(repgp_stream_t stream)
{
    struct repgp_stream *s = (struct repgp_stream *) stream;

    if (!s)
        return;

    if (s->type == REPGP_STREAM_STD) {
        free(s->filepath);
    } else if (s->type == REPGP_STREAM_FILE) {
        free(s->filepath);
    } else if (s->type == REPGP_STREAM_BUFFER) {
        free(s->buffer.data);
    } else {
        /* Must never happen */
        assert(false);
    }
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
        case REPGP_STREAM_FILE:
            output = rio->out->filepath;
            break;
        case REPGP_STREAM_STD:
            output = rio->out->std.data;
            break;
        case REPGP_STREAM_BUFFER:
            output = rio->out->buffer.data;
            output_size = rio->out->buffer.size;
            break;
        default:
            RNP_LOG("Unsupported output stream");
            return RNP_ERROR_BAD_PARAMETERS;
        }
    }

    if (rio->in->type == REPGP_STREAM_FILE) {
        return rnp_verify_file((rnp_ctx_t *) ctx, rio->in->filepath, output);
    } else if (rio->in->type == REPGP_STREAM_STD) {
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

    if (rio->in->type == REPGP_STREAM_FILE) {
        return rnp_decrypt_file((void *) ctx, rio->in->filepath, rio->out->filepath);
    } else if (rio->in->type == REPGP_STREAM_STD) {
        return rnp_decrypt_memory((void *) ctx,
                                  rio->in->std.data,
                                  rio->in->std.size,
                                  (char *) rio->out->buffer.data,
                                  rio->out->buffer.size);
    }

    return RNP_SUCCESS;
}

void
repgp_set_input(repgp_io_t io, repgp_stream_t stream)
{
    struct repgp_io *rio = (struct repgp_io *) io;
    if (rio) {
        rio->in = stream;
    }
}

void
repgp_set_output(repgp_io_t io, repgp_stream_t stream)
{
    struct repgp_io *rio = (struct repgp_io *) io;
    if (rio) {
        rio->out = stream;
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
        repgp_destroy_stream(rio->in);
        repgp_destroy_stream(rio->out);
    }
}

static pgp_cb_ret_t
cb_list_packets(const pgp_packet_t *pkt, pgp_cbdata_t *cbinfo)
{
    pgp_print_packet(&cbinfo->printstate, pkt);
    return PGP_RELEASE_MEMORY;
}

rnp_result
repgp_list_packets(const void *ctx, const repgp_stream_t input)
{
    const rnp_ctx_t *rctx = (rnp_ctx_t *) ctx;
    if (!rctx || !rctx->rnp || (input == REPGP_HANDLE_NULL)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    const struct repgp_stream *i = (struct repgp_stream *) input;
    if ((i == REPGP_HANDLE_NULL) || (i->type != REPGP_STREAM_FILE)) {
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
    pgp_parse_options(stream, PGP_PTAG_SS_ALL, PGP_PARSE_PARSED);
    stream->cryptinfo.secring = rnp->secring;
    stream->cryptinfo.pubring = rnp->pubring;
    stream->cryptinfo.passphrase_provider = rnp->passphrase_provider;
    if (rctx->armour) {
        pgp_reader_push_dearmour(stream);
    }

    if (!pgp_parse(stream, true)) {
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
static rnp_result
pgp_validate_key_sigs(pgp_validation_t *     result,
                      const pgp_key_t *      key,
                      const rnp_key_store_t *keyring,
                      pgp_cb_ret_t cb_get_passphrase(const pgp_packet_t *, pgp_cbdata_t *))
{
    pgp_stream_t *    stream;
    validate_key_cb_t keysigs;
    const bool        printerrors = true;

    (void) memset(&keysigs, 0x0, sizeof(keysigs));
    keysigs.result = result;
    keysigs.getpassphrase = cb_get_passphrase;

    stream = pgp_new(sizeof(*stream));
    /* pgp_parse_options(&opt,PGP_PTAG_CT_SIGNATURE,PGP_PARSE_PARSED); */

    keysigs.keyring = keyring;

    pgp_set_callback(stream, pgp_validate_key_cb, &keysigs);
    stream->readinfo.accumulate = 1;
    if (!pgp_key_reader_set(stream, key)) {
        return false;
    }

    /* Note: Coverity incorrectly reports an error that keysigs.reader */
    /* is never used. */
    keysigs.reader = stream->readinfo.arg;

    pgp_parse(stream, !printerrors);

    pgp_pubkey_free(&keysigs.pubkey);
    if (keysigs.subkey.version) {
        pgp_pubkey_free(&keysigs.subkey);
    }
    pgp_userid_free(&keysigs.userid);
    pgp_data_free(&keysigs.userattr);

    pgp_stream_delete(stream);

    return (!result->invalidc && !result->unknownc && result->validc);
}

static char *
fmtsecs(int64_t n, char *buf, size_t size)
{
    if (n > 365 * 24 * 60 * 60) {
        n /= (365 * 24 * 60 * 60);
        (void) snprintf(buf, size, "%" PRId64 " year%s", n, (n == 1) ? "" : "s");
        return buf;
    }
    if (n > 30 * 24 * 60 * 60) {
        n /= (30 * 24 * 60 * 60);
        (void) snprintf(buf, size, "%" PRId64 " month%s", n, (n == 1) ? "" : "s");
        return buf;
    }
    if (n > 24 * 60 * 60) {
        n /= (24 * 60 * 60);
        (void) snprintf(buf, size, "%" PRId64 " day%s", n, (n == 1) ? "" : "s");
        return buf;
    }
    if (n > 60 * 60) {
        n /= (60 * 60);
        (void) snprintf(buf, size, "%" PRId64 " hour%s", n, (n == 1) ? "" : "s");
        return buf;
    }
    if (n > 60) {
        n /= 60;
        (void) snprintf(buf, size, "%" PRId64 " minute%s", n, (n == 1) ? "" : "s");
        return buf;
    }
    (void) snprintf(buf, size, "%" PRId64 " second%s", n, (n == 1) ? "" : "s");
    return buf;
}

/**
 * \ingroup HighLevel_Verify
 * \brief Indicicates whether any errors were found
 * \param result Validation result to check
 * \return 0 if any invalid signatures or unknown signers
        or no valid signatures; else 1
 */
static bool
validate_result_status(const char *f, pgp_validation_t *val)
{
    time_t now;
    time_t t;
    char   buf[128];

    now = time(NULL);
    if (now < val->birthtime) {
        /* signature is not valid yet! */
        if (f) {
            (void) fprintf(stderr, "\"%s\": ", f);
        } else {
            (void) fprintf(stderr, "memory ");
        }
        (void) fprintf(stderr,
                       "signature not valid until %.24s (%s)\n",
                       ctime(&val->birthtime),
                       fmtsecs((int64_t)(val->birthtime - now), buf, sizeof(buf)));
        return false;
    }
    if (val->duration != 0 && now > val->birthtime + val->duration) {
        /* signature has expired */
        t = val->duration + val->birthtime;
        if (f) {
            (void) fprintf(stderr, "\"%s\": ", f);
        } else {
            (void) fprintf(stderr, "memory ");
        }
        (void) fprintf(stderr,
                       "signature not valid after %.24s (%s ago)\n",
                       ctime(&t),
                       fmtsecs((int64_t)(now - t), buf, sizeof(buf)));
        return false;
    }
    return val->validc && !val->invalidc && !val->unknownc;
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
